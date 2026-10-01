//! S3-compatible certificate storage signed with AWS Signature Version 4.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::provider::{BackgroundGuard, CertProvider, ProviderFuture};

const IMDS_ENDPOINT: &str = "http://169.254.169.254";

/// Configuration for an S3-compatible object store.
///
/// Empty access and secret keys use the standard AWS environment variables.
/// A custom endpoint can point to S3-compatible services such as MinIO.
#[derive(Clone)]
pub struct S3Config {
    /// Bucket that receives the certificate files.
    pub bucket_name: String,
    /// Store endpoint, including `https://` or `http://`.
    pub endpoint: String,
    /// Explicit access key, or empty to use `AWS_ACCESS_KEY_ID`.
    pub access_key: String,
    /// Explicit secret key, or empty to use `AWS_SECRET_ACCESS_KEY`.
    pub secret_key: String,
    /// Signing region; empty uses `AWS_REGION` or `us-east-1`.
    pub region: String,
    /// Optional key prefix, often a domain name.
    pub prefix: Option<String>,
}

impl S3Config {
    /// Read S3 settings from environment variables.
    ///
    /// Bucket and endpoint use `NAGO_ACME_S3_BUCKET` and
    /// `NAGO_ACME_S3_ENDPOINT`. The endpoint defaults to the regional AWS S3
    /// endpoint. Credentials use the standard AWS environment variable names.
    pub fn from_env() -> Result<Self> {
        let bucket_name = env_nonempty("NAGO_ACME_S3_BUCKET")
            .or_else(|| env_nonempty("AWS_BUCKET_NAME"))
            .ok_or_else(|| Error::Config("NAGO_ACME_S3_BUCKET is required".into()))?;
        let region = env_nonempty("AWS_REGION")
            .or_else(|| env_nonempty("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| "us-east-1".into());
        let endpoint = env_nonempty("NAGO_ACME_S3_ENDPOINT")
            .or_else(|| env_nonempty("AWS_ENDPOINT_URL_S3"))
            .unwrap_or_else(|| {
                if region == "us-east-1" {
                    "https://s3.amazonaws.com".into()
                } else {
                    format!("https://s3.{region}.amazonaws.com")
                }
            });
        Ok(Self {
            bucket_name,
            endpoint,
            access_key: String::new(),
            secret_key: String::new(),
            region,
            prefix: env_nonempty("NAGO_ACME_S3_PREFIX"),
        })
    }
}

/// Certificate and account-cache synchronization with an S3-compatible store.
pub struct S3CertSync {
    config: S3Config,
    endpoint: Endpoint,
    imdsv2: bool,
    session_token: Option<String>,
}

impl S3CertSync {
    /// Validate and create a sync client.
    pub fn new(mut config: S3Config) -> Result<Self> {
        if config.bucket_name.trim().is_empty() {
            return Err(Error::Config("S3 bucket name is required".into()));
        }
        if config.region.trim().is_empty() {
            config.region = env_nonempty("AWS_REGION")
                .or_else(|| env_nonempty("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|| "us-east-1".into());
        }
        let endpoint = Endpoint::parse(&config.endpoint)?;
        Ok(Self {
            config,
            endpoint,
            imdsv2: false,
            session_token: None,
        })
    }

    /// Read configuration from environment variables and create a sync client.
    pub fn from_env() -> Result<Self> {
        Self::new(S3Config::from_env()?)
    }

    /// Enable credential lookup through an IMDSv2 token and role credentials.
    ///
    /// This is used only when explicit credentials and environment credentials
    /// are unavailable.
    #[must_use]
    pub fn with_imdsv2(mut self) -> Self {
        self.imdsv2 = true;
        self
    }

    /// Supply a session token alongside explicit access and secret keys.
    #[must_use]
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    /// Upload any present certificate, private-key, and account-cache files.
    pub async fn push_from(&self, cert_dir: &Path) -> Result<()> {
        for relative in stored_files() {
            let path = cert_dir.join(relative);
            let body = match std::fs::read(&path) {
                Ok(body) => body,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            self.put_object(&self.object_key(relative), &body).await?;
        }
        Ok(())
    }

    /// Download any present stored files into the certificate directory.
    /// Missing objects are ignored so a new store can be initialized.
    pub async fn pull_to(&self, cert_dir: &Path) -> Result<()> {
        for relative in stored_files() {
            let Some(body) = self.get_object(&self.object_key(relative)).await? else {
                continue;
            };
            let path = cert_dir.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if relative == "privkey.pem" || relative == "acme_cache/acme_account_credentials.json" {
                crate::acme::write_secret_file(&path, &body)?;
            } else {
                std::fs::write(path, body)?;
            }
        }
        Ok(())
    }

    /// Upload one object.
    pub async fn put_object(&self, key: &str, body: &[u8]) -> Result<()> {
        let response = self.request("PUT", key, body).await?;
        if !(200..300).contains(&response.status) {
            return Err(http_error(
                "S3 object upload",
                response.status,
                &response.body,
            ));
        }
        Ok(())
    }

    /// Download one object, returning `None` when it does not exist.
    pub async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let response = self.request("GET", key, &[]).await?;
        if response.status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&response.status) {
            return Err(http_error(
                "S3 object download",
                response.status,
                &response.body,
            ));
        }
        Ok(Some(response.body))
    }

    fn object_key(&self, relative: &str) -> String {
        let prefix = self
            .config
            .prefix
            .as_deref()
            .unwrap_or_default()
            .trim_matches('/');
        if prefix.is_empty() {
            relative.to_owned()
        } else {
            format!("{prefix}/{relative}")
        }
    }

    async fn request(&self, method: &str, key: &str, body: &[u8]) -> Result<S3Response> {
        let credentials = self.credentials().await?;
        let date_time = format_utc(SystemTime::now())?;
        let payload_hash = sha256_hex(body);
        let path = self.endpoint.object_path(&self.config.bucket_name, key);
        let host = self.endpoint.authority.to_ascii_lowercase();
        let mut signed_headers = vec![
            ("host".to_owned(), host),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), date_time.clone()),
        ];
        if let Some(token) = &credentials.session_token {
            signed_headers.push(("x-amz-security-token".into(), token.clone()));
        }
        let authorization = sign_v4(
            method,
            &path,
            "",
            &signed_headers,
            &payload_hash,
            &credentials.access_key,
            &credentials.secret_key,
            &self.config.region,
            &date_time,
        );
        let mut headers = vec![
            ("x-amz-content-sha256".into(), payload_hash),
            ("x-amz-date".into(), date_time),
            ("Authorization".into(), authorization),
        ];
        if let Some(token) = credentials.session_token {
            headers.push(("x-amz-security-token".into(), token));
        }
        let url = format!(
            "{}://{}{}",
            self.endpoint.scheme, self.endpoint.authority, path
        );
        let client =
            nago_http::Client::global().map_err(|error| Error::HttpClient(error.to_string()))?;
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value): &(String, String)| (name.as_str(), value.as_str()))
            .collect();
        let response = if method == "GET" {
            client.send(method, &url, &headers, None).await
        } else {
            client
                .send(
                    method,
                    &url,
                    &headers,
                    Some(("application/octet-stream", body)),
                )
                .await
        }
        .map_err(|error| Error::HttpClient(error.to_string()))?;
        Ok(S3Response {
            status: response.status,
            body: response.body,
        })
    }

    async fn credentials(&self) -> Result<Credentials> {
        let explicit_access = !self.config.access_key.is_empty();
        let explicit_secret = !self.config.secret_key.is_empty();
        if explicit_access || explicit_secret {
            if !(explicit_access && explicit_secret) {
                return Err(Error::Config(
                    "explicit S3 credentials require both access_key and secret_key".into(),
                ));
            }
            return Ok(Credentials {
                access_key: self.config.access_key.clone(),
                secret_key: self.config.secret_key.clone(),
                session_token: self.session_token.clone(),
            });
        }
        match (
            env_nonempty("AWS_ACCESS_KEY_ID"),
            env_nonempty("AWS_SECRET_ACCESS_KEY"),
        ) {
            (Some(access_key), Some(secret_key)) => {
                return Ok(Credentials {
                    access_key,
                    secret_key,
                    session_token: env_nonempty("AWS_SESSION_TOKEN"),
                });
            }
            (None, None) => {}
            _ => {
                return Err(Error::Config(
                    "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together".into(),
                ));
            }
        }
        if self.imdsv2 {
            return self.imdsv2_credentials().await;
        }
        Err(Error::Config(
            "S3 credentials are missing; set explicit credentials or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY".into(),
        ))
    }

    async fn imdsv2_credentials(&self) -> Result<Credentials> {
        let client =
            nago_http::Client::global().map_err(|error| Error::HttpClient(error.to_string()))?;
        let token_response = client
            .send(
                "PUT",
                &format!("{IMDS_ENDPOINT}/latest/api/token"),
                &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
                None,
            )
            .await
            .map_err(|error| Error::HttpClient(format!("IMDSv2 token request: {error}")))?;
        if !(200..300).contains(&token_response.status) {
            return Err(http_error(
                "IMDSv2 token request",
                token_response.status,
                &token_response.body,
            ));
        }
        let token = String::from_utf8(token_response.body)
            .map_err(|error| Error::Config(format!("IMDSv2 token was not UTF-8: {error}")))?;
        let headers = [("X-aws-ec2-metadata-token", token.trim())];
        let role_response = client
            .get(
                &format!("{IMDS_ENDPOINT}/latest/meta-data/iam/security-credentials/"),
                &headers,
            )
            .await
            .map_err(|error| Error::HttpClient(format!("IMDSv2 role request: {error}")))?;
        if !(200..300).contains(&role_response.status) {
            return Err(http_error(
                "IMDSv2 role request",
                role_response.status,
                &role_response.body,
            ));
        }
        let role = String::from_utf8(role_response.body)
            .map_err(|error| Error::Config(format!("IMDSv2 role was not UTF-8: {error}")))?;
        let role = role.trim();
        if role.is_empty() || role.contains('/') || role.contains("..") {
            return Err(Error::Config("IMDSv2 returned an invalid role name".into()));
        }
        let credentials_response = client
            .get(
                &format!("{IMDS_ENDPOINT}/latest/meta-data/iam/security-credentials/{role}"),
                &headers,
            )
            .await
            .map_err(|error| Error::HttpClient(format!("IMDSv2 credentials request: {error}")))?;
        if !(200..300).contains(&credentials_response.status) {
            return Err(http_error(
                "IMDSv2 credentials request",
                credentials_response.status,
                &credentials_response.body,
            ));
        }
        let credentials: ImdsCredentials = serde_json::from_slice(&credentials_response.body)
            .map_err(|error| Error::Config(format!("IMDSv2 credentials JSON: {error}")))?;
        if credentials.code != "Success" {
            return Err(Error::Config(format!(
                "IMDSv2 credentials request returned {}",
                credentials.code
            )));
        }
        Ok(Credentials {
            access_key: credentials.access_key_id,
            secret_key: credentials.secret_access_key,
            session_token: Some(credentials.token),
        })
    }
}

/// Wrap a certificate provider so remote files are pulled before provisioning
/// and pushed after the initial certificate is ready.
pub struct S3CertProvider<P: CertProvider> {
    inner: P,
    sync: std::sync::Arc<S3CertSync>,
}

impl<P: CertProvider> S3CertProvider<P> {
    /// Wrap a provider with an already-created shared sync client.
    #[must_use]
    pub fn from_arc(inner: P, sync: std::sync::Arc<S3CertSync>) -> Self {
        Self { inner, sync }
    }
}

impl<P: CertProvider> CertProvider for S3CertProvider<P> {
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a> {
        Box::pin(async move {
            self.sync.pull_to(&cert_dir).await?;
            let guard = self.inner.init(cert_dir.clone(), domains).await?;
            self.sync.push_from(&cert_dir).await?;
            Ok(BackgroundGuard::holding(guard))
        })
    }
}

#[derive(Clone)]
struct Credentials {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

struct S3Response {
    status: u16,
    body: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImdsCredentials {
    code: String,
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

#[derive(Clone)]
struct Endpoint {
    scheme: String,
    authority: String,
    path_prefix: String,
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self> {
        let (scheme, remainder) = value
            .split_once("://")
            .ok_or_else(|| Error::Config("S3 endpoint must include http:// or https://".into()))?;
        if scheme != "http" && scheme != "https" {
            return Err(Error::Config(
                "S3 endpoint scheme must be http or https".into(),
            ));
        }
        let authority_end = remainder.find('/').unwrap_or(remainder.len());
        let (authority, path) = remainder.split_at(authority_end);
        if authority.is_empty()
            || authority.contains('@')
            || authority.contains('?')
            || authority.contains('#')
            || path.contains('?')
            || path.contains('#')
        {
            return Err(Error::Config("S3 endpoint is malformed".into()));
        }
        if authority.chars().any(char::is_whitespace) || path.chars().any(char::is_whitespace) {
            return Err(Error::Config(
                "S3 endpoint cannot contain whitespace".into(),
            ));
        }
        let path_prefix = path.trim_end_matches('/').to_owned();
        Ok(Self {
            scheme: scheme.to_owned(),
            authority: authority.to_ascii_lowercase(),
            path_prefix,
        })
    }

    fn object_path(&self, bucket: &str, key: &str) -> String {
        let bucket = uri_encode(bucket.as_bytes());
        let key = encode_key(key);
        format!("{}/{bucket}/{key}", self.path_prefix)
    }
}

fn stored_files() -> [&'static str; 3] {
    [
        "fullchain.pem",
        "privkey.pem",
        "acme_cache/acme_account_credentials.json",
    ]
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn http_error(service: &str, status: u16, body: &[u8]) -> Error {
    Error::HttpClient(format!(
        "{service} returned HTTP {status}: {}",
        String::from_utf8_lossy(body)
    ))
}

fn encode_key(key: &str) -> String {
    key.split('/')
        .map(|segment| uri_encode(segment.as_bytes()))
        .collect::<Vec<_>>()
        .join("/")
}

fn uri_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

#[allow(clippy::too_many_arguments)]
fn sign_v4(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    date_time: &str,
) -> String {
    let date = &date_time[..8];
    let mut canonical_headers = BTreeMap::new();
    for (name, value) in headers {
        canonical_headers.insert(name.to_ascii_lowercase(), normalize_header(value));
    }
    let signed_headers = canonical_headers
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = canonical_headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date_time}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let mut key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    key = hmac_sha256(&key, region.as_bytes());
    key = hmac_sha256(&key, b"s3");
    key = hmac_sha256(&key, b"aws4_request");
    let signature = hex_encode(&hmac_sha256(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={signed_headers},Signature={signature}"
    )
}

fn normalize_header(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message)
        .as_ref()
        .to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn format_utc(time: SystemTime) -> Result<String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::Config(format!("system clock predates Unix epoch: {error}")))?
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const EMPTY_HASH: &str = EMPTY_SHA256;

    #[test]
    fn sigv4_matches_aws_get_object_vector() {
        let headers = vec![
            ("host".into(), "examplebucket.s3.amazonaws.com".into()),
            ("range".into(), "bytes=0-9".into()),
            ("x-amz-content-sha256".into(), EMPTY_HASH.into()),
            ("x-amz-date".into(), "20130524T000000Z".into()),
        ];
        let authorization = sign_v4(
            "GET",
            "/test.txt",
            "",
            &headers,
            EMPTY_HASH,
            ACCESS,
            SECRET,
            "us-east-1",
            "20130524T000000Z",
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn sigv4_matches_aws_put_object_vector() {
        let payload = b"Welcome to Amazon S3.";
        let payload_hash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        assert_eq!(sha256_hex(payload), payload_hash);
        let headers = vec![
            ("date".into(), "Fri, 24 May 2013 00:00:00 GMT".into()),
            ("host".into(), "examplebucket.s3.amazonaws.com".into()),
            ("x-amz-content-sha256".into(), payload_hash.into()),
            ("x-amz-date".into(), "20130524T000000Z".into()),
            ("x-amz-storage-class".into(), "REDUCED_REDUNDANCY".into()),
        ];
        let authorization = sign_v4(
            "PUT",
            "/test%24file.text",
            "",
            &headers,
            payload_hash,
            ACCESS,
            SECRET,
            "us-east-1",
            "20130524T000000Z",
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn endpoint_and_object_keys_are_encoded_without_normalizing_slashes() {
        let endpoint = Endpoint::parse("https://store.example:9000/s3/").unwrap();
        assert_eq!(endpoint.authority, "store.example:9000");
        assert_eq!(
            endpoint.object_path("certs", "site name/fullchain.pem"),
            "/s3/certs/site%20name/fullchain.pem"
        );
    }
}
