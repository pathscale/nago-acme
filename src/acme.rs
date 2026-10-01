//! RFC 8555 client, order state machine, and certificate issuance flow.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::dns::DnsProvider;
use crate::error::{Error, Result};
use crate::jwk::{AccountKey, base64url_encode};
use crate::jws::flattened_jws;

const STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
const MAX_ORDER_POLL_DELAY: Duration = Duration::from_secs(30);
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug)]
pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<(String, Vec<u8>)>,
}

#[derive(Clone, Debug)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl HttpResponse {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub(crate) trait Transport: Send + Sync {
    fn request<'a>(&'a self, request: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>>;
}

pub(crate) struct NagoTransport;

impl Transport for NagoTransport {
    fn request<'a>(&'a self, request: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>> {
        Box::pin(async move {
            let client = nago_http::Client::global()
                .map_err(|error| Error::HttpClient(error.to_string()))?;
            let headers: Vec<(&str, &str)> = request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let response = match request.body.as_ref() {
                Some((content_type, bytes)) => {
                    client
                        .send(
                            &request.method,
                            &request.url,
                            &headers,
                            Some((content_type.as_str(), bytes.as_slice())),
                        )
                        .await
                }
                None => {
                    client
                        .send(&request.method, &request.url, &headers, None)
                        .await
                }
            }
            .map_err(|error| Error::HttpClient(error.to_string()))?;
            Ok(HttpResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            })
        })
    }
}

fn http_status_error(service: &str, response: &HttpResponse) -> Error {
    Error::HttpClient(format!(
        "{service} returned HTTP {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    ))
}

fn parse_json<T: for<'de> Deserialize<'de>>(response: &HttpResponse, service: &str) -> Result<T> {
    if !response.is_success() {
        return Err(http_status_error(service, response));
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| Error::AcmeProtocol(format!("{service} returned invalid JSON: {error}")))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Serialize, Deserialize)]
struct CachedCredentials {
    directory_url: String,
    kid: String,
    account_key_pkcs8_hex: String,
}

/// An authenticated ACME account session.
pub(crate) struct AcmeClient {
    transport: Arc<dyn Transport>,
    directory: AcmeDirectory,
    key: AccountKey,
    kid: Mutex<Option<String>>,
    replay_nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    fn new(
        transport: Arc<dyn Transport>,
        directory: AcmeDirectory,
        key: AccountKey,
        kid: Option<String>,
        replay_nonce: Option<String>,
    ) -> Self {
        Self {
            transport,
            directory,
            key,
            kid: Mutex::new(kid),
            replay_nonce: Mutex::new(replay_nonce),
        }
    }

    fn set_kid(&self, kid: String) {
        *self.kid.lock().expect("ACME kid mutex poisoned") = Some(kid);
    }

    fn remember_nonce(&self, response: &HttpResponse) {
        if let Some(nonce) = response.header("Replay-Nonce") {
            *self.replay_nonce.lock().expect("ACME nonce mutex poisoned") = Some(nonce.to_owned());
        }
    }

    async fn fetch_nonce(&self) -> Result<String> {
        let response = self
            .transport
            .request(HttpRequest {
                method: "HEAD".into(),
                url: self.directory.new_nonce.clone(),
                headers: Vec::new(),
                body: None,
            })
            .await?;
        if !response.is_success() {
            return Err(http_status_error("ACME newNonce", &response));
        }
        let nonce = response
            .header("Replay-Nonce")
            .ok_or_else(|| Error::AcmeProtocol("newNonce response omitted Replay-Nonce".into()))?
            .to_owned();
        Ok(nonce)
    }

    async fn next_nonce(&self) -> Result<String> {
        if let Some(nonce) = self
            .replay_nonce
            .lock()
            .expect("ACME nonce mutex poisoned")
            .take()
        {
            return Ok(nonce);
        }
        self.fetch_nonce().await
    }

    async fn signed_post(&self, url: &str, payload: &[u8]) -> Result<HttpResponse> {
        for attempt in 0..=1 {
            let nonce = self.next_nonce().await?;
            let kid = self.kid.lock().expect("ACME kid mutex poisoned").clone();
            let (body, _) = flattened_jws(&self.key, &nonce, url, payload, kid.as_deref())?;
            let response = self
                .transport
                .request(HttpRequest {
                    method: "POST".into(),
                    url: url.to_owned(),
                    headers: Vec::new(),
                    body: Some(("application/jose+json".into(), body)),
                })
                .await?;
            self.remember_nonce(&response);
            if attempt == 0 && response_is_bad_nonce(&response) {
                continue;
            }
            return Ok(response);
        }
        Err(Error::AcmeProtocol(
            "ACME server rejected a request nonce twice".into(),
        ))
    }

    async fn post_json(&self, url: &str, payload: &Value) -> Result<HttpResponse> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| Error::AcmeProtocol(format!("serialize ACME payload: {error}")))?;
        self.signed_post(url, &body).await
    }

    async fn post_as_get(&self, url: &str) -> Result<HttpResponse> {
        self.signed_post(url, &[]).await
    }
}

fn response_is_bad_nonce(response: &HttpResponse) -> bool {
    if response.status != 400 {
        return false;
    }
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|problem| {
            problem
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|problem_type| problem_type.ends_with(":badNonce"))
}

pub(crate) async fn load_or_create_account(
    cache_dir: &Path,
    email: &str,
    production: bool,
) -> Result<Arc<AcmeClient>> {
    let directory_url = if production {
        PRODUCTION_DIRECTORY
    } else {
        STAGING_DIRECTORY
    };
    let credentials_path = cache_dir.join("acme_account_credentials.json");
    let cached = std::fs::read_to_string(&credentials_path)
        .ok()
        .and_then(|json| serde_json::from_str::<CachedCredentials>(&json).ok());
    let (key, cached_kid) = match cached {
        Some(credentials) if credentials.directory_url == directory_url => {
            match hex_decode(&credentials.account_key_pkcs8_hex)
                .and_then(|bytes| AccountKey::from_pkcs8(bytes).ok())
            {
                Some(key) => (key, Some(credentials.kid)),
                None => (AccountKey::generate()?, None),
            }
        }
        _ => (AccountKey::generate()?, None),
    };

    let transport: Arc<dyn Transport> = Arc::new(NagoTransport);
    let directory_response = transport
        .request(HttpRequest {
            method: "GET".into(),
            url: directory_url.to_owned(),
            headers: vec![("Accept".into(), "application/json".into())],
            body: None,
        })
        .await?;
    let replay_nonce = directory_response.header("Replay-Nonce").map(str::to_owned);
    let directory: AcmeDirectory = parse_json(&directory_response, "ACME directory")?;
    let client = Arc::new(AcmeClient::new(
        transport,
        directory,
        key,
        cached_kid,
        replay_nonce,
    ));

    let needs_registration = client
        .kid
        .lock()
        .expect("ACME kid mutex poisoned")
        .is_none();
    if needs_registration {
        let contact = format!("mailto:{email}");
        let response = client
            .post_json(
                &client.directory.new_account,
                &json!({"contact":[contact], "termsOfServiceAgreed":true}),
            )
            .await?;
        if !response.is_success() {
            return Err(Error::Account(format!(
                "ACME newAccount failed: {}",
                String::from_utf8_lossy(&response.body)
            )));
        }
        let kid = response
            .header("Location")
            .ok_or_else(|| Error::Account("newAccount response omitted Location".into()))?
            .to_owned();
        client.set_kid(kid);
        let credentials = CachedCredentials {
            directory_url: directory_url.to_owned(),
            kid: client
                .kid
                .lock()
                .expect("ACME kid mutex poisoned")
                .clone()
                .expect("kid was just set"),
            account_key_pkcs8_hex: hex_encode(client.key.pkcs8()),
        };
        let encoded = serde_json::to_vec_pretty(&credentials)
            .map_err(|error| Error::Account(format!("serialize account credentials: {error}")))?;
        write_secret_file(&credentials_path, &encoded)?;
    }
    Ok(client)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(encoded: &str) -> Option<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    Ok(())
}

/// Build an RFC 8555 DNS-01 key authorization from a challenge token and JWK
/// thumbprint.
#[must_use]
pub fn key_authorization(token: &str, account_thumbprint: &str) -> String {
    format!("{token}.{account_thumbprint}")
}

/// Compute the base64url SHA-256 DNS TXT value for an ACME key authorization.
#[must_use]
pub fn dns_txt_value(key_authorization: &str) -> String {
    crate::jwk::sha256_base64url(key_authorization.as_bytes())
}

fn generate_csr(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = KeyPair::generate()
        .map_err(|error| Error::Config(format!("CSR key generation: {error}")))?;
    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|error| Error::Config(format!("CSR parameters: {error}")))?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|error| Error::Config(format!("CSR serialization: {error}")))?;
    Ok((csr.der().to_vec(), key_pair.serialize_pem().into_bytes()))
}

pub(crate) fn read_cert_not_after(fullchain_path: &Path) -> Result<SystemTime> {
    let pem_bytes = std::fs::read(fullchain_path)?;
    let (_, pem) = parse_x509_pem(&pem_bytes)
        .map_err(|error| Error::Config(format!("certificate PEM parse: {error}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|error| Error::Config(format!("certificate DER parse: {error}")))?;
    let timestamp = cert.validity().not_after.timestamp();
    if timestamp < 0 {
        return Err(Error::Config(
            "certificate NotAfter is before the Unix epoch".into(),
        ));
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
}

#[derive(Deserialize)]
struct AcmeOrder {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    #[serde(default)]
    finalize: String,
    certificate: Option<String>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct AcmeAuthorization {
    status: String,
    identifier: AcmeIdentifier,
    #[serde(default)]
    challenges: Vec<AcmeChallenge>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct AcmeIdentifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}

struct ChallengeInfo {
    fqdn: String,
    dns_value: String,
}

pub(crate) async fn issue_certificate<D: DnsProvider>(
    dns: &D,
    account: &AcmeClient,
    domains: &[String],
    propagation_secs: u64,
    cert_dir: &Path,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
) -> Result<()> {
    let mut challenges = Vec::new();
    let result = issue_certificate_inner(
        dns,
        account,
        domains,
        propagation_secs,
        cert_dir,
        cancel,
        notify,
        &mut challenges,
    )
    .await;
    for challenge in &challenges {
        let _ = dns
            .remove_txt_record(&challenge.fqdn, &challenge.dns_value)
            .await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn issue_certificate_inner<D: DnsProvider>(
    dns: &D,
    account: &AcmeClient,
    domains: &[String],
    propagation_secs: u64,
    cert_dir: &Path,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
    cleanup: &mut Vec<ChallengeInfo>,
) -> Result<()> {
    check_cancelled(cancel)?;
    let identifiers: Vec<Value> = domains
        .iter()
        .map(|domain| json!({"type":"dns", "value":domain}))
        .collect();
    let response = account
        .post_json(
            &account.directory.new_order,
            &json!({"identifiers":identifiers}),
        )
        .await?;
    let mut order: AcmeOrder = parse_json(&response, "ACME newOrder")?;
    let order_url = response
        .header("Location")
        .ok_or_else(|| Error::Order("newOrder response omitted Location".into()))?
        .to_owned();

    let mut cleaned_names = HashSet::new();
    let mut challenge_urls = Vec::new();
    for authorization_url in &order.authorizations {
        check_cancelled(cancel)?;
        let response = account.post_as_get(authorization_url).await?;
        let authorization: AcmeAuthorization = parse_json(&response, "ACME authorization")?;
        if authorization.status == "valid" {
            continue;
        }
        if authorization.status == "invalid" {
            return Err(Error::Challenge(
                authorization
                    .error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "ACME authorization became invalid".into()),
            ));
        }
        if authorization.identifier.kind != "dns" {
            return Err(Error::Config(
                "ACME authorization identifier is not DNS".into(),
            ));
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "dns-01")
            .ok_or_else(|| Error::Challenge("ACME server offered no DNS-01 challenge".into()))?;
        if challenge.token.is_empty() {
            return Err(Error::Challenge(
                "ACME DNS-01 challenge token was empty".into(),
            ));
        }
        let fqdn = format!("_acme-challenge.{}", authorization.identifier.value);
        if cleaned_names.insert(fqdn.clone()) {
            dns.cleanup_txt_records(&fqdn).await?;
        }
        let authorization = key_authorization(&challenge.token, &account.key.thumbprint());
        let dns_value = dns_txt_value(&authorization);
        dns.add_txt_record(&fqdn, &dns_value).await?;
        cleanup.push(ChallengeInfo { fqdn, dns_value });
        challenge_urls.push(challenge.url.clone());
    }

    if !cleanup.is_empty()
        && wait_or_cancel(cancel, notify, Duration::from_secs(propagation_secs)).await
    {
        return Err(Error::Cancelled);
    }
    check_cancelled(cancel)?;

    for challenge_url in challenge_urls {
        let response = account.post_json(&challenge_url, &json!({})).await?;
        if !response.is_success() {
            return Err(Error::Challenge(format!(
                "ACME challenge acknowledgement failed: {}",
                String::from_utf8_lossy(&response.body)
            )));
        }
    }

    order = poll_order(
        account,
        &order_url,
        OrderGoal::Ready,
        Duration::from_secs(1),
        cancel,
        notify,
    )
    .await?;

    let (csr, private_key) = generate_csr(domains)?;
    check_cancelled(cancel)?;
    if order.finalize.is_empty() {
        return Err(Error::Order("ACME order omitted finalize URL".into()));
    }
    let response = account
        .post_json(&order.finalize, &json!({"csr":base64url_encode(&csr)}))
        .await?;
    if !response.is_success() {
        return Err(Error::Order(format!(
            "ACME finalize failed: {}",
            String::from_utf8_lossy(&response.body)
        )));
    }

    order = poll_order(
        account,
        &order_url,
        OrderGoal::Valid,
        Duration::from_secs(1),
        cancel,
        notify,
    )
    .await?;
    let certificate_url = order
        .certificate
        .ok_or_else(|| Error::Order("valid ACME order omitted certificate URL".into()))?;
    let response = account.post_as_get(&certificate_url).await?;
    if !response.is_success() {
        return Err(http_status_error("ACME certificate download", &response));
    }
    if !response
        .body
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----")
    {
        return Err(Error::Pem(
            "ACME certificate response was not a PEM chain".into(),
        ));
    }
    std::fs::write(cert_dir.join("fullchain.pem"), &response.body)?;
    write_secret_file(&cert_dir.join("privkey.pem"), &private_key)?;
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OrderGoal {
    Ready,
    Valid,
}

async fn poll_order(
    account: &AcmeClient,
    order_url: &str,
    goal: OrderGoal,
    first_delay: Duration,
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
) -> Result<AcmeOrder> {
    let mut delay = first_delay;
    loop {
        check_cancelled(cancel)?;
        let response = account.post_as_get(order_url).await?;
        let order: AcmeOrder = parse_json(&response, "ACME order status")?;
        if order.status == "invalid" {
            let detail = order
                .error
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "ACME order became invalid".into());
            return Err(Error::Challenge(detail));
        }
        let reached = match goal {
            OrderGoal::Ready => order.status == "ready" || order.status == "valid",
            OrderGoal::Valid => order.status == "valid",
        };
        if reached {
            return Ok(order);
        }
        if !matches!(order.status.as_str(), "pending" | "processing" | "ready") {
            return Err(Error::Order(format!(
                "unexpected ACME order status {}",
                order.status
            )));
        }
        if wait_or_cancel(cancel, notify, delay).await {
            return Err(Error::Cancelled);
        }
        delay = delay.saturating_mul(2).min(MAX_ORDER_POLL_DELAY);
    }
}

fn check_cancelled(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

async fn wait_or_cancel(
    cancel: Option<&AtomicBool>,
    notify: Option<&nagoya::sync::Notify>,
    duration: Duration,
) -> bool {
    if cancel.is_none() {
        if !duration.is_zero() {
            nagoya::sleep(duration).await;
        }
        return false;
    }
    let Some(cancel) = cancel else {
        return false;
    };
    if let Some(notify) = notify {
        let mut notified = std::pin::pin!(notify.notified());
        let mut timer = std::pin::pin!(nagoya::sleep(duration));
        return std::future::poll_fn(|context| {
            if cancel.load(Ordering::Acquire) {
                return std::task::Poll::Ready(true);
            }
            if notified.as_mut().poll(context).is_ready() {
                return std::task::Poll::Ready(true);
            }
            if timer.as_mut().poll(context).is_ready() {
                return std::task::Poll::Ready(cancel.load(Ordering::Acquire));
            }
            std::task::Poll::Pending
        })
        .await;
    }
    let mut remaining = duration;
    while !remaining.is_zero() && !cancel.load(Ordering::Acquire) {
        let slice = remaining.min(CANCEL_POLL_INTERVAL);
        nagoya::sleep(slice).await;
        remaining = remaining.saturating_sub(slice);
    }
    cancel.load(Ordering::Acquire)
}

pub(crate) async fn renewal_loop<F, Fut>(
    cancel: Arc<AtomicBool>,
    notify: Arc<nagoya::sync::Notify>,
    mut next: F,
) where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Duration> + Send,
{
    loop {
        if cancel.load(Ordering::Acquire) {
            return;
        }
        let delay = next().await;
        if wait_or_cancel(Some(cancel.as_ref()), Some(notify.as_ref()), delay).await {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Clone)]
    struct RecordedRequest {
        method: String,
        url: String,
        body: Option<(String, Vec<u8>)>,
    }

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    impl FakeTransport {
        fn with_responses(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Transport for FakeTransport {
        fn request<'a>(&'a self, request: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(RecordedRequest {
                    method: request.method,
                    url: request.url,
                    body: request.body,
                });
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| Error::HttpClient("fake response queue is empty".into()))
            })
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn test_client(transport: Arc<dyn Transport>, nonce: &str) -> AcmeClient {
        AcmeClient::new(
            transport,
            AcmeDirectory {
                new_nonce: "https://ca.example/new-nonce".into(),
                new_account: "https://ca.example/new-account".into(),
                new_order: "https://ca.example/new-order".into(),
            },
            AccountKey::generate().unwrap(),
            Some("https://ca.example/account/1".into()),
            Some(nonce.into()),
        )
    }

    #[test]
    fn key_authorization_and_txt_value_match_rfc_8555() {
        let authorization = key_authorization("token", "thumb");
        assert_eq!(authorization, "token.thumb");
        assert_eq!(
            dns_txt_value(&authorization),
            "lCdftpJCXapaZHkBGIZbcubeKW8RmA0jSG_aZN01zbU"
        );
    }

    #[test]
    fn bad_nonce_retries_once_using_the_replay_nonce() {
        let fake = Arc::new(FakeTransport::with_responses(vec![
            response(
                400,
                &[("Replay-Nonce", "nonce-retry")],
                r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#,
            ),
            response(200, &[("Replay-Nonce", "nonce-next")], "{}"),
        ]));
        let client = test_client(fake.clone(), "nonce-first");
        let result =
            nagoya::block_on(client.post_json("https://ca.example/action", &json!({"x":1})));
        assert_eq!(result.unwrap().status, 200);
        let requests = fake.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, "https://ca.example/action");
        assert_eq!(
            requests[0].body.as_ref().unwrap().0,
            "application/jose+json"
        );
        let first: Value = serde_json::from_slice(&requests[0].body.as_ref().unwrap().1).unwrap();
        let second: Value = serde_json::from_slice(&requests[1].body.as_ref().unwrap().1).unwrap();
        let first_header: Value = serde_json::from_slice(
            &crate::jwk::base64url_decode(first["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let second_header: Value = serde_json::from_slice(
            &crate::jwk::base64url_decode(second["protected"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(first_header["nonce"], "nonce-first");
        assert_eq!(second_header["nonce"], "nonce-retry");
    }

    #[test]
    fn order_state_machine_polls_pending_ready_processing_and_valid() {
        let fake = Arc::new(FakeTransport::with_responses(vec![
            response(200, &[("Replay-Nonce", "n1")], r#"{"status":"pending"}"#),
            response(200, &[("Replay-Nonce", "n2")], r#"{"status":"ready"}"#),
            response(200, &[("Replay-Nonce", "n3")], r#"{"status":"processing"}"#),
            response(
                200,
                &[("Replay-Nonce", "n4")],
                r#"{"status":"valid","certificate":"https://ca.example/cert/1"}"#,
            ),
        ]));
        let client = test_client(fake.clone(), "n0");
        let ready = nagoya::block_on(poll_order(
            &client,
            "https://ca.example/order/1",
            OrderGoal::Ready,
            Duration::ZERO,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(ready.status, "ready");
        let valid = nagoya::block_on(poll_order(
            &client,
            "https://ca.example/order/1",
            OrderGoal::Valid,
            Duration::ZERO,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(valid.status, "valid");
        assert_eq!(
            valid.certificate.as_deref(),
            Some("https://ca.example/cert/1")
        );
        assert_eq!(fake.requests().len(), 4);
    }
}
