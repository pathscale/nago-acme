//! DNS provider interface and the built-in bunny.net implementation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::acme::{HttpRequest, HttpResponse, NagoTransport, Transport};
use crate::error::{Error, Result};

/// A boxed, sendable future used by [`DnsProvider`].
pub type DnsFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Implement this to plug in a DNS provider for DNS-01 challenges.
///
/// Methods receive the fully-qualified `_acme-challenge.<domain>` name and
/// the TXT record value. `cleanup_txt_records` defaults to a no-op for APIs
/// that cannot list records.
pub trait DnsProvider: Send + Sync + 'static {
    /// Remove stale challenge TXT records at a name before starting a new
    /// challenge. Providers that cannot list records may keep this no-op.
    fn cleanup_txt_records<'a>(&'a self, _fqdn: &'a str) -> DnsFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    /// Add a TXT record for the challenge.
    fn add_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a>;

    /// Remove a TXT record after the challenge finishes.
    fn remove_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a>;
}

impl<T: DnsProvider> DnsProvider for Arc<T> {
    fn cleanup_txt_records<'a>(&'a self, fqdn: &'a str) -> DnsFuture<'a> {
        Box::pin(async move { self.as_ref().cleanup_txt_records(fqdn).await })
    }

    fn add_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move { self.as_ref().add_txt_record(fqdn, value).await })
    }

    fn remove_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move { self.as_ref().remove_txt_record(fqdn, value).await })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZone {
    id: u64,
    domain: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneList {
    items: Vec<BunnyZone>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyRecord {
    id: u64,
    #[serde(rename = "Type")]
    record_type: u8,
    name: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyZoneDetail {
    #[serde(rename = "Records")]
    dns_records: Vec<BunnyRecord>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BunnyAddRecord<'a> {
    #[serde(rename = "Type")]
    record_type: u8,
    name: &'a str,
    value: &'a str,
    ttl: u32,
}

/// DNS-01 provider backed by the bunny.net DNS API.
///
/// Create an API key in the bunny.net dashboard and pass it to [`Self::new`].
pub struct BunnyDns {
    api_key: String,
    transport: Arc<dyn Transport>,
}

impl BunnyDns {
    /// Create a Bunny DNS client using the shared nago-http transport.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            transport: Arc::new(NagoTransport),
        }
    }

    fn base(&self) -> &'static str {
        "https://api.bunny.net"
    }

    async fn find_zone(&self, fqdn: &str) -> Result<(u64, String)> {
        let name = fqdn.trim_end_matches('.');
        let parts: Vec<&str> = name.split('.').collect();
        for index in 0..parts.len().saturating_sub(1) {
            let candidate = parts[index..].join(".");
            let url = format!(
                "{}/dnszone?search={}&page=1&perPage=10",
                self.base(),
                candidate
            );
            let response = self
                .request(
                    "GET",
                    url,
                    vec![("accept".into(), "application/json".into())],
                    None,
                )
                .await?;
            if !response.is_success() {
                continue;
            }
            let zones: BunnyZoneList = serde_json::from_slice(&response.body)
                .map_err(|error| Error::AcmeProtocol(format!("bunny.net zones JSON: {error}")))?;
            for zone in zones.items {
                if is_domain_or_subdomain(name, &zone.domain) {
                    return Ok((zone.id, zone.domain));
                }
            }
        }
        Err(Error::Config(format!(
            "bunny.net: no DNS zone found for {fqdn}"
        )))
    }

    fn relative_name<'a>(&self, fqdn: &'a str, zone_domain: &str) -> &'a str {
        let name = fqdn.trim_end_matches('.');
        let zone = zone_domain.trim_end_matches('.');
        if name.eq_ignore_ascii_case(zone) {
            return "@";
        }
        let suffix = format!(".{}", zone.to_ascii_lowercase());
        if name.to_ascii_lowercase().ends_with(&suffix) {
            let relative_end = name.len() - suffix.len();
            if let Some(relative) = name.get(..relative_end) {
                return relative;
            }
        }
        name
    }

    async fn records(&self, zone_id: u64) -> Result<Vec<BunnyRecord>> {
        let response = self
            .request(
                "GET",
                format!("{}/dnszone/{zone_id}", self.base()),
                vec![("accept".into(), "application/json".into())],
                None,
            )
            .await?;
        if !response.is_success() {
            return Err(http_status_error("bunny.net zone fetch", &response));
        }
        let detail: BunnyZoneDetail = serde_json::from_slice(&response.body)
            .map_err(|error| Error::AcmeProtocol(format!("bunny.net zone JSON: {error}")))?;
        Ok(detail.dns_records)
    }

    async fn delete_record(&self, zone_id: u64, record_id: u64) -> Result<()> {
        let response = self
            .request(
                "DELETE",
                format!("{}/dnszone/{zone_id}/records/{record_id}", self.base()),
                Vec::new(),
                None,
            )
            .await?;
        if !response.is_success() {
            return Err(http_status_error("bunny.net record delete", &response));
        }
        Ok(())
    }

    async fn request(
        &self,
        method: &str,
        url: String,
        mut headers: Vec<(String, String)>,
        body: Option<(String, Vec<u8>)>,
    ) -> Result<HttpResponse> {
        headers.push(("AccessKey".into(), self.api_key.clone()));
        self.transport
            .request(HttpRequest {
                method: method.to_owned(),
                url,
                headers,
                body,
            })
            .await
    }
}

impl DnsProvider for BunnyDns {
    fn cleanup_txt_records<'a>(&'a self, fqdn: &'a str) -> DnsFuture<'a> {
        Box::pin(async move {
            let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
            let record_name = self.relative_name(fqdn, &zone_domain);
            let records = self.records(zone_id).await?;
            let conflicts: Vec<String> = records
                .iter()
                .filter(|record| {
                    record.name.eq_ignore_ascii_case(record_name) && record.record_type != 3
                })
                .map(|record| format!("id={} type={}", record.id, record.record_type))
                .collect();
            if !conflicts.is_empty() {
                return Err(Error::Config(format!(
                    "bunny.net: non-TXT record conflicts with {fqdn}: {}",
                    conflicts.join(", ")
                )));
            }
            for record in records.iter().filter(|record| {
                record.name.eq_ignore_ascii_case(record_name) && record.record_type == 3
            }) {
                self.delete_record(zone_id, record.id).await?;
            }
            Ok(())
        })
    }

    fn add_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move {
            let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
            let record_name = self.relative_name(fqdn, &zone_domain);
            let payload = BunnyAddRecord {
                record_type: 3,
                name: record_name,
                value,
                ttl: 120,
            };
            let body = serde_json::to_vec(&payload)
                .map_err(|error| Error::Config(format!("serialize Bunny record: {error}")))?;
            let response = self
                .request(
                    "PUT",
                    format!("{}/dnszone/{zone_id}/records", self.base()),
                    vec![("accept".into(), "application/json".into())],
                    Some(("application/json".into(), body)),
                )
                .await?;
            if !response.is_success() {
                return Err(http_status_error("bunny.net TXT add", &response));
            }
            Ok(())
        })
    }

    fn remove_txt_record<'a>(&'a self, fqdn: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move {
            let (zone_id, zone_domain) = self.find_zone(fqdn).await?;
            let record_name = self.relative_name(fqdn, &zone_domain);
            let records = self.records(zone_id).await?;
            for record in records.iter().filter(|record| {
                record.record_type == 3
                    && record.name.eq_ignore_ascii_case(record_name)
                    && record.value == value
            }) {
                self.delete_record(zone_id, record.id).await?;
            }
            Ok(())
        })
    }
}

fn is_domain_or_subdomain(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    let lowered_name = name.to_ascii_lowercase();
    let lowered_zone = zone.to_ascii_lowercase();
    name.eq_ignore_ascii_case(zone) || lowered_name.ends_with(&format!(".{lowered_zone}"))
}

fn http_status_error(service: &str, response: &HttpResponse) -> Error {
    Error::HttpClient(format!(
        "{service} returned HTTP {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    ))
}
