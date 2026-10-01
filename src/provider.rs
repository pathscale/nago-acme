//! Certificate provider and renewal loop.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::acme::{issue_certificate, load_or_create_account, read_cert_not_after, renewal_loop};
use crate::dns::DnsProvider;
use crate::error::{Error, Result};

const DEFAULT_PROPAGATION_SECS: u64 = 60;
const DEFAULT_RENEW_WITHIN_DAYS: u64 = 30;
const MAX_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(86_400);

/// A sendable future returned by [`CertProvider::init`].
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<RenewalGuard>> + Send + 'a>>;

/// Prepare local certificate files and return a guard for the renewal loop.
pub trait CertProvider: Send + Sync + 'static {
    /// Provision certificates in `cert_dir` for `domains` and start renewal.
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a>;
}

impl<T: CertProvider + ?Sized> CertProvider for Box<T> {
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a> {
        self.as_mut().init(cert_dir, domains)
    }
}

/// Keep this value alive for the process lifetime. Dropping it stops the
/// background renewal task at its next wait or challenge boundary.
pub struct BackgroundGuard {
    stop: Arc<AtomicBool>,
    notify: Arc<nagoya::sync::Notify>,
    keepalive: Option<Box<dyn Send>>,
}

/// Handle that stops the nagoya renewal loop when dropped.
pub type RenewalGuard = BackgroundGuard;

impl BackgroundGuard {
    pub(crate) fn with_atomic_cancel(
        stop: Arc<AtomicBool>,
        notify: Arc<nagoya::sync::Notify>,
    ) -> Self {
        Self {
            stop,
            notify,
            keepalive: None,
        }
    }

    pub(crate) fn holding(guard: BackgroundGuard) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(nagoya::sync::Notify::new()),
            keepalive: Some(Box::new(guard)),
        }
    }
}

impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.notify.notify_waiters();
        drop(self.keepalive.take());
    }
}

/// ACME provider using DNS-01 challenges.
pub struct DnsAcmeProvider<D: DnsProvider> {
    contact_email: String,
    dns: Arc<D>,
    production: bool,
    propagation_secs: u64,
    renew_within_days: u64,
    max_retries: u32,
    #[cfg(feature = "s3")]
    s3_sync: Option<Arc<crate::s3::S3CertSync>>,
}

impl<D: DnsProvider> DnsAcmeProvider<D> {
    /// Create a provider using the staging ACME directory by default.
    #[must_use]
    pub fn new(contact_email: impl Into<String>, dns: D) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns: Arc::new(dns),
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
            max_retries: 0,
            #[cfg(feature = "s3")]
            s3_sync: None,
        }
    }

    /// Create a provider with a shared DNS backend.
    #[must_use]
    pub fn from_arc(contact_email: impl Into<String>, dns: Arc<D>) -> Self {
        Self {
            contact_email: contact_email.into(),
            dns,
            production: false,
            propagation_secs: DEFAULT_PROPAGATION_SECS,
            renew_within_days: DEFAULT_RENEW_WITHIN_DAYS,
            max_retries: 0,
            #[cfg(feature = "s3")]
            s3_sync: None,
        }
    }

    /// Use the Let's Encrypt production directory.
    #[must_use]
    pub fn production(mut self) -> Self {
        self.production = true;
        self
    }

    /// Seconds to wait after publishing TXT records before acknowledging
    /// challenges.
    #[must_use]
    pub fn propagation_secs(mut self, secs: u64) -> Self {
        self.propagation_secs = secs;
        self
    }

    /// Begin renewal this many days before the certificate expires.
    #[must_use]
    pub fn renew_within_days(mut self, days: u64) -> Self {
        self.renew_within_days = days;
        self
    }

    /// Number of DNS challenge retries after the initial attempt.
    #[must_use]
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sync the account cache and certificates with an S3-compatible store.
    #[cfg(feature = "s3")]
    #[must_use]
    pub fn with_s3_sync(mut self, sync: Arc<crate::s3::S3CertSync>) -> Self {
        self.s3_sync = Some(sync);
        self
    }
}

impl<D: DnsProvider> CertProvider for DnsAcmeProvider<D> {
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a> {
        Box::pin(async move {
            let domains = domains.ok_or_else(|| Error::Config("domains are required".into()))?;
            if domains.is_empty() {
                return Err(Error::Config("at least one domain is required".into()));
            }
            std::fs::create_dir_all(&cert_dir)?;
            let cache_dir = cert_dir.join("acme_cache");
            std::fs::create_dir_all(&cache_dir)?;
            let fullchain_path = cert_dir.join("fullchain.pem");
            let private_key_path = cert_dir.join("privkey.pem");

            if !fullchain_path.exists() || !private_key_path.exists() {
                let account =
                    load_or_create_account(&cache_dir, &self.contact_email, self.production)
                        .await?;
                #[cfg(feature = "s3")]
                if let Some(sync) = &self.s3_sync {
                    sync.push_from(&cert_dir).await?;
                }
                let mut retries_left = self.max_retries;
                let mut retry_number = 0u64;
                loop {
                    match issue_certificate(
                        &self.dns,
                        &account,
                        &domains,
                        self.propagation_secs,
                        &cert_dir,
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(()) => break,
                        Err(Error::Challenge(_)) if retries_left > 0 => {
                            retries_left -= 1;
                            retry_number += 1;
                            let delay = Duration::from_secs(
                                self.propagation_secs.saturating_mul(retry_number),
                            );
                            nagoya::sleep(delay).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }

            let stop = Arc::new(AtomicBool::new(false));
            let notify = Arc::new(nagoya::sync::Notify::new());
            let task_stop = stop.clone();
            let task_notify = notify.clone();
            let dns = self.dns.clone();
            let task_cert_dir = cert_dir.clone();
            let task_cache_dir = cache_dir.clone();
            let contact_email = self.contact_email.clone();
            let task_domains = domains.clone();
            let production = self.production;
            let propagation_secs = self.propagation_secs;
            let renew_within = Duration::from_secs(self.renew_within_days.saturating_mul(86_400));
            let retry_delay = Arc::new(Mutex::new(Duration::from_secs(3_600)));
            #[cfg(feature = "s3")]
            let s3_sync = self.s3_sync.clone();

            drop(nagoya::spawn({
                let retry_delay = retry_delay.clone();
                let dns = dns.clone();
                let task_cert_dir = task_cert_dir.clone();
                let task_cache_dir = task_cache_dir.clone();
                let contact_email = contact_email.clone();
                let task_domains = task_domains.clone();
                let task_stop = task_stop.clone();
                let task_notify = task_notify.clone();
                #[cfg(feature = "s3")]
                let s3_sync = s3_sync.clone();
                async move {
                    renewal_loop(task_stop.clone(), task_notify.clone(), move || {
                        let retry_delay = retry_delay.clone();
                        let dns = dns.clone();
                        let task_cert_dir = task_cert_dir.clone();
                        let task_cache_dir = task_cache_dir.clone();
                        let contact_email = contact_email.clone();
                        let task_domains = task_domains.clone();
                        let task_stop = task_stop.clone();
                        let task_notify = task_notify.clone();
                        #[cfg(feature = "s3")]
                        let s3_sync = s3_sync.clone();
                        async move {
                            let current_retry = *retry_delay.lock().expect("retry mutex poisoned");
                            let until_renewal =
                                match read_cert_not_after(&task_cert_dir.join("fullchain.pem")) {
                                    Ok(not_after) => {
                                        *retry_delay.lock().expect("retry mutex poisoned") =
                                            Duration::from_secs(3_600);
                                        let renew_at = not_after
                                            .checked_sub(renew_within)
                                            .unwrap_or(not_after);
                                        renew_at
                                            .duration_since(SystemTime::now())
                                            .unwrap_or(Duration::ZERO)
                                    }
                                    Err(_) => {
                                        *retry_delay.lock().expect("retry mutex poisoned") =
                                            (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                        return current_retry;
                                    }
                                };
                            if !until_renewal.is_zero() {
                                return until_renewal;
                            }
                            if task_stop.load(Ordering::Acquire) {
                                return Duration::ZERO;
                            }
                            let account = match load_or_create_account(
                                &task_cache_dir,
                                &contact_email,
                                production,
                            )
                            .await
                            {
                                Ok(account) => account,
                                Err(_) => {
                                    *retry_delay.lock().expect("retry mutex poisoned") =
                                        (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                    return current_retry;
                                }
                            };
                            match issue_certificate(
                                &dns,
                                &account,
                                &task_domains,
                                propagation_secs,
                                &task_cert_dir,
                                Some(task_stop.as_ref()),
                                Some(task_notify.as_ref()),
                            )
                            .await
                            {
                                Ok(()) => {
                                    *retry_delay.lock().expect("retry mutex poisoned") =
                                        Duration::from_secs(3_600);
                                    #[cfg(feature = "s3")]
                                    if let Some(sync) = &s3_sync {
                                        let _ = sync.push_from(&task_cert_dir).await;
                                    }
                                    Duration::ZERO
                                }
                                Err(Error::Cancelled) => Duration::ZERO,
                                Err(_) => {
                                    *retry_delay.lock().expect("retry mutex poisoned") =
                                        (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                    current_retry
                                }
                            }
                        }
                    })
                    .await;
                }
            }));
            Ok(BackgroundGuard::with_atomic_cancel(stop, notify))
        })
    }
}

/// Compatibility namespace for callers moving from the previous provider
/// package. New code can import DNS types from [`crate::dns`].
pub mod dns01 {
    pub use super::DnsAcmeProvider;
    pub use crate::dns::{BunnyDns, DnsProvider};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_guard_stops_a_waiting_renewal_loop() {
        let cancel = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(nagoya::sync::Notify::new());
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let guard = BackgroundGuard::with_atomic_cancel(cancel.clone(), notify.clone());
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(guard);
        });
        let tick_counter = ticks.clone();
        nagoya::block_on(renewal_loop(cancel, notify, move || {
            tick_counter.fetch_add(1, Ordering::Relaxed);
            async { Duration::from_secs(3_600) }
        }));
        canceller.join().unwrap();
        assert_eq!(ticks.load(Ordering::Relaxed), 1);
    }
}
