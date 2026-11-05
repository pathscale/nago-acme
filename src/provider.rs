//! Certificate provider and renewal loop.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::acme::{issue_certificate, load_or_create_account, read_cert_not_after, renewal_loop};
use crate::certificate::{AcmeState, CertificateMaterial};
use crate::dns::DnsProvider;
use crate::error::{Error, Result};
use crate::jwk::AccountKey;

const DEFAULT_PROPAGATION_SECS: u64 = 60;
const DEFAULT_RENEW_WITHIN_DAYS: u64 = 30;
const MAX_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(86_400);

/// A sendable future returned by [`CertProvider::init`].
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<RenewalGuard>> + Send + 'a>>;

/// Prepare a public certificate-chain file and return a guard for renewal.
pub trait CertProvider: Send + Sync + 'static {
    /// Provision `fullchain.pem` in `cert_dir` for `domains` and start renewal.
    /// Private keys remain in the provider's in-memory state.
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
    state: Option<AcmeState>,
    keepalive: Option<Box<dyn Send>>,
}

/// Handle that stops the nagoya renewal loop when dropped.
pub type RenewalGuard = BackgroundGuard;

impl BackgroundGuard {
    pub(crate) fn with_atomic_cancel(
        stop: Arc<AtomicBool>,
        notify: Arc<nagoya::sync::Notify>,
        state: AcmeState,
    ) -> Self {
        Self {
            stop,
            notify,
            state: Some(state),
            keepalive: None,
        }
    }

    pub(crate) fn holding(guard: BackgroundGuard) -> Self {
        let state = guard.state.clone();
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(nagoya::sync::Notify::new()),
            state,
            keepalive: Some(Box::new(guard)),
        }
    }

    /// Return the latest certificate and private key held in memory.
    #[must_use]
    pub fn certificate(&self) -> Option<CertificateMaterial> {
        self.state.as_ref().and_then(AcmeState::certificate)
    }

    /// Return the ACME account key held in memory.
    #[must_use]
    pub fn account_key(&self) -> Option<AccountKey> {
        self.state.as_ref().and_then(AcmeState::account_key)
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
    state: AcmeState,
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
            state: AcmeState::new(),
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
            state: AcmeState::new(),
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

    /// Share certificate and account-key state with the application.
    #[must_use]
    pub fn with_state(mut self, state: AcmeState) -> Self {
        self.state = state;
        self
    }

    /// Sync public certificate chains with an S3-compatible store.
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
            let fullchain_path = cert_dir.join("fullchain.pem");
            let state = self.state.clone();
            let mut initial_account = None;
            if let Some(certificate) = state.certificate() {
                std::fs::write(&fullchain_path, certificate.fullchain_pem())?;
            } else {
                let account =
                    load_or_create_account(&self.contact_email, self.production, &state).await?;
                let mut retries_left = self.max_retries;
                let mut retry_number = 0u64;
                loop {
                    match issue_certificate(
                        &self.dns,
                        &account,
                        &domains,
                        self.propagation_secs,
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(certificate) => {
                            install_certificate(&cert_dir, &state, certificate)?;
                            break;
                        }
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
                initial_account = Some(account);
            }

            #[cfg(feature = "s3")]
            if let Some(sync) = &self.s3_sync {
                sync.push_from(&cert_dir).await?;
            }

            let stop = Arc::new(AtomicBool::new(false));
            let notify = Arc::new(nagoya::sync::Notify::new());
            let task_stop = stop.clone();
            let task_notify = notify.clone();
            let dns = self.dns.clone();
            let task_cert_dir = cert_dir.clone();
            let task_state = state.clone();
            let task_account = Arc::new(Mutex::new(initial_account));
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
                let task_state = task_state.clone();
                let task_account = task_account.clone();
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
                        let task_state = task_state.clone();
                        let task_account = task_account.clone();
                        let contact_email = contact_email.clone();
                        let task_domains = task_domains.clone();
                        let task_stop = task_stop.clone();
                        let task_notify = task_notify.clone();
                        #[cfg(feature = "s3")]
                        let s3_sync = s3_sync.clone();
                        async move {
                            let current_retry = *retry_delay.lock().expect("retry mutex poisoned");
                            let until_renewal = match task_state
                                .certificate()
                                .ok_or_else(|| Error::Config("certificate is missing".into()))
                                .and_then(|certificate| {
                                    read_cert_not_after(certificate.fullchain_pem())
                                }) {
                                Ok(not_after) => {
                                    *retry_delay.lock().expect("retry mutex poisoned") =
                                        Duration::from_secs(3_600);
                                    let renew_at =
                                        not_after.checked_sub(renew_within).unwrap_or(not_after);
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
                            let cached_account = {
                                task_account
                                    .lock()
                                    .expect("account task mutex poisoned")
                                    .clone()
                            };
                            let account = match cached_account {
                                Some(account) => account,
                                None => {
                                    let account = match load_or_create_account(
                                        &contact_email,
                                        production,
                                        &task_state,
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
                                    *task_account.lock().expect("account task mutex poisoned") =
                                        Some(account.clone());
                                    account
                                }
                            };
                            match issue_certificate(
                                &dns,
                                &account,
                                &task_domains,
                                propagation_secs,
                                Some(task_stop.as_ref()),
                                Some(task_notify.as_ref()),
                            )
                            .await
                            {
                                Ok(certificate) => {
                                    if install_certificate(&task_cert_dir, &task_state, certificate)
                                        .is_err()
                                    {
                                        *retry_delay.lock().expect("retry mutex poisoned") =
                                            (current_retry * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                        return current_retry;
                                    }
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
            Ok(BackgroundGuard::with_atomic_cancel(stop, notify, state))
        })
    }
}

fn install_certificate(
    cert_dir: &std::path::Path,
    state: &AcmeState,
    certificate: CertificateMaterial,
) -> Result<()> {
    std::fs::write(cert_dir.join("fullchain.pem"), certificate.fullchain_pem())?;
    state.set_certificate(certificate);
    Ok(())
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
        let guard =
            BackgroundGuard::with_atomic_cancel(cancel.clone(), notify.clone(), AcmeState::new());
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

    #[test]
    fn installing_certificate_keeps_private_key_out_of_cert_dir() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let cert_dir = std::env::temp_dir().join(format!(
            "nago-acme-no-disk-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&cert_dir).expect("create isolated test directory");

        let fullchain = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let private_key = b"test-only-private-key-marker";
        let certificate = CertificateMaterial::new(fullchain.to_vec(), private_key.to_vec())
            .expect("synthetic public chain and test key are accepted");
        let state = AcmeState::new();

        install_certificate(&cert_dir, &state, certificate).expect("install public chain");

        assert_eq!(
            std::fs::read(cert_dir.join("fullchain.pem")).expect("read public chain"),
            fullchain
        );
        assert!(!cert_dir.join("privkey.pem").exists());
        assert!(!cert_dir.join("acme_cache").exists());
        assert_eq!(
            state
                .certificate()
                .expect("certificate is kept in state")
                .private_key_pem(),
            private_key
        );

        std::fs::remove_dir_all(cert_dir).expect("remove isolated test directory");
    }
}
