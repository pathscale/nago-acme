//! Certificate provider and renewal loop.

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[cfg(feature = "s3")]
use std::time::Instant;

#[cfg(feature = "s3")]
use crate::acme::wait_or_cancel;
use crate::acme::{
    NagoTransport, Transport, issue_certificate, load_existing_account, load_or_create_account,
    read_cert_not_after, renewal_loop,
};
use crate::certificate::{AcmeState, CertificateMaterial};
use crate::dns::DnsProvider;
use crate::error::{Error, RestoreError, Result};
use crate::jwk::AccountKey;

const DEFAULT_PROPAGATION_SECS: u64 = 60;
const DEFAULT_RENEW_WITHIN_DAYS: u64 = 30;
const INITIAL_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(3_600);
const MAX_RENEWAL_RETRY_DELAY: Duration = Duration::from_secs(86_400);
#[cfg(feature = "s3")]
const INITIAL_S3_RETRY_DELAY: Duration = Duration::from_secs(60);
#[cfg(feature = "s3")]
const MAX_S3_RETRY_DELAY: Duration = Duration::from_secs(3_600);

/// A sendable future returned by [`CertProvider::init`].
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<RenewalGuard>> + Send + 'a>>;

/// A consumer's asynchronous acknowledgment of a renewal.
pub type RenewalAckFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

type RenewalAck =
    dyn for<'a> Fn(&'a CertificateMaterial, &'a AccountKey) -> RenewalAckFuture<'a> + Send + Sync;

/// Prepare a public certificate-chain file and return a guard for renewal.
pub trait CertProvider: Send + Sync + 'static {
    /// Whether this provider already publishes to an exact S3 request URL.
    #[cfg(feature = "s3")]
    fn publishes_to_s3_target(&self, _target: &str) -> bool {
        false
    }

    /// Provision `fullchain.pem` in `cert_dir` for `domains` and start renewal.
    /// Private keys remain in the provider's in-memory state.
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a>;

    /// Validate and capture startup input before a wrapper performs any I/O.
    ///
    /// This method must not perform I/O. Implementations that need early
    /// validation should return errors here and use the captured input in the
    /// returned future. Wrappers must forward preparation to their inner
    /// provider before doing any I/O. By default, the returned future calls
    /// [`Self::init`] when polled.
    fn prepare_init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<ProviderFuture<'a>> {
        Ok(Box::pin(async move { self.init(cert_dir, domains).await }))
    }
}

impl<T: CertProvider + ?Sized> CertProvider for Box<T> {
    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a> {
        self.as_mut().init(cert_dir, domains)
    }

    fn prepare_init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<ProviderFuture<'a>> {
        self.as_mut().prepare_init(cert_dir, domains)
    }

    #[cfg(feature = "s3")]
    fn publishes_to_s3_target(&self, target: &str) -> bool {
        self.as_ref().publishes_to_s3_target(target)
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

    #[cfg(feature = "s3")]
    pub(crate) fn holding(guard: BackgroundGuard, claim: crate::s3::PublisherClaim) -> Self {
        let state = guard.state.clone();
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(nagoya::sync::Notify::new()),
            state,
            keepalive: Some(Box::new((guard, claim))),
        }
    }

    /// Hold `guard` and `claim` like [`Self::holding`], and retry the upload of
    /// `cert_dir`'s public chain in the background until it succeeds or the
    /// returned guard is dropped.
    #[cfg(feature = "s3")]
    pub(crate) fn retrying_upload(
        guard: BackgroundGuard,
        claim: crate::s3::PublisherClaim,
        sync: Arc<crate::s3::S3CertSync>,
        cert_dir: PathBuf,
    ) -> Self {
        let state = guard.state.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(nagoya::sync::Notify::new());
        let claim = Arc::new(claim);
        drop(nagoya::spawn({
            let stop = stop.clone();
            let notify = notify.clone();
            let claim = claim.clone();
            async move {
                let _claim = claim;
                retry_startup_upload(&stop, &notify, &sync, &cert_dir).await;
            }
        }));
        Self {
            stop,
            notify,
            state,
            keepalive: Some(Box::new((guard, claim))),
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

/// How the DNS ACME provider treats application credentials at startup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StartupMode {
    /// Allow first issuance and account creation when credentials are missing.
    /// Supplied credentials are still reused. A restored certificate that has
    /// expired or does not cover the requested domains is replaced by a new
    /// issuance.
    #[default]
    Bootstrap,
    /// Require both restored credentials; deferred renewal may only use the
    /// existing CA account associated with the captured key.
    RequireRestored,
    /// Report a failed application restore and stop without filesystem or
    /// network access. Keep any underlying secret-store error in the application.
    RestoreFailed,
}

/// ACME provider using DNS-01 challenges.
///
/// Require-restored startup rejects restored certificates whose leaf is outside
/// its validity period or lacks DNS subject alternative names covering the
/// requested domains. Bootstrap startup issues a replacement for such a
/// certificate.
pub struct DnsAcmeProvider<D: DnsProvider> {
    contact_email: String,
    dns: Arc<D>,
    production: bool,
    propagation_secs: u64,
    renew_within_days: u64,
    max_retries: u32,
    state: AcmeState,
    startup_mode: StartupMode,
    renewal_ack: Option<Arc<RenewalAck>>,
    #[cfg(feature = "s3")]
    s3_sync: Option<Arc<crate::s3::S3CertSync>>,
    #[cfg(all(test, feature = "s3"))]
    test_acme: Option<AcmeTestHook>,
}

#[cfg(all(test, feature = "s3"))]
#[derive(Clone)]
struct AcmeTestHook {
    transport: Arc<dyn Transport>,
    renewal_pem_error: Arc<nagoya::sync::Notify>,
    s3_retry_delay: Duration,
    renewal_retry_delay: Duration,
}

impl<D: DnsProvider> DnsAcmeProvider<D> {
    /// Create a provider using the staging ACME directory and bootstrap mode.
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
            startup_mode: StartupMode::Bootstrap,
            renewal_ack: None,
            #[cfg(feature = "s3")]
            s3_sync: None,
            #[cfg(all(test, feature = "s3"))]
            test_acme: None,
        }
    }

    /// Create a provider in bootstrap mode with a shared DNS backend.
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
            startup_mode: StartupMode::Bootstrap,
            renewal_ack: None,
            #[cfg(feature = "s3")]
            s3_sync: None,
            #[cfg(all(test, feature = "s3"))]
            test_acme: None,
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

    /// Select how startup handles credentials supplied through [`Self::with_state`].
    #[must_use]
    pub fn with_startup_mode(mut self, startup_mode: StartupMode) -> Self {
        self.startup_mode = startup_mode;
        self
    }

    /// Share certificate and account-key state with the application.
    #[must_use]
    pub fn with_state(mut self, state: AcmeState) -> Self {
        self.state = state;
        self
    }

    /// Require acknowledgment of durable credential storage and TLS reload.
    ///
    /// The callback runs for renewals, using the issued chain, matching private
    /// key and signing account key. Prepare the consumer before calling
    /// `init`: a restored certificate may already be due for renewal.
    /// Return success only after persistence and TLS reload both succeed.
    /// On error the provider retries the same material while it remains valid.
    /// Implement the callback so it can be repeated after partial success.
    /// The provider's public chain, shared state and S3 publication advance
    /// only after acknowledgment. The application handles initial credentials
    /// separately during startup.
    ///
    /// One live guard should own the state and certificate directory. Dropping
    /// it cancels a pending callback future, which may have had side effects.
    #[must_use]
    pub fn with_renewal_ack<F>(mut self, acknowledge: F) -> Self
    where
        F: for<'a> Fn(&'a CertificateMaterial, &'a AccountKey) -> RenewalAckFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        self.renewal_ack = Some(Arc::new(acknowledge));
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
    #[cfg(feature = "s3")]
    fn publishes_to_s3_target(&self, target: &str) -> bool {
        self.s3_sync
            .as_ref()
            .is_some_and(|sync| sync.publisher_target() == target)
    }

    fn init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> ProviderFuture<'a> {
        Box::pin(async move { self.prepare_init(cert_dir, domains)?.await })
    }

    fn prepare_init<'a>(
        &'a mut self,
        cert_dir: PathBuf,
        domains: Option<Vec<String>>,
    ) -> Result<ProviderFuture<'a>> {
        if self.startup_mode == StartupMode::RestoreFailed {
            return Err(RestoreError::Failed.into());
        }
        let domains = domains.ok_or_else(|| Error::Config("domains are required".into()))?;
        if domains.is_empty() {
            return Err(Error::Config("at least one domain is required".into()));
        }
        let state = self.state.clone();
        let bootstrap = self.startup_mode == StartupMode::Bootstrap;
        let restored = state.certificate();
        let restored_account_key = if self.startup_mode == StartupMode::RequireRestored {
            if restored.is_none() {
                return Err(RestoreError::MissingCertificate.into());
            }
            Some(state.account_key().ok_or(RestoreError::MissingAccountKey)?)
        } else {
            None
        };
        let restored = usable_restored(restored, &domains, bootstrap)?;

        Ok(Box::pin(async move {
            // Preparation may precede an S3 pull or a delay before polling.
            let restored = usable_restored(restored, &domains, bootstrap)?;
            #[cfg(feature = "s3")]
            let publisher_claim = self
                .s3_sync
                .as_ref()
                .map(|sync| sync.claim_publisher())
                .transpose()?;
            std::fs::create_dir_all(&cert_dir)?;
            let transport: Arc<dyn Transport> = Arc::new(NagoTransport);
            #[cfg(all(test, feature = "s3"))]
            let test_acme = self.test_acme.clone();
            #[cfg(all(test, feature = "s3"))]
            let transport = test_acme
                .as_ref()
                .map_or(transport, |hook| hook.transport.clone());

            let mut initial_account = None;
            if let Some(certificate) = restored {
                if let Some(account_key) = &restored_account_key {
                    install_certificate(&cert_dir, &state, certificate)?;
                    state.set_account_key(account_key.clone());
                } else {
                    replace_public_chain(&cert_dir, certificate.fullchain_pem())?;
                }
            } else {
                let account = load_or_create_account(
                    &self.contact_email,
                    self.production,
                    &state,
                    transport.clone(),
                )
                .await?;
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
            let queued_chain = Arc::new(Mutex::new(None));
            #[cfg(feature = "s3")]
            if let Some(sync) = &self.s3_sync
                && let Err(error) = sync.push_from_claimed(&cert_dir).await
            {
                // A certificate issued during this startup exists only in memory
                // and the public chain, so retry its upload instead of failing.
                if initial_account.is_none() {
                    return Err(error);
                }
                let chain = state
                    .certificate()
                    .map(|certificate| certificate.fullchain_pem().to_vec());
                *queued_chain.lock().expect("S3 chain mutex poisoned") = chain;
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
            let renewal_ack = self.renewal_ack.clone();
            let pending_renewal = Arc::new(Mutex::new(None::<RenewalCandidate>));
            let account_state = if renewal_ack.is_some() {
                // Deferred registration must not change acknowledged state.
                let account_state = AcmeState::new();
                if let Some(key) = state.account_key() {
                    account_state.set_account_key(key);
                }
                account_state
            } else {
                state.clone()
            };
            let initial_retry = INITIAL_RENEWAL_RETRY_DELAY;
            #[cfg(all(test, feature = "s3"))]
            let initial_retry = test_acme
                .as_ref()
                .map_or(initial_retry, |hook| hook.renewal_retry_delay);
            let retry_delay = Arc::new(Mutex::new(initial_retry));
            #[cfg(feature = "s3")]
            let s3_sync = self.s3_sync.clone();
            #[cfg(feature = "s3")]
            let s3_retry_delay = INITIAL_S3_RETRY_DELAY;
            #[cfg(all(test, feature = "s3"))]
            let s3_retry_delay = test_acme
                .as_ref()
                .map_or(s3_retry_delay, |hook| hook.s3_retry_delay);

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
                async move {
                    #[cfg(feature = "s3")]
                    let _publisher_claim = publisher_claim;
                    let stop = task_stop.clone();
                    let notify = task_notify.clone();
                    #[cfg(feature = "s3")]
                    let queued = queued_chain.clone();
                    #[cfg(feature = "s3")]
                    let publishes_to_s3 = s3_sync.is_some();
                    let renew = move || {
                        let retry_delay = retry_delay.clone();
                        let dns = dns.clone();
                        let task_cert_dir = task_cert_dir.clone();
                        let task_state = task_state.clone();
                        let task_account = task_account.clone();
                        let contact_email = contact_email.clone();
                        let task_domains = task_domains.clone();
                        let task_stop = task_stop.clone();
                        let task_notify = task_notify.clone();
                        let transport = transport.clone();
                        let restored_account_key = restored_account_key.clone();
                        let renewal_ack = renewal_ack.clone();
                        let pending_renewal = pending_renewal.clone();
                        let account_state = account_state.clone();
                        #[cfg(all(test, feature = "s3"))]
                        let test_acme = test_acme.clone();
                        #[cfg(feature = "s3")]
                        let queued = queued.clone();
                        async move {
                            let result: Result<Duration> = async {
                                let pending = pending_renewal
                                    .lock()
                                    .expect("pending renewal mutex poisoned")
                                    .take()
                                    .filter(|candidate| !candidate.expired());
                                let mut candidate = if let Some(pending) = pending {
                                    pending
                                } else {
                                    let active = task_state.certificate().ok_or_else(|| {
                                        Error::Config("certificate is missing".into())
                                    })?;
                                    let not_after = read_cert_not_after(active.fullchain_pem())?;
                                    let renew_at =
                                        not_after.checked_sub(renew_within).unwrap_or(not_after);
                                    if let Ok(delay) = renew_at.duration_since(SystemTime::now())
                                        && !delay.is_zero()
                                    {
                                        return Ok(delay);
                                    }
                                    if task_stop.load(Ordering::Acquire) {
                                        return Err(Error::Cancelled);
                                    }
                                    let cached_account = task_account
                                        .lock()
                                        .expect("account task mutex poisoned")
                                        .clone();
                                    let account = match cached_account {
                                        Some(account) => account,
                                        None => {
                                            let account = match restored_account_key {
                                                Some(key) => {
                                                    load_existing_account(
                                                        production, key, transport,
                                                    )
                                                    .await?
                                                }
                                                None => {
                                                    load_or_create_account(
                                                        &contact_email,
                                                        production,
                                                        &account_state,
                                                        transport,
                                                    )
                                                    .await?
                                                }
                                            };
                                            *task_account
                                                .lock()
                                                .expect("account task mutex poisoned") =
                                                Some(account.clone());
                                            account
                                        }
                                    };
                                    let certificate = issue_certificate(
                                        &dns,
                                        &account,
                                        &task_domains,
                                        propagation_secs,
                                        Some(task_stop.as_ref()),
                                        Some(task_notify.as_ref()),
                                    )
                                    .await?;
                                    let managed = if let Some(acknowledge) = renewal_ack {
                                        certificate.validate_for_domains(&task_domains)?;
                                        let not_after =
                                            read_cert_not_after(certificate.fullchain_pem())?;
                                        *retry_delay.lock().expect("retry mutex poisoned") =
                                            initial_retry;
                                        Some(ManagedRenewal {
                                            acknowledge,
                                            account_key: account.account_key().clone(),
                                            not_after,
                                            acknowledged: false,
                                        })
                                    } else {
                                        None
                                    };
                                    RenewalCandidate {
                                        certificate,
                                        managed,
                                    }
                                };

                                #[cfg(feature = "s3")]
                                let chain = publishes_to_s3
                                    .then(|| candidate.certificate.fullchain_pem().to_vec());
                                if let Some(managed) = &mut candidate.managed {
                                    if let Err(error) = managed
                                        .acknowledge_and_install(
                                            &candidate.certificate,
                                            &task_cert_dir,
                                            &task_state,
                                            &task_stop,
                                            &task_notify,
                                        )
                                        .await
                                    {
                                        let can_retry = !task_stop.load(Ordering::Acquire)
                                            && !candidate.expired();
                                        if can_retry {
                                            *pending_renewal
                                                .lock()
                                                .expect("pending renewal mutex poisoned") =
                                                Some(candidate);
                                        }
                                        return Err(error);
                                    }
                                } else {
                                    install_certificate(
                                        &task_cert_dir,
                                        &task_state,
                                        candidate.certificate,
                                    )?;
                                }
                                #[cfg(feature = "s3")]
                                if let Some(chain) = chain {
                                    *queued.lock().expect("S3 chain mutex poisoned") = Some(chain);
                                }
                                Ok(Duration::ZERO)
                            }
                            .await;

                            let mut delay = retry_delay.lock().expect("retry mutex poisoned");
                            match result {
                                Ok(wait) => {
                                    *delay = initial_retry;
                                    wait
                                }
                                Err(_) if task_stop.load(Ordering::Acquire) => Duration::ZERO,
                                Err(_error) => {
                                    #[cfg(all(test, feature = "s3"))]
                                    if let (Some(hook), Error::Pem(_)) = (&test_acme, _error) {
                                        hook.renewal_pem_error.notify_one();
                                    }
                                    let wait = *delay;
                                    *delay = (wait * 2).min(MAX_RENEWAL_RETRY_DELAY);
                                    wait
                                }
                            }
                        }
                    };
                    #[cfg(feature = "s3")]
                    if let Some(sync) = s3_sync {
                        renew_with_s3(stop, notify, renew, &sync, queued_chain, s3_retry_delay)
                            .await;
                        return;
                    }
                    renewal_loop(stop, notify, renew).await;
                }
            }));
            Ok(BackgroundGuard::with_atomic_cancel(stop, notify, state))
        }))
    }
}

struct RenewalCandidate {
    certificate: CertificateMaterial,
    managed: Option<ManagedRenewal>,
}

impl RenewalCandidate {
    fn expired(&self) -> bool {
        self.managed
            .as_ref()
            .is_some_and(|managed| SystemTime::now() >= managed.not_after)
    }
}

struct ManagedRenewal {
    acknowledge: Arc<RenewalAck>,
    account_key: AccountKey,
    not_after: SystemTime,
    acknowledged: bool,
}

impl ManagedRenewal {
    async fn acknowledge_and_install(
        &mut self,
        certificate: &CertificateMaterial,
        cert_dir: &std::path::Path,
        state: &AcmeState,
        stop: &AtomicBool,
        notify: &nagoya::sync::Notify,
    ) -> Result<()> {
        if SystemTime::now() >= self.not_after {
            return Err(Error::Pem("renewal expired before acknowledgment".into()));
        }
        if !self.acknowledged {
            let mut cancelled = std::pin::pin!(notify.notified());
            let callback = &self.acknowledge;
            let account_key = &self.account_key;
            let mut acknowledge =
                std::pin::pin!(async move { callback(certificate, account_key).await });
            std::future::poll_fn(|context| {
                if cancelled.as_mut().poll(context).is_ready() || stop.load(Ordering::Acquire) {
                    std::task::Poll::Ready(Err(Error::Cancelled))
                } else {
                    acknowledge.as_mut().poll(context)
                }
            })
            .await?;
            self.acknowledged = true;
        }
        if stop.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        if SystemTime::now() >= self.not_after {
            return Err(Error::Pem("renewal expired before publication".into()));
        }
        replace_public_chain(cert_dir, certificate.fullchain_pem())?;
        state.set_credentials(certificate.clone(), self.account_key.clone());
        Ok(())
    }
}

pub(crate) fn replace_public_chain(cert_dir: &std::path::Path, chain: &[u8]) -> Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let staged = cert_dir.join(format!(".fullchain-{}-{sequence}.pem", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let written = file.write_all(chain);
    drop(file);
    let installed = written.and_then(|()| std::fs::rename(&staged, cert_dir.join("fullchain.pem")));
    if installed.is_err() {
        let _ = std::fs::remove_file(staged);
    }
    installed?;
    Ok(())
}

#[cfg(feature = "s3")]
async fn renew_with_s3<F, Fut>(
    stop: Arc<AtomicBool>,
    notify: Arc<nagoya::sync::Notify>,
    mut renew: F,
    sync: &crate::s3::S3CertSync,
    queued: Arc<Mutex<Option<Vec<u8>>>>,
    initial_retry: Duration,
) where
    F: FnMut() -> Fut + Send,
    Fut: Future<Output = Duration> + Send,
{
    // Preserve the ACME wait across S3-only wakes.
    let mut renewal_wait = (Instant::now(), Duration::ZERO);
    let mut pending = None;
    while !stop.load(Ordering::Acquire) {
        if renewal_wait.0.elapsed() >= renewal_wait.1 {
            let delay = renew().await;
            renewal_wait = (Instant::now(), delay);
            if let Some(chain) = queued.lock().expect("S3 chain mutex poisoned").take() {
                pending = Some((chain, Instant::now(), initial_retry));
            }
        }
        if stop.load(Ordering::Acquire) {
            return;
        }
        if let Some((chain, retry_at, delay)) = &mut pending
            && *retry_at <= Instant::now()
        {
            if sync.push_chain_claimed(chain).await.is_ok() {
                pending = None;
            } else {
                *retry_at = Instant::now() + *delay;
                *delay = (*delay * 2).min(MAX_S3_RETRY_DELAY);
            }
        }
        let renew_in = renewal_wait.1.saturating_sub(renewal_wait.0.elapsed());
        let delay = pending.as_ref().map_or(renew_in, |(_, retry_at, _)| {
            renew_in.min(retry_at.saturating_duration_since(Instant::now()))
        });
        if wait_or_cancel(Some(stop.as_ref()), Some(notify.as_ref()), delay).await {
            return;
        }
    }
}

#[cfg(feature = "s3")]
async fn retry_startup_upload(
    stop: &AtomicBool,
    notify: &nagoya::sync::Notify,
    sync: &crate::s3::S3CertSync,
    cert_dir: &std::path::Path,
) {
    let mut delay = INITIAL_S3_RETRY_DELAY;
    while !wait_or_cancel(Some(stop), Some(notify), delay).await {
        if sync.push_from_claimed(cert_dir).await.is_ok() {
            return;
        }
        delay = (delay * 2).min(MAX_S3_RETRY_DELAY);
    }
}

/// Return the restored certificate startup can use. Bootstrap treats an expired
/// or mismatched certificate as missing and issues a replacement; other modes
/// reject it.
fn usable_restored(
    restored: Option<CertificateMaterial>,
    domains: &[String],
    bootstrap: bool,
) -> Result<Option<CertificateMaterial>> {
    let Some(certificate) = restored else {
        return Ok(None);
    };
    match certificate.validate_for_domains(domains) {
        Ok(()) => Ok(Some(certificate)),
        Err(_) if bootstrap => Ok(None),
        Err(error) => Err(error),
    }
}

fn install_certificate(
    cert_dir: &std::path::Path,
    state: &AcmeState,
    certificate: CertificateMaterial,
) -> Result<()> {
    replace_public_chain(cert_dir, certificate.fullchain_pem())?;
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
    fn rejects_unusable_restored_certificates_before_touching_cert_dir() {
        use std::task::{Context, Poll, Waker};

        for case in ["expired", "not yet valid", "wrong name"] {
            let name = if case == "wrong name" {
                "unrelated.test"
            } else {
                "example.test"
            };
            let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
            match case {
                "expired" => params.not_after = rcgen::date_time_ymd(2000, 1, 1),
                "not yet valid" => params.not_before = rcgen::date_time_ymd(4090, 1, 1),
                _ => {}
            }
            let key = rcgen::KeyPair::generate().unwrap();
            let certificate = CertificateMaterial::new(
                params.self_signed(&key).unwrap().pem().into_bytes(),
                key.serialize_pem().into_bytes(),
            )
            .unwrap();
            let state = AcmeState::new();
            state.set_certificate(certificate);
            state.set_account_key(AccountKey::generate().unwrap());
            let mut provider =
                DnsAcmeProvider::new("admin@example.test", crate::dns::BunnyDns::new(""))
                    .with_state(state)
                    .with_startup_mode(StartupMode::RequireRestored);

            // A NUL makes filesystem access fail without creating any files.
            let mut init = provider.init(PathBuf::from("\0"), Some(vec!["example.test".into()]));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                matches!(
                    init.as_mut().poll(&mut cx),
                    Poll::Ready(Err(Error::Config(_)))
                ),
                "startup did not reject the {case} leaf before filesystem access"
            );
        }
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

        let generated = rcgen::generate_simple_self_signed(vec!["example.test".to_owned()])
            .expect("generate test certificate");
        let fullchain = generated.cert.pem().into_bytes();
        let private_key = generated.signing_key.serialize_pem().into_bytes();
        let certificate = CertificateMaterial::new(fullchain.clone(), private_key.clone())
            .expect("generated certificate and matching test key are accepted");
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

#[cfg(all(test, feature = "s3"))]
mod s3_acceptance {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    use rcgen::{CertificateParams, CertificateSigningRequestParams, Issuer, KeyPair};
    use serde_json::{Value, json};

    use super::*;
    use crate::acme::{BoxFuture, HttpRequest, HttpResponse};
    use crate::dns::DnsFuture;
    use crate::jwk::base64url_decode;
    use crate::s3::{S3CertProvider, S3CertSync, S3Config};

    const DOMAIN: &str = "example.test";
    const DEADLINE: Duration = Duration::from_secs(15);
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const NOT_FOUND: &[u8] =
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const FORBIDDEN: &[u8] =
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    struct ReusedDns;

    impl DnsProvider for ReusedDns {
        fn add_txt_record<'a>(&'a self, _: &'a str, _: &'a str) -> DnsFuture<'a> {
            panic!("a reused authorization must not create a DNS record")
        }

        fn remove_txt_record<'a>(&'a self, _: &'a str, _: &'a str) -> DnsFuture<'a> {
            panic!("a reused authorization must not remove a DNS record")
        }
    }

    #[derive(Default)]
    struct RenewalAcme {
        start: nagoya::sync::Notify,
        step: AtomicUsize,
        // Preloaded with the unrelated leaf for the rejection case.
        chain: Mutex<Option<Vec<u8>>>,
        expected_account_jwk: Option<Value>,
    }

    impl Transport for RenewalAcme {
        fn request<'a>(&'a self, request: HttpRequest) -> BoxFuture<'a, Result<HttpResponse>> {
            Box::pin(async move {
                let step = self.step.fetch_add(1, Ordering::SeqCst);
                let route = request.url.rsplit('/').next().unwrap();
                let mut headers = vec![("Replay-Nonce".into(), format!("nonce-{step}"))];
                let body = match (step, request.method.as_str(), route) {
                    (0, "GET", "directory") => {
                        nagoya::timeout(DEADLINE, self.start.notified())
                            .await
                            .expect("release ACME after provider init");
                        json!({
                            "newNonce": "https://ca.invalid/nonce",
                            "newAccount": "https://ca.invalid/account",
                            "newOrder": "https://ca.invalid/new-order"
                        })
                    }
                    (1, "POST", "account") => {
                        let (_, body) = request.body.unwrap();
                        let jws: Value = serde_json::from_slice(&body).unwrap();
                        let payload = base64url_decode(jws["payload"].as_str().unwrap()).unwrap();
                        let payload: Value = serde_json::from_slice(&payload).unwrap();
                        if let Some(expected_jwk) = &self.expected_account_jwk {
                            assert_eq!(payload, json!({"onlyReturnExisting": true}));
                            let protected =
                                base64url_decode(jws["protected"].as_str().unwrap()).unwrap();
                            let protected: Value = serde_json::from_slice(&protected).unwrap();
                            assert_eq!(&protected["jwk"], expected_jwk);
                        } else {
                            assert_eq!(
                                payload,
                                json!({
                                    "contact": ["mailto:admin@example.test"],
                                    "termsOfServiceAgreed": true
                                })
                            );
                        }
                        headers.push(("Location".into(), "https://ca.invalid/account/1".into()));
                        json!({})
                    }
                    (2, "POST", "new-order") => {
                        headers.push(("Location".into(), "https://ca.invalid/order".into()));
                        json!({"status": "ready", "authorizations": ["https://ca.invalid/auth"]})
                    }
                    (3, "POST", "auth") => {
                        json!({"status": "valid", "identifier": {"type": "dns", "value": DOMAIN}})
                    }
                    (4, "POST", "order") => {
                        json!({"status": "ready", "finalize": "https://ca.invalid/finalize"})
                    }
                    (5, "POST", "finalize") => {
                        let mut chain = self.chain.lock().unwrap();
                        if chain.is_none() {
                            let (_, body) = request.body.unwrap();
                            let jws: Value = serde_json::from_slice(&body).unwrap();
                            let payload =
                                base64url_decode(jws["payload"].as_str().unwrap()).unwrap();
                            let payload: Value = serde_json::from_slice(&payload).unwrap();
                            let csr = base64url_decode(payload["csr"].as_str().unwrap()).unwrap();
                            let csr =
                                CertificateSigningRequestParams::from_der(&csr.as_slice().into())
                                    .expect("parse and verify finalize CSR");
                            let mut ca = CertificateParams::default();
                            ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                            let issuer = Issuer::new(ca, KeyPair::generate().unwrap());
                            *chain = Some(csr.signed_by(&issuer).unwrap().pem().into_bytes());
                        }
                        json!({"status": "processing"})
                    }
                    (6, "POST", "order") => {
                        json!({"status": "valid", "certificate": "https://ca.invalid/certificate"})
                    }
                    (7, "POST", "certificate") => {
                        return Ok(HttpResponse {
                            status: 200,
                            headers,
                            body: self.chain.lock().unwrap().clone().unwrap(),
                        });
                    }
                    _ => panic!(
                        "unexpected ACME request {step}: {} {}",
                        request.method, request.url
                    ),
                };
                Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: serde_json::to_vec(&body).unwrap(),
                })
            })
        }
    }

    struct CertDir(PathBuf);

    impl CertDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir();
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join(format!(
                "s3-renewal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for CertDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Request {
        method: String,
        body: Vec<u8>,
    }

    impl Request {
        fn read(stream: &mut TcpStream) -> Self {
            let io_timeout = Some(Duration::from_secs(2));
            stream.set_read_timeout(io_timeout).unwrap();
            stream.set_write_timeout(io_timeout).unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap().to_owned();
            assert_eq!(parts.next(), Some("/certs/fullchain.pem"));
            let mut length = 0;
            loop {
                line.clear();
                assert_ne!(
                    reader.read_line(&mut line).unwrap(),
                    0,
                    "missing HTTP header terminator"
                );
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                if name.eq_ignore_ascii_case("Content-Length") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            Self { method, body }
        }
    }

    struct RecordingS3 {
        config: S3Config,
        requests: Arc<Mutex<Vec<Request>>>,
        release: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl RecordingS3 {
        fn new(hold_renewal: bool, reject_held: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let config = S3Config {
                endpoint: format!("http://{}", listener.local_addr().unwrap()),
                bucket_name: "certs".into(),
                access_key: "test-access".into(),
                secret_key: "test-secret".into(),
                region: "us-east-1".into(),
                prefix: None,
            };
            let requests = Arc::new(Mutex::new(Vec::new()));
            let release = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let worker = thread::spawn({
                let requests = requests.clone();
                let release = release.clone();
                let stop = stop.clone();
                move || {
                    let mut held: Option<TcpStream> = None;
                    while !stop.load(Ordering::Acquire) {
                        if release.load(Ordering::Acquire)
                            && let Some(mut stream) = held.take()
                        {
                            stream
                                .write_all(if reject_held { FORBIDDEN } else { OK })
                                .unwrap();
                        }
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                let request = Request::read(&mut stream);
                                let is_put = request.method == "PUT";
                                let mut requests = requests.lock().unwrap();
                                requests.push(request);
                                let hold = hold_renewal && is_put && requests.len() == 2;
                                drop(requests);
                                if hold {
                                    held = Some(stream);
                                } else {
                                    stream
                                        .write_all(if is_put { OK } else { NOT_FOUND })
                                        .unwrap();
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(POLL_INTERVAL);
                            }
                            Err(error) => panic!("accept loopback S3 request: {error}"),
                        }
                    }
                }
            });
            Self {
                config,
                requests,
                release,
                stop,
                worker: Some(worker),
            }
        }

        fn assert_puts(&self, bodies: &[&[u8]]) {
            let requests = self.requests.lock().unwrap();
            assert_eq!(requests.len(), bodies.len(), "recorded S3 requests");
            for (request, body) in requests.iter().zip(bodies) {
                assert_eq!(request.method, "PUT");
                assert_eq!(request.body.as_slice(), *body);
            }
        }
    }

    impl Drop for RecordingS3 {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let result = self.worker.take().unwrap().join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }

    #[test]
    fn retries_failed_s3_renewal_upload_from_installed_snapshot() {
        let dir = CertDir::new();
        let s3 = RecordingS3::new(true, true);
        let fake = Arc::new(RenewalAcme::default());
        let state = AcmeState::new();
        state.set_account_key(AccountKey::generate().unwrap());
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![DOMAIN.to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(1970, 1, 1)
            + SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
            + Duration::from_secs(86_400);
        let restored = params.self_signed(&key).unwrap().pem().into_bytes();
        state.set_certificate(
            CertificateMaterial::new(restored.clone(), key.serialize_pem().into_bytes()).unwrap(),
        );
        let sync = Arc::new(S3CertSync::new(s3.config.clone()).unwrap());
        let mut provider = DnsAcmeProvider::new("admin@example.test", ReusedDns)
            .with_state(state)
            .with_s3_sync(sync);
        provider.test_acme = Some(AcmeTestHook {
            transport: fake.clone(),
            renewal_pem_error: Arc::new(nagoya::sync::Notify::new()),
            s3_retry_delay: Duration::from_millis(10),
            renewal_retry_delay: INITIAL_RENEWAL_RETRY_DELAY,
        });
        let fullchain = dir.0.join("fullchain.pem");

        nagoya::block_on(nagoya::timeout(DEADLINE, async {
            let guard = provider
                .init(dir.0.clone(), Some(vec![DOMAIN.to_owned()]))
                .await
                .unwrap();
            s3.assert_puts(&[&restored]);
            fake.start.notify_one();
            while s3.requests.lock().unwrap().len() < 2 {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            let issued = fake.chain.lock().unwrap().clone().unwrap();
            assert_ne!(issued, restored);
            assert_eq!(std::fs::read(&fullchain).unwrap(), issued);
            assert_eq!(guard.certificate().unwrap().fullchain_pem(), issued);

            std::fs::remove_file(&fullchain).unwrap();
            s3.release.store(true, Ordering::Release);
            while s3.requests.lock().unwrap().len() < 3 {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            s3.assert_puts(&[&restored, &issued, &issued]);
            assert_eq!(fake.step.load(Ordering::SeqCst), 8);
            assert_eq!(guard.certificate().unwrap().fullchain_pem(), issued);
            assert!(!fullchain.exists());
        }))
        .expect("retry the failed S3 upload before the deadline");
    }

    #[test]
    fn boxed_dns_provider_restores_rejects_and_keeps_renewal_publisher_exclusive() {
        for renewal_matches_csr in [false, true] {
            let dir = CertDir::new();
            let s3 = RecordingS3::new(renewal_matches_csr, false);
            let account_key = AccountKey::generate().unwrap();
            let fake = Arc::new(RenewalAcme {
                expected_account_jwk: Some(serde_json::to_value(account_key.jwk()).unwrap()),
                ..RenewalAcme::default()
            });
            if !renewal_matches_csr {
                let unrelated =
                    rcgen::generate_simple_self_signed(vec![DOMAIN.to_owned()]).unwrap();
                *fake.chain.lock().unwrap() = Some(unrelated.cert.pem().into_bytes());
            }
            let state = AcmeState::new();
            state.set_account_key(account_key);
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![DOMAIN.to_owned()]).unwrap();
            params.not_after = rcgen::date_time_ymd(1970, 1, 1)
                + SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                + Duration::from_secs(86_400);
            let restored = params.self_signed(&key).unwrap().pem().into_bytes();
            let restored_key = key.serialize_pem().into_bytes();
            state.set_certificate(
                CertificateMaterial::new(restored.clone(), restored_key.clone()).unwrap(),
            );
            let sync = Arc::new(S3CertSync::new(s3.config.clone()).unwrap());
            let mut inner = DnsAcmeProvider::new("admin@example.test", ReusedDns)
                .with_state(state)
                .with_startup_mode(StartupMode::RequireRestored)
                .with_s3_sync(sync.clone());
            let renewal_pem_error = Arc::new(nagoya::sync::Notify::new());
            inner.test_acme = Some(AcmeTestHook {
                transport: fake.clone(),
                renewal_pem_error: renewal_pem_error.clone(),
                s3_retry_delay: INITIAL_S3_RETRY_DELAY,
                renewal_retry_delay: INITIAL_RENEWAL_RETRY_DELAY,
            });
            let boxed: Box<dyn CertProvider> = Box::new(inner);
            let mut wrapped = S3CertProvider::from_arc(boxed, sync);
            let fullchain = dir.0.join("fullchain.pem");

            nagoya::block_on(nagoya::timeout(DEADLINE, async {
                let guard = wrapped
                    .init(dir.0.clone(), Some(vec![DOMAIN.to_owned()]))
                    .await
                    .unwrap();
                assert_eq!(std::fs::read(&fullchain).unwrap(), restored);
                s3.assert_puts(&[&restored]);
                fake.start.notify_one();

                if !renewal_matches_csr {
                    renewal_pem_error.notified().await;
                    assert_eq!(fake.step.load(Ordering::SeqCst), 8);
                    let retained = guard.certificate().unwrap();
                    assert_eq!(retained.fullchain_pem(), restored);
                    assert_eq!(retained.private_key_pem(), restored_key);
                    assert_eq!(std::fs::read(&fullchain).unwrap(), restored);
                    s3.assert_puts(&[&restored]);
                    return;
                }

                while s3.requests.lock().unwrap().len() < 2 {
                    nagoya::sleep(POLL_INTERVAL).await;
                }
                let issued = fake.chain.lock().unwrap().clone().unwrap();
                assert_ne!(issued, restored);
                assert_eq!(guard.certificate().unwrap().fullchain_pem(), issued);
                assert_eq!(std::fs::read(&fullchain).unwrap(), issued);
                s3.assert_puts(&[&restored, &issued]);

                drop(guard);
                let second = S3CertSync::new(s3.config.clone()).unwrap();
                assert!(matches!(
                    second.push_from(&dir.0).await,
                    Err(Error::Config(_))
                ));
                s3.assert_puts(&[&restored, &issued]);
                s3.release.store(true, Ordering::Release);

                loop {
                    match second.push_from(&dir.0).await {
                        Ok(()) => break,
                        Err(Error::Config(_)) => nagoya::sleep(POLL_INTERVAL).await,
                        Err(error) => panic!("second publisher upload: {error}"),
                    }
                }
                s3.assert_puts(&[&restored, &issued, &issued]);
            }))
            .expect("complete S3 renewal acceptance before the deadline");
        }
    }

    fn startup_provider(
        mode: StartupMode,
        state: AcmeState,
        fake: Arc<RenewalAcme>,
    ) -> DnsAcmeProvider<ReusedDns> {
        let mut provider = DnsAcmeProvider::new("admin@example.test", ReusedDns)
            .with_state(state)
            .with_startup_mode(mode);
        provider.test_acme = Some(AcmeTestHook {
            transport: fake,
            renewal_pem_error: Arc::new(nagoya::sync::Notify::new()),
            s3_retry_delay: INITIAL_S3_RETRY_DELAY,
            renewal_retry_delay: INITIAL_RENEWAL_RETRY_DELAY,
        });
        provider
    }

    fn restored_material() -> CertificateMaterial {
        restored_material_expiring_at(SystemTime::now() + Duration::from_secs(86_400))
    }

    fn restored_material_expiring_at(not_after: SystemTime) -> CertificateMaterial {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![DOMAIN.to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(1970, 1, 1)
            + not_after.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        CertificateMaterial::new(
            params.self_signed(&key).unwrap().pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn renewal_ack_retries_persistence_and_reload_through_boxed_s3_provider() {
        let dir = CertDir::new();
        let fullchain = dir.0.join("fullchain.pem");
        let s3 = RecordingS3::new(false, false);
        let sync = Arc::new(S3CertSync::new(s3.config.clone()).unwrap());
        let fake = Arc::new(RenewalAcme::default());
        let state = AcmeState::new();
        let restored = restored_material();
        state.set_certificate(restored.clone());

        let attempts = Arc::new(AtomicUsize::new(0));
        let permit_reload_failure = Arc::new(nagoya::sync::Notify::new());
        let permit_success = Arc::new(nagoya::sync::Notify::new());
        let first_attempt = Arc::new(Mutex::new(None::<(CertificateMaterial, AccountKey)>));
        let durable = Arc::new(Mutex::new(None::<(CertificateMaterial, AccountKey)>));
        let live = Arc::new(Mutex::new(restored.clone()));
        let mut inner = startup_provider(StartupMode::Bootstrap, state.clone(), fake.clone())
            .with_s3_sync(sync.clone())
            .with_renewal_ack({
                let attempts = attempts.clone();
                let first_attempt = first_attempt.clone();
                let permit_reload_failure = permit_reload_failure.clone();
                let permit_success = permit_success.clone();
                let durable = durable.clone();
                let live = live.clone();
                move |certificate, account_key| {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    let first_attempt = first_attempt.clone();
                    let permit_reload_failure = permit_reload_failure.clone();
                    let permit_success = permit_success.clone();
                    let durable = durable.clone();
                    let live = live.clone();
                    Box::pin(async move {
                        if attempt == 0 {
                            *first_attempt.lock().unwrap() =
                                Some((certificate.clone(), account_key.clone()));
                            return Err(Error::Config("test credential persistence failed".into()));
                        }
                        {
                            let first = first_attempt.lock().unwrap();
                            let (first_cert, first_key) = first.as_ref().unwrap();
                            assert_eq!(certificate.fullchain_pem(), first_cert.fullchain_pem());
                            assert!(
                                certificate.private_key_pem() == first_cert.private_key_pem(),
                                "retry changed the certificate private key"
                            );
                            assert!(
                                account_key.pkcs8() == first_key.pkcs8(),
                                "retry changed the account key"
                            );
                        }
                        if attempt == 1 {
                            permit_reload_failure.notified().await;
                            *durable.lock().unwrap() =
                                Some((certificate.clone(), account_key.clone()));
                            return Err(Error::Config("test TLS reload failed".into()));
                        }
                        assert_eq!(attempt, 2);
                        permit_success.notified().await;
                        *durable.lock().unwrap() = Some((certificate.clone(), account_key.clone()));
                        *live.lock().unwrap() = certificate.clone();
                        Ok(())
                    })
                }
            });
        inner.test_acme.as_mut().unwrap().renewal_retry_delay = POLL_INTERVAL;
        let inner: Box<dyn CertProvider> = Box::new(inner);
        let mut provider = S3CertProvider::from_arc(inner, sync);

        nagoya::block_on(nagoya::timeout(DEADLINE, async {
            let guard = provider
                .init(dir.0.clone(), Some(vec![DOMAIN.to_owned()]))
                .await
                .unwrap();
            let assert_previous = |guard: &RenewalGuard| {
                assert_eq!(std::fs::read(&fullchain).unwrap(), restored.fullchain_pem());
                assert_eq!(
                    guard.certificate().unwrap().fullchain_pem(),
                    restored.fullchain_pem()
                );
                assert!(guard.account_key().is_none());
                assert_eq!(
                    live.lock().unwrap().fullchain_pem(),
                    restored.fullchain_pem()
                );
                s3.assert_puts(&[restored.fullchain_pem()]);
            };
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            fake.start.notify_one();
            while attempts.load(Ordering::SeqCst) < 2 {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            assert_previous(&guard);
            assert!(durable.lock().unwrap().is_none());
            permit_reload_failure.notify_one();
            while attempts.load(Ordering::SeqCst) < 3 {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            assert_previous(&guard);
            assert!(durable.lock().unwrap().is_some());
            permit_success.notify_one();
            while s3.requests.lock().unwrap().len() < 2 {
                nagoya::sleep(POLL_INTERVAL).await;
            }

            let issued = fake.chain.lock().unwrap().clone().unwrap();
            let durable = durable.lock().unwrap();
            let (saved_cert, saved_key) = durable.as_ref().unwrap();
            s3.assert_puts(&[restored.fullchain_pem(), &issued]);
            assert_eq!(std::fs::read(&fullchain).unwrap(), issued);
            assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
            assert_eq!(saved_cert.fullchain_pem(), issued);
            assert_eq!(live.lock().unwrap().fullchain_pem(), issued);
            let installed = state.certificate().unwrap();
            assert_eq!(installed.fullchain_pem(), issued);
            assert!(installed.private_key_pem() == saved_cert.private_key_pem());
            assert!(guard.account_key().unwrap().pkcs8() == saved_key.pkcs8());
            assert_eq!(attempts.load(Ordering::SeqCst), 3);
            assert_eq!(fake.step.load(Ordering::SeqCst), 8);
        }))
        .expect("complete consumer acknowledgment and S3 publication before the deadline");
    }

    #[test]
    fn renewal_ack_guard_drop_cancels_pending_callback() {
        struct CancelledCallback(Arc<AtomicBool>);

        impl Drop for CancelledCallback {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dir = CertDir::new();
        let fake = Arc::new(RenewalAcme::default());
        let state = AcmeState::new();
        let restored = restored_material();
        state.set_certificate(restored.clone());
        let entered = Arc::new(nagoya::sync::Notify::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut provider = startup_provider(StartupMode::Bootstrap, state.clone(), fake.clone())
            .with_renewal_ack({
                let entered = entered.clone();
                let cancelled = cancelled.clone();
                move |_, _| {
                    let entered = entered.clone();
                    let cancelled = cancelled.clone();
                    Box::pin(async move {
                        let _cancelled = CancelledCallback(cancelled);
                        entered.notify_one();
                        std::future::pending().await
                    })
                }
            });

        nagoya::block_on(nagoya::timeout(DEADLINE, async {
            let guard = provider
                .init(dir.0.clone(), Some(vec![DOMAIN.to_owned()]))
                .await
                .unwrap();
            fake.start.notify_one();
            entered.notified().await;
            drop(guard);
            while !cancelled.load(Ordering::Acquire) {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            assert_eq!(
                std::fs::read(dir.0.join("fullchain.pem")).unwrap(),
                restored.fullchain_pem()
            );
            assert_eq!(
                state.certificate().unwrap().fullchain_pem(),
                restored.fullchain_pem()
            );
            assert!(state.account_key().is_none());
            assert_eq!(fake.step.load(Ordering::SeqCst), 8);
        }))
        .expect("drop the pending callback before the deadline");
    }

    #[test]
    fn renewal_ack_local_publication_failure_retries_without_repeating_callback() {
        let dir = CertDir::new();
        let fullchain = dir.0.join("fullchain.pem");
        std::fs::create_dir(&fullchain).unwrap();
        let state = AcmeState::new();
        let restored = restored_material();
        state.set_certificate(restored.clone());
        let next = restored_material();
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut managed = ManagedRenewal {
            acknowledge: Arc::new({
                let attempts = attempts.clone();
                move |_, _| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(()) })
                }
            }),
            account_key: AccountKey::generate().unwrap(),
            not_after: read_cert_not_after(next.fullchain_pem()).unwrap(),
            acknowledged: false,
        };
        let stop = AtomicBool::new(false);
        let notify = nagoya::sync::Notify::new();
        nagoya::block_on(async {
            assert!(matches!(
                managed
                    .acknowledge_and_install(&next, &dir.0, &state, &stop, &notify)
                    .await,
                Err(Error::Io(_))
            ));
            assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
            assert_eq!(
                state.certificate().unwrap().fullchain_pem(),
                restored.fullchain_pem()
            );
            assert!(state.account_key().is_none());

            std::fs::remove_dir(&fullchain).unwrap();
            std::fs::write(&fullchain, restored.fullchain_pem()).unwrap();
            managed
                .acknowledge_and_install(&next, &dir.0, &state, &stop, &notify)
                .await
                .unwrap();
        });
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&fullchain).unwrap(), next.fullchain_pem());
        assert_eq!(
            state.certificate().unwrap().fullchain_pem(),
            next.fullchain_pem()
        );
        assert!(state.account_key().unwrap().pkcs8() == managed.account_key.pkcs8());
    }

    #[test]
    fn explicit_bootstrap_issues_from_empty_state() {
        let dir = CertDir::new();
        let cert_dir = dir.0.join("new");
        let fake = Arc::new(RenewalAcme::default());
        let state = AcmeState::new();
        let mut provider = startup_provider(StartupMode::Bootstrap, state.clone(), fake.clone());

        fake.start.notify_one();
        let guard = nagoya::block_on(nagoya::timeout(
            DEADLINE,
            provider.init(cert_dir.clone(), Some(vec![DOMAIN.to_owned()])),
        ))
        .expect("bootstrap before the deadline")
        .expect("issue the initial certificate");

        assert_eq!(fake.step.load(Ordering::SeqCst), 8);
        assert!(guard.account_key().is_some());
        let material = guard.certificate().unwrap();
        assert_eq!(
            std::fs::read(cert_dir.join("fullchain.pem")).unwrap(),
            material.fullchain_pem()
        );
        assert_eq!(std::fs::read_dir(cert_dir).unwrap().count(), 1);
    }

    #[test]
    fn restore_preflight_rejects_missing_or_failed_state_before_s3_pull() {
        let dir = CertDir::new();
        let s3 = RecordingS3::new(false, false);
        let sync = Arc::new(S3CertSync::new(s3.config.clone()).unwrap());
        let fake = Arc::new(RenewalAcme::default());

        for (i, (mode, has_certificate, has_account)) in [
            (StartupMode::RequireRestored, false, true),
            (StartupMode::RequireRestored, true, false),
            (StartupMode::RestoreFailed, true, true),
        ]
        .into_iter()
        .enumerate()
        {
            let state = AcmeState::new();
            if has_certificate {
                state.set_certificate(restored_material());
            }
            if has_account {
                state.set_account_key(AccountKey::generate().unwrap());
            }
            let inner: Box<dyn CertProvider> =
                Box::new(startup_provider(mode, state.clone(), fake.clone()));
            let mut wrapped = S3CertProvider::from_arc(inner, sync.clone());
            let cert_dir = dir.0.join(i.to_string());

            let result = nagoya::block_on(nagoya::timeout(
                DEADLINE,
                wrapped.init(cert_dir.clone(), Some(vec![DOMAIN.to_owned()])),
            ))
            .expect("reject restore before the deadline");
            assert!(matches!(
                (i, result),
                (0, Err(Error::Restore(RestoreError::MissingCertificate)))
                    | (1, Err(Error::Restore(RestoreError::MissingAccountKey)))
                    | (2, Err(Error::Restore(RestoreError::Failed)))
            ));
            assert!(!cert_dir.exists());
            assert_eq!(state.account_key().is_some(), has_account);
            assert_eq!(state.certificate().is_some(), has_certificate);
        }

        assert_eq!(fake.step.load(Ordering::SeqCst), 0);
        assert!(s3.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn prepared_restore_renews_with_captured_existing_account() {
        let dir = CertDir::new();
        let cert_dir = dir.0.join("restored");
        let s3 = RecordingS3::new(false, false);
        let sync = Arc::new(S3CertSync::new(s3.config.clone()).unwrap());
        let state = AcmeState::new();
        let restored = restored_material();
        let account_key = AccountKey::generate().unwrap();
        let account_thumbprint = account_key.thumbprint();
        let fake = Arc::new(RenewalAcme {
            expected_account_jwk: Some(serde_json::to_value(account_key.jwk()).unwrap()),
            ..RenewalAcme::default()
        });
        state.set_certificate(restored.clone());
        state.set_account_key(account_key);
        let inner: Box<dyn CertProvider> = Box::new(startup_provider(
            StartupMode::RequireRestored,
            state.clone(),
            fake.clone(),
        ));
        let mut wrapped = S3CertProvider::from_arc(inner, sync);

        nagoya::block_on(nagoya::timeout(DEADLINE, async {
            let startup = wrapped
                .prepare_init(cert_dir.clone(), Some(vec![DOMAIN.to_owned()]))
                .unwrap();
            assert!(!cert_dir.exists());
            assert!(s3.requests.lock().unwrap().is_empty());
            state.set_account_key(AccountKey::generate().unwrap());
            state.set_certificate(restored_material());

            let guard = startup.await.unwrap();
            assert_eq!(
                guard.account_key().unwrap().thumbprint(),
                account_thumbprint
            );
            assert_eq!(
                guard.certificate().unwrap().fullchain_pem(),
                restored.fullchain_pem()
            );
            {
                let requests = s3.requests.lock().unwrap();
                assert_eq!(requests.len(), 2);
                assert_eq!(requests[0].method, "GET");
                assert_eq!(requests[1].method, "PUT");
                assert_eq!(requests[1].body, restored.fullchain_pem());
            }
            let fullchain = cert_dir.join("fullchain.pem");
            assert_eq!(std::fs::read(&fullchain).unwrap(), restored.fullchain_pem());

            fake.start.notify_one();
            loop {
                let material = guard.certificate().unwrap();
                if material.fullchain_pem() != restored.fullchain_pem() {
                    assert_eq!(fake.step.load(Ordering::SeqCst), 8);
                    assert_eq!(std::fs::read(&fullchain).unwrap(), material.fullchain_pem());
                    break;
                }
                nagoya::sleep(POLL_INTERVAL).await;
            }
        }))
        .expect("renew restored certificate before the deadline");
    }

    #[test]
    fn prepared_restore_rejects_certificate_that_expires_before_install() {
        let dir = CertDir::new();
        let cert_dir = dir.0.join("expired");
        let state = AcmeState::new();
        let fake = Arc::new(RenewalAcme::default());
        let domains = vec![DOMAIN.to_owned()];
        let certificate = restored_material_expiring_at(SystemTime::now() + Duration::from_secs(3));
        state.set_certificate(certificate.clone());
        state.set_account_key(AccountKey::generate().unwrap());
        let mut provider = startup_provider(StartupMode::RequireRestored, state, fake.clone());
        let startup = provider
            .prepare_init(cert_dir.clone(), Some(domains.clone()))
            .unwrap();

        nagoya::block_on(nagoya::timeout(DEADLINE, async {
            while certificate.validate_for_domains(&domains).is_ok() {
                nagoya::sleep(POLL_INTERVAL).await;
            }
            assert!(matches!(startup.await, Err(Error::Config(_))));
        }))
        .expect("reject the expired certificate before the deadline");
        assert!(!cert_dir.exists());
        assert_eq!(fake.step.load(Ordering::SeqCst), 0);
    }
}
