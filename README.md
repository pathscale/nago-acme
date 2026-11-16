# nago-acme

DNS-01 ACME certificates over [nagoya](https://github.com/pathscale/nagoya)
and [nago-http](https://github.com/pathscale/nago-http). The crate provisions
PEM certificate chains, keeps the matching private key in process memory, and
renews before expiry. It has no async runtime of its own.

DNS-01 is the only challenge type. `BunnyDns` is included for bunny.net DNS;
implement `DnsProvider` to use another provider.

```rust,no_run
use nago_acme::{AcmeState, CertProvider, DnsAcmeProvider, StartupMode, dns::BunnyDns};
use std::path::PathBuf;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let dns = BunnyDns::new(std::env::var("BUNNYCDN_API_KEY")?);
let state = AcmeState::new();
let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
    .with_startup_mode(StartupMode::Bootstrap)
    .production()
    .propagation_secs(90)
    .renew_within_days(30)
    .max_retries(3)
    .with_state(state.clone());
let renewal_guard = provider
    .init(PathBuf::from("/data/certs"), Some(vec!["example.com".into()]))
    .await?;
let certificate = renewal_guard.certificate().expect("certificate is ready");
let _fullchain_pem = certificate.fullchain_pem();
let _private_key_pem = certificate.private_key_pem();
# Ok(())
# }
```

The provider defaults to Let's Encrypt staging. Keep the returned guard alive
for as long as renewals should run. Dropping it wakes and stops the renewal
loop. The provider writes only the public `fullchain.pem` to the certificate
directory.
`AcmeState` holds the certificate private key and ACME account key in memory;
`RenewalGuard::certificate()` and `RenewalGuard::account_key()` expose their
latest values to the application.

Use `StartupMode::Bootstrap` for intentional first-time provisioning. The
constructors keep this behavior by default for existing callers: missing
credentials can lead to new account registration and certificate issuance,
which can hit CA rate limits if repeated on restart. In bootstrap mode, a
restored certificate that has expired or does not cover the requested domains
is replaced by a new issuance. For routine startup,
load both `CertificateMaterial` and `AccountKey` from your secret store, put
them in `AcmeState`, and select `StartupMode::RequireRestored` before calling
`init`. If the load fails, return the application error or select
`StartupMode::RestoreFailed` to make `init` return
`Error::Restore(RestoreError::Failed)`. Keep secret-store error details in the
application.

Require-restored startup rejects missing credentials before writing the public
chain or contacting ACME or S3. It validates the restored certificate's names
and validity, and deferred renewal looks up the existing CA account with the
restored key. If the CA does not recognize the key, renewal cannot register a
replacement account in this mode. Successful startup exposes the captured
certificate and account key through shared state. Seed the state before
initialization and let the provider manage it through startup and renewal.

### Upgrading from 0.1

Version 0.2 neither reads nor deletes the secret files 0.1 kept in the
certificate directory: `privkey.pem` and
`acme_cache/acme_account_credentials.json`. To keep the existing certificate
and ACME account, load them once before calling `init`. Pass the old
`fullchain.pem` and `privkey.pem` bytes to `CertificateMaterial::new`.
Hex-decode the `account_key_pkcs8_hex` field of the credentials file and pass
the bytes to `AccountKey::from_pkcs8`. The key belongs to the ACME directory
(staging or production) named in its `directory_url` field. Put both values in
`AcmeState` and save them to your secret store, then delete `privkey.pem` and
`acme_cache/`, because the provider leaves them on disk. If you skip this,
bootstrap startup with empty state registers a new account and issues a new
certificate.

### Acknowledge persistence and TLS reload

Register `DnsAcmeProvider::with_renewal_ack` before `init` to require the
application to save the certificate, its private key and the ACME account key
and activate the new TLS configuration. The callback receives the matching
material directly. Configure the TLS consumer before starting the provider,
since a restored certificate can already be due for renewal. For first-time
provisioning, save and activate the initial credentials during application
startup. The callback covers background renewals. Without the callback,
renewals continue to update the public chain and shared state directly.

```rust,no_run
use std::sync::Arc;
use nago_acme::{AccountKey, CertificateMaterial, DnsAcmeProvider, RenewalAckFuture, Result};
use nago_acme::dns::DnsProvider;

trait ApplicationTls: Send + Sync + 'static {
    fn persist<'a>(
        &'a self,
        certificate: &'a CertificateMaterial,
        account_key: &'a AccountKey,
    ) -> RenewalAckFuture<'a>;

    fn reload_tls(&self, certificate: &CertificateMaterial) -> Result<()>;
}

fn require_ack<D: DnsProvider>(
    provider: DnsAcmeProvider<D>,
    tls: Arc<impl ApplicationTls>,
) -> DnsAcmeProvider<D> {
    provider.with_renewal_ack(move |certificate, account_key| {
        let tls = tls.clone();
        Box::pin(async move {
            tls.persist(certificate, account_key).await?;
            tls.reload_tls(certificate)
        })
    })
}
```

Return `Ok(())` only after both steps complete. Build and activate TLS from
the callback's material instead of reading `fullchain.pem` or the guard during
the callback. The provider advances the public chain and shared state after
success, then queues the new public chain if its own S3 sync is configured.
Use one live guard per certificate directory and shared state.

If persistence or reload returns an error, the provider retains the previous
public chain and shared state. It retries the same credentials without another
ACME order, starting after one hour and backing off to one day. An expired
pending certificate is discarded. If local chain publication fails after
acknowledgment, the provider retries publication for that material without
calling the consumer again. The callback should be idempotent across partial
success and handle its own operation timeouts and error reporting. Dropping
the guard cancels a pending callback future and discards in-memory retry state.
The application owns recovery of persistence or reload work that already
completed, including across restarts.

## Implementing `DnsProvider`

Each method returns a boxed future so DNS clients can use the house executor
without an async-trait dependency.

```rust,no_run
use nago_acme::{Error, Result, dns::{DnsFuture, DnsProvider}};

struct MyDns;

impl DnsProvider for MyDns {
    fn add_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move {
            // Publish value as a TXT record at name.
            let _ = (name, value);
            Ok(())
        })
    }

    fn remove_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a> {
        Box::pin(async move {
            // Remove only this challenge value from name.
            let _ = (name, value);
            Ok(())
        })
    }
}

fn report(error: Error) -> Result<()> {
    Err(error)
}
```

`cleanup_txt_records` defaults to success. Implement it when the DNS API can
remove stale TXT records before a challenge starts.

## S3-compatible sync

Enable the `s3` feature to sync the public certificate chain. Private keys and
ACME account keys stay in `AcmeState` memory and are never uploaded. The signer
uses hand-written SigV4 over nago-http and supports path-style buckets on AWS
S3 and compatible stores.

Pass explicit credentials through `S3Config`, or use `S3Config::from_env()`
with `NAGO_ACME_S3_BUCKET`, `NAGO_ACME_S3_ENDPOINT`, `NAGO_ACME_S3_PREFIX`,
`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally
`AWS_SESSION_TOKEN`. Call `.with_imdsv2()` on `S3CertSync` to enable EC2 role
credential lookup when explicit and environment credentials are absent.
Use `.with_session_token(...)` with explicit temporary credentials.

```rust,no_run
use std::{path::PathBuf, sync::Arc};
use nago_acme::{AcmeState, CertProvider, DnsAcmeProvider, StartupMode, dns::BunnyDns};
use nago_acme::s3::{S3CertSync, S3Config};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let sync = Arc::new(S3CertSync::new(S3Config::from_env()?)?);
let dns = BunnyDns::new(std::env::var("BUNNYCDN_API_KEY")?);
let state = AcmeState::new();
let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
    .with_startup_mode(StartupMode::Bootstrap)
    .with_state(state)
    .with_s3_sync(sync.clone());
let _guard = provider
    .init(PathBuf::from("/data/certs"), Some(vec!["example.com".into()]))
    .await?;
# Ok(())
# }
```

S3 sync transfers the public certificate chain only. It cannot restore the
private certificate key or ACME account key; callers must seed those through
`AcmeState`. Existing private-key or account-cache objects from older versions
are not deleted automatically and need a separately reviewed migration. S3
sync is disabled by default. A provider claims one publisher per exact
`fullchain.pem` request URL for its local lifetime. DNS providers configured with
`with_s3_sync` retry failed renewal uploads, and a failed upload of a
certificate issued at startup, from the installed public chain in
memory, starting after one minute and backing off up to one hour. A newer
successful renewal replaces any pending upload. An S3 wrapper publishes to
its own target only at startup. If that upload fails, the wrapper keeps the
inner provider's guard and retries the upload from `fullchain.pem` in the
background with the same backoff until it succeeds or the guard is dropped.
A same-target S3 wrapper
delegates directly, skipping both the startup pull and duplicate upload.
A separate-target wrapper validates and captures the inner provider's restored
credentials before it pulls a public chain.
Endpoint aliases, other processes, and server-side completion after local
cancellation are outside this process-local guarantee. The full feature set
has no Tokio dependency:
`cargo tree --all-features -i tokio` is empty.

## License

MIT.
