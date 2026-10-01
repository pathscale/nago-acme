# nago-acme

DNS-01 ACME certificates over [nagoya](https://github.com/pathscale/nagoya)
and [nago-http](https://github.com/pathscale/nago-http). The crate provisions
PEM certificate chains, stores the matching private key, and renews before
expiry. It has no async runtime of its own.

DNS-01 is the only challenge type. `BunnyDns` is included for bunny.net DNS;
implement `DnsProvider` to use another provider.

```rust,no_run
use nago_acme::{CertProvider, DnsAcmeProvider, dns::BunnyDns};
use std::path::PathBuf;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let dns = BunnyDns::new(std::env::var("BUNNYCDN_API_KEY")?);
let mut provider = DnsAcmeProvider::new("admin@example.com", dns)
    .production()
    .propagation_secs(90)
    .renew_within_days(30)
    .max_retries(3);
let _renewal_guard = provider
    .init(PathBuf::from("/data/certs"), Some(vec!["example.com".into()]))
    .await?;
# Ok(())
# }
```

The provider defaults to Let's Encrypt staging. Keep the returned guard alive
for as long as renewals should run. Dropping it wakes and stops the renewal
loop. The files are `fullchain.pem` and `privkey.pem` in the certificate
directory.

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

Enable the `s3` feature to sync the certificate chain, private key, and ACME
account cache. The signer uses hand-written SigV4 over nago-http and supports
path-style buckets on AWS S3 and compatible stores.

Pass explicit credentials through `S3Config`, or use `S3Config::from_env()`
with `NAGO_ACME_S3_BUCKET`, `NAGO_ACME_S3_ENDPOINT`, `NAGO_ACME_S3_PREFIX`,
`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally
`AWS_SESSION_TOKEN`. Call `.with_imdsv2()` on `S3CertSync` to enable EC2 role
credential lookup when explicit and environment credentials are absent.
Use `.with_session_token(...)` with explicit temporary credentials.

```rust,no_run
use std::{path::PathBuf, sync::Arc};
use nago_acme::{CertProvider, DnsAcmeProvider, dns::BunnyDns};
use nago_acme::s3::{S3CertProvider, S3CertSync, S3Config};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let sync = Arc::new(S3CertSync::new(S3Config::from_env()?)?);
let dns = BunnyDns::new(std::env::var("BUNNYCDN_API_KEY")?);
let provider = DnsAcmeProvider::new("admin@example.com", dns).with_s3_sync(sync.clone());
let mut provider = S3CertProvider::from_arc(provider, sync);
let _guard = provider
    .init(PathBuf::from("/data/certs"), Some(vec!["example.com".into()]))
    .await?;
# Ok(())
# }
```

S3 sync is disabled by default. The full feature set has no Tokio dependency:
`cargo tree --all-features -i tokio` is empty.

## License

MIT.
