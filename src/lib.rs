//! DNS-01 ACME certificates over the nagoya and nago-http stack.
//!
//! [`provider::DnsAcmeProvider`] obtains and renews certificates, while
//! [`dns::DnsProvider`] lets a caller use its own DNS API implementation.
//! Bunny DNS is included. The optional `s3` feature syncs the certificate,
//! private key, and account cache with an S3-compatible object store.

pub mod acme;
pub mod dns;
pub mod error;
pub mod jwk;
pub mod jws;
pub mod provider;
#[cfg(feature = "s3")]
pub mod s3;

pub use error::{Error, Result};
pub use provider::{BackgroundGuard, CertProvider, DnsAcmeProvider, RenewalGuard};
