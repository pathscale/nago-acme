//! DNS-01 ACME certificates over the nagoya and nago-http stack.
//!
//! [`provider::DnsAcmeProvider`] obtains and renews certificates, while
//! [`dns::DnsProvider`] lets a caller use its own DNS API implementation.
//! Bunny DNS is included. Certificate and ACME account private keys stay in
//! [`AcmeState`] memory; the optional `s3` feature syncs only public chains.

pub mod acme;
pub mod certificate;
pub mod dns;
pub mod error;
pub mod jwk;
pub mod jws;
pub mod provider;
#[cfg(feature = "s3")]
pub mod s3;

pub use certificate::{AcmeState, CertificateMaterial};
pub use error::{Error, Result};
pub use jwk::AccountKey;
pub use provider::{BackgroundGuard, CertProvider, DnsAcmeProvider, RenewalGuard};
