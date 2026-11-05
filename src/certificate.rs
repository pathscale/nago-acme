//! In-memory certificate and ACME account state.

use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::jwk::AccountKey;

/// A certificate chain and its matching PEM private key, kept in process memory.
///
/// This type intentionally does not implement `Debug` so formatting it cannot
/// expose the private key.
#[derive(Clone)]
pub struct CertificateMaterial {
    fullchain_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

impl CertificateMaterial {
    /// Create certificate material from public chain bytes and private-key bytes.
    pub fn new(fullchain_pem: Vec<u8>, private_key_pem: Vec<u8>) -> Result<Self> {
        validate_public_certificate_chain(&fullchain_pem)?;
        if private_key_pem.is_empty() {
            return Err(Error::Pem("certificate private key is empty".into()));
        }
        Ok(Self {
            fullchain_pem,
            private_key_pem,
        })
    }

    /// Return the public PEM certificate chain.
    #[must_use]
    pub fn fullchain_pem(&self) -> &[u8] {
        &self.fullchain_pem
    }

    /// Return the private key PEM bytes held in process memory.
    #[must_use]
    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key_pem
    }
}

/// Shared in-memory state for the current certificate and ACME account key.
///
/// Clone this value to share state with the provider and the application. The
/// state can be seeded from an OS keychain before initialization, then read
/// after renewal to update the keychain without writing secrets to files.
#[derive(Clone, Default)]
pub struct AcmeState {
    certificate: Arc<Mutex<Option<CertificateMaterial>>>,
    account_key: Arc<Mutex<Option<AccountKey>>>,
}

impl AcmeState {
    /// Create empty in-memory ACME state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the current certificate and private key, if provisioned.
    #[must_use]
    pub fn certificate(&self) -> Option<CertificateMaterial> {
        self.certificate
            .lock()
            .expect("certificate state mutex poisoned")
            .clone()
    }

    /// Replace the current certificate and private key in memory.
    pub fn set_certificate(&self, certificate: CertificateMaterial) {
        *self
            .certificate
            .lock()
            .expect("certificate state mutex poisoned") = Some(certificate);
    }

    /// Return the ACME account key, if one has been provisioned.
    #[must_use]
    pub fn account_key(&self) -> Option<AccountKey> {
        self.account_key
            .lock()
            .expect("account key state mutex poisoned")
            .clone()
    }

    /// Replace the ACME account key in memory.
    pub fn set_account_key(&self, account_key: AccountKey) {
        *self
            .account_key
            .lock()
            .expect("account key state mutex poisoned") = Some(account_key);
    }
}

pub(crate) fn validate_public_certificate_chain(pem: &[u8]) -> Result<()> {
    let pem = std::str::from_utf8(pem)
        .map_err(|_| Error::Pem("certificate chain was not UTF-8 PEM".into()))?;
    let mut in_certificate = false;
    let mut found_certificate = false;

    for line in pem.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !in_certificate {
            if line != "-----BEGIN CERTIFICATE-----" {
                return Err(Error::Pem(
                    "certificate chain contained non-certificate PEM data".into(),
                ));
            }
            in_certificate = true;
        } else if line == "-----END CERTIFICATE-----" {
            in_certificate = false;
            found_certificate = true;
        } else if line.starts_with("-----BEGIN")
            || line.starts_with("-----END")
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(Error::Pem(
                "certificate chain contained non-certificate PEM data".into(),
            ));
        }
    }

    if in_certificate || !found_certificate {
        return Err(Error::Pem("certificate chain was not a PEM chain".into()));
    }
    Ok(())
}
