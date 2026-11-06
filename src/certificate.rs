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
        let leaf_spki = certificate_chain_leaf_spki(&fullchain_pem)?;
        let private_key_der = validate_private_key(&private_key_pem)?;
        let key_pair = rcgen::KeyPair::try_from(private_key_der.as_slice())
            .map_err(|_| Error::Pem("certificate private key is not supported PKCS#8".into()))?;
        use rcgen::PublicKeyData;
        if key_pair.subject_public_key_info().as_slice() != leaf_spki.as_slice() {
            return Err(Error::Pem(
                "certificate leaf does not match its private key".into(),
            ));
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
    certificate_chain_leaf_spki(pem).map(|_| ())
}

fn certificate_chain_leaf_spki(pem: &[u8]) -> Result<Vec<u8>> {
    validate_pem_envelope(pem, "CERTIFICATE", true)
        .map_err(|_| Error::Pem("certificate chain was not a certificate-only PEM chain".into()))?;

    let mut leaf_spki = None;
    let mut certificate_count = 0;
    for block in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let block =
            block.map_err(|_| Error::Pem("certificate chain contained invalid PEM data".into()))?;
        if block.label != "CERTIFICATE" {
            return Err(Error::Pem(
                "certificate chain contained non-certificate PEM data".into(),
            ));
        }
        let (remaining, certificate) = x509_parser::parse_x509_certificate(&block.contents)
            .map_err(|_| Error::Pem("certificate chain contained invalid DER".into()))?;
        if !remaining.is_empty() {
            return Err(Error::Pem(
                "certificate chain contained trailing DER data".into(),
            ));
        }
        if leaf_spki.is_none() {
            leaf_spki = Some(certificate.public_key().raw.to_vec());
        }
        certificate_count += 1;
    }

    if certificate_count == 0 {
        return Err(Error::Pem("certificate chain was not a PEM chain".into()));
    }
    leaf_spki.ok_or_else(|| Error::Pem("certificate chain was not a PEM chain".into()))
}

fn validate_private_key(pem: &[u8]) -> Result<Vec<u8>> {
    validate_pem_envelope(pem, "PRIVATE KEY", false)
        .map_err(|_| Error::Pem("certificate private key must be one PKCS#8 PEM block".into()))?;
    let mut blocks = x509_parser::pem::Pem::iter_from_buffer(pem);
    let block = blocks
        .next()
        .ok_or_else(|| Error::Pem("certificate private key is missing".into()))?
        .map_err(|_| Error::Pem("certificate private key PEM is malformed".into()))?;
    if block.label != "PRIVATE KEY" || blocks.next().is_some() {
        return Err(Error::Pem(
            "certificate private key must be one PKCS#8 PEM block".into(),
        ));
    }
    Ok(block.contents)
}

fn validate_pem_envelope(
    pem: &[u8],
    label: &str,
    allow_multiple: bool,
) -> std::result::Result<(), ()> {
    let pem = std::str::from_utf8(pem).map_err(|_| ())?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut in_block = false;
    let mut block_count = 0;

    for line in pem.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !in_block {
            if line != begin.as_str() {
                return Err(());
            }
            block_count += 1;
            if !allow_multiple && block_count > 1 {
                return Err(());
            }
            in_block = true;
        } else if line == end.as_str() {
            in_block = false;
        } else if line.starts_with("-----BEGIN")
            || line.starts_with("-----END")
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(());
        }
    }

    if in_block || block_count == 0 {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    fn generated_material() -> (Vec<u8>, Vec<u8>) {
        let generated = generate_simple_self_signed(vec!["example.test".to_owned()])
            .expect("generate test certificate");
        (
            generated.cert.pem().into_bytes(),
            generated.signing_key.serialize_pem().into_bytes(),
        )
    }

    fn certificate_block(contents: &[u8]) -> Vec<u8> {
        let encoded = base64_encode(contents);
        format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n").into_bytes()
    }

    fn base64_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            output.push(TABLE[(a >> 2) as usize] as char);
            output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            output.push(if chunk.len() > 1 {
                TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            output.push(if chunk.len() > 2 {
                TABLE[(c & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        output
    }

    #[test]
    fn accepts_rcgen_leaf_and_matching_pkcs8_key() {
        let (chain, key) = generated_material();
        assert!(CertificateMaterial::new(chain, key).is_ok());
    }

    #[test]
    fn rejects_rcgen_leaf_with_a_different_private_key() {
        let (chain, _) = generated_material();
        let (_, other_key) = generated_material();
        let error = CertificateMaterial::new(chain, other_key.clone())
            .err()
            .expect("mismatched key must be rejected");
        assert!(
            !error
                .to_string()
                .contains(std::str::from_utf8(&other_key).expect("generated PEM is UTF-8"))
        );
    }

    #[test]
    fn rejects_malformed_leaf_der() {
        let (_, key) = generated_material();
        let error = CertificateMaterial::new(certificate_block(b"invalid DER"), key)
            .err()
            .expect("malformed leaf must be rejected");
        assert!(matches!(error, Error::Pem(_)));
    }

    #[test]
    fn accepts_a_chain_with_a_later_rcgen_certificate() {
        let (mut chain, key) = generated_material();
        let (later, _) = generated_material();
        chain.extend(later);
        assert!(CertificateMaterial::new(chain, key).is_ok());
    }

    #[test]
    fn rejects_malformed_later_chain_certificate() {
        let (mut chain, key) = generated_material();
        chain.extend(certificate_block(b"invalid later DER"));
        let error = CertificateMaterial::new(chain, key)
            .err()
            .expect("malformed later certificate must be rejected");
        assert!(matches!(error, Error::Pem(_)));
    }

    #[test]
    fn rejects_malformed_or_non_pkcs8_private_keys() {
        let (chain, _) = generated_material();
        for key in [
            b"not a PEM key".to_vec(),
            b"-----BEGIN RSA PRIVATE KEY-----\nAQ==\n-----END RSA PRIVATE KEY-----\n".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----\n".to_vec(),
        ] {
            assert!(CertificateMaterial::new(chain.clone(), key).is_err());
        }
    }

    #[test]
    fn rejects_multiple_private_key_blocks() {
        let (chain, key) = generated_material();
        let key = [key.as_slice(), key.as_slice()].concat();
        assert!(CertificateMaterial::new(chain, key).is_err());
    }

    #[test]
    fn public_chain_validation_keeps_its_existing_result_contract() {
        let (chain, _) = generated_material();
        let result: Result<()> = validate_public_certificate_chain(&chain);
        assert!(result.is_ok());
    }
}
