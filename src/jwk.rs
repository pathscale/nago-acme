//! JSON Web Key support for ES256 ACME accounts.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// The public portion of a P-256 elliptic-curve key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EcJwk {
    /// Key type, always `EC`.
    pub kty: String,
    /// Curve, always `P-256`.
    pub crv: String,
    /// Base64url-encoded 32-byte X coordinate.
    pub x: String,
    /// Base64url-encoded 32-byte Y coordinate.
    pub y: String,
}

impl EcJwk {
    /// The RFC 7638 SHA-256 thumbprint of this key.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint_fields(&[
            ("crv", &self.crv),
            ("kty", &self.kty),
            ("x", &self.x),
            ("y", &self.y),
        ])
    }
}

/// Compute an RFC 7638 thumbprint from the required members of a JSON Web Key.
pub fn thumbprint(jwk: &Value) -> Result<String> {
    let key_type = jwk
        .get("kty")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Config("JWK omitted string member kty".into()))?;
    let required: &[&str] = match key_type {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "oct" => &["k", "kty"],
        "OKP" => &["crv", "kty", "x"],
        _ => return Err(Error::Config(format!("unsupported JWK type {key_type}"))),
    };
    let values = required
        .iter()
        .map(|name| {
            jwk.get(*name)
                .and_then(Value::as_str)
                .map(|value| (*name, value))
                .ok_or_else(|| Error::Config(format!("JWK omitted string member {name}")))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(thumbprint_fields(&values))
}

fn thumbprint_fields(fields: &[(&str, &str)]) -> String {
    let mut canonical = String::from("{");
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 {
            canonical.push(',');
        }
        canonical.push('"');
        canonical.push_str(name);
        canonical.push_str("\":\"");
        canonical.push_str(value);
        canonical.push('"');
    }
    canonical.push('}');
    sha256_base64url(canonical.as_bytes())
}

/// An ES256 account key held in process memory.
///
/// This type intentionally does not implement `Debug` so formatting it cannot
/// expose the private key. Applications may load or save its PKCS#8 bytes with
/// an OS keychain or key agent.
#[derive(Clone)]
pub struct AccountKey {
    pkcs8: Vec<u8>,
    jwk: EcJwk,
}

impl AccountKey {
    /// Generate a new ES256 account key.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::Account("could not generate the ES256 account key".into()))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec())
    }

    /// Load an ES256 account key from PKCS#8 bytes in memory.
    pub fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|_| Error::Account("account key is not a P-256 key".into()))?;
        let public = pair.public_key().as_ref();
        if public.len() != 65 || public[0] != 4 {
            return Err(Error::Account(
                "account key has an unexpected public point".into(),
            ));
        }
        Ok(Self {
            pkcs8,
            jwk: EcJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: base64url_encode(&public[1..33]),
                y: base64url_encode(&public[33..65]),
            },
        })
    }

    pub(crate) fn jwk(&self) -> &EcJwk {
        &self.jwk
    }

    pub(crate) fn thumbprint(&self) -> String {
        self.jwk.thumbprint()
    }

    /// Return the PKCS#8 bytes so an application can keep the key in its OS
    /// keychain or key agent.
    #[must_use]
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8, &rng)
            .map_err(|_| Error::Account("could not load the ES256 account key".into()))?;
        pair.sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| Error::Account("could not sign the ACME request".into()))
    }
}

/// Encode bytes with the URL-safe Base64 alphabet and no padding.
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let (chunks, remainder) = bytes.as_chunks::<3>();
    for chunk in chunks {
        let value = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        output.push(ALPHABET[(value & 0x3f) as usize] as char);
    }
    match remainder {
        [a] => {
            output.push(ALPHABET[(a >> 2) as usize] as char);
            output.push(ALPHABET[((a & 0x03) << 4) as usize] as char);
        }
        [a, b] => {
            output.push(ALPHABET[(a >> 2) as usize] as char);
            output.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            output.push(ALPHABET[((b & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }
    output
}

#[cfg(test)]
pub(crate) fn base64url_decode(encoded: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(Error::AcmeProtocol("invalid base64url value".into())),
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    if bits >= 6 || (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) {
        return Err(Error::AcmeProtocol("invalid base64url padding bits".into()));
    }
    Ok(output)
}

pub(crate) fn sha256_base64url(bytes: &[u8]) -> String {
    base64url_encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_matches_the_rfc_7638_example() {
        assert_eq!(
            thumbprint(&serde_json::json!({
                "e":"AQAB",
                "kty":"RSA",
                "n":concat!(
                    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
                    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
                    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
                    "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
                    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
                    "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                )
            }))
            .unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
