//! Flattened JSON Web Signatures used by the ACME client.

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::jwk::{AccountKey, base64url_encode};

pub(crate) fn flattened_jws(
    key: &AccountKey,
    nonce: &str,
    url: &str,
    payload: &[u8],
    kid: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let protected = match kid {
        Some(kid) => json!({"alg":"ES256", "nonce":nonce, "url":url, "kid":kid}),
        None => json!({"alg":"ES256", "nonce":nonce, "url":url, "jwk":key.jwk()}),
    };
    let protected = serde_json::to_vec(&protected)
        .map_err(|error| Error::AcmeProtocol(format!("serialize JWS header: {error}")))?;
    let protected = base64url_encode(&protected);
    let payload = base64url_encode(payload);
    let signing_input = format!("{protected}.{payload}");
    let signature = base64url_encode(&key.sign(signing_input.as_bytes())?);
    let flattened = json!({
        "protected":protected,
        "payload":payload,
        "signature":signature
    });
    let body = serde_json::to_vec(&flattened)
        .map_err(|error| Error::AcmeProtocol(format!("serialize JWS: {error}")))?;
    Ok((body, signing_input))
}

/// Parse a flattened JWS body as JSON.
pub fn parse_flattened(body: &[u8]) -> Result<Value> {
    serde_json::from_slice(body)
        .map_err(|error| Error::AcmeProtocol(format!("parse flattened JWS: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::base64url_decode;

    #[test]
    fn jws_has_flattened_es256_shape() {
        let key = AccountKey::generate().unwrap();
        let payload = br#"{"termsOfServiceAgreed":true}"#;
        let (body, signing_input) = flattened_jws(
            &key,
            "nonce-value",
            "https://ca.example/new-account",
            payload,
            None,
        )
        .unwrap();
        let flattened = parse_flattened(&body).unwrap();
        let protected = flattened["protected"].as_str().unwrap();
        let payload_part = flattened["payload"].as_str().unwrap();
        assert_eq!(signing_input, format!("{protected}.{payload_part}"));
        assert_eq!(base64url_decode(payload_part).unwrap(), payload);
        let header: Value = serde_json::from_slice(&base64url_decode(protected).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "nonce-value");
        assert_eq!(header["url"], "https://ca.example/new-account");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert!(header.get("kid").is_none());
        assert_eq!(
            base64url_decode(flattened["signature"].as_str().unwrap())
                .unwrap()
                .len(),
            64
        );
    }
}
