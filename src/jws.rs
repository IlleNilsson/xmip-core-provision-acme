//! A request body as RFC 8555 section 6.2 has it: a JWS in the flattened
//! JSON serialization, ES256, its protected header naming the nonce, the
//! URL and the account — its key on the first request, its URL after.
//!
//! Both halves are here so the client and the authority that serves ACME
//! (`internal-ca`) cannot drift: what one signs the other verifies.

use codec::base64::{decode_url, encode_url_unpadded};
use provision::{KeyPair, ProvisionError, Result, verify_fixed};
use serde_json::{Value, json};

use crate::Jwk;

/// Who signs: the account's key, by its key before the account exists and
/// by its URL after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    /// The key itself, in the header: `newAccount`.
    Key(Jwk),
    /// The account's URL: every request after.
    Account(String),
}

/// A body signed by `key`, for `url`, with `nonce`; `payload` `None` is a
/// POST-as-GET, whose payload is empty (RFC 8555 section 6.3).
///
/// # Errors
///
/// Where signing fails.
pub fn sign(
    key: &KeyPair,
    signer: &Signer,
    nonce: &str,
    url: &str,
    payload: Option<&Value>,
) -> Result<Vec<u8>> {
    let mut header = json!({ "alg": "ES256", "nonce": nonce, "url": url });
    match signer {
        Signer::Key(jwk) => header["jwk"] = jwk.json(),
        Signer::Account(account) => header["kid"] = Value::String(account.clone()),
    }
    let protected = encode_url_unpadded(header.to_string().as_bytes());
    let payload = payload.map_or_else(String::new, |payload| {
        encode_url_unpadded(payload.to_string().as_bytes())
    });
    let signature = key.sign_fixed(format!("{protected}.{payload}").as_bytes())?;
    let body = json!({
        "protected": protected,
        "payload": payload,
        "signature": encode_url_unpadded(&signature),
    });
    Ok(body.to_string().into_bytes())
}

/// A body read, before its signature is checked: what the authority needs
/// to find the key it must verify with.
#[derive(Clone, Debug)]
pub struct Signed {
    /// The nonce the client used.
    pub nonce: String,
    /// The URL the client signed for.
    pub url: String,
    /// The key or the account that signed.
    pub signer: Signer,
    /// The payload, empty for a POST-as-GET.
    pub payload: Vec<u8>,
    input: Vec<u8>,
    signature: Vec<u8>,
}

impl Signed {
    /// A body as it arrived.
    ///
    /// # Errors
    ///
    /// Where it is not a flattened JWS, its algorithm is not ES256, or its
    /// header names neither a key nor an account, or both.
    pub fn read(body: &[u8]) -> Result<Self> {
        let malformed = |what: &str| ProvisionError::new(format!("the request's JWS {what}"));
        let outer: Value = serde_json::from_slice(body).map_err(|_| malformed("is not JSON"))?;
        let part = |name: &str| outer.get(name).and_then(Value::as_str).unwrap_or_default();
        let header: Value = serde_json::from_slice(&decode_url(part("protected"))?)
            .map_err(|_| malformed("has a header that is not JSON"))?;
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(malformed("is not signed with ES256"));
        }
        let text = |name: &str| header.get(name).and_then(Value::as_str).map(str::to_string);
        let signer = match (header.get("jwk"), text("kid")) {
            (Some(jwk), None) => Signer::Key(Jwk::from_json(jwk)?),
            (None, Some(account)) => Signer::Account(account),
            _ => return Err(malformed("names neither a key nor an account, or both")),
        };
        Ok(Self {
            nonce: text("nonce").ok_or_else(|| malformed("has no nonce"))?,
            url: text("url").ok_or_else(|| malformed("has no url"))?,
            signer,
            payload: decode_url(part("payload"))?,
            input: format!("{}.{}", part("protected"), part("payload")).into_bytes(),
            signature: decode_url(part("signature"))?,
        })
    }

    /// Whether `key` signed it.
    #[must_use]
    pub fn verified_by(&self, key: &Jwk) -> bool {
        verify_fixed(&key.point(), &self.input, &self.signature)
    }

    /// The payload as JSON, `null` for a POST-as-GET.
    ///
    /// # Errors
    ///
    /// Where a payload is there and is not JSON.
    pub fn json(&self) -> Result<Value> {
        if self.payload.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.payload)
            .map_err(|_| ProvisionError::new("the request's payload is not JSON"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_one_side_signs_the_other_reads_and_verifies() {
        let key = KeyPair::generate().expect("a key");
        let jwk = Jwk::from_point(key.point()).expect("a jwk");
        let payload = json!({ "termsOfServiceAgreed": true });
        let body = sign(
            &key,
            &Signer::Key(jwk.clone()),
            "n1",
            "https://a/new",
            Some(&payload),
        )
        .expect("signed");
        let signed = Signed::read(&body).expect("read");
        assert_eq!(signed.nonce, "n1");
        assert_eq!(signed.url, "https://a/new");
        assert_eq!(signed.signer, Signer::Key(jwk.clone()));
        assert!(signed.verified_by(&jwk));
        assert_eq!(signed.json().expect("json"), payload);

        let other = Jwk::from_point(KeyPair::generate().expect("a key").point()).expect("jwk");
        assert!(!signed.verified_by(&other));
        let account = Signer::Account("https://a/acct/1".to_string());
        let body = sign(&key, &account, "n2", "https://a/order", None).expect("signed");
        let signed = Signed::read(&body).expect("read");
        assert_eq!(signed.signer, account);
        assert_eq!(signed.json().expect("empty"), Value::Null);
        assert!(Signed::read(b"{}").is_err());
    }
}
