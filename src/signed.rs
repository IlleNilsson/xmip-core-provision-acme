//! A request body as RFC 8555 section 6.2 has it: a JWS in the flattened
//! JSON serialization, ES256, its protected header naming the nonce, the
//! URL and the account — its key on the first request, its URL after.
//!
//! Both halves are here so the client and the authority that serves ACME
//! (`internal-ca`) cannot drift: what one signs the other verifies. The JWS
//! itself — its serialization, its base64url, its ES256 check — and the
//! account key's JWK are the estate's one JOSE (`xmip-core-library-jose`);
//! what ACME asks of the header is here.

use jose::jwk::Key;
use jose::jws::{self, Algorithm, Jws};
use provision::{KeyPair, ProvisionError, Result};
use serde_json::{Map, Value};

/// Who signs: the account's key, by its key before the account exists and
/// by its URL after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    /// The key itself, in the header: `newAccount`.
    Key(Key),
    /// The account's URL: every request after.
    Account(String),
}

/// A body signed by `key`, for `url`, with `nonce`; `payload` `None` is a
/// POST-as-GET, whose payload is empty (RFC 8555 section 6.3).
///
/// # Errors
///
/// Where the signer's key is not a P-256 key, or signing fails.
pub fn sign(
    key: &KeyPair,
    signer: &Signer,
    nonce: &str,
    url: &str,
    payload: Option<&Value>,
) -> Result<Vec<u8>> {
    let mut header = Map::new();
    header.insert("nonce".to_string(), Value::from(nonce));
    header.insert("url".to_string(), Value::from(url));
    match signer {
        Signer::Key(account) => {
            let jwk = account
                .json()
                .ok_or_else(|| ProvisionError::new("the account key is not a P-256 key"))?;
            header.insert("jwk".to_string(), jwk);
        }
        Signer::Account(account) => {
            header.insert("kid".to_string(), Value::from(account.as_str()));
        }
    }
    let payload = payload.map_or_else(Vec::new, |payload| payload.to_string().into_bytes());
    Ok(jws::sign_flattened(header, &payload, key)?)
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
    jws: Jws,
}

impl Signed {
    /// A body as it arrived.
    ///
    /// # Errors
    ///
    /// Where it is not a flattened JWS, its algorithm is not ES256, its
    /// header names neither a key nor an account, or both, or the key it
    /// names is not a P-256 key.
    pub fn read(body: &[u8]) -> Result<Self> {
        let malformed = |what: &str| ProvisionError::new(format!("the request's JWS {what}"));
        let jws = Jws::read_flattened(body)?;
        if jws.algorithm() != Some(Algorithm::Es256.name()) {
            return Err(malformed("is not signed with ES256"));
        }
        let signer = match (jws.header.get("jwk"), jws.key_id()) {
            (Some(jwk), None) => Signer::Key(
                Key::read(jwk)?
                    .filter(|key| key.algorithm() == Algorithm::Es256)
                    .ok_or_else(|| {
                        ProvisionError::new("the account key is not an EC key on P-256")
                    })?,
            ),
            (None, Some(account)) => Signer::Account(account.to_string()),
            _ => return Err(malformed("names neither a key nor an account, or both")),
        };
        let text = |name: &str| jws.text(name).map(str::to_string);
        Ok(Self {
            nonce: text("nonce").ok_or_else(|| malformed("has no nonce"))?,
            url: text("url").ok_or_else(|| malformed("has no url"))?,
            signer,
            jws,
        })
    }

    /// Whether `key` signed it, with the ES256 the header names.
    #[must_use]
    pub fn verified_by(&self, key: &Key) -> bool {
        key.algorithm() == Algorithm::Es256
            && key.verifies(self.jws.signing_input.as_bytes(), &self.jws.signature)
    }

    /// The payload as JSON, `null` for a POST-as-GET.
    ///
    /// # Errors
    ///
    /// Where a payload is there and is not JSON.
    pub fn json(&self) -> Result<Value> {
        if self.jws.payload.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.jws.payload)
            .map_err(|_| ProvisionError::new("the request's payload is not JSON"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_one_side_signs_the_other_reads_and_verifies() {
        let key = KeyPair::generate().expect("a key");
        let jwk = Key::p256_point(None, key.point()).expect("a jwk");
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
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

        let other = KeyPair::generate().expect("a key");
        let other = Key::p256_point(None, other.point()).expect("jwk");
        assert!(!signed.verified_by(&other));
        let account = Signer::Account("https://a/acct/1".to_string());
        let body = sign(&key, &account, "n2", "https://a/order", None).expect("signed");
        let signed = Signed::read(&body).expect("read");
        assert_eq!(signed.signer, account);
        assert_eq!(signed.json().expect("empty"), Value::Null);
        assert!(Signed::read(b"{}").is_err());
    }

    #[test]
    fn a_request_signed_otherwise_or_by_another_kind_of_key_is_refused() {
        let key = KeyPair::generate().expect("a key");
        let secret = Signer::Key(Key::secret(None, b"shared"));
        let refused = sign(&key, &secret, "n1", "https://a/new", None).expect_err("a secret");
        assert!(refused.message.contains("P-256"), "{refused}");

        let mut header = Map::new();
        header.insert("nonce".to_string(), Value::from("n1"));
        header.insert("url".to_string(), Value::from("https://a/new"));
        header.insert("kid".to_string(), Value::from("https://a/acct/1"));
        let hs256 = jws::sign_flattened(header, b"", &Shared).expect("signed");
        let refused = Signed::read(&hs256).expect_err("HS256");
        assert!(refused.message.contains("ES256"), "{refused}");
    }

    /// A shared secret signing HS256, which ACME does not take.
    struct Shared;

    impl jws::SigningKey for Shared {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Hs256
        }

        fn sign(&self, input: &[u8]) -> jose::Result<Vec<u8>> {
            Ok(codec::digest::hmac_sha256(b"shared", input).to_vec())
        }
    }
}
