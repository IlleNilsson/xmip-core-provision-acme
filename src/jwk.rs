//! An account's public key as a JSON Web Key (RFC 7517), its thumbprint
//! (RFC 7638) and the key authorization a challenge is answered with (RFC
//! 8555 section 8.1).

use codec::base64::{decode_url, encode_url_unpadded};
use provision::{ProvisionError, Result, sha256};
use serde_json::{Value, json};

/// A P-256 public key as JWK: its two coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    x: Vec<u8>,
    y: Vec<u8>,
}

impl Jwk {
    /// The key whose uncompressed point is `point`.
    ///
    /// # Errors
    ///
    /// Where `point` is not 65 bytes opening with `0x04`.
    pub fn from_point(point: &[u8]) -> Result<Self> {
        match point.split_first() {
            Some((4, coordinates)) if coordinates.len() == 64 => Ok(Self {
                x: coordinates[..32].to_vec(),
                y: coordinates[32..].to_vec(),
            }),
            _ => Err(ProvisionError::new("not an uncompressed P-256 point")),
        }
    }

    /// The key a JWK object holds.
    ///
    /// # Errors
    ///
    /// Where it is not an EC key on P-256 with both coordinates.
    pub fn from_json(value: &Value) -> Result<Self> {
        let member = |name: &str| value.get(name).and_then(Value::as_str);
        if member("kty") != Some("EC") || member("crv") != Some("P-256") {
            return Err(ProvisionError::new(
                "the account key is not an EC key on P-256",
            ));
        }
        let coordinate = |name: &str| -> Result<Vec<u8>> {
            let bytes = decode_url(member(name).unwrap_or_default())?;
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(ProvisionError::new(format!(
                    "the key's {name} is not 32 bytes"
                )))
            }
        };
        Ok(Self {
            x: coordinate("x")?,
            y: coordinate("y")?,
        })
    }

    /// The uncompressed point.
    #[must_use]
    pub fn point(&self) -> Vec<u8> {
        [&[4][..], &self.x, &self.y].concat()
    }

    /// The JWK object.
    #[must_use]
    pub fn json(&self) -> Value {
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": encode_url_unpadded(&self.x),
            "y": encode_url_unpadded(&self.y),
        })
    }

    /// The thumbprint: SHA-256 over the required members in lexical order
    /// with no white space, base64url (RFC 7638 section 3).
    #[must_use]
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            encode_url_unpadded(&self.x),
            encode_url_unpadded(&self.y)
        );
        encode_url_unpadded(&sha256(canonical.as_bytes()))
    }

    /// What a challenge's `token` is answered with by this account: the
    /// token, a dot, the thumbprint.
    #[must_use]
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reads_back_from_its_json_and_authorizes_a_token() {
        let key =
            Jwk::from_point(&[[4u8].as_slice(), &[1; 32], &[2; 32]].concat()).expect("a point");
        assert_eq!(Jwk::from_json(&key.json()).expect("read back"), key);
        assert_eq!(key.thumbprint().len(), 43);
        assert!(key.key_authorization("t0k3n").starts_with("t0k3n."));
        assert!(Jwk::from_json(&json!({"kty": "RSA"})).is_err());
        assert!(Jwk::from_point(&[4; 10]).is_err());
    }
}
