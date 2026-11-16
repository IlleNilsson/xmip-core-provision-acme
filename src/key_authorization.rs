//! What a challenge's token is answered with by an account (RFC 8555
//! section 8.1): the token, a dot, and the account key's thumbprint (RFC
//! 7638), which is the library's (`jose::jwk::Key::thumbprint`). http-01
//! serves it and dns-01 publishes its digest; the client answers with it
//! and the authority that serves ACME (`internal-ca`) expects it.

use jose::jwk::Key;
use provision::{ProvisionError, Result};

/// What `token` is answered with by `account`.
///
/// # Errors
///
/// Where the account key is not a P-256 key, which alone has a thumbprint
/// here.
pub fn key_authorization(account: &Key, token: &str) -> Result<String> {
    let thumbprint = account
        .thumbprint()
        .ok_or_else(|| ProvisionError::new("the account key is not a P-256 key"))?;
    Ok(format!("{token}.{thumbprint}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use provision::KeyPair;

    #[test]
    fn a_token_is_answered_with_the_account_keys_thumbprint() {
        let pair = KeyPair::generate().expect("a key");
        let account = Key::p256_point(None, pair.point()).expect("a P-256 key");
        let thumbprint = account.thumbprint().expect("a thumbprint");

        let answer = key_authorization(&account, "t0k3n").expect("an answer");

        assert_eq!(answer, format!("t0k3n.{thumbprint}"));
        assert!(key_authorization(&Key::secret(None, b"x"), "t0k3n").is_err());
    }
}
