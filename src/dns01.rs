//! The dns-01 challenge (RFC 8555 section 8.4): a TXT record at
//! `_acme-challenge.<domain>` holding the key authorization's SHA-256,
//! base64url. It needs no port, so it suits a node behind a firewall, and
//! it is the only challenge a wildcard name can be validated by.
//!
//! Writing a domain's DNS is the DNS provider's: a provider implements
//! [`DnsWriter`] for its own service, and Xmip ships none for a vendor (the
//! owner leaves vendors to providers).

use codec::base64::encode_url_unpadded;
use provision::{Result, sha256};

/// Writes and removes a domain's TXT records: what a DNS provider's module
/// implements so a node can answer dns-01.
pub trait DnsWriter: Send + Sync {
    /// Publish a TXT record `name` holding `value`, and return once the
    /// provider has accepted it.
    ///
    /// # Errors
    ///
    /// Where the provider refuses, in its words.
    fn publish(&self, name: &str, value: &str) -> Result<()>;

    /// Remove the TXT record `name` holding `value`; other values at the
    /// same name stay.
    ///
    /// # Errors
    ///
    /// Where the provider refuses, in its words.
    fn withdraw(&self, name: &str, value: &str) -> Result<()>;
}

/// The record's name for `domain`; a wildcard is validated at its base.
#[must_use]
pub fn record_name(domain: &str) -> String {
    format!("_acme-challenge.{}", domain.trim_start_matches("*."))
}

/// The record's value for `key_authorization`.
#[must_use]
pub fn record_value(key_authorization: &str) -> String {
    encode_url_unpadded(&sha256(key_authorization.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_named_at_the_base_and_holds_a_digest() {
        assert_eq!(record_name("*.a.example"), "_acme-challenge.a.example");
        assert_eq!(record_name("a.example"), "_acme-challenge.a.example");
        assert_eq!(record_value("t.p").len(), 43);
    }
}
