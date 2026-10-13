//! An ACME client (RFC 8555 section 7): an account opened, an order placed,
//! each name's authorization proven by the challenge a node is configured
//! for, the order finalized with a CSR and the chain fetched.

use std::sync::Arc;
use std::time::{Duration, Instant};

use provision::{KeyPair, ProvisionError, Result, csr};
use serde_json::{Value, json};

use crate::Jwk;
use crate::channel::{Channel, json};
use crate::dns01::{DnsWriter, record_name, record_value};
use crate::http01::Answering;
use crate::jws::Signer;

/// How a node proves it controls a name.
#[derive(Clone)]
pub enum Challenge {
    /// http-01, answered on `listen`, any port; the authority asks on
    /// port 80, reached through forwarding where `listen` is elsewhere.
    Http01 {
        /// The address the answer listens on.
        listen: String,
    },
    /// dns-01, written through a DNS provider's writer. No port.
    Dns01(Arc<dyn DnsWriter>),
}

impl Challenge {
    /// The challenge's type, as an authorization lists it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Http01 { .. } => "http-01",
            Self::Dns01(_) => "dns-01",
        }
    }
}

/// An account at one ACME server.
pub struct Client {
    channel: Channel,
    new_nonce: String,
    new_order: String,
    key: KeyPair,
    account: Signer,
}

/// One authorization still to prove.
struct Pending {
    authorization: String,
    challenge: String,
    token: String,
    domain: String,
}

impl Client {
    /// The account `key` holds at the server `directory` describes, opened
    /// or found again: `contact` a URL the server may reach the operator
    /// at, `agree_terms` whether the operator agrees to its terms.
    ///
    /// # Errors
    ///
    /// Where the directory cannot be read or the server refuses the account.
    pub fn open(
        channel: Channel,
        directory: &str,
        key: KeyPair,
        contact: Option<&str>,
        agree_terms: bool,
    ) -> Result<Self> {
        let described = json(&channel.get(directory)?)?;
        let entry = |name: &str| {
            described
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    ProvisionError::new(format!("the ACME directory {directory} names no {name}"))
                })
        };
        let (new_nonce, new_account, new_order) =
            (entry("newNonce")?, entry("newAccount")?, entry("newOrder")?);
        let mut payload = json!({ "termsOfServiceAgreed": agree_terms });
        if let Some(contact) = contact {
            payload["contact"] = json!([contact]);
        }
        let signer = Signer::Key(Jwk::from_point(key.point())?);
        let answer = channel.post(&key, &signer, &new_account, Some(&payload), &new_nonce)?;
        let account = answer
            .header_value("location")
            .ok_or_else(|| ProvisionError::new("the ACME server gave the account no URL"))?
            .to_string();
        Ok(Self {
            channel,
            new_nonce,
            new_order,
            key,
            account: Signer::Account(account),
        })
    }

    /// A certificate for `names`: the chain, PEM, leaf first, and the key it
    /// is for. Each name is proven by `challenge`, the authority given
    /// `wait` to validate and to issue.
    ///
    /// # Errors
    ///
    /// Where the order is refused, a name cannot be proven — the
    /// authority's reason given — or the wait runs out.
    pub fn certificate(
        &self,
        names: &[String],
        challenge: &Challenge,
        wait: Duration,
    ) -> Result<(String, KeyPair)> {
        let deadline = Instant::now() + wait;
        let identifiers: Vec<Value> = names
            .iter()
            .map(|name| json!({ "type": "dns", "value": name }))
            .collect();
        let payload = json!({ "identifiers": identifiers });
        let answer = self.post(&self.new_order, Some(&payload))?;
        let order_url = answer
            .header_value("location")
            .ok_or_else(|| ProvisionError::new("the ACME server gave the order no URL"))?
            .to_string();
        let order = json(&answer)?;

        let pending = self.pending(&order, challenge)?;
        let thumbprint = Jwk::from_point(self.key.point())?;
        let proven = self.prove(&pending, challenge, &thumbprint, deadline);
        proven?;

        let key = KeyPair::generate()?;
        let request = codec::base64::encode_url_unpadded(&csr::write(&key, names)?);
        let finalize = text(&order, "finalize")?;
        self.post(&finalize, Some(&json!({ "csr": request })))?;
        let order = self.poll(&order_url, deadline, "the order")?;
        let chain = self.post(&text(&order, "certificate")?, None)?;
        let chain = String::from_utf8(chain.body)
            .map_err(|_| ProvisionError::new("the certificate chain is not text"))?;
        Ok((chain, key))
    }

    /// The authorizations of `order` not yet valid, each with its challenge
    /// of `challenge`'s type.
    fn pending(&self, order: &Value, challenge: &Challenge) -> Result<Vec<Pending>> {
        let mut pending = Vec::new();
        let listed = order.get("authorizations").and_then(Value::as_array);
        for url in listed.into_iter().flatten().filter_map(Value::as_str) {
            let authorization = json(&self.post(url, None)?)?;
            if authorization.get("status").and_then(Value::as_str) == Some("valid") {
                continue;
            }
            let domain = authorization
                .pointer("/identifier/value")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let offered = authorization
                .get("challenges")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|offer| offer.get("type").and_then(Value::as_str) == Some(challenge.kind()))
                .ok_or_else(|| {
                    ProvisionError::new(format!(
                        "the ACME server offers no {} challenge for {domain}",
                        challenge.kind()
                    ))
                })?;
            pending.push(Pending {
                authorization: url.to_string(),
                challenge: text(offered, "url")?,
                token: text(offered, "token")?,
                domain,
            });
        }
        Ok(pending)
    }

    /// Answer every pending challenge, ask the authority to validate each,
    /// and wait until each is valid; the answers are taken down after,
    /// whatever happened.
    fn prove(
        &self,
        pending: &[Pending],
        challenge: &Challenge,
        account: &Jwk,
        deadline: Instant,
    ) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let authorizations: Vec<(String, String)> = pending
            .iter()
            .map(|one| (one.token.clone(), account.key_authorization(&one.token)))
            .collect();
        let _answering = match challenge {
            Challenge::Http01 { listen } => Some(Answering::start(listen, authorizations.clone())?),
            Challenge::Dns01(_) => None,
        };
        let records: Vec<(String, String)> = pending
            .iter()
            .zip(&authorizations)
            .map(|(one, (_, authorization))| {
                (record_name(&one.domain), record_value(authorization))
            })
            .collect();
        let result = (|| {
            if let Challenge::Dns01(writer) = challenge {
                for (name, value) in &records {
                    writer.publish(name, value)?;
                }
            }
            for one in pending {
                self.post(&one.challenge, Some(&json!({})))?;
            }
            for one in pending {
                self.poll(&one.authorization, deadline, &one.domain)?;
            }
            Ok(())
        })();
        if let Challenge::Dns01(writer) = challenge {
            for (name, value) in &records {
                let _ = writer.withdraw(name, value);
            }
        }
        result
    }

    /// Ask `url` until its object is `valid`, refusing `invalid` with the
    /// authority's reason, resting as the server's `Retry-After` says or
    /// from a short first rest doubling, until `deadline`.
    fn poll(&self, url: &str, deadline: Instant, what: &str) -> Result<Value> {
        let mut rest = Duration::from_millis(50);
        loop {
            let answer = self.post(url, None)?;
            let object = json(&answer)?;
            match object.get("status").and_then(Value::as_str) {
                Some("valid") => return Ok(object),
                Some("invalid") => {
                    return Err(ProvisionError::new(format!(
                        "the ACME server found {what} invalid: {}",
                        reason(&object)
                    )));
                }
                _ => {}
            }
            let said = answer
                .header_value("retry-after")
                .and_then(|seconds| seconds.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            let wait = said.unwrap_or(rest);
            if Instant::now() + wait > deadline {
                return Err(ProvisionError::new(format!(
                    "the ACME server did not make {what} valid in time"
                )));
            }
            std::thread::sleep(wait);
            rest = (rest * 2).min(Duration::from_secs(2));
        }
    }

    fn post(&self, url: &str, payload: Option<&Value>) -> Result<net::http::Response> {
        self.channel
            .post(&self.key, &self.account, url, payload, &self.new_nonce)
    }
}

/// A string member of an ACME object.
fn text(object: &Value, name: &str) -> Result<String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ProvisionError::new(format!("an ACME object has no {name}")))
}

/// The reason an invalid object gives: its own error, or its challenges'.
fn reason(object: &Value) -> String {
    let detail = |error: &Value| {
        error
            .get("detail")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    object
        .get("error")
        .and_then(detail)
        .or_else(|| {
            object
                .get("challenges")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find_map(|challenge| challenge.get("error").and_then(detail))
        })
        .unwrap_or_else(|| "no reason was given".to_string())
}
