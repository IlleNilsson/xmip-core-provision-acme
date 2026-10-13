//! The way to an ACME server: HTTPS through Xmip's own TLS and HTTP, one
//! connection a request, every answer's `Replay-Nonce` kept for the next
//! signed request (RFC 8555 section 6.5).
//!
//! The server's certificate is checked against the anchors a node names —
//! the cluster's authority — or, where it names none, the operating
//! system's trust store, which a public authority such as Let's Encrypt is
//! reached through. ACME is HTTPS only (RFC 8555 section 6.1).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use net::http::{Request, Response, exchange};
use provision::{KeyPair, ProvisionError, Result};
use serde_json::Value;

use crate::jws::{Signer, sign};

/// The media type every signed request carries.
const JOSE: &str = "application/jose+json";

/// The way to one ACME server.
pub struct Channel {
    config: Option<Arc<tls::ClientConfig>>,
    timeout: Duration,
    nonce: Mutex<Option<String>>,
}

impl Channel {
    /// A channel trusting `anchors`, PEM, or the operating system's trust
    /// store where it is `None`, each request bounded by `timeout`.
    ///
    /// # Errors
    ///
    /// Where `anchors` holds no certificate a trust store takes.
    pub fn new(anchors: Option<&str>, timeout: Duration) -> Result<Self> {
        let config = anchors
            .map(|pem| tls::trusting(pem.as_bytes()).map(Arc::new))
            .transpose()
            .map_err(|failure| ProvisionError::new(failure.message))?;
        Ok(Self {
            config,
            timeout,
            nonce: Mutex::new(None),
        })
    }

    /// `GET url`.
    ///
    /// # Errors
    ///
    /// Where the server cannot be reached or does not answer in HTTP.
    pub fn get(&self, url: &str) -> Result<Response> {
        self.send(url, Request::new("GET", String::new()))
    }

    /// A signed `POST` to `url` from `signer`, `payload` `None` a
    /// POST-as-GET. A `badNonce` refusal is asked once more with the fresh
    /// nonce it carried, as RFC 8555 section 6.5 expects a client to.
    ///
    /// # Errors
    ///
    /// Where the server cannot be reached, gives no nonce, or refuses;
    /// a refusal names the problem's type and detail.
    pub fn post(
        &self,
        key: &KeyPair,
        signer: &Signer,
        url: &str,
        payload: Option<&Value>,
        new_nonce: &str,
    ) -> Result<Response> {
        for attempt in 0..2 {
            if self
                .nonce
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
            {
                self.get(new_nonce)?;
            }
            let nonce = self
                .take_nonce()
                .ok_or_else(|| ProvisionError::new("the ACME server gave no nonce"))?;
            let body = sign(key, signer, &nonce, url, payload)?;
            let request = Request::new("POST", String::new())
                .header("Content-Type", JOSE)
                .body(&body);
            let answer = self.send(url, request)?;
            if answer.status < 400 {
                return Ok(answer);
            }
            let (kind, detail) = problem(&answer);
            if attempt == 0 && kind.ends_with(":badNonce") {
                continue;
            }
            return Err(ProvisionError::new(format!(
                "the ACME server refused {url} with {}: {kind}: {detail}",
                answer.status
            )));
        }
        Err(ProvisionError::new("the ACME server refused every nonce"))
    }

    /// One request to `url`, `request`'s path and host filled from it.
    fn send(&self, url: &str, mut request: Request) -> Result<Response> {
        let target = net::Target::parse(url).map_err(failed)?;
        if !target.is(&["https"]) {
            return Err(ProvisionError::new(format!(
                "ACME is spoken over HTTPS only, and {url} is not"
            )));
        }
        let (host, port) = target.host_and_port().map_err(failed)?;
        let port = port.unwrap_or(443);
        request.path = format!("/{}", target.path());
        request.query = target.query();
        let request = request.header("Host", target.authority());
        let tcp = net::connect((host.trim_matches(['[', ']']), port), Some(self.timeout))
            .map_err(failed)?;
        let host = host.trim_matches(['[', ']']);
        let stream = match &self.config {
            Some(config) => tls::client_with(host, tcp, Arc::clone(config)),
            None => tls::client(host, tcp),
        }
        .map_err(|failure| ProvisionError::new(failure.message))?;
        let answer = exchange(stream, &request).map_err(failed)?;
        if let Some(nonce) = answer.header_value("replay-nonce") {
            *self.nonce.lock().unwrap_or_else(PoisonError::into_inner) = Some(nonce.to_string());
        }
        Ok(answer)
    }

    fn take_nonce(&self) -> Option<String> {
        self.nonce
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// A problem document's type and detail (RFC 7807, RFC 8555 section 6.7).
#[must_use]
pub fn problem(answer: &Response) -> (String, String) {
    let document: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
    let text = |name: &str| {
        document
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (text("type"), text("detail"))
}

/// The JSON an answer carries.
///
/// # Errors
///
/// Where its body is not JSON.
pub fn json(answer: &Response) -> Result<Value> {
    serde_json::from_slice(&answer.body)
        .map_err(|_| ProvisionError::new("the ACME server answered with something not JSON"))
}

fn failed(failure: net::NetError) -> ProvisionError {
    ProvisionError::new(failure.message)
}
