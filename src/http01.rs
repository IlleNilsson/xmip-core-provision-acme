//! The http-01 challenge (RFC 8555 section 8.3): the key authorization
//! served at `/.well-known/acme-challenge/<token>` while the authority
//! looks for it.
//!
//! The authority asks on the name's port 80 — Let's Encrypt on port 80 and
//! no other: *The HTTP-01 challenge can only be done on port 80*
//! (letsencrypt.org/docs/challenge-types). The node listens on any port its
//! configuration names; one that listens elsewhere is reached from public
//! port 80 through forwarding (the owner, 2026-10-13: *On any port*). It
//! listens only while an order is answered, and stops when it is done.

use std::io::BufReader;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use net::http::{Response, read_request, write_response};
use provision::Result;

use crate::Listening;

/// Where a challenge's answer is served.
pub const PREFIX: &str = "/.well-known/acme-challenge/";

/// How long one connection from the authority is given to ask.
const ASKING: Duration = Duration::from_secs(5);

/// Answers being served, until dropped.
pub struct Answering {
    listening: Listening,
}

impl Answering {
    /// Serve `answers`, each a token and its key authorization, on
    /// `listen`.
    ///
    /// # Errors
    ///
    /// Where `listen` cannot be bound, naming it.
    pub fn start(listen: &str, answers: Vec<(String, String)>) -> Result<Self> {
        let listening = Listening::start(listen, "the http-01 answer", move |connection| {
            answer(connection, &answers);
        })?;
        Ok(Self { listening })
    }

    /// The address it listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.listening.address()
    }
}

/// One request answered: the key authorization for a token served, and
/// 404 for anything else.
fn answer(connection: TcpStream, answers: &[(String, String)]) {
    let _ = connection.set_read_timeout(Some(ASKING));
    let _ = connection.set_write_timeout(Some(ASKING));
    let Ok(mut writer) = connection.try_clone() else {
        return;
    };
    let Ok(Some(request)) = read_request(&mut BufReader::new(connection)) else {
        return;
    };
    let found = request
        .path
        .strip_prefix(PREFIX)
        .and_then(|token| answers.iter().find(|(known, _)| known == token));
    let response = match found {
        Some((_, authorization)) if request.method == "GET" => Response::new(200)
            .header("Content-Type", "application/octet-stream")
            .body(authorization.as_bytes()),
        _ => Response::new(404),
    };
    let _ = write_response(&mut writer, &response);
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::http::{Request, exchange};

    #[test]
    fn a_token_is_answered_with_its_authorization_and_nothing_else_is() {
        let answers = vec![("t1".to_string(), "t1.print".to_string())];
        let serving = Answering::start("127.0.0.1:0", answers).expect("listens");
        let ask = |path: &str| {
            let tcp = net::connect(serving.address(), Some(ASKING)).expect("connects");
            exchange(tcp, &Request::new("GET", path).header("Host", "x")).expect("answer")
        };
        let found = ask("/.well-known/acme-challenge/t1");
        assert_eq!(
            (found.status, found.body.as_slice()),
            (200, &b"t1.print"[..])
        );
        assert_eq!(ask("/.well-known/acme-challenge/t2").status, 404);
        drop(serving);
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let taken = held.local_addr().expect("address").to_string();
        let refused = Answering::start(&taken, Vec::new()).err().expect("taken");
        assert!(refused.message.contains(&taken), "{refused}");
    }
}
