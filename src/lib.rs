#![forbid(unsafe_code)]

//! ACME (RFC 8555): a node obtains and renews its certificate from any ACME
//! directory its configuration names. A technology of `xmip-core-provision`.
//!
//! **Any directory, none assumed.** Let's Encrypt's directory is one value a
//! node may name, never a default (the owner, 2026-10-13: *As an option*):
//! the cluster's own authority (`internal-ca`) answers ACME too, and so does
//! any authority an end user runs. The directory's TLS certificate is
//! checked against the anchors a node names, or the operating system's
//! trust store.
//!
//! **The steps** (section 7): the directory read, a nonce, an account opened
//! by a P-256 key signing JWS with ES256 ([`jws`]) and kept across
//! renewals, an order placed, each name proven, the order finalized with a
//! CSR and the chain fetched ([`Client`]).
//!
//! **Proving a name.** http-01 ([`http01`]) answers on any port the node
//! names; the authority asks on port 80, so a node listening elsewhere is
//! reached through forwarding. dns-01 ([`dns01`]) needs no port and writes
//! the domain's DNS through a [`DnsWriter`] a DNS provider's module
//! implements; Xmip ships none for a vendor. tls-alpn-01 is not built.
//!
//! **Over Xmip's own HTTP and TLS** (`xmip-core-library-net`,
//! `xmip-core-library-tls`), never a platform client.
//!
//! **What a public authority cannot give.** Let's Encrypt has issued server
//! authentication alone since 2026-07-08, so its certificate serves what
//! Parties reach and never a node between nodes; [`Acme`] refuses a
//! certificate that does not serve the purpose it was asked for.

mod channel;
mod client;
pub mod dns01;
pub mod http01;
mod jwk;
pub mod jws;
mod listening;
mod source;

pub use channel::{Channel, json, problem};
pub use client::{Challenge, Client};
pub use dns01::DnsWriter;
pub use jwk::Jwk;
pub use listening::Listening;
pub use source::{Acme, SETTINGS, TECHNOLOGY};
