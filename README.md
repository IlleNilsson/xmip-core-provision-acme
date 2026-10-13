# xmip-core-provision-acme

ACME (RFC 8555): a node obtains and renews its certificate from any ACME
directory its configuration names. A technology of
[xmip-core-provision](https://github.com/IlleNilsson/xmip-core-provision).

Let's Encrypt's directory is one value a node may name, never a default (the
owner, 2026-10-13: *As an option*). The cluster's own authority
(`internal-ca`) answers ACME too, and so does any authority an end user runs.

## What it does

The directory read, a nonce, an account opened by a P-256 key signing JWS
with ES256 and kept in the purpose's place across renewals, an order placed,
each name proven, the order finalized with a CSR and the chain fetched — over
Xmip's own HTTP and TLS (`xmip-core-library-net`, `xmip-core-library-tls`).
The directory's certificate is checked against the anchors a node names, or
the operating system's trust store. A certificate that does not serve the
purpose asked — one without client authentication, asked for `node` — is
refused in words: Let's Encrypt has issued server authentication alone since
2026-07-08.

- **http-01** — the answer listens on any port the node names
  (`challenge_listen`, `0.0.0.0:80` unless said); the authority asks on port
  80, so a node listening elsewhere is reached through forwarding (the
  owner, 2026-10-13: *On any port*). It listens only while an order is
  answered.
- **dns-01** — a TXT record at `_acme-challenge.<domain>`, written through a
  `DnsWriter` a DNS provider's module implements; no port. Xmip ships none
  for a vendor.
- **tls-alpn-01** — not built.

`Acme` is the `provision::Source`; `SETTINGS` its declaration. `jws`, `Jwk`,
the `http01` answer and `Listening` are the carrier `internal-ca` serves ACME
from (ADR-0044 clause 1).

## Verification

Unit tests here; the whole exchange is proved in `internal-ca`'s tests
against its ACME server, offline. The workflow is manual-only and calls the
versioned shared workflow at `IlleNilsson/.github@v1`.
