//! ACME as a node's source of certificates: its settings, declared once,
//! and an order obtained with them.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use provision::{KeyPair, NAMES, Order, ProvisionError, Provisioned, Result, Source, serves};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};
use zeroize::Zeroizing;

use crate::channel::Channel;
use crate::client::{Challenge, Client};
use crate::dns01::DnsWriter;

/// The technology's module name.
pub const TECHNOLOGY: &str = "xmip-core-provision-acme";

/// The file an account's key is kept in, in the purpose's place: one
/// account across renewals, as an authority's rate limits expect.
const ACCOUNT_KEY: &str = "account.key";

/// Every setting `[provision.<purpose>]` takes with `source =
/// "xmip-core-provision-acme"`.
pub const SETTINGS: &Settings = &Settings {
    technology: TECHNOLOGY,
    settings: &[
        Setting {
            name: "directory",
            kind: Kind::Address,
            presence: Presence::Required,
            meaning: "The ACME directory's URL; Let's Encrypt's is one value, never assumed.",
            applies: Applies::Both,
        },
        NAMES,
        Setting {
            name: "challenge",
            kind: Kind::Choice {
                choices: &["http-01", "dns-01"],
            },
            presence: Presence::Default(Fixed::Text("http-01")),
            meaning: "How the node proves it controls each name.",
            applies: Applies::Both,
        },
        Setting {
            name: "challenge_listen",
            kind: Kind::Address,
            presence: Presence::Default(Fixed::Text("0.0.0.0:80")),
            meaning: "Where the http-01 answer listens, any port; the authority asks on \
                      public port 80, reached through forwarding where this is elsewhere.",
            applies: Applies::Both,
        },
        Setting {
            name: "anchors",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "The PEM anchors the directory's TLS certificate must reach; absent, \
                      the operating system's trust store.",
            applies: Applies::Both,
        },
        Setting {
            name: "contact",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "A URL the authority may reach the operator at, such as a mailto URL.",
            applies: Applies::Both,
        },
        Setting {
            name: "agree_terms",
            kind: Kind::Boolean,
            presence: Presence::Default(Fixed::Boolean(false)),
            meaning: "Whether the operator agrees to the authority's terms of service.",
            applies: Applies::Both,
        },
        Setting {
            name: "timeout",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(Duration::from_secs(10))),
            meaning: "How long each request to the authority may take.",
            applies: Applies::Both,
        },
        Setting {
            name: "validation_wait",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(Duration::from_secs(120))),
            meaning: "How long the authority is given to validate the names and issue.",
            applies: Applies::Both,
        },
    ],
};

/// ACME, configured.
pub struct Acme {
    directory: String,
    challenge: Challenge,
    anchors: Option<String>,
    contact: Option<String>,
    agree_terms: bool,
    timeout: Duration,
    wait: Duration,
}

impl Acme {
    /// ACME as `settings`, read through [`SETTINGS`], says: `base` the
    /// directory a relative `anchors` is read from, `dns` the DNS provider's
    /// writer a dns-01 challenge needs.
    ///
    /// # Errors
    ///
    /// Where dns-01 is chosen and the program links no DNS writer, or the
    /// anchors cannot be read.
    pub fn configured(
        settings: &Read,
        base: &Path,
        dns: Option<Arc<dyn DnsWriter>>,
    ) -> Result<Self> {
        let challenge = match (settings.text("challenge"), dns) {
            ("dns-01", Some(writer)) => Challenge::Dns01(writer),
            ("dns-01", None) => {
                return Err(ProvisionError::new(
                    "dns-01 writes the domain's DNS, and this program links no DNS writer",
                ));
            }
            _ => Challenge::Http01 {
                listen: settings.text("challenge_listen").to_string(),
            },
        };
        let anchors = settings
            .optional_text("anchors")
            .map(|path| {
                let path = base.join(path);
                std::fs::read_to_string(&path).map_err(|failure| {
                    ProvisionError::new(format!("reading {}: {failure}", path.display()))
                })
            })
            .transpose()?;
        Ok(Self {
            directory: settings.text("directory").to_string(),
            challenge,
            anchors,
            contact: settings.optional_text("contact").map(str::to_string),
            agree_terms: settings.boolean("agree_terms"),
            timeout: settings.duration("timeout"),
            wait: settings.duration("validation_wait"),
        })
    }

    /// The account key the purpose's place keeps, made the first time.
    fn account_key(keep: &Path) -> Result<KeyPair> {
        let path = keep.join(ACCOUNT_KEY);
        match std::fs::read_to_string(&path) {
            Ok(pem) => KeyPair::from_pem(&pem),
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate()?;
                std::fs::create_dir_all(keep)
                    .and_then(|()| std::fs::write(&path, key.pem().as_bytes()))
                    .map_err(|failure| {
                        ProvisionError::new(format!("writing {}: {failure}", path.display()))
                    })?;
                Ok(key)
            }
            Err(failure) => Err(ProvisionError::new(format!(
                "reading {}: {failure}",
                path.display()
            ))),
        }
    }
}

impl Source for Acme {
    fn technology(&self) -> &'static str {
        TECHNOLOGY
    }

    fn obtain(&self, order: &Order<'_>) -> Result<Provisioned> {
        let channel = Channel::new(self.anchors.as_deref(), self.timeout)?;
        let client = Client::open(
            channel,
            &self.directory,
            Self::account_key(order.keep)?,
            self.contact.as_deref(),
            self.agree_terms,
        )?;
        let (chain, key) = client.certificate(order.names, &self.challenge, self.wait)?;
        let leaf = provision::pem::decode("CERTIFICATE", &chain)?
            .into_iter()
            .next()
            .ok_or_else(|| ProvisionError::new("the ACME server's chain holds no certificate"))?;
        if !serves(&leaf, order.purpose)? {
            return Err(ProvisionError::new(format!(
                "{} issued a certificate without client authentication, which a node's \
                 certificate between nodes needs; Let's Encrypt has issued none since \
                 2026-07-08, and the cluster's own authority does",
                self.directory
            )));
        }
        Provisioned::new(
            chain,
            Zeroizing::new(key.pem().to_string()),
            self.anchors.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_sound_and_names_no_authority_as_a_default() {
        assert!(SETTINGS.problems().is_empty(), "{:?}", SETTINGS.problems());
        let directory = SETTINGS.setting("directory").expect("declared");
        assert_eq!(directory.presence, Presence::Required);
    }
}
