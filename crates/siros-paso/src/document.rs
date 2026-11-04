//! The PaSO document a credential's registration holds under [`DOCUMENT`]: the issuer's signed
//! credential metadata (Proof Metadata §4) as the wallet verified it at issuance, with the JWT's
//! integrity value, the credential's type and its issuer's key material.
//!
//! `{"integrity": SRI, "type": the credential type, "issuer": {"iss", "keys": {kid: secret}} or
//! {"iss", "x5c": {"root", "subject"}}, "transaction_data_types": {type: metadata},
//! "risk_signals_encryption_keys"?: {"keys": [JWK]}}`; a secret is the model's stand-in for
//! the issuer key a signature verifies under.

use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Node, Object};
use siros_openid4vp::request::AgreeableKey;

/// The key of the PaSO document in a credential's registration.
pub const DOCUMENT: &str = "paso";

/// A PaSO document that is none.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.document")]
pub enum DocumentError {
    /// The document is no UTF-8.
    #[error("the PaSO document is not UTF-8")]
    NotUtf8,
    /// The document is no JSON with unique member names.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// A member is absent or of another kind.
    #[error("the PaSO document's {0} is absent or malformed")]
    Member(#[explain(name = "member")] &'static str),
}

/// The credential issuer's key material, which an ad-hoc metadata JWT verifies under (Proof
/// Metadata §5.3 step 3).
#[derive(Debug, Clone, Copy)]
pub enum Issuer<'d> {
    /// Keys published in a key set, each by its `kid`.
    KeySet {
        /// The Credential Issuer Identifier.
        iss: &'d str,
        /// The keys by `kid`.
        keys: &'d Object<'d>,
    },
    /// Keys certified by an x5c chain.
    Chain {
        /// The Credential Issuer Identifier.
        iss: &'d str,
        /// The chain's root certificate.
        root: &'d str,
        /// The leaf certificate's subject.
        subject: &'d str,
    },
}

impl<'d> Issuer<'d> {
    /// The Credential Issuer Identifier.
    #[must_use]
    pub const fn iss(&self) -> &'d str {
        match self {
            Self::KeySet { iss, .. } | Self::Chain { iss, .. } => iss,
        }
    }
}

/// A credential's PaSO document, read.
#[derive(Debug, Clone)]
pub struct PasoDocument<'d> {
    /// The integrity value of the signed credential metadata JWT (Core §6.1
    /// `metadata_integrity`).
    pub integrity: &'d str,
    /// The credential's type: its `vct` or its doctype.
    pub credential_type: &'d str,
    /// Its issuer's key material.
    pub issuer: Issuer<'d>,
    types: &'d Object<'d>,
    keys: &'d [Node<'d>],
}

impl<'d> PasoDocument<'d> {
    /// The document's JSON from the registration's bytes.
    pub fn json(bytes: &'d [u8]) -> Result<Node<'d>, DocumentError> {
        let text = std::str::from_utf8(bytes).map_err(|_| DocumentError::NotUtf8)?;
        Ok(Node::parse(text)?)
    }

    /// Reads the document.
    pub fn read(node: &'d Node<'d>) -> Result<Self, DocumentError> {
        let text = |name: &'static str| {
            node.get(name)
                .and_then(Node::as_str)
                .ok_or(DocumentError::Member(name))
        };
        let issuer = node.get("issuer").ok_or(DocumentError::Member("issuer"))?;
        let iss = issuer
            .get("iss")
            .and_then(Node::as_str)
            .ok_or(DocumentError::Member("issuer.iss"))?;
        let issuer = match (issuer.get("x5c"), issuer.get("keys")) {
            (Some(chain), _) => Issuer::Chain {
                iss,
                root: chain
                    .get("root")
                    .and_then(Node::as_str)
                    .ok_or(DocumentError::Member("issuer.x5c.root"))?,
                subject: chain
                    .get("subject")
                    .and_then(Node::as_str)
                    .ok_or(DocumentError::Member("issuer.x5c.subject"))?,
            },
            (None, Some(Node::Object(keys))) => Issuer::KeySet { iss, keys },
            (None, _) => return Err(DocumentError::Member("issuer.keys")),
        };
        let keys = match node.get("risk_signals_encryption_keys") {
            None => &[][..],
            Some(published) => match published.get("keys") {
                None => &[][..],
                Some(keys) => keys
                    .as_array()
                    .ok_or(DocumentError::Member("risk_signals_encryption_keys.keys"))?,
            },
        };
        Ok(Self {
            integrity: text("integrity")?,
            credential_type: text("type")?,
            issuer,
            types: node
                .get("transaction_data_types")
                .and_then(Node::as_object)
                .ok_or(DocumentError::Member("transaction_data_types"))?,
            keys,
        })
    }

    /// The metadata the signed credential metadata lists for a type.
    #[must_use]
    pub fn metadata(&self, kind: &str) -> Option<&'d Node<'d>> {
        self.types.get(kind)
    }

    /// Risk Signals §7.3: the first published key, `use` `enc` with a `kid` and an `alg`, that
    /// the wallet can agree a key with: an ECDH-ES agreement (RFC 7518 §4.6) on an `EC` curve
    /// of RFC 7518 §6.2.1.1 or an `OKP` curve of RFC 8037 §2.
    #[must_use]
    pub fn encryption_key(&self) -> Option<AgreeableKey<'d>> {
        self.keys.iter().find_map(|key| {
            let usable =
                key.get("use") == Some(&Node::String("enc".into())) && key.get("alg").is_some();
            usable
                .then(|| AgreeableKey::of(key))
                .flatten()
                .filter(|agreeable| agrees(key, agreeable))
        })
    }
}

/// The ECDH-ES key agreements of RFC 7518 §4.6.
const AGREEMENTS: [&str; 4] = [
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
];

/// The curves of RFC 7518 §6.2.1.1 (`EC`) and RFC 8037 §2's ECDH curves (`OKP`).
const CURVES: [(&str, &str); 5] = [
    ("EC", "P-256"),
    ("EC", "P-384"),
    ("EC", "P-521"),
    ("OKP", "X25519"),
    ("OKP", "X448"),
];

/// Whether the wallet agrees a key with the JWK: its `alg` an ECDH-ES agreement and its key type
/// and curve one of [`CURVES`].
fn agrees(jwk: &Node<'_>, key: &AgreeableKey<'_>) -> bool {
    let kty = jwk.get("kty").and_then(Node::as_str);
    key.alg()
        .is_some_and(|alg| AGREEMENTS.contains(&alg.as_str()))
        && CURVES
            .iter()
            .any(|(t, crv)| kty == Some(*t) && key.curve().as_str() == *crv)
}
