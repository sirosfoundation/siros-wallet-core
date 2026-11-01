//! What the entry a chosen credential takes binds into the credential's KB-JWT (T7; OpenID4VP
//! 1.0, B.3.3.1; EC TS12 v1.0.1, Section 3.6).

use serde_json::Value;
use siros_codec::base64url::{self, Base64Url};
use siros_oid4vp::ResponseMode;

use crate::amr::Amr;
use crate::entry::Entry;
use crate::hash::AlgClaim;
use crate::sources::Rulebook;

/// An entry bound to the credential that takes it, under its payload's rulebook.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'e> {
    entry: &'e Entry,
    rulebook: Rulebook,
}

/// `jti`: a fresh, random KB-JWT identifier (RFC 7519, Section 4.1.7; EC TS12 v1.0.1, Section
/// 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jti(Base64Url);

impl Jti {
    /// The identifier of `random`, 128 bits the host's CSPRNG drew for this presentation: their
    /// base64url.
    #[must_use]
    pub fn new(random: [u8; 16]) -> Self {
        Self(base64url::encode(&random))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The inputs of the KB-JWT claims the TS12 rulebooks require: `jti`, the request's
/// `response_mode`, and the signing key's `amr`.
#[derive(Debug, Clone)]
pub struct KbJwtInputs {
    jti: Jti,
    response_mode: ResponseMode,
    amr: Amr,
}

impl KbJwtInputs {
    /// The inputs.
    #[must_use]
    pub fn new(jti: Jti, response_mode: ResponseMode, amr: Amr) -> Self {
        Self {
            jti,
            response_mode,
            amr,
        }
    }
}

impl<'e> Binding<'e> {
    /// `entry`, bound under `rulebook`, the rulebook of the view the credential took it with.
    #[must_use]
    pub fn new(entry: &'e Entry, rulebook: Rulebook) -> Self {
        Self { entry, rulebook }
    }

    /// The entry.
    #[must_use]
    pub fn entry(&self) -> &'e Entry {
        self.entry
    }

    /// The claims the entry adds to the credential's KB-JWT, which
    /// `siros_sdjwt::Presentation::key_binding` takes as its extra claims (S4):
    /// `transaction_data_hashes`, the hash of the entry as received; `transaction_data_hashes_alg`
    /// when the entry carried `transaction_data_hashes_alg` (B.3.3.1); then, under a TS12
    /// rulebook, `jti`, `response_mode` and `amr` of `inputs`, which only that rulebook calls.
    ///
    /// # Errors
    ///
    /// What `inputs` gives.
    pub fn kb_jwt_claims<E>(
        &self,
        inputs: impl FnOnce() -> Result<KbJwtInputs, E>,
    ) -> Result<Vec<(String, Value)>, E> {
        let hashes = self.entry.hashes();
        let alg = hashes.alg();
        let hash = Value::String(alg.hash(self.entry.raw()).into());
        let mut claims = vec![("transaction_data_hashes", Value::Array(vec![hash]))];
        if hashes.claim() == AlgClaim::Repeated {
            claims.push(("transaction_data_hashes_alg", alg.identifier().into()));
        }
        if let Rulebook::Ts12(_) = self.rulebook {
            let inputs = inputs()?;
            claims.push(("jti", inputs.jti.as_str().into()));
            claims.push(("response_mode", inputs.response_mode.as_str().into()));
            claims.push(("amr", inputs.amr.claim()));
        }
        Ok(claims
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect())
    }
}
