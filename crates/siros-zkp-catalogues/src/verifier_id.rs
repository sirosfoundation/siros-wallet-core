//! The Verifier's identity, and `verifier_input` and the `sha-256` pseudonym it selects
//! (nym_auth catalogue, `pseudonym`: "Verifier identity" and "Configurations").

use sha2::{Digest, Sha256};
use siros_oid4vp::{ClientId, ClientIdPrefix, SemanticIdError, SemanticIdentifier};

use crate::catalogue::Config;

/// `verifier_id`: a UTF-8 string naming the Verifier, in the one form its trust framework
/// fixes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifierId(String);

/// Why the `verifier_id` of the fixed form cannot be obtained. Each makes the query invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum VerifierIdRule {
    /// The form is `semantic` and no semantic identifier comes from an authenticated source.
    SemanticIdMissing,
    /// The form is `semantic` and the authenticated certificate's subject gives no semantics
    /// identifier.
    SemanticId(#[source] SemanticIdError),
    /// The form is `x509_san_dns` and the Client Identifier has another prefix.
    ClientIdPrefix,
    /// The form is `x509_san_dns` and the registration certificate names an intermediary.
    Intermediary,
    /// The request carries a registration certificate, which no intake authenticates: the
    /// semantic identifier and the intermediary it names come from no authenticated source.
    RegistrationCertificate,
}

impl VerifierIdRule {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::SemanticIdMissing => "semantic_id_missing",
            Self::SemanticId(e) => e.code(),
            Self::ClientIdPrefix => "client_id_prefix",
            Self::Intermediary => "intermediary",
            Self::RegistrationCertificate => "registration_certificate",
        }
    }
}

/// Whether the Verifier's registration certificate names an intermediary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Intermediary {
    /// It names none, or the request carries no registration certificate.
    Absent,
    /// It names one.
    Named,
}

impl VerifierId {
    /// The `semantic` form: `"semantic_id:"` and the end Relying Party's semantics identifier,
    /// from the registration certificate when present, else from the access certificate.
    pub fn semantic(identifier: &SemanticIdentifier) -> Self {
        Self(format!("semantic_id:{}", identifier.as_str()))
    }

    /// The `x509_san_dns` form: the Client Identifier itself, whose prefix gives its DNS name.
    ///
    /// # Errors
    ///
    /// [`VerifierIdRule::ClientIdPrefix`] for another prefix, and
    /// [`VerifierIdRule::Intermediary`] when the registration certificate names an
    /// intermediary.
    pub fn x509_san_dns(
        client_id: &ClientId,
        intermediary: Intermediary,
    ) -> Result<Self, VerifierIdRule> {
        if client_id.prefix() != ClientIdPrefix::X509SanDns {
            return Err(VerifierIdRule::ClientIdPrefix);
        }
        if intermediary == Intermediary::Named {
            return Err(VerifierIdRule::Intermediary);
        }
        Ok(Self(client_id.as_str().to_owned()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The form of `verifier_id` the Verifier's trust framework fixes (nym_auth catalogue,
/// "Verifier identity").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifierIdForm {
    /// `semantic`: `"semantic_id:"` and the end Relying Party's semantic identifier.
    Semantic,
    /// `x509_san_dns`: the Client Identifier.
    X509SanDns,
}

/// Declares 32 bytes with one role in the `pseudonym` function.
macro_rules! bytes32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// The value `bytes`.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = LengthError;

            fn try_from(bytes: &[u8]) -> Result<Self, LengthError> {
                bytes
                    .try_into()
                    .map(Self)
                    .map_err(|_| LengthError(bytes.len()))
            }
        }
    };
}

/// Bytes of this length, where the value has 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{0} bytes, where the value has 32")]
pub struct LengthError(pub usize);

bytes32!(
    /// `verifier_input`: what the configuration derives from the Verifier (the table of
    /// "Configurations").
    VerifierInput
);

bytes32!(
    /// `prover_input`: what the configuration derives from the attestation; 32 zero bytes for
    /// the `ssc` configurations.
    ProverInput
);

bytes32!(
    /// A pseudonym: the result of a `pseudonym` item.
    PseudonymValue
);

impl ProverInput {
    /// The `prover_input` of the `ssc` configurations.
    pub const ZEROS: Self = Self([0; 32]);
}

/// `verifier_input` of a `pseudonym` with the configuration `config`.
#[must_use]
pub fn verifier_input(config: &Config, verifier_id: &VerifierId) -> VerifierInput {
    let id = sha256(verifier_id.as_str().as_bytes());
    VerifierInput(match config {
        Config::UserManagedPseudonymXsiteSsc => [0; 32],
        Config::AccountRecoverySsc { verifier_context } => {
            sha256(&[id, sha256(verifier_context.as_str().as_bytes())].concat())
        }
        Config::KnownOffenderMatchingSsc | Config::KnownOffenderMatchingPsc => id,
    })
}

/// `pseudonym = SHA256(DST ‖ seed ‖ prover_input ‖ verifier_input)` with
/// `DST = UTF-8("nym_auth/v1/<config>")`, the `sha-256` PRF of `ver` 1. `seed` is the 16-byte
/// `secret_seed`.
#[must_use]
pub fn pseudonym_sha256(
    config: &Config,
    seed: &[u8; 16],
    prover_input: &ProverInput,
    verifier_input: &VerifierInput,
) -> PseudonymValue {
    let mut hash = Sha256::new();
    hash.update(b"nym_auth/v1/");
    hash.update(config.as_str().as_bytes());
    hash.update(seed);
    hash.update(prover_input.0);
    hash.update(verifier_input.0);
    PseudonymValue(hash.finalize().into())
}

/// SHA-256.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
