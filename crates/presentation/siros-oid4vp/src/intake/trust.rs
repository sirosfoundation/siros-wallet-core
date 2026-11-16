//! The `Trust` effect: the host asks its AuthZEN PDP whether a name is bound to key material
//! (host effect H2).

use p256::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use siros_codec::chain::CertificateChain;

use super::{Answers, Halt, IntakeError};
use crate::client_id::ClientId;
use crate::jose;
use crate::values::{AttestationIssuer, Kid, Origin, TrustChain};

/// The name a [`Trust`] effect asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustSubject {
    /// A Client Identifier, prefix included.
    Client(ClientId),
    /// The issuer of the Verifier Attestation JWT of a `verifier_attestation` client.
    AttestationIssuer(AttestationIssuer),
    /// The calling origin of an `openid4vp-v1-unsigned` DC API request.
    Origin(Origin),
}

/// The key material a [`Trust`] effect binds to its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// None: the request is unsigned.
    None,
    /// An `x5c` chain. The host validates the chain; the core has bound the leaf to the subject
    /// and verified the signature with its key.
    X509Chain(CertificateChain),
    /// A key the host resolves and returns in [`TrustAnswer`]: a DID's verification method,
    /// an OpenID Federation entity's key, or an attestation issuer's key.
    Resolve {
        /// The `kid` Header Parameter of the signature.
        kid: Option<Kid>,
        /// The `trust_chain` Header Parameter of an `openid_federation` request.
        trust_chain: Option<TrustChain>,
    },
}

/// A trust question for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    subject: TrustSubject,
    key: KeyMaterial,
}

impl Trust {
    /// The name to evaluate.
    #[must_use]
    pub fn subject(&self) -> &TrustSubject {
        &self.subject
    }

    /// The key material bound to it.
    #[must_use]
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }
}

/// The host's AuthZEN decision on a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "bool", into = "bool")]
pub enum Verdict {
    /// The subject is trusted.
    Trusted,
    /// The subject is not trusted.
    Untrusted,
}

impl From<bool> for Verdict {
    fn from(trusted: bool) -> Self {
        if trusted {
            Self::Trusted
        } else {
            Self::Untrusted
        }
    }
}

impl From<Verdict> for bool {
    fn from(verdict: Verdict) -> Self {
        verdict == Verdict::Trusted
    }
}

/// The host's answer to a [`Trust`] effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnswer {
    trusted: Verdict,
    key: Option<Value>,
    metadata: Option<Value>,
}

impl TrustAnswer {
    /// The AuthZEN decision, with what the evaluation resolved.
    ///
    /// `key` is the resolved public JWK, for [`KeyMaterial::Resolve`] only. `metadata` is the
    /// Verifier metadata of an `openid_federation` client's Trust Chain, which replaces its
    /// `client_metadata` (Section 5.9.3).
    #[must_use]
    pub fn new(verdict: Verdict, key: Option<Value>, metadata: Option<Value>) -> Self {
        Self {
            trusted: verdict,
            key,
            metadata,
        }
    }
}

/// The verdict on a subject whose key the request carries or the request is unsigned.
pub(super) fn verdict(
    answers: &mut Answers<'_>,
    subject: TrustSubject,
    key: KeyMaterial,
) -> Result<Verdict, Halt> {
    let answer = answers.trust(Trust { subject, key })?;
    if answer.key.is_some() || answer.metadata.is_some() {
        return Err(Halt::HostFault(IntakeError::UnexpectedTrustKey));
    }
    Ok(answer.trusted)
}

/// Whether the host may answer a key lookup with Verifier metadata: for an `openid_federation`
/// client's Trust Chain only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataAnswer {
    /// The answer may carry Verifier metadata.
    Taken,
    /// An answer with Verifier metadata is a host fault.
    Refused,
}

/// What the host resolved for a subject whose key it looks up.
pub(super) struct Resolved {
    pub(super) trusted: Verdict,
    pub(super) key: PublicKey,
    pub(super) metadata: Option<Value>,
}

/// The verdict and the resolved key of `subject`.
pub(super) fn resolve(
    answers: &mut Answers<'_>,
    subject: TrustSubject,
    kid: Option<Kid>,
    trust_chain: Option<TrustChain>,
    metadata: MetadataAnswer,
) -> Result<Resolved, Halt> {
    let answer = answers.trust(Trust {
        subject,
        key: KeyMaterial::Resolve { kid, trust_chain },
    })?;
    if answer.metadata.is_some() && metadata == MetadataAnswer::Refused {
        return Err(Halt::HostFault(IntakeError::UnexpectedTrustKey));
    }
    let jwk = answer.key.as_ref().ok_or(IntakeError::KeyNotResolved)?;
    let key = jose::p256_key(jwk).map_err(IntakeError::ResolvedKeyInvalid)?;
    Ok(Resolved {
        trusted: answer.trusted,
        key,
        metadata: answer.metadata.clone(),
    })
}
