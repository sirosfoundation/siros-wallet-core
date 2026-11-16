//! The interface to the provers. A host implements it with a system's prover and verifier,
//! such as those of zk-cred-longfellow and zk-cred-vega; this crate holds no prover.
//!
//! Both sides build the same [`Statement`] (system rulebooks, Section 4): the Wallet from the
//! credential and the session, the Verifier from its own request, session, clock and trust
//! configuration and from the prover-supplied values of the presentation.

use siros_codec::date::{Date, DateTime};
use siros_codec::signature::Es256Signature;
use siros_mdoc::{MessageDigest, SessionTranscript};
use siros_zkp_req::{InputName, ProofBackend, ZkProof};

use crate::attestation::{DocumentSigner, OpenedSeed, UsableAttestation};
use crate::system::NymAuthSystem;
use crate::verifier_id::{PseudonymValue, VerifierInput};

/// `Proof.inputs.issuer_key_set`: the Document Signer certificate (system rulebooks, Section 3).
pub(crate) const ISSUER_KEY_SET: InputName = InputName::from_static("issuer_key_set");
/// `Proof.inputs.proof_time`: T (system rulebooks, Section 3).
pub(crate) const PROOF_TIME: InputName = InputName::from_static("proof_time");

/// The public values of a nym_auth mdoc proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The system.
    pub system: NymAuthSystem,
    /// The proof backend.
    pub proof_backend: ProofBackend,
    /// `inputs.issuer_key_set[0]`: the Document Signer certificate, with the issuer key Q.
    pub issuer: DocumentSigner,
    /// T: `inputs.proof_time`.
    pub proof_time: DateTime,
    /// E, the earliest birth date; `None` for the system's widest value.
    pub earliest: Option<Date>,
    /// C, the latest birth date; `None` for the system's widest value.
    pub cutoff: Option<Date>,
    /// `verifier_input` of the `pseudonym` item.
    pub verifier_input: VerifierInput,
    /// The `SessionTranscript`, which seeds Longfellow's transcript.
    pub session_transcript: SessionTranscript,
    /// e2: the SHA-256 of the message the device key signed.
    pub challenge_digest: MessageDigest,
}

/// What a prover needs to prove a [`Statement`] (system rulebooks, Section 7): a usable
/// attestation, the seed that opens its `ssc`, and the device signature.
pub struct ProofJob {
    statement: Statement,
    attestation: UsableAttestation,
    seed: OpenedSeed,
    device_signature: Es256Signature,
}

impl ProofJob {
    /// The job for `statement`. `device_signature` verifies under the MSO's device key.
    #[cfg(feature = "request")]
    pub(crate) fn new(
        statement: Statement,
        attestation: UsableAttestation,
        seed: OpenedSeed,
        device_signature: Es256Signature,
    ) -> Self {
        Self {
            statement,
            attestation,
            seed,
            device_signature,
        }
    }

    /// The public values.
    #[must_use]
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The credential's `IssuerSigned`, as issued.
    #[must_use]
    pub fn issuer_signed(&self) -> &[u8] {
        self.attestation.credential().mdoc().issuer_signed()
    }

    /// The 16-byte `secret_seed`. It is zeroed when the job is dropped.
    #[must_use]
    pub fn secret_seed(&self) -> &[u8; 16] {
        self.seed.secret_seed()
    }

    /// The device key's ES256 signature on the data to sign.
    #[must_use]
    pub fn device_signature(&self) -> &Es256Signature {
        &self.device_signature
    }
}

impl std::fmt::Debug for ProofJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofJob")
            .field("statement", &self.statement)
            .finish_non_exhaustive()
    }
}

/// What a prover returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOutput {
    /// `zk_proof`, as the proof backend specification defines it.
    pub zk_proof: ZkProof,
    /// The pseudonym the proof establishes. It must equal the catalogue's value.
    pub pseudonym: PseudonymValue,
}

/// Why a prover made no proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ProverFailure {
    /// The credential lies outside the form the system reads (Section 2): `credential_form`.
    CredentialForm,
    /// The User or the host cancelled.
    Cancelled,
    /// The system's artifacts or prover are not available here.
    Unavailable,
    /// Proving failed.
    Failed,
}

impl ProverFailure {
    /// A stable identifier: `credential_form` is the code of the system rulebooks' Section 9.
    pub fn code(self) -> &'static str {
        match self {
            Self::CredentialForm => "credential_form",
            Self::Cancelled => "prover_cancelled",
            Self::Unavailable => "prover_unavailable",
            Self::Failed => "prover_failed",
        }
    }
}

/// A system's prover.
pub trait NymAuthProver {
    /// Proves the statement of `job`.
    ///
    /// # Errors
    ///
    /// [`ProverFailure`]: why no proof was made.
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure>;
}

/// Why a verifier refused a proof (system rulebooks, Section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ProofFailure {
    /// `zk_proof` breaks the format of the proof backend: `proof_encoding`.
    #[error("`zk_proof` breaks the format of the proof backend")]
    Encoding,
    /// A circuit's proof fails: `proof_invalid`.
    #[error("a circuit's proof fails")]
    Invalid,
    /// The proof's public values differ from the statement: `public_input`.
    #[error("the proof's public values differ from the statement")]
    PublicInput,
    /// The verifier failed on its own inputs, artifacts or code, and judged nothing.
    #[error("the verifier failed on its own inputs, artifacts or code, and judged nothing")]
    Internal,
}

/// A system's verifier.
pub trait NymAuthProofVerifier {
    /// Verifies `zk_proof` against `statement` and the pseudonym of `results`.
    ///
    /// # Errors
    ///
    /// [`ProofFailure`]: why the proof is refused.
    fn verify(
        &self,
        statement: &Statement,
        pseudonym: &PseudonymValue,
        zk_proof: &ZkProof,
    ) -> Result<(), ProofFailure>;
}
