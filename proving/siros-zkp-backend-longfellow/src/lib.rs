//! `urn:circuits:longfellow:nym_auth:v1` on `longfellow-libzk-v1`: zk-cred-longfellow behind the
//! system rulebook's artifact pins (Section 8) and its statement encoding (Section 4).
//!
//! The host fetches `circuits.zst`; [`LongfellowProver::load`] and [`LongfellowVerifier::load`]
//! check it against the pin before they decompress or parse it.

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use siros_codec::date::Date;
use siros_zkp_req::ZkProof;
use siros_zkp_req_nym_auth::prover::{
    NymAuthProofVerifier, NymAuthProver, ProofFailure, ProofJob, ProofOutput, ProverFailure,
    Statement,
};
use siros_zkp_req_nym_auth::system::{ArtifactPin, NymAuthSystem};
use siros_zkp_req_nym_auth::verifier_id::PseudonymValue;
use zk_cred_longfellow::nymauth::{
    NymAuthCircuitParams, NymAuthError, NymAuthProver as Prover, NymAuthRequest,
    NymAuthVerifier as Verifier, NymAuthWitnessInput,
};

const SYSTEM: NymAuthSystem = NymAuthSystem::LongfellowV1;

/// `params.tsv` of Section 8: the Ligero `block_enc` and the ids of both circuits.
fn params() -> NymAuthCircuitParams {
    NymAuthCircuitParams {
        block_enc_hash: 6983,
        block_enc_sig: 4679,
        hash_circuit_id: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729".into(),
        sig_circuit_id: "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb".into(),
    }
}

/// Why `circuits.zst` was not loaded.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The bytes are not the pinned file.
    #[error("not the pinned {} ({} bytes)", .0.name, .0.len)]
    Pin(ArtifactPin),
    /// The pinned file does not decompress within its content's length.
    #[error("the circuits do not decompress")]
    Decompress(#[source] std::io::Error),
    /// zk-cred-longfellow refused the circuits.
    #[error("zk-cred-longfellow refused the circuits")]
    Circuits(#[source] NymAuthError),
}

/// The decompressed circuits of a `circuits.zst` that matches its pin.
fn circuits(circuits_zst: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let artifact = SYSTEM.circuit_artifact();
    if !artifact.compressed.matches(circuits_zst) {
        return Err(ArtifactError::Pin(artifact.compressed));
    }
    zstd::bulk::decompress(circuits_zst, artifact.content.len).map_err(ArtifactError::Decompress)
}

/// The prover of the system.
pub struct LongfellowProver(Prover);

impl LongfellowProver {
    /// Loads the prover from `circuits.zst`.
    ///
    /// # Errors
    ///
    /// [`ArtifactError`]: the bytes are not the pinned artifact.
    pub fn load(circuits_zst: &[u8]) -> Result<Self, ArtifactError> {
        let circuits = circuits(circuits_zst)?;
        Prover::new(&circuits, &params())
            .map(Self)
            .map_err(ArtifactError::Circuits)
    }
}

/// The verifier of the system.
pub struct LongfellowVerifier(Verifier);

impl LongfellowVerifier {
    /// Loads the verifier from `circuits.zst`.
    ///
    /// # Errors
    ///
    /// [`ArtifactError`]: the bytes are not the pinned artifact.
    pub fn load(circuits_zst: &[u8]) -> Result<Self, ArtifactError> {
        let circuits = circuits(circuits_zst)?;
        Verifier::new(&circuits, &params())
            .map(Self)
            .map_err(ArtifactError::Circuits)
    }
}

/// Whether the statement is one of this system on this backend.
fn serves(statement: &Statement) -> bool {
    statement.system == SYSTEM && SYSTEM.runs_on(&statement.proof_backend)
}

/// The text values of the hash circuit (Section 4): T, and E and C with their values for no
/// bound.
struct Dates {
    time: String,
    earliest: String,
    cutoff: String,
}

impl Dates {
    /// `None` for a date past the 10 characters of `YYYY-MM-DD`.
    fn of(statement: &Statement) -> Option<Self> {
        let bound = |date: Option<Date>, none: &str| match date {
            Some(d) => Date::to_full_date(d),
            None => Some(none.to_owned()),
        };
        Some(Self {
            time: statement.proof_time.to_string(),
            earliest: bound(statement.earliest, "0000-00-00")?,
            cutoff: bound(statement.cutoff, "9999-12-31")?,
        })
    }

    fn request<'a>(&'a self, statement: &'a Statement) -> NymAuthRequest<'a> {
        NymAuthRequest {
            issuer_key_x: statement.issuer.key().x(),
            issuer_key_y: statement.issuer.key().y(),
            time: &self.time,
            earliest: &self.earliest,
            cutoff: &self.cutoff,
            challenge_digest: statement.challenge_digest.as_bytes(),
            verifier_input: statement.verifier_input.as_bytes(),
            transcript_seed: statement.session_transcript.as_bytes(),
        }
    }
}

impl NymAuthProver for LongfellowProver {
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure> {
        let statement = job.statement();
        if !serves(statement) {
            return Err(ProverFailure::Unavailable);
        }
        let dates = Dates::of(statement).ok_or(ProverFailure::Failed)?;
        let witness = NymAuthWitnessInput {
            issuer_signed: job.issuer_signed(),
            secret_seed: job.secret_seed(),
            device_signature: job.device_signature().as_bytes(),
        };
        let proved = self
            .0
            .prove(&dates.request(statement), &witness)
            .map_err(|e| match e {
                NymAuthError::Credential(_) => ProverFailure::CredentialForm,
                NymAuthError::InvalidInput(_)
                | NymAuthError::Circuit(_)
                | NymAuthError::UnsupportedCircuit(_)
                | NymAuthError::Unsatisfied(_)
                | NymAuthError::Prover(_)
                | NymAuthError::ProofEncoding(_)
                | NymAuthError::Verification(_) => ProverFailure::Failed,
            })?;
        Ok(ProofOutput {
            zk_proof: ZkProof::new(proved.proof),
            pseudonym: PseudonymValue::new(proved.pseudonym),
        })
    }
}

impl NymAuthProofVerifier for LongfellowVerifier {
    fn verify(
        &self,
        statement: &Statement,
        pseudonym: &PseudonymValue,
        zk_proof: &ZkProof,
    ) -> Result<(), ProofFailure> {
        if !serves(statement) {
            return Err(ProofFailure::Internal);
        }
        let dates = Dates::of(statement).ok_or(ProofFailure::Internal)?;
        self.0
            .verify(
                &dates.request(statement),
                pseudonym.as_bytes(),
                zk_proof.as_bytes(),
            )
            .map_err(|e| match e {
                NymAuthError::ProofEncoding(_) => ProofFailure::Encoding,
                NymAuthError::Verification(_) => ProofFailure::Invalid,
                NymAuthError::InvalidInput(_)
                | NymAuthError::Circuit(_)
                | NymAuthError::UnsupportedCircuit(_)
                | NymAuthError::Credential(_)
                | NymAuthError::Unsatisfied(_)
                | NymAuthError::Prover(_) => ProofFailure::Internal,
            })
    }
}
