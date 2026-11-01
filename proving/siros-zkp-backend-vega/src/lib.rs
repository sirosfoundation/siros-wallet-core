//! `urn:circuits:vega:nym_auth:v1` on `vega-v1`: zk-cred-vega behind the system rulebook's artifact
//! pins (Section 8) and its statement (Section 4).
//!
//! The host fetches `shapes.zst`; [`VegaNymAuth::load`] checks it against the pin before it
//! decompresses it, then derives the prover and verifier keys from the shapes.

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
use zk_cred_vega::nymauth_vega::engine::statement::{
    self as vega, Error, Holder, Keys, Statement as VegaStatement,
};

const SYSTEM: NymAuthSystem = NymAuthSystem::VegaV1;

/// Why `shapes.zst` was not loaded.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// The bytes are not the pinned file.
    #[error("not the pinned {} ({} bytes)", .0.name, .0.len)]
    Pin(ArtifactPin),
    /// The pinned file does not decompress within its content's length.
    #[error("the shapes do not decompress")]
    Decompress(#[source] std::io::Error),
    /// zk-cred-vega refused the shapes.
    #[error("zk-cred-vega refused the shapes")]
    Shapes(#[source] Error),
}

/// The prover and verifier keys of the system.
pub struct VegaNymAuth(Keys);

impl VegaNymAuth {
    /// Loads the keys from `shapes.zst`.
    ///
    /// # Errors
    ///
    /// [`ArtifactError`]: the bytes are not the pinned artifact.
    pub fn load(shapes_zst: &[u8]) -> Result<Self, ArtifactError> {
        let artifact = SYSTEM.circuit_artifact();
        if !artifact.compressed.matches(shapes_zst) {
            return Err(ArtifactError::Pin(artifact.compressed));
        }
        let shapes = zstd::bulk::decompress(shapes_zst, artifact.content.len)
            .map_err(ArtifactError::Decompress)?;
        Keys::from_shapes(&shapes)
            .map(Self)
            .map_err(ArtifactError::Shapes)
    }
}

/// Whether the statement is one of this system on this backend.
fn serves(statement: &Statement) -> bool {
    statement.system == SYSTEM && SYSTEM.runs_on(&statement.proof_backend)
}

/// The text values zk-cred-vega reads: T, and E and C with its values for no bound.
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

    fn statement<'a>(&'a self, statement: &'a Statement) -> VegaStatement<'a> {
        VegaStatement {
            issuer_key_x: statement.issuer.key().x(),
            issuer_key_y: statement.issuer.key().y(),
            time: &self.time,
            earliest: &self.earliest,
            cutoff: &self.cutoff,
            challenge_digest: statement.challenge_digest.as_bytes(),
            verifier_input: statement.verifier_input.as_bytes(),
        }
    }
}

impl NymAuthProver for VegaNymAuth {
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure> {
        let statement = job.statement();
        if !serves(statement) {
            return Err(ProverFailure::Unavailable);
        }
        let dates = Dates::of(statement).ok_or(ProverFailure::Failed)?;
        let holder = Holder {
            issuer_signed: job.issuer_signed(),
            secret_seed: job.secret_seed(),
            device_signature: job.device_signature().as_bytes(),
        };
        // `Input` and `Refused(Credential)` hold a credential outside the system's form together
        // with other causes, so neither is `credential_form`.
        let proved =
            vega::prove(&self.0, &dates.statement(statement), &holder).map_err(|e| match e {
                Error::Input(_)
                | Error::Shapes(_)
                | Error::UnknownCircuit(_)
                | Error::Refused(_)
                | Error::Prover(_)
                | Error::ProofEncoding(_)
                | Error::ProofInvalid(_)
                | Error::Mismatch(_)
                | Error::Internal(_) => ProverFailure::Failed,
            })?;
        Ok(ProofOutput {
            zk_proof: ZkProof::new(proved.proof),
            pseudonym: PseudonymValue::new(proved.pseudonym),
        })
    }
}

impl NymAuthProofVerifier for VegaNymAuth {
    /// Tests 1 to 3 of Section 4. The pseudonym is a public value of the core: one that differs
    /// from `results` fails test 3.
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
        let reported = vega::verify(&self.0, &dates.statement(statement), zk_proof.as_bytes())
            .map_err(|e| match e {
                Error::ProofEncoding(_) => ProofFailure::Encoding,
                Error::ProofInvalid(_) => ProofFailure::Invalid,
                Error::Mismatch(_) => ProofFailure::PublicInput,
                Error::Input(_)
                | Error::Shapes(_)
                | Error::UnknownCircuit(_)
                | Error::Refused(_)
                | Error::Prover(_)
                | Error::Internal(_) => ProofFailure::Internal,
            })?;
        if reported == *pseudonym.as_bytes() {
            Ok(())
        } else {
            Err(ProofFailure::PublicInput)
        }
    }
}
