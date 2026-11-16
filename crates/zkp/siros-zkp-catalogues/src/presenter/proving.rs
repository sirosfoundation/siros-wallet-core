//! The statement of an answer, the device signature, the prover's job and the presentation
//! (system rulebooks, Section 7; `zkp_req`, Section 4).

use std::fmt;

use siros_codec::cbor::Value as Cbor;
use siros_codec::signature::Es256Signature;
use siros_mdoc::{
    device_signing_input, es256_verifies, DeviceNameSpaces, SessionTranscript, SigStructure,
};
use siros_zkp_req::{
    PairRefusal, ProofEnvelope, QueryOption, ReqSetIndex, ResultKey, ZkpPresentation,
};

use super::answer::{Answer, Unanswerable};
use super::Session;
use crate::age::Unencodable;
use crate::attestation::{OpenedSeed, UsableAttestation};
use crate::catalogue::{nym_auth_doc_type, Item, NymAuthQuery};
use crate::outcome::{CredentialCode, ZkpError};
use crate::prover::{
    NymAuthProver, ProofJob, ProofOutput, ProverFailure, Statement, ISSUER_KEY_SET, PROOF_TIME,
};
use crate::request::NymAuthRequest;
use crate::system::{pair_code, Unsupported};
use crate::verifier_id::{pseudonym_sha256, verifier_input, ProverInput, PseudonymValue};

/// Why no presentation was made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ProveError {
    /// The attestation is usable for another query than the answer's.
    OtherQuery,
    /// The attestation was tested at another date than the pair's proof date.
    ProofDate,
    /// The pair is no longer usable for its option.
    NotUsable(#[source] PairRefusal<Unsupported>),
    /// The credential fails for the option.
    Rejected(Vec<ZkpError>),
    /// The prover made no proof.
    Prover(#[source] ProverFailure),
    /// The prover's pseudonym differs from the catalogue's.
    PseudonymMismatch,
    /// The prover's `zk_proof` breaks the proof backend's length rules.
    ZkProofLength,
}

impl ProveError {
    /// The error code for the Verifier (`zkp_req`, Section 5): `access_denied`.
    #[must_use]
    pub fn error_code(&self) -> siros_zkp_req::ErrorCode {
        siros_zkp_req::ErrorCode::AccessDenied
    }

    /// A stable identifier: the code of the pair refusal or the prover; `credential` for a
    /// credential that fails, with its codes in the variant.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::OtherQuery => "other_query",
            Self::ProofDate => "proof_date",
            Self::NotUsable(refusal) => pair_code(refusal),
            Self::Rejected(_) => "credential",
            Self::Prover(e) => e.code(),
            Self::PseudonymMismatch => "pseudonym_mismatch",
            Self::ZkProofLength => "zk_proof_length",
        }
    }
}

impl From<Unanswerable> for ProveError {
    fn from(e: Unanswerable) -> Self {
        match e {
            Unanswerable::OtherQuery => Self::OtherQuery,
            Unanswerable::ProofDate => Self::ProofDate,
            Unanswerable::Failed(errors) => Self::Rejected(errors),
        }
    }
}

/// A presentation ready for the device signature, then for the prover.
pub struct Prepared {
    statement: Statement,
    attestation: UsableAttestation,
    seed: OpenedSeed,
    data_to_sign: SigStructure,
    req_set: Option<ReqSetIndex>,
    results: Vec<(ResultKey, Cbor)>,
    pseudonym: PseudonymValue,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("statement", &self.statement)
            .field("req_set", &self.req_set)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    /// The statement of `answer` in the session of `request` (system rulebooks, Section 7).
    ///
    /// # Errors
    ///
    /// [`ProveError::NotUsable`] for an `age_check` bound the system does not encode.
    pub fn new(answer: Answer<'_>, request: &NymAuthRequest<'_>) -> Result<Self, ProveError> {
        build(answer, request.session())
    }
}

/// The statement of `answer` in `session`, and the data the device key signs.
fn build(answer: Answer<'_>, session: &Session) -> Result<Prepared, ProveError> {
    let (pair, attestation, seed) = answer.into_parts();
    let pseudonym_item = pair.pseudonym().pseudonym;
    let session_transcript = SessionTranscript::new(session.handover.session_transcript());
    let data_to_sign = device_signing_input(
        &session_transcript,
        &nym_auth_doc_type(),
        &DeviceNameSpaces::empty(),
    );
    let (earliest, cutoff) = pair.bounds().dates().map_err(|Unencodable| {
        ProveError::NotUsable(PairRefusal::Unsupported(Unsupported::AgeBounds))
    })?;
    let statement = Statement {
        system: pair.system(),
        proof_backend: pair.backend().clone(),
        issuer: attestation.credential().signer().clone(),
        proof_time: attestation.proof_time(),
        earliest,
        cutoff,
        verifier_input: verifier_input(pseudonym_item.config(), &session.verifier_id),
        session_transcript,
        challenge_digest: data_to_sign.digest(),
    };
    let pseudonym = pseudonym_sha256(
        pseudonym_item.config(),
        seed.secret_seed(),
        &ProverInput::ZEROS,
        &statement.verifier_input,
    );
    let option = pair.option();
    let results = results(option.query(), option.option(), &pseudonym);
    Ok(Prepared {
        statement,
        attestation,
        seed,
        data_to_sign,
        req_set: option.option().req_set(),
        results,
        pseudonym,
    })
}

/// `results`: the pseudonym under its handle, `true` under the handle of a function without a
/// result (`zkp_req`, Section 3).
fn results(
    query: &NymAuthQuery,
    option: &QueryOption,
    pseudonym: &PseudonymValue,
) -> Vec<(ResultKey, Cbor)> {
    query
        .option_items(option)
        .filter_map(|(_, item)| {
            let value = match item {
                Item::Pseudonym { .. } => Cbor::Bytes(pseudonym.as_bytes().to_vec()),
                Item::AgeCheck { .. } => Cbor::Bool(true),
            };
            item.ret().map(|handle| (ResultKey::from(handle), value))
        })
        .collect()
}

impl Prepared {
    /// The data the device key signs with ES256: the COSE `Sig_structure` of Section 5.
    #[must_use]
    pub fn data_to_sign(&self) -> &SigStructure {
        &self.data_to_sign
    }

    /// The statement the proof establishes.
    #[must_use]
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The prover's job, once the device signature verifies under the MSO's device key.
    ///
    /// # Errors
    ///
    /// `device_binding` for a signature that does not verify.
    pub fn job(&self, device_signature: &Es256Signature) -> Result<ProofJob, ProveError> {
        let device_key = self.attestation.credential().mdoc().device_key();
        if !es256_verifies(device_key, self.data_to_sign.as_bytes(), device_signature) {
            return Err(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::DeviceBinding,
            )]));
        }
        Ok(ProofJob::new(
            self.statement.clone(),
            self.attestation.clone(),
            self.seed.clone(),
            *device_signature,
        ))
    }

    /// The presentation of the prover's output (`zkp_req`, Section 4, and the proof backends'
    /// `Proof`).
    ///
    /// # Errors
    ///
    /// [`ProveError::PseudonymMismatch`] when the prover's pseudonym is not the catalogue's,
    /// and [`ProveError::ZkProofLength`] for a `zk_proof` the backend would refuse.
    pub fn assemble(&self, output: &ProofOutput) -> Result<ZkpPresentation, ProveError> {
        if output.pseudonym != self.pseudonym {
            return Err(ProveError::PseudonymMismatch);
        }
        if !self.statement.system.admits_zk_proof(&output.zk_proof) {
            return Err(ProveError::ZkProofLength);
        }
        let envelope = ProofEnvelope {
            inputs: vec![
                (
                    ISSUER_KEY_SET,
                    Cbor::Array(vec![Cbor::Bytes(
                        self.statement.issuer.certificate().der().to_vec(),
                    )]),
                ),
                (
                    PROOF_TIME,
                    Cbor::Tag(
                        0,
                        Box::new(Cbor::Text(self.statement.proof_time.to_string())),
                    ),
                ),
            ],
            zk_proof: output.zk_proof.clone(),
        };
        Ok(ZkpPresentation {
            system_id: self.statement.system.id(),
            proof_backend: self.statement.proof_backend.clone(),
            req_set: self.req_set,
            proof: envelope.encode(),
            results: self.results.clone(),
        })
    }
}

impl Prepared {
    /// The job, the prover and `assemble`, for a host that links a prover.
    ///
    /// # Errors
    ///
    /// [`ProveError`]: the device signature, the prover's failure, or its output.
    pub fn prove(
        &self,
        device_signature: &Es256Signature,
        prover: &dyn NymAuthProver,
    ) -> Result<ZkpPresentation, ProveError> {
        let job = self.job(device_signature)?;
        let output = prover.prove(&job).map_err(|failure| match failure {
            ProverFailure::CredentialForm => {
                ProveError::Rejected(vec![ZkpError::Credential(CredentialCode::CredentialForm)])
            }
            ProverFailure::Cancelled | ProverFailure::Unavailable | ProverFailure::Failed => {
                ProveError::Prover(failure)
            }
        })?;
        self.assemble(&output)
    }
}
