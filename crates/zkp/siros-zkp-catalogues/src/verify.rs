//! The Verifier's side (`zkp_req`, Section 4.1, and system rulebooks, Sections 4 and 9): it
//! builds the statement from its own request, session, clock and trust configuration, takes
//! only `req_set`, `results` and the prover-supplied values from the presentation, and hands
//! the proof to a system's verifier.

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_dcql::{CredentialQuery, QueryError};
use siros_mdoc::{device_signing_input, DeviceNameSpaces, SessionTranscript};
use siros_trust::{Certificate, IssuerChain, PathRefusal};
use siros_zkp_req::{
    answered_option, EncodingError, InputName, ProofBackend, ProofEnvelope, QueryOption,
    ReqSetIndex, ResultKey, StructureRejection, ZkProof, ZkpFormats, ZkpPresentation, ZkpReqQuery,
};

use crate::age::{Bounds, Unencodable};
use crate::attestation::{DocumentSigner, DocumentSignerError};
use crate::catalogue::{has_result, nym_auth_doc_type, NymAuthQuery, PseudonymItem};
use crate::outcome::InvalidRequest;
use crate::presenter::Session;
use crate::prover::{NymAuthProofVerifier, ProofFailure, Statement, ISSUER_KEY_SET, PROOF_TIME};
use crate::system::{NymAuthSystem, Unsupported};
use crate::verifier_id::{verifier_input, LengthError, PseudonymValue};

/// How far `proof_time` may lie from the Verifier's clock, in whole seconds each way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tolerance {
    future: u32,
    past: u32,
}

/// What the Verifier holds.
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// Its Credential Query.
    pub query: &'a Value,
    /// Its `client_metadata`.
    pub client_metadata: &'a Value,
    /// Its session: the `Handover` of the request it sent, and its `verifier_id`.
    pub session: &'a Session,
    /// The presentation, CBOR.
    pub presentation: &'a [u8],
    /// Its clock.
    pub now: DateTime,
    /// Its tolerance for `proof_time`.
    pub tolerance: Tolerance,
    /// Its trust configuration: the certificates it trusts for this query.
    pub trust_anchors: &'a [Certificate],
}

/// What an accepted presentation establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The system.
    pub system: NymAuthSystem,
    /// The proof backend.
    pub proof_backend: ProofBackend,
    /// The answered option's index in `_req_sets`.
    pub req_set: Option<ReqSetIndex>,
    /// `results`.
    pub results: Vec<(ResultKey, Cbor)>,
    /// The Document Signer the proof was made against.
    pub issuer: DocumentSigner,
    /// The proof time.
    pub proof_time: DateTime,
}

/// Why the Verifier's own query is unusable: `request`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OwnQueryFault {
    /// DCQL refuses it (OpenID4VP 1.0, Section 6).
    #[error("DCQL refuses it (OpenID4VP 1.0, Section 6)")]
    Dcql(#[source] QueryError),
    /// It breaks a rule of `zkp_req` or of the catalogue.
    #[error("it breaks a rule of `zkp_req` or of the catalogue")]
    Invalid(#[source] InvalidRequest),
    /// It asks for another credential type than the nym_auth attestation.
    #[error("it asks for another credential type than the nym_auth attestation")]
    OtherType,
}

/// Why `proof` or its `inputs` break the proof backend's format or Section 3:
/// `proof_encoding`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofEncodingFault {
    /// `proof` is no `Proof`.
    #[error("`proof` is no `Proof`")]
    Envelope(#[source] EncodingError),
    /// `zk_proof` has a length the system's proof backend does not read.
    #[error("`zk_proof` has a length the system's proof backend does not read")]
    ZkProofLength,
    /// `inputs` holds other members than `issuer_key_set` and `proof_time`.
    #[error("`inputs` holds other members than `issuer_key_set` and `proof_time`")]
    Inputs,
    /// `inputs` lacks this member.
    #[error("`inputs` lacks the member `{0}`")]
    InputMissing(InputName),
    /// `issuer_key_set` is no array of byte strings.
    #[error("`issuer_key_set` is no array of byte strings")]
    IssuerKeySet,
    /// `proof_time` is no `tdate`: text under tag 0.
    #[error("`proof_time` is no `tdate`: text under tag 0")]
    ProofTime,
}

/// Why the pseudonym of `results` is refused: `results`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ResultsFault {
    /// `results` has no value under the `pseudonym` item's handle.
    #[error("`results` has no value under the `pseudonym` item's handle")]
    Absent,
    /// The value is not a byte string.
    #[error("the value is not a byte string")]
    NotBytes,
    /// The byte string is no 32-byte pseudonym.
    #[error("the byte string is no 32-byte pseudonym")]
    Length(#[source] LengthError),
}

/// Why `issuer_key_set` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssuerKeySetError {
    /// It holds this many certificates, where the systems take one.
    #[error("`issuer_key_set` holds {0} certificates, where the systems take one")]
    Count(usize),
    /// The certificate is not one of the systems' form.
    #[error("the certificate is not one of the systems' form")]
    Certificate(#[source] DocumentSignerError),
    /// The certificate has no path to the Verifier's `trust_anchors` at its clock (TR3).
    #[error("the certificate has no path to the Verifier's `trust_anchors` at its clock (TR3)")]
    Untrusted(#[source] PathRefusal),
}

/// Why `proof_time` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ProofTimeError {
    /// It is not exactly `YYYY-MM-DDThh:mm:ssZ`, a real UTC second.
    #[error("`proof_time` is not exactly `YYYY-MM-DDThh:mm:ssZ`, a real UTC second")]
    Malformed,
    /// It lies beyond the tolerance of the Verifier's clock.
    #[error("`proof_time` lies beyond the tolerance of the Verifier's clock")]
    Tolerance,
}

/// Why a presentation is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {:?}", self.code(), self)]
pub enum Rejection {
    /// The Verifier's own query is unusable.
    Request(#[source] OwnQueryFault),
    /// The Verifier's own option lies outside the system's Section 2: `request`.
    Unsupported(#[source] Unsupported),
    /// The presentation is not a `ZkpPresentation`.
    Presentation(#[source] EncodingError),
    /// Steps 1 to 5 of `zkp_req`, Section 4.1.
    Structure(#[source] StructureRejection),
    /// `proof` breaks the proof backend's format, or `inputs` breaks Section 3.
    ProofEncoding(#[source] ProofEncodingFault),
    /// `issuer_key_set`.
    IssuerKeySet(#[source] IssuerKeySetError),
    /// `proof_time`.
    ProofTime(#[source] ProofTimeError),
    /// The pseudonym of `results`.
    Results(#[source] ResultsFault),
    /// The system's verifier refused the proof.
    Proof(#[source] ProofFailure),
}

impl Rejection {
    /// The code of the system rulebooks' Section 9 table, or the step of `zkp_req`,
    /// Section 4.1.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Request(_) | Self::Unsupported(_) => "request",
            Self::Presentation(_) => "presentation",
            Self::Structure(_) => "structure",
            Self::ProofEncoding(_) | Self::Proof(ProofFailure::Encoding) => "proof_encoding",
            Self::IssuerKeySet(_) => "issuer_key_set",
            Self::ProofTime(_) => "proof_time",
            Self::Results(_) => "results",
            Self::Proof(ProofFailure::Invalid) => "proof_invalid",
            Self::Proof(ProofFailure::PublicInput) => "public_input",
            Self::Proof(ProofFailure::Internal) => "verifier_internal",
        }
    }
}

/// A presentation that follows the draft's structure for the Verifier's own request: steps 1
/// to 5 of `zkp_req`, Section 4.1, `Proof` and its `inputs` (system rulebooks, Section 3), the
/// option's support (Section 2) and the types of `results`. Neither the Verifier's clock, nor
/// its trust configuration, nor the proof has judged it yet.
#[derive(Debug, Clone)]
pub struct CheckedPresentation {
    query: NymAuthQuery,
    option: QueryOption,
    system: NymAuthSystem,
    presentation: ZkpPresentation,
    signer: DocumentSigner,
    proof_time: DateTime,
    bounds: Bounds,
    pseudonym: PseudonymValue,
    zk_proof: ZkProof,
}

/// Checks the structure of a presentation for the Verifier's own query.
///
/// # Errors
///
/// [`Rejection`]: the first check that fails.
pub fn check_presentation(
    query: &Value,
    client_metadata: &Value,
    presentation: &[u8],
) -> Result<CheckedPresentation, Rejection> {
    let (query, formats) = own_query(query, client_metadata)?;
    let presentation = ZkpPresentation::decode(presentation).map_err(Rejection::Presentation)?;
    let (option, system) = answered_option(
        query.query(),
        &formats,
        &presentation,
        NymAuthSystem::from_id,
        |item| has_result(item.fn_id()),
    )
    .map_err(Rejection::Structure)?;
    let option = option.clone();
    let envelope = ProofEnvelope::decode(&presentation.proof)
        .map_err(|e| encoding(ProofEncodingFault::Envelope(e)))?;
    if !system.admits_zk_proof(&envelope.zk_proof) {
        return Err(encoding(ProofEncodingFault::ZkProofLength));
    }
    if envelope.inputs.len() != 2 {
        return Err(encoding(ProofEncodingFault::Inputs));
    }
    let signer = issuer_certificate(input_of(&envelope, &ISSUER_KEY_SET)?)?;
    let proof_time = proof_time(input_of(&envelope, &PROOF_TIME)?)?;
    let bounds = own_bounds(&query, &option, system, proof_time)?;
    let pseudonym_item = query
        .option_pseudonym(&option)
        .ok_or(Rejection::Unsupported(Unsupported::NoPseudonym))?;
    let pseudonym = pseudonym_result(pseudonym_item, &presentation)?;
    Ok(CheckedPresentation {
        query,
        option,
        system,
        presentation,
        signer,
        proof_time,
        bounds,
        pseudonym,
        zk_proof: envelope.zk_proof,
    })
}

/// Verifies a presentation for one query.
///
/// # Errors
///
/// [`Rejection`]: the first check that fails.
pub fn verify(
    input: &VerifyInput<'_>,
    verifier: &dyn NymAuthProofVerifier,
) -> Result<Verified, Rejection> {
    let checked = check_presentation(input.query, input.client_metadata, input.presentation)?;
    if !input.tolerance.admits(input.now, checked.proof_time) {
        return Err(Rejection::ProofTime(ProofTimeError::Tolerance));
    }
    let chain = IssuerChain::new(checked.signer.certificate().clone(), Vec::new());
    chain
        .validate_path(input.trust_anchors, input.now)
        .map(drop)
        .map_err(|refusal| Rejection::IssuerKeySet(IssuerKeySetError::Untrusted(refusal)))?;
    let (earliest, cutoff) = checked
        .bounds
        .dates()
        .map_err(|Unencodable| Rejection::Unsupported(Unsupported::AgeBounds))?;
    let pseudonym_item = checked
        .query
        .option_pseudonym(&checked.option)
        .ok_or(Rejection::Unsupported(Unsupported::NoPseudonym))?;
    let session_transcript = SessionTranscript::new(input.session.handover.session_transcript());
    let challenge_digest = device_signing_input(
        &session_transcript,
        &nym_auth_doc_type(),
        &DeviceNameSpaces::empty(),
    )
    .digest();
    let statement = Statement {
        system: checked.system,
        proof_backend: checked.presentation.proof_backend.clone(),
        issuer: checked.signer.clone(),
        proof_time: checked.proof_time,
        earliest,
        cutoff,
        verifier_input: verifier_input(
            pseudonym_item.pseudonym.config(),
            &input.session.verifier_id,
        ),
        session_transcript,
        challenge_digest,
    };
    verifier
        .verify(&statement, &checked.pseudonym, &checked.zk_proof)
        .map_err(Rejection::Proof)?;
    Ok(Verified {
        system: checked.system,
        proof_backend: checked.presentation.proof_backend,
        req_set: checked.option.req_set(),
        results: checked.presentation.results,
        issuer: checked.signer,
        proof_time: checked.proof_time,
    })
}

impl Tolerance {
    /// `future` seconds ahead of the clock and `past` seconds behind it.
    #[must_use]
    pub fn seconds(future: u32, past: u32) -> Self {
        Self { future, past }
    }

    /// Whether `proof_time` lies within this tolerance of `now`, both ends included.
    #[must_use]
    pub fn admits(&self, now: DateTime, proof_time: DateTime) -> bool {
        let earliest = now.unix() - i64::from(self.past);
        let latest = now.unix() + i64::from(self.future);
        (earliest..=latest).contains(&proof_time.unix())
    }
}

fn encoding(fault: ProofEncodingFault) -> Rejection {
    Rejection::ProofEncoding(fault)
}

fn own_query(
    query: &Value,
    client_metadata: &Value,
) -> Result<(NymAuthQuery, ZkpFormats), Rejection> {
    let invalid = |rule: InvalidRequest| Rejection::Request(OwnQueryFault::Invalid(rule));
    let query = CredentialQuery::parse(query)
        .map_err(|error| Rejection::Request(OwnQueryFault::Dcql(error)))?;
    let parsed = ZkpReqQuery::parse(&query).map_err(|r| invalid(r.into()))?;
    let formats =
        ZkpFormats::from_client_metadata(client_metadata).map_err(|r| invalid(r.into()))?;
    let query = NymAuthQuery::from_query(parsed)
        .map_err(|r| invalid(r.into()))?
        .nym_auth()
        .ok_or(Rejection::Request(OwnQueryFault::OtherType))?;
    Ok((query, formats))
}

/// The input `name` of `Proof.inputs`.
fn input_of<'e>(envelope: &'e ProofEnvelope, name: &InputName) -> Result<&'e Cbor, Rejection> {
    envelope
        .inputs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .ok_or_else(|| encoding(ProofEncodingFault::InputMissing(name.clone())))
}

/// `issuer_key_set`: `[ bstr ]`, exactly one DER certificate with a P-256 key.
fn issuer_certificate(value: &Cbor) -> Result<DocumentSigner, Rejection> {
    let Cbor::Array(set) = value else {
        return Err(encoding(ProofEncodingFault::IssuerKeySet));
    };
    let ders = set
        .iter()
        .map(|c| match c {
            Cbor::Bytes(der) => Ok(der),
            _ => Err(encoding(ProofEncodingFault::IssuerKeySet)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [der] = ders.as_slice() else {
        return Err(Rejection::IssuerKeySet(IssuerKeySetError::Count(
            ders.len(),
        )));
    };
    DocumentSigner::parse(der)
        .map_err(|e| Rejection::IssuerKeySet(IssuerKeySetError::Certificate(e)))
}

/// `proof_time`: `tdate`, exactly 20 characters `YYYY-MM-DDThh:mm:ssZ`.
fn proof_time(value: &Cbor) -> Result<DateTime, Rejection> {
    let Cbor::Tag(0, text) = value else {
        return Err(encoding(ProofEncodingFault::ProofTime));
    };
    let Cbor::Text(text) = text.as_ref() else {
        return Err(encoding(ProofEncodingFault::ProofTime));
    };
    DateTime::parse(text).ok_or(Rejection::ProofTime(ProofTimeError::Malformed))
}

/// E and C of the Verifier's own option at the proof date, which the system must support.
fn own_bounds(
    query: &NymAuthQuery,
    option: &QueryOption,
    system: NymAuthSystem,
    proof_time: DateTime,
) -> Result<Bounds, Rejection> {
    let bounds = query.option_bounds(option, proof_time.date());
    system
        .supports(query.option_items(option).map(|(_, i)| i), &bounds)
        .map_err(Rejection::Unsupported)?;
    Ok(bounds)
}

/// The pseudonym of `results`: a 32-byte `bstr` under the `pseudonym` item's handle.
fn pseudonym_result(
    item: PseudonymItem<'_>,
    presentation: &ZkpPresentation,
) -> Result<PseudonymValue, Rejection> {
    let value = presentation
        .results
        .iter()
        .find(|(k, _)| k.as_str() == item.ret.as_str())
        .map(|(_, v)| v)
        .ok_or(Rejection::Results(ResultsFault::Absent))?;
    let Cbor::Bytes(bytes) = value else {
        return Err(Rejection::Results(ResultsFault::NotBytes));
    };
    PseudonymValue::try_from(bytes.as_slice())
        .map_err(|e| Rejection::Results(ResultsFault::Length(e)))
}
