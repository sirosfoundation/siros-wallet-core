//! G3: one fixture per refusal rule, each with the exact typed error it must give.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod refusal_cases;
mod support;

use serde_json::{json, Value};
use siros_codec::cbor::{CborError, Unsupported as CborUnsupported, Value as Cbor};
use siros_codec::date::DateTime;
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_dcql::{CredentialQuery, QueryError};
use siros_oid4vp::{ClientId, ClientIdError, Origin};
use siros_trust::Certificate;
use siros_zkp_req::{
    EncodingError, IdentifierFault, InputName, ItemIndex, OptionFault, PairRefusal, ProofBackend,
    ProofContent, ProofEnvelope, ReqSetIndex, RequestRule, ResultKey, ReturnFault,
    ReturnHandleError, StructureRejection, TypeValueFault, ZkProof, ZkpFormats, ZkpPresentation,
    ZkpReqQuery,
};
use siros_zkp_req_nym_auth::attestation::{SecretSeed, Unusable};
use siros_zkp_req_nym_auth::catalogue::{
    CatalogueRule, ContextFault, NymAuthQuery, ParamFault, Prf,
};
use siros_zkp_req_nym_auth::outcome::{CredentialCode, InvalidRequest, ItemCode, ZkpError};
use siros_zkp_req_nym_auth::policy::PolicyRule;
use siros_zkp_req_nym_auth::presenter::{Answer, ProveError, Unanswerable};
use siros_zkp_req_nym_auth::prover::{ProofFailure, ProverFailure};
use siros_zkp_req_nym_auth::request_object::{check_request, Channel, Signing};
use siros_zkp_req_nym_auth::system::{NymAuthSystem, Unsupported};
use siros_zkp_req_nym_auth::verifier_id::{Intermediary, LengthError, VerifierId, VerifierIdRule};
use siros_zkp_req_nym_auth::verify::{
    verify, IssuerKeySetError, OwnQueryFault, ProofEncodingFault, ProofTimeError, Rejection,
    ResultsFault, Tolerance, VerifyInput,
};
use support::*;
use zeroize::Zeroizing;

/// What a fixture gives.
#[derive(Debug, PartialEq)]
enum Got {
    Dcql(QueryError),
    Invalid(InvalidRequest),
    Unsupported(PairRefusal<Unsupported>),
    Credential(Vec<CredentialCode>),
    Unanswerable(Unanswerable),
    Prove(ProveError),
    Verify(Rejection),
    Policy(PolicyRule),
    VerifierId(VerifierIdRule),
    Accepted,
}

fn protocol(rule: RequestRule) -> Got {
    Got::Invalid(InvalidRequest::Protocol(rule))
}

fn catalogue(rule: CatalogueRule) -> Got {
    Got::Invalid(InvalidRequest::Catalogue(rule))
}

fn ds() -> Issuer {
    Issuer::root(0x11, "Test Document Signer")
}

/// The nym_auth query of `query` and the Verifier's formats of `metadata`.
fn parsed(query: &Value, metadata: &Value) -> Result<(NymAuthQuery, ZkpFormats), Got> {
    let invalid = |rule: InvalidRequest| Got::Invalid(rule);
    let query = CredentialQuery::parse(query).map_err(Got::Dcql)?;
    let parsed = ZkpReqQuery::parse(&query).map_err(|r| invalid(r.into()))?;
    let formats = ZkpFormats::from_client_metadata(metadata).map_err(|r| invalid(r.into()))?;
    let nym = NymAuthQuery::from_query(parsed)
        .map_err(|r| invalid(r.into()))?
        .nym_auth()
        .expect("a nym_auth query");
    Ok((nym, formats))
}

/// The answer of `query`'s first option with a usable Longfellow pair by the credential `data`
/// with `seed`, at the proof time: the request rules, the pair, the credential tests and the
/// items.
fn answered(query: &Value, metadata: &Value, data: &str, seed: [u8; 16]) -> Got {
    let now = DateTime::from_unix(NOW).unwrap();
    let (nym, formats) = match parsed(query, metadata) {
        Ok(parsed) => parsed,
        Err(got) => return got,
    };
    let pairs: Vec<_> = nym
        .options()
        .map(|option| option.pair(&formats, NymAuthSystem::LongfellowV1, now.date()))
        .collect();
    let pair = match pairs.iter().position(Result::is_ok) {
        Some(position) => pairs.into_iter().nth(position).unwrap().unwrap(),
        None => return Got::Unsupported(pairs.into_iter().next().unwrap().unwrap_err()),
    };
    let usable = match usable(query, &nym, data, now) {
        Ok(usable) => usable,
        Err(Presenting::Unusable(unusable @ (Unusable::Fails(_) | Unusable::Unreadable(_)))) => {
            return Got::Credential(unusable.codes().to_vec())
        }
        Err(other) => panic!("{other:?}"),
    };
    match Answer::new(pair, usable, &SecretSeed::new(Zeroizing::new(seed))) {
        Ok(_) => Got::Accepted,
        Err(unanswerable) => Got::Unanswerable(unanswerable),
    }
}

/// Answers `query` after `edit` with the default credential.
fn match_query_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut q = query(Some("18+"), false);
    edit(&mut q);
    answered(
        &q,
        &client_metadata(),
        &issue(&ds(), &Spec::default()),
        SEED,
    )
}

fn match_metadata_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut metadata = client_metadata();
    edit(&mut metadata);
    answered(
        &query(None, false),
        &metadata,
        &issue(&ds(), &Spec::default()),
        SEED,
    )
}

fn match_credential(spec: Spec, range: Option<&str>, seed: [u8; 16]) -> Got {
    answered(
        &query(range, false),
        &client_metadata(),
        &issue(&ds(), &spec),
        seed,
    )
}

/// Proves the default credential with this device key and prover.
fn prove(device: u8, fail: Option<ProverFailure>) -> Got {
    let q = query(None, false);
    let data = issue(&ds(), &Spec::default());
    let request = verified_request(&q, NONCE);
    let prepared = prepared(NymAuthSystem::LongfellowV1, &q, &data, &SEED, &request).unwrap();
    match present(&prepared, device, &TestProver { fail }) {
        Ok(_) => Got::Accepted,
        Err(e) => Got::Prove(e),
    }
}

fn policy(edit: impl FnOnce(&mut Value), signing: Signing, channel: Channel) -> Got {
    let mut request = request_object(&query(None, false), NONCE);
    edit(&mut request);
    match check_request(&request, signing, channel) {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::Policy(rule),
    }
}

fn verifier_id(result: Result<VerifierId, VerifierIdRule>) -> Got {
    match result {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::VerifierId(rule),
    }
}

/// An honest presentation for `query`, made with `system`.
fn honest(system: NymAuthSystem, query: &Value) -> Vec<u8> {
    let data = issue(&ds(), &Spec::default());
    let request = verified_request(query, NONCE);
    let prepared = prepared(system, query, &data, &SEED, &request).unwrap();
    present(
        &prepared,
        Spec::default().device,
        &TestProver { fail: None },
    )
    .unwrap()
    .encode()
}

fn sets_query() -> Value {
    let mut q = query(Some("18+"), true);
    q["_req_sets"] = json!([[0, 1], [0]]);
    q
}

struct Verifying {
    query: Value,
    metadata: Value,
    trust_anchors: Vec<Certificate>,
    now: DateTime,
}

impl Default for Verifying {
    fn default() -> Self {
        Self {
            query: sets_query(),
            metadata: client_metadata(),
            trust_anchors: vec![Certificate::parse(&ds().der).unwrap()],
            now: DateTime::from_unix(NOW + 5).unwrap(),
        }
    }
}

fn verified(v: Verifying, bytes: &[u8]) -> Got {
    let result = verify(
        &VerifyInput {
            query: &v.query,
            client_metadata: &v.metadata,
            session: &session(&v.query, NONCE),
            presentation: bytes,
            now: v.now,
            tolerance: Tolerance::seconds(60, 600),
            trust_anchors: &v.trust_anchors,
        },
        &TestVerifier,
    );
    match result {
        Ok(_) => Got::Accepted,
        Err(r) => Got::Verify(r),
    }
}

/// Verifies the honest Longfellow presentation after `edit`.
fn verify_edit(edit: impl FnOnce(&mut ZkpPresentation)) -> Got {
    verify_edit_as(NymAuthSystem::LongfellowV1, Verifying::default(), edit)
}

fn verify_edit_as(
    system: NymAuthSystem,
    v: Verifying,
    edit: impl FnOnce(&mut ZkpPresentation),
) -> Got {
    let mut p = ZkpPresentation::decode(&honest(system, &sets_query())).unwrap();
    edit(&mut p);
    verified(v, &p.encode())
}

fn edit_envelope(p: &mut ZkpPresentation, edit: impl FnOnce(&mut ProofEnvelope)) {
    let mut envelope = ProofEnvelope::decode(&p.proof).unwrap();
    edit(&mut envelope);
    p.proof = envelope.encode();
}

fn set_input(envelope: &mut ProofEnvelope, name: &str, value: Cbor) {
    for (k, v) in &mut envelope.inputs {
        if k.as_str() == name {
            *v = value.clone();
        }
    }
}

fn set_result(p: &mut ZkpPresentation, handle: &str, value: Option<Cbor>) {
    p.results.retain(|(k, _)| k.as_str() != handle);
    if let Some(value) = value {
        p.results.push((ResultKey::new(handle), value));
    }
}

/// `zk_proof` without its last byte.
fn shortened(zk_proof: &ZkProof) -> ZkProof {
    let bytes = zk_proof.as_bytes();
    ZkProof::new(bytes[..bytes.len() - 1].to_vec())
}

fn credential_error(code: CredentialCode) -> Got {
    Got::Credential(vec![code])
}

#[test]
fn every_refusal_rule() {
    let cases = refusal_cases::all();
    // The honest inputs each fixture edits are accepted: each fixture breaks only its rule.
    assert_eq!(match_query_edit(|_| {}), Got::Accepted);
    assert_eq!(prove(Spec::default().device, None), Got::Accepted);
    assert_eq!(verify_edit(|_| {}), Got::Accepted);
    assert_eq!(
        policy(|_| {}, Signing::Signed, Channel::Redirect),
        Got::Accepted
    );
    let failures: Vec<String> = cases
        .into_iter()
        .filter(|(_, got, want)| got != want)
        .map(|(name, got, want)| format!("{name}: got {got:?}, want {want:?}"))
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The honest presentation of a query without `_req_sets`, with a `req_set` added.
fn edited_no_sets() -> Vec<u8> {
    let mut p = ZkpPresentation::decode(&honest(
        NymAuthSystem::LongfellowV1,
        &query(Some("18+"), true),
    ))
    .unwrap();
    p.req_set = Some(ReqSetIndex::new(0));
    p.encode()
}
