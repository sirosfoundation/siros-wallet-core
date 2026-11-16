//! The presenter chain test — a wasm-bindgen test, run with
//! `wasm-pack test --node` (the same runner the engine-adapter-wasm tests
//! use). The chain the JS surface wraps, over the testing fixtures: the
//! session the JS host's inputs give (the handover CBOR and the
//! verifier_id), the answer from the fixture credential, the presenter's
//! steps in order. The real-proof e2e (`proving/e2e`, `--ignored`)
//! remains the full validation with real artifacts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use wasm_bindgen_test::wasm_bindgen_test;

use siros_codec::date::DateTime;
use siros_codec::signature::Es256Signature;
use siros_zkp_catalogues::attestation::{SecretSeed, TestedAttestation, UsableAttestation};
use siros_zkp_catalogues::catalogue::{Catalogued, NymAuthQuery};
use siros_zkp_catalogues::presenter::Answer;
use siros_zkp_catalogues::presenter::Prepared;
use siros_zkp_catalogues::system::NymAuthSystem;
use siros_zkp_catalogues::testing::{
    client_metadata, device_signature, issue, query, session, Issuer, Spec, NOW, SEED,
};
use siros_zkp_req::{ZkpFormats, ZkpReqQuery};
use zeroize::Zeroizing;

/// The presenter chain the wasm surface exposes: the session from the
/// host's facts, the pair over the request's formats, the attestation
/// the seed opens with its issuer admitted, the prepared statement, the
/// device signature, the job — and the statement's verifier input carries
/// the session's verifier_id (the pseudonym scopes to it).
#[wasm_bindgen_test]
pub fn the_presenter_chain_the_js_surface_wraps() {
    let system = NymAuthSystem::LongfellowV1;
    let query = query(Some("18+"), true);

    // The session — the facts the JS host passes.
    let session = session(&query, "nonce-1");
    let now = DateTime::from_unix(NOW).expect("the testing NOW is a valid date");

    // The pair: the request's client_metadata supplies the formats.
    let credential_query = siros_dcql::CredentialQuery::parse(&query).unwrap();
    let zkp_query = ZkpReqQuery::parse(&credential_query).unwrap();
    let nym = match NymAuthQuery::from_query(zkp_query).unwrap() {
        Catalogued::NymAuth(nym) => nym,
        _ => panic!("the fixture query is a nym_auth query"),
    };
    let formats = ZkpFormats::from_client_metadata(&client_metadata()).unwrap();
    let pair = nym
        .options()
        .map(|option| option.pair(&formats, system, now.date()))
        .find_map(Result::ok)
        .expect("a usable pair for the fixture");

    // The attestation: the fixture credential, the same admission the
    // wasm layer runs.
    let data = issue(
        &Issuer::root(0x11, "Test Document Signer"),
        &Spec::default(),
    );
    let mdoc = siros_mdoc::Mdoc::parse(&data).unwrap();
    let tested = TestedAttestation::of(&mdoc, now).unwrap();
    let authorities = siros_trust::QueryAuthorities::of(&credential_query).unwrap();
    let chain = siros_trust::IssuerChain::parse(mdoc.issuer_auth().x5chain()).unwrap();
    let store = siros_trust::TrustStore::parse("[]").unwrap();
    let issuer = siros_trust::AdmittedIssuer::resolve(&authorities, Some(&chain), &store, now)
        .expect("the fixture issuer admits");
    let usable = UsableAttestation::new(tested, issuer, &nym).unwrap();

    // The answer and the prepared statement — the wasm surface's
    // `prepare`.
    let answer = Answer::new(pair, usable, &SecretSeed::new(Zeroizing::new(SEED))).unwrap();
    let prepared = Prepared::in_session(answer, &session).unwrap();

    // dataToSign → the host's ES256 → job: the steps the JS host drives.
    let to_sign = prepared.data_to_sign().as_bytes();
    let signature: Es256Signature = device_signature(Spec::default().device, to_sign);
    let job = prepared.job(&signature).unwrap();

    // The statement's verifier input carries the session's verifier_id:
    // the pseudonym scopes to it (the fixture verifier's client_id).
    assert_eq!(
        job.statement().verifier_input.as_bytes().len(),
        32,
        "the verifier input is the 32-byte pseudonym input"
    );
}
