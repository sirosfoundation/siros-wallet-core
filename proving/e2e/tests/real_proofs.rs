//! G1 and G5 with real proofs, per system: the request is answered on the plan's path, the device
//! key signs, the backend builds the witness and proves, the presenter assembles, and the
//! Verifier with the same backend accepts. Tampered inputs are refused with the code the system rulebook's Section 9
//! gives.
//!
//! Slow, so ignored. `proving/scripts/fetch-artifacts.sh`, then
//! `cargo test --release --manifest-path proving/Cargo.toml -- --ignored`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_trust::Certificate;
use siros_zkp_backend_longfellow::{LongfellowProver, LongfellowVerifier};
use siros_zkp_backend_vega::VegaNymAuth;
use siros_zkp_req::ZkProof;
use siros_zkp_req_nym_auth::prover::{
    NymAuthProofVerifier, NymAuthProver, ProofFailure, Statement,
};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{
    client_metadata, device_signature, expected_pseudonym, issue, prepared, query, session,
    verified_request, Issuer, Spec, CLIENT_ID, NONCE, NOW, SEED,
};
use siros_zkp_req_nym_auth::verifier_id::PseudonymValue;
use siros_zkp_req_nym_auth::verify::{verify, Rejection, Tolerance, Verified, VerifyInput};

fn tolerance() -> Tolerance {
    Tolerance::seconds(60, 600)
}

fn artifact(path: &str) -> Vec<u8> {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../artifacts")
        .join(path);
    std::fs::read(&file).unwrap_or_else(|e| {
        panic!(
            "{}: {e}; run proving/scripts/fetch-artifacts.sh",
            file.display()
        )
    })
}

/// What one system needs, and what the Verifier must answer when it checks the proof against
/// another session's statement.
struct Backend<'a> {
    system: NymAuthSystem,
    prover: &'a dyn NymAuthProver,
    verifier: &'a dyn NymAuthProofVerifier,
    other_session: ProofFailure,
}

/// A presentation, and what the Verifier needs besides it.
struct Proved {
    query: Value,
    trust_anchors: [Certificate; 1],
    statement: Statement,
    zk_proof: ZkProof,
    presentation: Vec<u8>,
}

/// Answers and proves the query with `age_check` `range`, in the session of `NONCE`.
fn prove(backend: &Backend<'_>, range: &str) -> Proved {
    let ds = Issuer::root(0x11, "Test Document Signer");
    let data = issue(&ds, &Spec::default());
    let query = query(Some(range), true);
    let request = verified_request(&query, NONCE);
    let prepared = prepared(backend.system, &query, &data, &SEED, &request).unwrap();
    let signature = device_signature(Spec::default().device, prepared.data_to_sign().as_bytes());
    let job = prepared.job(&signature).unwrap();
    let output = backend.prover.prove(&job).unwrap();
    assert_eq!(
        output.pseudonym,
        PseudonymValue::new(expected_pseudonym(&SEED, CLIENT_ID))
    );
    Proved {
        presentation: prepared.assemble(&output).unwrap().encode(),
        query,
        trust_anchors: [Certificate::parse(&ds.der).unwrap()],
        statement: job.statement().clone(),
        zk_proof: output.zk_proof,
    }
}

/// The Verifier's judgement in the session of `nonce`.
fn verify_in(backend: &Backend<'_>, proved: &Proved, nonce: &str) -> Result<Verified, Rejection> {
    verify(
        &VerifyInput {
            query: &proved.query,
            client_metadata: &client_metadata(),
            session: &session(&proved.query, nonce),
            presentation: &proved.presentation,
            now: DateTime::from_unix(NOW + 5).unwrap(),
            tolerance: tolerance(),
            trust_anchors: &proved.trust_anchors,
        },
        backend.verifier,
    )
}

fn accepted(backend: &Backend<'_>, proved: &Proved) {
    let verified = verify_in(backend, proved, NONCE).unwrap();
    assert_eq!(verified.system, backend.system);
    let pseudonym = expected_pseudonym(&SEED, CLIENT_ID).to_vec();
    assert!(verified
        .results
        .iter()
        .any(|(handle, value)| *handle == "nym" && *value == Cbor::Bytes(pseudonym.clone())));
}

fn run(backend: &Backend<'_>) {
    let proved = prove(backend, "18+");
    accepted(backend, &proved);
    assert_eq!(
        verify_in(backend, &proved, "aNotherNonce-0123456789").unwrap_err(),
        Rejection::Proof(backend.other_session)
    );
    let pseudonym = PseudonymValue::new(expected_pseudonym(&SEED, CLIENT_ID));
    let bytes = proved.zk_proof.as_bytes();
    let short = ZkProof::new(bytes[..bytes.len() - 1].to_vec());
    assert_eq!(
        backend
            .verifier
            .verify(&proved.statement, &pseudonym, &short),
        Err(ProofFailure::Encoding)
    );
    // E in year 0000: 0000-10-10 at the proof date 2026-10-09.
    let proved = prove(backend, "0-2025");
    assert_eq!(
        proved.statement.earliest.and_then(|e| e.to_full_date()),
        Some("0000-10-10".to_owned())
    );
    accepted(backend, &proved);
}

/// Longfellow derives every public input from the Verifier's own statement, so a proof for
/// another session fails a circuit: `proof_invalid`.
#[test]
#[ignore = "real proofs: run with --release after proving/scripts/fetch-artifacts.sh"]
fn longfellow() {
    let circuits = artifact("longfellow/circuits.zst");
    let prover = LongfellowProver::load(&circuits).unwrap();
    let verifier = LongfellowVerifier::load(&circuits).unwrap();
    run(&Backend {
        system: NymAuthSystem::LongfellowV1,
        prover: &prover,
        verifier: &verifier,
        other_session: ProofFailure::Invalid,
    });
}

/// Vega's core reports its public values; another session's e2 differs from them: test 3,
/// `public_input`.
#[test]
#[ignore = "real proofs: run with --release after proving/scripts/fetch-artifacts.sh"]
fn vega() {
    let keys = VegaNymAuth::load(&artifact("vega/shapes.zst")).unwrap();
    run(&Backend {
        system: NymAuthSystem::VegaV1,
        prover: &keys,
        verifier: &keys,
        other_session: ProofFailure::PublicInput,
    });
}
