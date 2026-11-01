//! G2, a differential check against readdit (readdit-demo `1cf3f26`): `nym-longfellow` and
//! `nym-vega`, the reference code of the system rulebooks' Section 10. `tests/vectors/readdit.json`
//! holds what each computes for a credential of the test issuer, a redirect session and, for
//! Longfellow, a v0.4 presentation; `scripts/readdit-differential` recomputes it from readdit's
//! pinned commit. This crate presents the same credential in the same session and must reach the
//! same values.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use ciborium::value::Value as Ciborium;
use serde_json::{json, Value};
use siros_codec::date::DateTime;
use siros_mdoc::{Mdoc, P256Key};
use siros_oid4vp::ec_jwk_thumbprint;
use siros_zkp_req::ZkProof;
use siros_zkp_req_nym_auth::attestation::TestedAttestation;
use siros_zkp_req_nym_auth::catalogue::MDOC_DOCTYPE;
use siros_zkp_req_nym_auth::presenter::Prepared;
use siros_zkp_req_nym_auth::prover::ProofOutput;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::PseudonymValue;
use support::*;

fn facts() -> Value {
    serde_json::from_str(include_str!("vectors/readdit.json")).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let text = v.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> Value {
    Value::String(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn key(k: &P256Key) -> Value {
    json!([hex(k.x()), hex(k.y())])
}

fn proof_time(facts: &Value) -> DateTime {
    DateTime::parse(facts["inputs"]["proof_time"].as_str().unwrap()).unwrap()
}

/// Each value readdit computed equals this crate's value of the same name, except those
/// `elsewhere` names.
fn assert_agrees(reference: &str, theirs: &Value, ours: &Value, elsewhere: &[&str]) {
    let theirs = theirs.as_object().unwrap();
    assert!(!theirs.is_empty());
    for (name, value) in theirs {
        if !elsewhere.contains(&name.as_str()) {
            assert_eq!(&ours[name], value, "{reference}: {name}");
        }
    }
}

/// The credential as this crate reads it, under readdit's names.
fn our_credential(facts: &Value) -> Value {
    let data = facts["inputs"]["credential"].as_str().unwrap();
    let attestation = match TestedAttestation::of(&Mdoc::parse(data).unwrap(), proof_time(facts)) {
        Ok(attestation) => attestation,
        Err(unusable) => panic!("the credential fails its tests: {unusable:?}"),
    };
    let credential = attestation.credential();
    let mdoc = credential.mdoc();
    json!({
        "sig_structure": hex(mdoc.sig_structure().as_bytes()),
        "issuer_signature": hex(mdoc.issuer_signature().as_bytes()),
        "birth_date_item": hex(mdoc.birth_date().bytes()),
        "ssc_item": hex(mdoc.ssc().bytes()),
        "document_signer": hex(credential.signer().certificate().der()),
        "doc_type": MDOC_DOCTYPE,
        "device_key": key(mdoc.device_key()),
        "valid_from": mdoc.valid_from().to_string(),
        "valid_until": mdoc.valid_until().to_string(),
        "birth_date": mdoc.birth_date().value().to_string(),
        "ssc": hex(mdoc.ssc().value().as_bytes()),
        "digests_listed": true,
        "issuer_key": key(credential.signer().key()),
    })
}

/// The presenter's phases up to the prover, on readdit's inputs: the query `nym` with
/// `age_check` `18+`, in readdit's session.
fn prepared_for(facts: &Value, system: NymAuthSystem) -> Prepared {
    let inputs = &facts["inputs"];
    assert_eq!(inputs["client_id"], CLIENT_ID);
    assert_eq!(inputs["nonce"], NONCE);
    assert_eq!(inputs["response_uri"], RESPONSE_URI);
    assert_eq!(unhex(&inputs["secret_seed"]), SEED);
    assert_eq!(proof_time(facts).unix(), NOW);
    assert_eq!(
        unhex(&inputs["jwk_thumbprint"]),
        ec_jwk_thumbprint(&encryption_jwk()).unwrap().as_bytes()
    );
    let query = query(Some("18+"), true);
    let request = verified_request(&query, NONCE);
    let data = inputs["credential"].as_str().unwrap();
    prepared(system, &query, data, &SEED, &request).unwrap()
}

/// A prover's output with the pseudonym readdit computed. The presenter assembles a
/// presentation only with the catalogue's pseudonym, so assembling it shows the two agree.
fn readdit_output(facts: &Value, reference: &str, zk_proof: Vec<u8>) -> ProofOutput {
    let pseudonym = unhex(&facts[reference]["pseudonym"]);
    ProofOutput {
        zk_proof: ZkProof::new(zk_proof),
        pseudonym: PseudonymValue::try_from(pseudonym.as_slice()).unwrap(),
    }
}

/// The credential readdit reads, the session it binds, and the statement and pseudonym it
/// proves, for each system.
#[test]
fn the_wallet_reaches_readdits_values() {
    let facts = facts();
    let credential = our_credential(&facts);
    for (system, reference) in [
        (NymAuthSystem::LongfellowV1, "longfellow"),
        (NymAuthSystem::VegaV1, "vega"),
    ] {
        assert_agrees(reference, &facts[reference]["mdoc"], &credential, &[]);
        let prepared = prepared_for(&facts, system);
        let statement = prepared.statement();
        assert_eq!(statement.system, system);
        assert_eq!(statement.proof_time, proof_time(&facts));
        assert_eq!(
            hex(statement.issuer.certificate().der()),
            credential["document_signer"]
        );
        let ours = json!({
            "session_transcript": hex(statement.session_transcript.as_bytes()),
            "device_message": hex(prepared.data_to_sign().as_bytes()),
            "challenge_digest": hex(statement.challenge_digest.as_bytes()),
            "verifier_input": hex(statement.verifier_input.as_bytes()),
            "issuer_key": key(statement.issuer.key()),
        });
        let elsewhere = ["mdoc", "pseudonym", "presentation_v0_4"];
        assert_agrees(reference, &facts[reference], &ours, &elsewhere);
        let zk_proof = vec![7; system.zk_proof_len().unwrap_or(64)];
        prepared
            .assemble(&readdit_output(&facts, reference, zk_proof))
            .unwrap();
    }
}

fn member<'a>(map: &'a Ciborium, key: &str) -> &'a Ciborium {
    map.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("{key} is missing"))
}

fn keys(map: &Ciborium) -> Vec<&str> {
    let mut keys: Vec<&str> = map
        .as_map()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_text().unwrap())
        .collect();
    keys.sort_unstable();
    keys
}

fn sorted(map: &Ciborium) -> Vec<(String, Ciborium)> {
    let mut entries: Vec<(String, Ciborium)> = map
        .as_map()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_text().unwrap().to_owned(), v.clone()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// The draft presentation of the same parts holds each value of readdit's v0.4 presentation:
/// `issuer_key_set` and `proof_time` move into `Proof.inputs`, readdit's `proof` becomes
/// `Proof.zk_proof`, and `proof_backend` is new. Both are read with ciborium.
#[test]
fn the_draft_presentation_carries_readdits_v0_4_values() {
    let facts = facts();
    let output = readdit_output(&facts, "longfellow", unhex(&facts["inputs"]["proof"]));
    let ours = prepared_for(&facts, NymAuthSystem::LongfellowV1)
        .assemble(&output)
        .unwrap()
        .encode();
    let ours: Ciborium = ciborium::from_reader(ours.as_slice()).unwrap();
    let v0_4 = unhex(&facts["longfellow"]["presentation_v0_4"]);
    let v0_4: Ciborium = ciborium::from_reader(v0_4.as_slice()).unwrap();

    assert_eq!(
        keys(&v0_4),
        [
            "issuer_key_set",
            "proof",
            "proof_time",
            "results",
            "system_id"
        ]
    );
    assert_eq!(
        keys(&ours),
        ["proof", "proof_backend", "results", "system_id"]
    );
    assert_eq!(member(&ours, "system_id"), member(&v0_4, "system_id"));
    assert_eq!(
        member(&ours, "proof_backend").as_text(),
        Some("longfellow-libzk-v1")
    );
    assert_eq!(
        sorted(member(&ours, "results")),
        sorted(member(&v0_4, "results"))
    );

    let proof = member(&ours, "proof").as_bytes().unwrap();
    let proof: Ciborium = ciborium::from_reader(proof.as_slice()).unwrap();
    assert_eq!(keys(&proof), ["inputs", "zk_proof"]);
    assert_eq!(member(&proof, "zk_proof"), member(&v0_4, "proof"));
    let inputs = member(&proof, "inputs");
    assert_eq!(keys(inputs), ["issuer_key_set", "proof_time"]);
    assert_eq!(
        member(inputs, "issuer_key_set"),
        member(&v0_4, "issuer_key_set")
    );
    assert_eq!(member(inputs, "proof_time"), member(&v0_4, "proof_time"));
}
