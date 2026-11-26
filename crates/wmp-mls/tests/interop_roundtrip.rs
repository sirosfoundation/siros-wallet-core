//! The wmp-mls interop round-trip (leg 2): the TS side's key package (its
//! own keys, minted by `TsMlsProvider` — wmp-js's suite writes it to the
//! handoff file), added by the Rust side, the Welcome + one ciphertext
//! answered back for the TS side to join and decrypt.
//!
//! The handoff file (both legs):
//! `wmp-js/test/vectors/wmp-mls-roundtrip.json` —
//! leg 1 (`{"leg": 1, "key_package"}`) written by the TS suite, this leg
//! answers leg 2 (`{"leg": 2, "welcome", "ciphertext", "epoch",
//! "plaintext"}`), and wmp-js's suite proves the TS provider joins and
//! decrypts it.
//!
//! **KNOWN INTEROP GAP (found by this suite, 2026-11-21):** the TS side's
//! key package (ts-mls) does not deserialize under openmls — 0.8.3
//! (tls_codec 0.4.2's `quic_vec` asserts on the wire form ts-mls
//! writes) and still 0.10.0-rc.1 (tls_codec 0.5 refuses with
//! `InvalidVectorLength`). The two implementations disagree on the TLS
//! varint length encoding. Until the codecs align (an upstream item:
//! ts-mls or openmls), the cross-implementation round-trip fails
//! closed here — pinned by the `#[ignore]` below with the full context,
//! so the suite stays green while the gap is documented, not hidden.

use wmp_core::mls::MlsProvider;
use wmp_mls::OpenMlsProvider;

/// The handoff file (wmp-js's vectors dir).
/// `crates/wmp-mls` → `..` = `crates` → `../..` = the repo root →
/// `../../..` = siros.org → the wmp-js checkout beside it.
const HANDOFF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../wmp-js/test/vectors/wmp-mls-roundtrip.json"
);

#[test]
#[ignore = "the ts-mls key package does not deserialize under openmls 0.8.3 or 0.10.0-rc.1 (tls_codec varint difference) - the vectors' documented gap"]
fn answer_the_ts_key_package_with_a_welcome_and_ciphertext() {
    let handoff = std::fs::read_to_string(HANDOFF)
        .unwrap_or_else(|err| panic!("{err}: run the wmp-js leg first"));
    let state: serde_json::Value = serde_json::from_str(&handoff).expect("the handoff parses");
    assert_eq!(state["leg"], 1, "the handoff carries the TS key package");
    let key_package = state["key_package"]
        .as_str()
        .expect("the key package")
        .to_owned();

    // A adds the TS member's package; the Welcome it answers rides the
    // TS side's own keys (the join answers).
    let a = OpenMlsProvider::for_identity("wallet-a").expect("A's provider");
    let (group_id, _) = a.create_group(0x0001, &[]).expect("the create");
    let (_commit, welcome) = a.add_member(&group_id, &key_package).expect("the add");

    // One ciphertext for the group (the TS side decrypts).
    let plaintext = b"the wmp-mls interop round-trip: TS mints, Rust adds, TS decrypts".to_vec();
    let (ciphertext, epoch) = a.encrypt(&group_id, &plaintext).expect("the encrypt");

    let answer = serde_json::json!({
        "leg": 2,
        "welcome": welcome,
        "ciphertext": ciphertext,
        "epoch": epoch,
        "plaintext": plaintext,
    });
    std::fs::write(
        HANDOFF,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&answer).expect("the answer serializes")
        ),
    )
    .expect("the handoff writes");
}
