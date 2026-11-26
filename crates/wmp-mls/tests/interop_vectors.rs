//! The wmp-js interop vectors: the Rust-side fixtures a TS implementation
//! (`TsMlsProvider`, ts-mls) must join and decrypt — the two
//! implementations agreeing on the RFC 9420 wire contract through WMP's
//! base64url shapes.
//!
//! Writing the vectors (a small `wmp/vectors`-style JSON file, the same
//! convention wmp-core's conformance suite uses):
//!
//! ```text
//! cargo test -p wmp-mls --test interop_vectors -- --nocapture write
//! ```
//!
//! Then the TS side (wmp-js) runs `TsMlsProvider.processWelcome` on the
//! Welcome and `decrypt` on the ciphertext — the reciprocal suite.

use std::io::Write as _;

use wmp_core::mls::MlsProvider;
use wmp_mls::OpenMlsProvider;

/// The vectors file (the wmp-mls suite's fixture path).
const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wmp-mls-interop.json"
);

#[test]
fn write_the_interop_vectors() {
    // A creates a group; B's package joins it. The Welcome and one
    // ciphertext land in the vectors for the TS side.
    let a = OpenMlsProvider::for_identity("wallet-a").expect("A's provider");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("B's provider");

    let (group_id, _) = a.create_group(0x0001, &[]).expect("the create");
    let package = b.generate_key_package(0x0001).expect("B's package");
    let (_commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("the add");

    let plaintext = b"the wmp-mls interop vector: A encrypts, TS decrypts".to_vec();
    let (ciphertext, epoch) = a.encrypt(&group_id, &plaintext).expect("the encrypt");

    let vectors = serde_json::json!({
        "version": 1,
        "note": "the wmp-mls interop vectors: A (Rust, openmls 0.10.0-rc.1) mints; the TS implementation joins by the Welcome and decrypts the ciphertext",
        "cipher_suite": 0x0001,
        "welcome": welcome,
        "ciphertext": ciphertext,
        "epoch": epoch,
        "plaintext": plaintext,
    });
    let path = std::path::Path::new(VECTORS);
    std::fs::create_dir_all(path.parent().expect("the vectors dir")).expect("the dir");
    let mut file = std::fs::File::create(path).expect("the vectors file");
    serde_json::to_writer_pretty(&mut file, &vectors).expect("the vectors serialize");
    writeln!(file).expect("the trailing newline");
    println!("wrote {}", VECTORS);
    assert!(!welcome.is_empty());
    assert!(!ciphertext.is_empty());
}
