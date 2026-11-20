//! The OpenMLS provider's round-trip: the group lifecycle and the
//! application-message encryption, driven through the WMP wire shapes
//! (base64url members, the provider's own group ids).
//!
//! The oracle: OpenMLS's own tests (RFC 9420 vectors) prove the library;
//! this suite pins the *provider's* mapping onto it — the WMP wire forms
//! (base64url in, base64url out), the group-id minting, the epoch answers
//! — not the cryptography.

use wmp_core::mls::MlsProvider;
use wmp_mls::OpenMlsProvider;

/// base64url decode (the test-side twin of the provider's own codec — the
/// assertions parse what the provider serialized).
fn decode(encoded: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET.iter().position(|&a| a == byte).unwrap() as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

#[test]
fn a_key_package_serializes_the_wmp_wire_shape() {
    let provider = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    // 0x0001 (the MUST suite) and 0x0002 (the SHOULD) both build.
    for suite in [0x0001, 0x0002] {
        let package = provider
            .generate_key_package(suite)
            .expect("the key package");
        assert!(
            package.id.starts_with("kp-"),
            "the id is minted: {}",
            package.id
        );
        assert_eq!(package.cipher_suite, suite);
        // The wire form: base64url, decodes to non-empty TLS bytes.
        let bytes = decode(&package.key_package);
        assert!(!bytes.is_empty(), "the package carries bytes");
    }
    // An unknown suite refuses -32602 (Invalid params).
    let refused = provider
        .generate_key_package(0x0099)
        .expect_err("an unknown suite refuses");
    assert_eq!(refused.to_rpc().code, wmp_core::error::ERR_INVALID_PARAMS);
}

#[test]
fn a_created_group_mints_and_holds() {
    let provider = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let (group_id, welcomes) = provider.create_group(0x0001, &[]).expect("the create");
    assert!(
        group_id.starts_with("grp-"),
        "the id is minted: {}",
        group_id
    );
    assert!(
        welcomes.is_empty(),
        "the participant-less create answers no welcomes"
    );
    // A create WITH participants is the add flow's shape (their packages
    // arrive) — the create refuses the not-yet-wired form, never mints
    // placeholder Welcomes.
    let refused = provider
        .create_group(0x0001, &["wallet-b".to_owned()])
        .expect_err("a create naming participants refuses until the packages ride");
    assert_eq!(refused.to_rpc().code, wmp_core::error::ERR_INTERNAL_ERROR);
}

#[test]
fn an_unknown_group_refuses_the_mls_error() {
    let provider = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let add = provider.add_member("grp-none", "kp").map(|_| ());
    let update = provider.self_update("grp-none").map(|_| ());
    let encrypt = provider.encrypt("grp-none", b"hi").map(|_| ());
    let decrypt = provider.decrypt("grp-none", "ciphertext").map(|_| ());
    for result in [add, update, encrypt, decrypt] {
        let err = result.expect_err("an unknown group refuses");
        assert_eq!(err.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);
    }
}

#[test]
fn a_member_set_grows_and_shrinks_by_commit() {
    // The lifecycle on one group: the creator adds a member by their key
    // package, removes them, self-updates — every step answering a
    // serializable commit (the merge the provider owns), the epochs
    // advancing.
    let a = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("the provider");
    let (group_id, _) = a.create_group(0x0001, &[]).expect("the create");

    // B joins by their key package (the add flow).
    let package = b.generate_key_package(0x0001).expect("B's package");
    let (commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("the add");
    assert!(!decode(&commit).is_empty(), "the add answers a commit");
    assert!(!decode(&welcome).is_empty(), "the add answers a welcome");

    // B joins by processing the Welcome (their own provider holds their
    // private keys).
    let (b_group, _epoch) = b.process_welcome(&welcome).expect("B joins");
    assert!(b_group.starts_with("grp-"), "the join mints B's group id");

    // A self-update (the key-rotation step, spec 3.5) — B's group processes
    // A's commit and stays decryptable after it (spec 3.4's counterpart).
    let update = a.self_update(&group_id).expect("the update");
    assert!(!decode(&update).is_empty(), "the update answers a commit");
    let after_update = b
        .process_commit(&b_group, &update)
        .expect("B processes the rotation");
    assert!(
        after_update >= 1,
        "the rotation advances the epoch: {after_update}"
    );

    // The removal: A removes B, the commit answers.
    let removal = a.remove_member(&group_id, "wallet-b").expect("the removal");
    assert!(!decode(&removal).is_empty(), "the removal answers a commit");
}

#[test]
fn a_message_round_trips_across_members() {
    // The encrypted hello world (the ladder's level-3 step 3.3), the real
    // cross-wallet shape: A creates, adds B by B's key package, B joins by
    // the Welcome — then A encrypts and B DECRYPTS (MLS ratchets: A's own
    // provider cannot decrypt its own message; the recipient's answers).
    let a = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("the provider");
    let (group_id, _) = a.create_group(0x0001, &[]).expect("the create");
    let package = b.generate_key_package(0x0001).expect("B's package");
    let (_commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("the add");
    let (b_group, _epoch) = b.process_welcome(&welcome).expect("B joins");

    let plaintext = b"hello group, encrypted end to end".to_vec();
    let (ciphertext, encrypt_epoch) = a.encrypt(&group_id, &plaintext).expect("the encrypt");
    // The wire form: base64url bytes, and NOT the plaintext in the clear.
    let ciphertext_bytes = decode(&ciphertext);
    assert!(!ciphertext_bytes.is_empty());
    assert!(
        !ciphertext_bytes
            .windows(plaintext.len())
            .any(|w| w == plaintext),
        "the ciphertext does not carry the plaintext in the clear"
    );
    // A's own provider cannot decrypt its own message (the ratchet).
    let own = a.decrypt(&group_id, &ciphertext);
    assert!(own.is_err(), "own ciphertext does not decrypt");

    // B decrypts: the plaintext answers.
    let (decrypted, _epoch) = b.decrypt(&b_group, &ciphertext).expect("the decrypt");
    assert_eq!(decrypted, plaintext, "the round trip answers the plaintext");
    assert!(
        encrypt_epoch >= 1,
        "the encrypt named its epoch: {encrypt_epoch}"
    );
}

#[test]
fn a_welcome_for_another_member_refuses_fail_closed() {
    // A Welcome encrypted to B's package, offered to C's provider: C holds
    // no matching key, the join refuses (never silently accepts).
    let a = OpenMlsProvider::for_identity("wallet-a").expect("the provider");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("the provider");
    let c = OpenMlsProvider::for_identity("wallet-c").expect("the provider");
    let (group_id, _) = a.create_group(0x0001, &[]).expect("the create");
    let package = b.generate_key_package(0x0001).expect("B's package");
    let (_commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("the add");
    let err = c
        .process_welcome(&welcome)
        .expect_err("C cannot join B's Welcome");
    assert_eq!(err.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);
}
