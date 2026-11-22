//! The FFI surface's e2e (the wmp-mls spec): the same functions the
//! Kotlin/Swift wallets drive, round-tripped in Rust — a member creates
//! a group, a second member joins by the Welcome, and the two
//! encrypt/decrypt to each other through the epoch keys.
//!
//! The engine's own handler surface (the `wmp.mls.*` methods) rides
//! `mls_e2e.rs`; this tests the SDK surface the wallets embed.

use engine_adapter_sdk::mls::{MlsException, WmpMls};

/// The X25519 suite (0x0001, the MUST).
const SUITE: i64 = 1;

fn member(identity: &str) -> WmpMls {
    WmpMls::new(identity.to_owned()).expect("the provider mints")
}

#[test]
fn a_create_adds_a_member_who_joins_and_reads_the_epoch() {
    let alice = member("alice");
    let bob = member("bob");

    // The group (spec §3.1): the create mints alone, epoch 0.
    let group = alice.create_group(SUITE).expect("the group mints");
    assert_eq!(group.epoch, 0);
    // The id: the group's own MLS GroupId (base64url), NOT a provider
    // mint — the same id the joiner's process_welcome answers.
    assert!(!group.group_id.is_empty() && !group.group_id.starts_with("grp-"));

    // Bob's KeyPackage (spec §2.3) — the add flow's input.
    let package = bob.generate_key_package(SUITE).expect("the package mints");
    assert!(package.key_package.len() > 32);
    assert!(package.id.starts_with("kp-"));

    // The add (spec §3.3): the commit merged into Alice's group, the
    // Welcome for Bob.
    let staged = alice
        .add_member(group.group_id.clone(), package.key_package)
        .expect("the add stages");
    assert!(!staged.commit.is_empty());
    assert!(!staged.welcome.is_empty());

    // Bob joins (spec §3.2): the Welcome processes, the epoch answers.
    let joined = bob
        .process_welcome(staged.welcome)
        .expect("the welcome joins");
    assert!(joined.epoch >= 1, "the join answers the post-add epoch");
}

#[test]
fn two_members_round_trip_a_message() {
    let alice = member("alice");
    let bob = member("bob");
    let group = alice.create_group(SUITE).expect("the group mints");
    let package = bob.generate_key_package(SUITE).expect("the package mints");
    let staged = alice
        .add_member(group.group_id.clone(), package.key_package)
        .expect("the add stages");
    bob.process_welcome(staged.welcome)
        .expect("the welcome joins");

    // The message (spec §4.1): Alice encrypts to the epoch key, Bob
    // decrypts. MLS ratchets: Alice's own provider refuses her own
    // ciphertext (the recipient's provider answers).
    let plaintext = b"hello from alice, under the epoch key".to_vec();
    let sent = alice
        .encrypt(group.group_id.clone(), plaintext.clone())
        .expect("the message encrypts");
    assert!(sent.epoch >= 1);
    assert!(!sent.ciphertext.is_empty());

    let received = bob
        .decrypt(group.group_id.clone(), sent.ciphertext.clone())
        .expect("the message decrypts");
    assert_eq!(received.plaintext, plaintext);
    assert_eq!(received.epoch, sent.epoch);

    // Her own ciphertext back to herself refuses (MLS ratchets).
    let own = alice.decrypt(group.group_id, sent.ciphertext);
    assert!(own.is_err(), "own ciphertexts do not decrypt");
}

#[test]
fn a_removal_excludes_the_member() {
    let alice = member("alice");
    let bob = member("bob");
    let group = alice.create_group(SUITE).expect("the group mints");
    let package = bob.generate_key_package(SUITE).expect("the package mints");
    let staged = alice
        .add_member(group.group_id.clone(), package.key_package)
        .expect("the add stages");
    let joined = bob
        .process_welcome(staged.welcome)
        .expect("the welcome joins");

    // The removal (spec §3.4): the commit cryptographically excludes Bob;
    // the group advanced an epoch (his provider needs the commit to keep
    // following, but the NEXT message will not decrypt for him).
    let commit = alice
        .remove_member(group.group_id.clone(), "bob".to_owned())
        .expect("the removal stages");
    let advanced = bob
        .process_commit(joined.group_id.clone(), commit)
        .expect("the commit processes");
    assert!(advanced > joined.epoch, "the epoch advanced");
}

#[test]
fn unknown_group_operations_refuse() {
    let alice = member("alice");
    match alice.encrypt("grp-none".to_owned(), vec![1, 2, 3]) {
        Err(MlsException::Refused(detail)) => {
            assert!(
                detail.contains("unknown group"),
                "the refusal names the cause: {detail}"
            );
        }
        other => panic!("the unknown group refuses, got {other:?}"),
    }
    // An empty identity mints fine (the member names itself nothing — MLS
    // basic credentials carry it); NOT a refusal surface. The guard here
    // is the constructor's fallibility itself (a keypair failure refuses).
    let _ = WmpMls::new(String::new()).expect("an empty identity mints");
}

#[test]
fn the_identity_answers_its_constructor() {
    let alice = member("alice@example");
    assert_eq!(alice.identity(), "alice@example");
}
