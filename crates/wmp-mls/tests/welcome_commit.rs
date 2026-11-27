//! The join's commit discipline (issue #127): a Welcome commits a
//! group only when it may. The expected-group refusal leaves **nothing**
//! in the provider's map — a Welcome for group B processed under a
//! declaration for group A must not leave B stated — and the staged
//! split holds the join uncommitted between the caller's own checks and
//! the commit.
//!
//! The oracle: the provider's own map — a group that was never
//! committed answers `unknown group` on every operation, and the group
//! the Welcome actually names joins cleanly once the caller declares it
//! truthfully.

use wmp_core::mls::MlsProvider;
use wmp_mls::OpenMlsProvider;

/// A adds B to a freshly created 0x0001 group; the Welcome answers.
fn welcome_for_b(a: &OpenMlsProvider, b: &OpenMlsProvider) -> (String, String) {
    let (group_id, _) = a.create_group(0x0001, &[]).expect("A creates the group");
    let package = b.generate_key_package(0x0001).expect("B's package");
    let (_commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("A adds B");
    (group_id, welcome)
}

/// The misdelivery refusal: the Welcome names its own group, the
/// declaration names another, and the join refuses — both ids in the
/// refusal's data — committing nothing: the provider's map holds no
/// group at all. The Welcome itself is spent (MLS consumed its key
/// material at the staging — the library's own rule), so the clean
/// join after the refusal rides a fresh package and a fresh add.
#[test]
fn a_welcome_for_another_group_refuses_and_commits_nothing() {
    let a = OpenMlsProvider::for_identity("wallet-a").expect("A mints");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("B mints");
    let (group_id, welcome) = welcome_for_b(&a, &b);
    // The declaration the misdelivery carries: another group's id.
    let (other_id, _) = a
        .create_group(0x0001, &[])
        .expect("A creates the second group");
    assert_ne!(group_id, other_id, "two groups mint two ids");

    let refused = b
        .process_welcome_for_group(&welcome, &other_id)
        .expect_err("the misdelivered Welcome refuses");
    assert_eq!(refused.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);
    let data = refused
        .to_rpc()
        .data
        .expect("the refusal names the mismatch");
    let data: serde_json::Value =
        serde_json::from_str(data.get()).expect("the refusal data is JSON");
    assert_eq!(
        data.get("expected").and_then(|v| v.as_str()),
        Some(other_id.as_str()),
        "the refusal names the declared group"
    );
    assert_eq!(
        data.get("actual").and_then(|v| v.as_str()),
        Some(group_id.as_str()),
        "the refusal names the Welcome's own group"
    );

    // Nothing committed: every operation on either id — the Welcome's
    // own group and the one the caller declared — answers unknown
    // group: the provider's map is empty after the refusal.
    for id in [&group_id, &other_id] {
        let missing = b
            .encrypt(id, b"probe")
            .expect_err("the refused join committed nothing");
        assert_eq!(missing.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);
    }

    // The refusal is not sticky: the group joins cleanly once declared
    // truthfully. A fresh package (the misdelivery spent the old one's
    // key material — MLS's own rule), and B's unjoined epoch-1 leaf
    // removed first: the package carries the member's ONE configured
    // signer (issue #127's fix — the duplicate-signature-key refusal
    // openmls answers here is that binding holding), so the re-add
    // needs the leaf the first add committed gone.
    let package = b.generate_key_package(0x0001).expect("B's fresh package");
    let _removal = a
        .remove_member(&group_id, "wallet-b")
        .expect("A removes the unjoined leaf");
    let (_commit, welcome) = a
        .add_member(&group_id, &package.key_package)
        .expect("A re-adds B");
    let (joined, _epoch) = b
        .process_welcome_for_group(&welcome, &group_id)
        .expect("the truthful declaration joins");
    assert_eq!(joined, group_id, "the join answers the Welcome's own group");
}

/// The staged split: the join held between `stage_welcome` and
/// `commit_staged` commits nothing on its own — the group answers
/// nothing until the commit, then answers everything.
#[test]
fn the_staged_split_holds_the_join_uncommitted() {
    let a = OpenMlsProvider::for_identity("wallet-a").expect("A mints");
    let b = OpenMlsProvider::for_identity("wallet-b").expect("B mints");
    let (group_id, welcome) = welcome_for_b(&a, &b);

    let (staged, staged_id) = b.stage_welcome(&welcome).expect("the Welcome stages");
    assert_eq!(staged_id, group_id, "the staged id is the Welcome's own");
    // Held: the group is not in the provider's map yet.
    let missing = b
        .encrypt(&group_id, b"probe")
        .expect_err("the staged join commits nothing");
    assert_eq!(missing.to_rpc().code, wmp_core::error::ERR_MLS_ERROR);

    // Committed: the group answers the round trip.
    let (joined, _epoch) = b.commit_staged(staged).expect("the commit lands");
    assert_eq!(joined, group_id, "the commit answers the staged id");
    let plaintext = b"held between the stage and the commit".to_vec();
    let (ciphertext, _) = a.encrypt(&group_id, &plaintext).expect("A encrypts");
    let (decrypted, _) = b.decrypt(&joined, &ciphertext).expect("B decrypts");
    assert_eq!(decrypted, plaintext, "the round trip answers the plaintext");
}
