//! The principal's owner key and its TAC permissions.

use wmp_core::principal::Principal;

#[test]
fn key_escapes_both_parts() {
    let p = Principal::new("user@example.com", "acme");
    assert_eq!(p.key(), "acme/user%40example.com");
}

#[test]
fn empty_tenant_leaves_the_leading_separator() {
    let p = Principal::new("alice", "");
    assert_eq!(p.key(), "/alice");
}

#[test]
fn anonymous_principal_owns_nothing() {
    let p = Principal::default();
    assert_eq!(p.key(), "");
    assert!(!p.is_authenticated());
    assert!(Principal::new("alice", "acme").is_authenticated());
}

#[test]
fn tac_grants_carry_their_permission_characters() {
    // The Go engine's TAC model: a string of permission characters,
    // Has / HasAll substring semantics.
    let p = Principal::with_token("alice", "acme", "jti-1", "ri");
    assert!(p.tac_has('r'), "carries read");
    assert!(p.tac_has('i'), "carries insert");
    assert!(!p.tac_has('w'), "carries not write");
    assert!(p.tac_has_all("ri"));
    assert!(p.tac_has_all("r"));
    assert!(!p.tac_has_all("rw"), "write missing");
    // The empty TAC grants nothing — but see the flow-start gate:
    // an empty TAC means legacy auth (no TAC concept), not "no
    // permissions", so the gate does not enforce at all.
    let legacy = Principal::new("alice", "acme");
    assert!(!legacy.tac_has('r'));
}

#[test]
fn distinct_principals_never_share_a_key() {
    // The escape is injective on each part and the separator cannot occur
    // unescaped, so no two distinct principals collide.
    let a = Principal::new("a/b", "t");
    let b = Principal::new("b", "t/a");
    assert_ne!(a.key(), b.key());
    assert_eq!(a.key(), "t/a%2Fb");
    assert_eq!(b.key(), "t%2Fa/b");
}
