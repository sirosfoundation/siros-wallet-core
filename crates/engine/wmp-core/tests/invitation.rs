//! Invitations: the nonce, the `wmp://` and HTTPS URIs, RFC 3339 expiry and
//! the nonce store.

use wmp_core::invitation::{
    new_invitation, parse_invitation_uri, Invitation, InvitationError, InvitationStore,
    MemoryInvitationStore,
};
use wmp_core::sessionservice::EntropyFn;

fn entropy() -> EntropyFn {
    std::sync::Arc::new(|bytes: &mut [u8]| {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        true
    })
}

/// An invitation that expires at `expires_at`.
fn expiring(expires_at: &str) -> Invitation {
    Invitation {
        expires_at: Some(expires_at.to_owned()),
        ..Invitation::default()
    }
}

#[test]
fn nonce_round_trips_through_the_uri() {
    let inv = new_invitation(
        "x509:san:dns:example.com",
        "alice",
        600,
        1_730_000_000,
        &entropy(),
    )
    .expect("invitation");
    assert!(inv.nonce.starts_with("inv-"));
    let uri = inv.uri().expect("uri");
    assert!(uri.starts_with("wmp://invite?data="));
    let back = parse_invitation_uri(&uri).expect("parse");
    assert_eq!(back.nonce, inv.nonce);
    assert_eq!(back.provider, inv.provider);
    assert_eq!(back.sender, inv.sender);
}

#[test]
fn https_fallback_needs_a_domain() {
    let inv = Invitation {
        provider: "did:key:z6Mk".to_owned(),
        ..Invitation::default()
    };
    assert!(matches!(inv.https_uri(), Err(InvitationError::NoDomain(_))));
    let inv = Invitation {
        provider: "x509:san:dns:example.com".to_owned(),
        ..Invitation::default()
    };
    let uri = inv.https_uri().expect("uri");
    assert!(uri.starts_with("https://example.com/wmp/invite#"));
    assert!(parse_invitation_uri(&uri).is_ok());
}

#[test]
fn expiry_reads_rfc3339_and_refuses_the_unreadable() {
    let inv = expiring("2024-05-01T00:00:00Z");
    // 2024-05-01T00:00:00Z is 1714521600.
    assert!(inv.is_expired(1_714_521_601));
    assert!(!inv.is_expired(1_714_521_599));
    let unreadable = expiring("tomorrow");
    assert!(unreadable.is_expired(0));
    let unbounded = Invitation::default();
    assert!(!unbounded.is_expired(1_000_000_000));
}

#[test]
fn the_nonce_store_consumes_once_and_cleans_up() {
    let store = MemoryInvitationStore::new();
    let inv = new_invitation("p", "s", 60, 1_730_000_000, &entropy()).expect("invitation");
    store.put(&inv.nonce, &inv).expect("put");
    assert!(store.put(&inv.nonce, &inv).is_err());
    assert!(store.consume(1_730_000_010, &inv.nonce).is_some());
    assert!(store.consume(1_730_000_010, &inv.nonce).is_none());

    let expired = new_invitation("p", "s", 1, 1_730_000_000, &entropy()).expect("invitation");
    store.put(&expired.nonce, &expired).expect("put");
    assert!(store.consume(1_730_000_100, &expired.nonce).is_none());
    assert_eq!(store.cleanup(1_730_000_100).expect("cleanup"), 0);
}

/// An expiry read as `t` is expired exactly from `t + 1` on; an unreadable
/// one is expired at every instant, `i64::MIN` included.
#[test]
fn rfc3339_conversions_agree() {
    // 2024-05-01T00:00:00Z reads as 1714521600.
    let may_first = expiring("2024-05-01T00:00:00Z");
    assert!(!may_first.is_expired(1_714_521_600));
    assert!(may_first.is_expired(1_714_521_601));
    // 1970-01-01T00:00:00Z reads as 0.
    let epoch = expiring("1970-01-01T00:00:00Z");
    assert!(!epoch.is_expired(0));
    assert!(epoch.is_expired(1));
    // 1714521600 writes as 2024-05-01T00:00:00Z.
    let written = new_invitation("p", "s", 0, 1_714_521_600, &entropy()).expect("invitation");
    assert_eq!(written.expires_at.as_deref(), Some("2024-05-01T00:00:00Z"));
    // A date without a time does not read.
    assert!(expiring("2024-05-01").is_expired(i64::MIN));
}
