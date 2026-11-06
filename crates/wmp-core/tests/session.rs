//! The session's owner binding and expiry, and the in-memory store's
//! optional operations.

use wmp_core::session::{MemorySessionStore, Session, SessionStore, StoreError};

fn session(id: &str, expires: Option<i64>) -> Session {
    Session {
        id: id.to_owned(),
        resumption_token: "tok-1".to_owned(),
        expires_at: expires,
        owner: "acme/alice".to_owned(),
        ..Session::default()
    }
}

#[test]
fn owner_binding_never_matches_an_empty_key() {
    let s = session("ses-1", None);
    assert!(!s.owned_by(""));
    assert!(s.owned_by("acme/alice"));
    let unowned = Session::default();
    assert!(!unowned.owned_by(""));
}

#[test]
fn expiry_takes_the_now_argument() {
    let s = session("ses-1", Some(100));
    assert!(!s.is_expired(99));
    assert!(!s.is_expired(100));
    assert!(s.is_expired(101));
    assert!(!session("ses-2", None).is_expired(1_000_000_000));
}

#[test]
fn token_rotation_is_single_use_and_checked() {
    let store = MemorySessionStore::new();
    store.create(session("ses-1", None)).expect("create");
    // Wrong old token, empty old token, and same-as-old new token.
    assert_eq!(
        store.rotate_resumption_token(0, "ses-1", "wrong", "tok-2", None),
        Err(StoreError::TokenMismatch)
    );
    assert_eq!(
        store.rotate_resumption_token(0, "ses-1", "", "tok-2", None),
        Err(StoreError::TokenMismatch)
    );
    assert_eq!(
        store.rotate_resumption_token(0, "ses-1", "tok-1", "tok-1", None),
        Err(StoreError::InvalidNewToken)
    );
    // A good rotation consumes the old token.
    let updated = store
        .rotate_resumption_token(0, "ses-1", "tok-1", "tok-2", Some(500))
        .expect("rotate");
    assert_eq!(updated.resumption_token, "tok-2");
    assert_eq!(updated.resumption_token_expires_at, Some(500));
    assert_eq!(
        store.rotate_resumption_token(0, "ses-1", "tok-1", "tok-3", None),
        Err(StoreError::TokenMismatch)
    );
    // The rotated token expires on its own clock.
    assert_eq!(
        store.rotate_resumption_token(501, "ses-1", "tok-2", "tok-3", None),
        Err(StoreError::TokenExpired)
    );
    let updated = store
        .rotate_resumption_token(499, "ses-1", "tok-2", "tok-3", None)
        .expect("rotate before the token's own expiry");
    assert_eq!(updated.resumption_token, "tok-3");
}

#[test]
fn create_if_absent_and_update_if_present() {
    let store = MemorySessionStore::new();
    store
        .create_if_absent(session("ses-1", None))
        .expect("first");
    assert_eq!(
        store.create_if_absent(session("ses-1", None)),
        Err(StoreError::SessionExists)
    );
    let mut second = session("ses-2", None);
    assert_eq!(
        store.update_if_present(second.clone()),
        Err(StoreError::NoSuchSession)
    );
    second.id = "ses-1".to_owned();
    store.update_if_present(second).expect("update");
}

#[test]
fn listing_and_cleanup_respect_expiry() {
    let store = MemorySessionStore::new();
    store
        .create(session("ses-live", Some(100)))
        .expect("create");
    store.create(session("ses-dead", Some(10))).expect("create");
    assert_eq!(store.list(50).expect("list").len(), 1);
    assert_eq!(store.list_expired(50).expect("list").len(), 1);
    assert_eq!(store.cleanup(50).expect("cleanup"), 1);
    assert!(store.get("ses-dead").is_none());
}
