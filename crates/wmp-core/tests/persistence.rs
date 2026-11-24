//! The file-backed stores (#109): the sessions and invitations survive a
//! restart (a new `FileSessionStore::open` on the same path) — the
//! property the engine's `ENGINE_PERSISTENCE_PATH` buys.

use wmp_core::invitation::{FileInvitationStore, Invitation, InvitationStore as _};
use wmp_core::session::{FileSessionStore, Session, SessionStore as _};
use wmp_core::types::SecurityMode;

fn temp_path(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("wmp-core-persistence-test-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name).to_str().unwrap().to_owned()
}

#[test]
fn sessions_survive_a_restart() {
    let path = temp_path("sessions");

    // Create + mutate.
    {
        let store = FileSessionStore::open(&path);
        store
            .create(Session {
                id: "ses-persist-1".to_owned(),
                participants: vec!["alice".to_owned()],
                security: SecurityMode::default(),
                ..Default::default()
            })
            .unwrap();
        store
            .create(Session {
                id: "ses-persist-2".to_owned(),
                ..Default::default()
            })
            .unwrap();
        store.delete("ses-persist-2").unwrap();
    }

    // Reopen: the state survived.
    let reopened = FileSessionStore::open(&path);
    assert!(reopened.get("ses-persist-1").is_some(), "the live session");
    assert!(
        reopened.get("ses-persist-2").is_none(),
        "the deleted session"
    );
}

#[test]
fn invitations_survive_a_restart() {
    let path = temp_path("invitations");

    // Put.
    {
        let store = FileInvitationStore::open(&path);
        store
            .put(
                "nonce-persist-1",
                &Invitation {
                    provider: "https://relay.example.com".to_owned(),
                    sender: "x509:san:dns:alice.example.com".to_owned(),
                    nonce: "nonce-persist-1".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    // Reopen: the nonce survived.
    let reopened = FileInvitationStore::open(&path);
    let inv = reopened
        .consume(999_999_999_999, "nonce-persist-1")
        .expect("the invitation survived the restart");
    assert_eq!(inv.nonce, "nonce-persist-1");
    assert!(
        reopened
            .consume(999_999_999_999, "nonce-persist-1")
            .is_none(),
        "the consume was single-use"
    );
}
