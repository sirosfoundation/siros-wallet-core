//! The #319 token cut-off gate: the stateless claim check, the store-backed
//! override, and the principal without token claims.

use engine_adapter_server::token::{
    principal_token_is_stale, token_is_stale, NoTokenGate, TokenGate, ValidatedToken,
};
use wmp_core::principal::Principal;

/// A store answering a fixed cut-off.
struct FixedGate(Option<i64>);

impl TokenGate for FixedGate {
    fn auth_invalid_before(&self, _subject: &str, _tenant: &str) -> Option<i64> {
        self.0
    }
}

#[test]
fn a_token_predating_its_stamped_cut_off_is_stale() {
    let token = ValidatedToken {
        subject: "alice".to_owned(),
        tenant: "acme".to_owned(),
        iat: Some(100),
        auth_invalid_before: Some(200),
        ..ValidatedToken::default()
    };
    assert!(token_is_stale(&token, &NoTokenGate));
}

#[test]
fn a_token_after_its_cut_off_is_not_stale() {
    let token = ValidatedToken {
        subject: "alice".to_owned(),
        tenant: "acme".to_owned(),
        iat: Some(300),
        auth_invalid_before: Some(200),
        ..ValidatedToken::default()
    };
    assert!(!token_is_stale(&token, &NoTokenGate));
}

#[test]
fn the_store_backed_gate_overrides_the_stamp() {
    // The stamp passes (iat 300 > stamp 200); the store answers a newer
    // cut-off the token predates.
    let token = ValidatedToken {
        subject: "alice".to_owned(),
        tenant: "acme".to_owned(),
        iat: Some(300),
        auth_invalid_before: Some(200),
        ..ValidatedToken::default()
    };
    let gate = FixedGate(Some(400));
    assert!(
        token_is_stale(&token, &gate),
        "the live cut-off overrides the stamp"
    );
    let gate = FixedGate(Some(100));
    assert!(!token_is_stale(&token, &gate));
}

#[test]
fn a_principal_without_token_claims_is_not_stale() {
    let principal = Principal::new("alice", "acme");
    assert!(!principal_token_is_stale(&principal, &NoTokenGate));
    // With claims, the same rules as the token.
    let stale = Principal::with_token_claims("alice", "acme", "jti-1", "ri", Some(100), Some(200));
    assert!(principal_token_is_stale(&stale, &NoTokenGate));
    let gate = FixedGate(Some(400));
    let fresh_stamp =
        Principal::with_token_claims("alice", "acme", "jti-1", "ri", Some(300), Some(200));
    assert!(principal_token_is_stale(&fresh_stamp, &gate));
}
