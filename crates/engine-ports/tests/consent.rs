//! The presentation consent policy's wire shapes (#525), as the Go
//! stack defines them: the `presentation.dcql_consent_check` mode
//! (`config.DCQLConsentCheckMode.Effective()`, branch
//! `feat/consent-component` of `go-wallet-backend`), the credential
//! selection ask's `AvailableCredential` (the engine's
//! `messages.go` tags), and the default ask an older host inherits.

use engine_ports::{
    AvailableCredential, ConsentCheckMode, ConsentParams, ConsentResult, CredentialSelectionParams,
    Host, HostError, MatchParams, MatchResult, SignParams, SignResult,
};
use serde_json::json;

/// The mode names, as the Go config parses them: `off`, `warn`,
/// `enforce` — and the default: the empty configured value is warn
/// (`Effective()`), so a deployment that configured nothing gets the
/// check that records and proceeds, never the one that skips.
#[test]
fn the_mode_names_parse_with_warn_as_the_default() {
    assert_eq!(ConsentCheckMode::parse("warn"), ConsentCheckMode::Warn);
    assert_eq!(
        ConsentCheckMode::parse("enforce"),
        ConsentCheckMode::Enforce
    );
    assert_eq!(ConsentCheckMode::parse("off"), ConsentCheckMode::Off);
    assert_eq!(
        ConsentCheckMode::parse(""),
        ConsentCheckMode::Warn,
        "the empty configured value is the default, warn"
    );
}

/// The `AvailableCredential` the `awaiting_selection` progress carries,
/// with the Go engine's field names and its omitempty shapes: `id`,
/// `display` (absent when the configuration carries none), `format`,
/// `vct` (absent when empty).
#[test]
fn an_available_credential_carries_the_go_wire_names() {
    let available = AvailableCredential {
        id: "UniversityDegree".to_owned(),
        display: Some(json!({"name": "University Degree", "locale": "en-US"})),
        format: "dc+sd-jwt".to_owned(),
        vct: "https://vc.example/degree".to_owned(),
    };
    let wire: serde_json::Value =
        serde_json::to_value(&available).expect("an available credential serializes");
    assert_eq!(
        wire,
        json!({
            "id": "UniversityDegree",
            "display": {"name": "University Degree", "locale": "en-US"},
            "format": "dc+sd-jwt",
            "vct": "https://vc.example/degree",
        })
    );

    // The omitempty shapes: no display, no vct — the members are
    // absent, never null (the Go tags).
    let bare = AvailableCredential {
        id: "Mdl".to_owned(),
        display: None,
        format: "mso_mdoc".to_owned(),
        vct: String::new(),
    };
    let wire: serde_json::Value =
        serde_json::to_value(&bare).expect("an available credential serializes");
    assert_eq!(
        wire,
        json!({"id": "Mdl", "format": "mso_mdoc"}),
        "no display and an empty vct are absent, not null"
    );
}

/// The default `request_credential_selection` an older host inherits:
/// a refusal (Cannot), never an answer — a host that cannot ask its
/// user fails closed rather than naming a configuration unasked.
#[tokio::test]
async fn the_default_selection_ask_refuses() {
    /// The older host: the asks that existed before the selection,
    /// and nothing else.
    struct OlderHost;

    #[async_trait::async_trait]
    impl Host for OlderHost {
        async fn request_sign(&self, _params: SignParams) -> Result<SignResult, HostError> {
            Err(HostError::Cannot("no sign".to_owned()))
        }
        async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, HostError> {
            Ok(MatchResult::default())
        }
        async fn request_consent(
            &self,
            _params: ConsentParams,
        ) -> Result<ConsentResult, HostError> {
            Ok(ConsentResult { consented: true })
        }
        async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
            Err(HostError::Cannot("no tx code".to_owned()))
        }
        async fn open_authorization(&self, _flow_id: &str, _url: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
    }

    let answer = OlderHost
        .request_credential_selection(CredentialSelectionParams {
            flow_id: "flow-1".to_owned(),
            available: Vec::new(),
        })
        .await;
    assert!(
        matches!(answer, Err(HostError::Cannot(_))),
        "the inherited default refuses, it never selects"
    );
}

/// A match answer from an older host — one that carried no handle —
/// deserialises with no handle, and the presentation ask omits the
/// selection_handle member when there is none: the wire an old host
/// sees is unchanged.
#[test]
fn the_handle_rides_the_wire_as_an_absent_member_when_there_is_none() {
    let answer: MatchResult = serde_json::from_str(
        r#"{"selections": [{"credential_query_id": "q", "credential_id": "c"}]}"#,
    )
    .expect("an old answer deserialises");
    assert_eq!(answer.handle, None);

    let params = engine_ports::VpParams {
        flow_id: "flow-1".to_owned(),
        audience: "https://verifier.example".to_owned(),
        nonce: "n".to_owned(),
        selections: answer.selections,
        response_uri: "https://verifier.example/response".to_owned(),
        verifier_jwk_thumbprint: String::new(),
        verifier_session_id: String::new(),
        transaction_data: Vec::new(),
        origin: String::new(),
        selection_handle: answer.handle,
        verified_request: None,
        response_encryption: None,
    };
    let wire: serde_json::Value = serde_json::to_value(&params).expect("the ask serialises");
    assert!(
        wire.get("selection_handle").is_none(),
        "no handle, no member"
    );
    assert_eq!(
        wire.get("selections"),
        Some(&json!([{"credential_query_id": "q", "credential_id": "c", "disclosed_claims": []}])),
        "the selections ride unchanged"
    );
}

/// The verified request and the response encryption carry the exact member
/// set the wallets' `VerifiedRequest`/`ResponseEncryptionRequest` readers
/// expect (go-wallet-backend#471's shape — the Kotlin transport's
/// `@SerialName`s). The ZK policy gate reads `signed` AND
/// `signature_verification == "verified"` — an absent member reads as not
/// verified and every zkp_req sign ask refuses at step=unsigned-request
/// (found on-device 2026-11-13: the first cut of the struct omitted it).
/// This test is the drift guard: a renamed or missing member fails here,
/// not on a device.
#[test]
fn the_verified_request_carries_the_wallets_gate_members() {
    let params = engine_ports::VpParams {
        flow_id: "flow-1".to_owned(),
        audience: "x509_san_dns:verifier.example".to_owned(),
        nonce: "n".to_owned(),
        selections: Vec::new(),
        response_uri: "https://verifier.example/response".to_owned(),
        verifier_jwk_thumbprint: "thumbprint".to_owned(),
        verifier_session_id: String::new(),
        transaction_data: Vec::new(),
        origin: String::new(),
        selection_handle: None,
        verified_request: Some(engine_ports::VpVerifiedRequest {
            client_id: "x509_san_dns:verifier.example".to_owned(),
            client_id_scheme: "x509_san_dns".to_owned(),
            response_mode: "direct_post.jwt".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            signed: true,
            signature_verification: "verified".to_owned(),
            request_jwt: Some("header.payload.signature".to_owned()),
        }),
        response_encryption: Some(engine_ports::VpResponseEncryption {
            jwk: json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
            alg: "ECDH-ES".to_owned(),
            enc: "A256GCM".to_owned(),
        }),
    };
    let wire: serde_json::Value = serde_json::to_value(&params).expect("the ask serialises");

    let verified = wire
        .get("verified_request")
        .expect("the verified request rides the ask");
    let members: std::collections::BTreeSet<String> = verified
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        members,
        [
            "client_id",
            "client_id_scheme",
            "request_jwt",
            "response_mode",
            "response_uri",
            "signature_verification",
            "signed"
        ]
        .map(str::to_owned)
        .into(),
        "the member set matches the wallet's VerifiedRequest readers"
    );
    assert_eq!(
        verified.get("signature_verification"),
        Some(&json!("verified")),
        "the gate's required value"
    );
    assert_eq!(
        verified.get("signed"),
        Some(&json!(true)),
        "the convenience mirror the gate also reads"
    );

    let encryption = wire
        .get("response_encryption")
        .expect("the response encryption rides the ask");
    let members: std::collections::BTreeSet<String> = encryption
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        members,
        ["alg", "enc", "jwk"].map(str::to_owned).into(),
        "the member set matches the wallet's ResponseEncryptionRequest readers"
    );
}
