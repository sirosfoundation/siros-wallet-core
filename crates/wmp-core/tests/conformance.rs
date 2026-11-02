//! The vector referee: runs `wmp/vectors/*.json` against this crate, the
//! mirror of go-wmp's `conformance_test.go`, `interop_test.go` and
//! `sessionservice_vectors_test.go`.
//!
//! `WMP_VECTORS_DIR` overrides the search (to run the suite against a spec
//! branch that is not a sibling); the local default is the sibling checkout
//! `../../../wmp/vectors` (three levels up from `crates/wmp-core`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use wmp_core::context::RequestContext;
use wmp_core::error::RpcError;
use wmp_core::handler::{Handler, HandlerError};
use wmp_core::methods::*;
use wmp_core::peer::{Authorizer, Peer, PeerBuilder, Validator};
use wmp_core::principal::Principal;
use wmp_core::session::{MemorySessionStore, SessionStore};
use wmp_core::sessionservice::{SessionHandler, SessionService, SessionServiceConfig};
use wmp_core::types::Capabilities;

/// Where the vectors live: the override, else the sibling checkout.
fn vectors_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WMP_VECTORS_DIR") {
        return PathBuf::from(dir);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../../wmp/vectors")
}

/// One vector of the spec's `vector-schema.json`.
#[derive(Debug, Clone, Deserialize)]
struct TestVector {
    id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    conformance_level: String,
    input: Value,
    #[serde(default)]
    expected_response: Option<Value>,
    #[serde(default)]
    expected_error: Option<Value>,
    #[serde(default)]
    handler_action: Option<HandlerAction>,
    #[serde(default)]
    peer_options: Option<PeerOptions>,
    #[serde(default)]
    #[allow(dead_code)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct HandlerAction {
    method: String,
    #[serde(default)]
    r#return: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerOptions {
    #[serde(default)]
    authorize: Option<bool>,
    #[serde(default)]
    validate: Option<bool>,
}

fn load_vectors(file: &str) -> Vec<TestVector> {
    let path = vectors_dir().join(file);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("vectors not available at {}: checkout the wmp repository as a sibling, or set WMP_VECTORS_DIR", path.display()));
    serde_json::from_str(&data).unwrap_or_else(|err| panic!("parse {file}: {err}"))
}

const KNOWN_METHODS: &[&str] = &[
    METHOD_SESSION_CREATE,
    METHOD_SESSION_RESUME,
    METHOD_SESSION_CLOSE,
    METHOD_SESSION_AUTHENTICATE,
    METHOD_MESSAGE_DELIVER,
    METHOD_MESSAGE_ACK,
    METHOD_MESSAGE_POLL,
    METHOD_MESSAGE_STATUS,
    METHOD_CAPABILITY_UPDATE,
    METHOD_CAPABILITY_LIST,
    METHOD_FLOW_START,
    METHOD_FLOW_PROGRESS,
    METHOD_FLOW_ACTION,
    METHOD_FLOW_COMPLETE,
    METHOD_FLOW_ERROR,
    METHOD_FLOW_CANCEL,
    METHOD_CREDENTIAL_NOTIFICATION,
    METHOD_RESOLVE,
    METHOD_RELAY_REGISTER,
];

fn known_error(code: i64) -> bool {
    const KNOWN: &[i64] = &[
        -32700, -32600, -32601, -32602, -32603, -31000, -31001, -31002, -31003, -31004, -31005,
        -31006, -31007, -31008, -31009, -31010, -31011, -31012, -31013, -31014, -31015, -31016,
        -31017, -31018, -31019, -31020,
    ];
    KNOWN.contains(&code)
}

/// Structural validity of an input request (go-wmp's `assertValidRequest`).
fn assert_valid_request(vector: &TestVector) {
    let jsonrpc = vector.input.get("jsonrpc").and_then(Value::as_str);
    assert_eq!(jsonrpc, Some("2.0"), "{}: jsonrpc must be 2.0", vector.id);
    let method = vector.input.get("method").and_then(Value::as_str);
    let Some(method) = method else {
        panic!("{}: method must not be empty", vector.id);
    };
    if !KNOWN_METHODS.contains(&method) {
        return; // some vectors deliberately use unknown methods
    }
    if let Some(params) = vector.input.get("params") {
        if let Some(map) = params.as_object() {
            assert!(
                map.contains_key("wmp"),
                "{}: params.wmp must exist for method {method}",
                vector.id
            );
        }
    }
}

/// Structural validity of an expected response (`assertValidResponse`).
fn assert_valid_response(vector: &TestVector, raw: &Value) {
    assert_eq!(
        raw.get("jsonrpc").and_then(Value::as_str),
        Some("2.0"),
        "{}: response jsonrpc must be 2.0",
        vector.id
    );
    if let Some(result) = raw.get("result") {
        assert!(
            result.get("wmp").is_some(),
            "{}: result.wmp must exist",
            vector.id
        );
    }
}

/// Structural validity of an expected error (`assertValidError`).
fn assert_valid_error(vector: &TestVector, raw: &Value) {
    assert_eq!(
        raw.get("jsonrpc").and_then(Value::as_str),
        Some("2.0"),
        "{}: error response jsonrpc must be 2.0",
        vector.id
    );
    let error = raw
        .get("error")
        .unwrap_or_else(|| panic!("{}: error member must exist", vector.id));
    let code = error.get("code").and_then(Value::as_i64);
    let Some(code) = code else {
        panic!("{}: error.code must exist", vector.id);
    };
    assert!(
        known_error(code),
        "{}: unknown error code {code}",
        vector.id
    );
    assert!(
        error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|m| !m.is_empty()),
        "{}: error.message must not be empty",
        vector.id
    );
}

#[test]
fn conformance_structural_validity() {
    for file in [
        "interop.json",
        "message-deliver.json",
        "resolve.json",
        "session-create.json",
        "session-lifecycle.json",
    ] {
        for vector in load_vectors(file) {
            if vector.input.is_object() {
                assert_valid_request(&vector);
            }
            if let Some(response) = &vector.expected_response {
                if !response.is_null() {
                    assert_valid_response(&vector, response);
                }
            }
            if let Some(error) = &vector.expected_error {
                assert_valid_error(&vector, error);
            }
        }
    }
    // errors.json: the inputs use deliberately invalid methods, but they are
    // still JSON-RPC 2.0 messages.
    for vector in load_vectors("errors.json") {
        let jsonrpc = vector.input.get("jsonrpc").and_then(Value::as_str);
        assert_eq!(jsonrpc, Some("2.0"), "{}: jsonrpc must be 2.0", vector.id);
        if let Some(error) = &vector.expected_error {
            assert_valid_error(&vector, error);
        }
    }
    // flow-lifecycle.json: a vector is a multi-step sequence (an array of
    // {step, message}) or a single message; every message is a valid
    // request. go-wmp also checks DCQL query-id consistency here — that
    // check returns with the openid4x profile, out of this crate's scope.
    for vector in load_vectors("flow-lifecycle.json") {
        match &vector.input {
            Value::Array(steps) => {
                for step in steps {
                    let message = step
                        .get("message")
                        .unwrap_or_else(|| panic!("{}: step without message", vector.id));
                    let step_vector = TestVector {
                        id: format!(
                            "{}/{}",
                            vector.id,
                            step.get("step").and_then(Value::as_str).unwrap_or("?")
                        ),
                        input: message.clone(),
                        ..vector.clone()
                    };
                    assert_valid_request(&step_vector);
                }
            }
            single => {
                let single_vector = TestVector {
                    input: single.clone(),
                    ..vector.clone()
                };
                assert_valid_request(&single_vector);
            }
        }
        if let Some(response) = &vector.expected_response {
            if !response.is_null() {
                assert_valid_response(&vector, response);
            }
        }
    }
}

/// Every method a vector uses is a known WMP method constant
/// (`TestConformanceMethodCoverage`).
#[test]
fn conformance_method_coverage() {
    let mut vector_methods = std::collections::BTreeSet::new();
    for file in [
        "session-create.json",
        "session-lifecycle.json",
        "message-deliver.json",
        "resolve.json",
    ] {
        for vector in load_vectors(file) {
            if let Some(method) = vector.input.get("method").and_then(Value::as_str) {
                if !method.is_empty() {
                    vector_methods.insert(method.to_owned());
                }
            }
        }
    }
    for method in vector_methods {
        assert!(
            KNOWN_METHODS.contains(&method.as_str()),
            "vector method {method:?} not in known method constants"
        );
    }
}

// --- The interop execution harness (`interop_test.go`) ---

/// A handler whose `resolve` is driven by the vector's `handler_action`.
struct InteropHandler {
    action: Option<HandlerAction>,
}

impl Handler for InteropHandler {
    fn resolve(
        &self,
        _ctx: &RequestContext,
        _params: &ResolveParams,
    ) -> Result<ResolveResult, HandlerError> {
        let Some(action) = &self.action else {
            return Err(RpcError::code(-32601).into());
        };
        if action.method != METHOD_RESOLVE {
            return Err(RpcError::code(-32601).into());
        }
        if let Some(error) = &action.error {
            let error: RpcError = serde_json::from_value(error.clone())
                .unwrap_or_else(|e| panic!("parse handler action error: {e}"));
            return Err(error.into());
        }
        if let Some(result) = &action.r#return {
            return serde_json::from_value(result.clone())
                .map_err(|e| HandlerError::Internal(Box::new(e)));
        }
        Err(RpcError::code(-32601).into())
    }
}

/// Rejects every method when false.
struct StaticValidator {
    valid: bool,
}

impl Validator for StaticValidator {
    fn validate_method(&self, _method: &str, _data: &[u8]) -> Result<(), String> {
        self.valid
            .then_some(())
            .ok_or_else(|| "rejected by test validator".to_owned())
    }
}

/// Rejects every method when false.
struct StaticAuthorizer {
    allowed: bool,
}

impl Authorizer for StaticAuthorizer {
    fn authorize(&self, _ctx: &RequestContext, _method: &str, _params: &Value) -> bool {
        self.allowed
    }
}

#[test]
fn interop_vectors() {
    for vector in load_vectors("interop.json") {
        let handler = Arc::new(InteropHandler {
            action: vector.handler_action.clone(),
        });
        let mut builder = PeerBuilder::new(handler).max_message_size(1 << 20);
        if let Some(options) = &vector.peer_options {
            if options.authorize == Some(false) {
                builder = builder.authorizer(Arc::new(StaticAuthorizer { allowed: false }));
            }
            if options.validate == Some(false) {
                builder = builder.validator(Arc::new(StaticValidator { valid: false }));
            }
        }
        let peer = builder.build();
        let data = serde_json::to_vec(&vector.input).expect("serialize input");
        let response = peer
            .handle_request_sync(&RequestContext::default(), &data)
            .unwrap_or_else(|err| panic!("{}: handle_request_sync failed: {err}", vector.id));

        // A notification-style vector expects no response.
        if vector
            .expected_response
            .as_ref()
            .is_some_and(Value::is_null)
        {
            assert!(response.is_none(), "{}: expected no response", vector.id);
            continue;
        }
        if let Some(expected) = &vector.expected_error {
            let Some(bytes) = &response else {
                panic!("{}: expected an error response, got none", vector.id);
            };
            let actual: Value =
                serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{}: {e}", vector.id));
            let actual_error = actual.get("error").cloned().unwrap_or_else(|| {
                panic!("{}: expected an error, got a success: {actual}", vector.id)
            });
            let actual_code = actual_error.get("code").and_then(Value::as_i64);
            let expected_code = expected
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_i64);
            assert_eq!(
                actual_code, expected_code,
                "{}: error code mismatch",
                vector.id
            );
            assert!(
                actual_error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|m| !m.is_empty()),
                "{}: error message must not be empty",
                vector.id
            );
            continue;
        }
        if let Some(expected) = &vector.expected_response {
            let Some(bytes) = &response else {
                panic!("{}: expected a success response, got none", vector.id);
            };
            let actual: Value =
                serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("{}: {e}", vector.id));
            assert_eq!(actual, *expected, "{}: response mismatch", vector.id);
            continue;
        }
        assert!(
            response.is_none(),
            "{}: expected no response, got {:?}",
            vector.id,
            String::from_utf8_lossy(response.as_deref().unwrap_or(&[]))
        );
    }
}

// --- The session-create execution harness (`sessionservice_vectors_test.go`) ---

/// A deterministic entropy source: a counter, so identifiers and tokens are
/// unguessable in shape but reproducible in tests.
fn counter_entropy() -> wmp_core::sessionservice::EntropyFn {
    let counter = Arc::new(AtomicU64::new(0));
    Arc::new(move |bytes: &mut [u8]| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (n >> (i % 8)) as u8;
        }
        true
    })
}

/// A fixed clock: the service never reads the wall clock.
fn fixed_clock() -> wmp_core::sessionservice::Clock {
    Arc::new(|| 1_730_000_000)
}

fn service_peer() -> (Arc<Peer>, Arc<dyn SessionStore>) {
    let store = Arc::new(MemorySessionStore::new());
    let supported = Capabilities(
        [(
            "messaging".to_owned(),
            serde_json::from_str::<Box<serde_json::value::RawValue>>(r#"{"max_size":65536}"#)
                .expect("parse capability"),
        )]
        .into_iter()
        .collect(),
    );
    let service = Arc::new(
        SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            supported,
            entropy: Some(counter_entropy()),
            ..SessionServiceConfig::default()
        })
        .expect("service"),
    );
    let handler = Arc::new(SessionHandler::new(service, fixed_clock()));
    let peer = PeerBuilder::new(handler)
        .session_store(store.clone())
        .build();
    (peer, store)
}

#[test]
fn session_create_vectors() {
    let (peer, _store) = service_peer();
    let ctx = RequestContext {
        principal: Some(Principal::new("alice", "")),
        ..RequestContext::default()
    };
    for vector in load_vectors("session-create.json") {
        // Only tls-mode creates run; MLS vectors need an MLS-capable service.
        let mode = vector
            .input
            .get("params")
            .and_then(|p| p.get("security"))
            .and_then(|s| s.get("mode"))
            .and_then(Value::as_str);
        if mode != Some("tls") || vector.expected_response.is_none() {
            continue;
        }
        let data = serde_json::to_vec(&vector.input).expect("serialize input");
        let response = peer
            .handle_request_sync(&ctx, &data)
            .unwrap_or_else(|err| panic!("{}: {err}", vector.id))
            .unwrap_or_else(|| panic!("{}: expected a response", vector.id));
        let actual: Value =
            serde_json::from_slice(&response).unwrap_or_else(|e| panic!("{}: {e}", vector.id));
        let expected = vector.expected_response.clone().unwrap();

        // The session id is server-generated: match the metadata schema's
        // pattern rather than the literal.
        let session_id = actual
            .get("result")
            .and_then(|r| r.get("wmp"))
            .and_then(|w| w.get("session_id"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{}: result.wmp.session_id missing", vector.id));
        assert!(
            session_id.starts_with("ses-")
                && session_id.len() > 4
                && session_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{}: session_id {session_id:?} does not match ^ses-[a-zA-Z0-9]+$",
            vector.id
        );
        // challenge (the identity-assertion replay nonce) is a separate
        // feature; the harness does not assert it.
        let version = actual
            .get("result")
            .and_then(|r| r.get("wmp"))
            .and_then(|w| w.get("version"))
            .cloned()
            .unwrap_or_default();
        let expected_version = expected
            .get("result")
            .and_then(|r| r.get("wmp"))
            .and_then(|w| w.get("version"))
            .cloned()
            .unwrap_or_default();
        assert_eq!(version, expected_version, "{}: version", vector.id);
        for member in ["capabilities", "security"] {
            let got = actual
                .get("result")
                .and_then(|r| r.get(member))
                .cloned()
                .unwrap_or_default();
            let want = expected
                .get("result")
                .and_then(|r| r.get(member))
                .cloned()
                .unwrap_or_default();
            assert_eq!(got, want, "{}: {member}", vector.id);
        }
    }
}

/// Generated ids and create results satisfy the shape the schema demands,
/// including a result with no negotiated capabilities (the `capabilities`
/// member is required, even empty).
#[test]
fn session_create_result_has_capabilities() {
    let (peer, _store) = service_peer();
    let ctx = RequestContext {
        principal: Some(Principal::new("alice", "")),
        ..RequestContext::default()
    };
    let request = br#"{"jsonrpc":"2.0","id":"1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"capabilities_offered":{"messaging":{}},"security":{"mode":"tls"}}}"#;
    for _ in 0..50 {
        let response = peer
            .handle_request_sync(&ctx, request)
            .expect("handle")
            .expect("response");
        let actual: Value = serde_json::from_slice(&response).expect("parse");
        let capabilities = actual
            .get("result")
            .and_then(|r| r.get("capabilities"))
            .cloned()
            .unwrap_or_else(|| panic!("capabilities missing: {actual}"));
        assert!(capabilities.is_object(), "capabilities must be an object");
    }
}
