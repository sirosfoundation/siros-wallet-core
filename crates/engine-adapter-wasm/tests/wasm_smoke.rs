//! The browser smoke: the engine built over mock JS callbacks — the
//! page's fetch, the wallet's sign callback, the PDP — driving the
//! pre-authorized issuance end to end through `WasmEngine::request`,
//! under Node (the same JS event loop the browser runs).

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use engine_adapter_wasm::WasmEngine;

/// The page's fetch: scripted per URL, answering the engine's shape.
fn scripted_fetch() -> js_sys::Function {
    js_sys::Function::new_with_args(
        "request",
        r#"
        const issuer = {
            credential_issuer: "https://issuer.example",
            authorization_servers: ["https://as.example"],
            credential_configurations_supported: { UniversityDegree: { scope: "openid" } }
        };
        const as = { issuer: "https://as.example", token_endpoint: "https://as.example/token" };
        const bytes = (text) => Array.from(new TextEncoder().encode(text));
        if (request.url === "https://issuer.example/.well-known/openid-credential-issuer") {
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify(issuer)) });
        }
        if (request.url === "https://as.example/.well-known/oauth-authorization-server") {
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify(as)) });
        }
        if (request.url === "https://as.example/token") {
            const form = new TextDecoder().decode(new Uint8Array(request.body));
            if (!form.includes("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code")) {
                return Promise.reject(new Error("unexpected grant: " + form));
            }
            const token = {
                access_token: "at-js-1", token_type: "Bearer",
                c_nonce: "n-js-1", refresh_token: "rt-js-1"
            };
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify(token)) });
        }
        if (request.url === "https://issuer.example/credential") {
            return Promise.resolve({
                status: 200, headers: [], body: bytes(JSON.stringify({ credential: "credential-js-1" }))
            });
        }
        if (request.url === "https://issuer.example/notification") {
            return Promise.resolve({ status: 200, headers: [], body: bytes("{}") });
        }
        return Promise.reject(new Error("unexpected fetch: " + request.url));
        "#,
    )
}

/// Builds the engine over the mock page.
fn engine() -> WasmEngine {
    let host = js_sys::Object::new();
    js_sys::Reflect::set(
        &host,
        &JsValue::from_str("sign"),
        &js_sys::Function::new_with_args(
            "",
            "return Promise.resolve({ signature: [1, 2, 3, 4] });",
        ),
    )
    .expect("set the sign callback");

    let pdp = js_sys::Object::new();
    js_sys::Reflect::set(
        &pdp,
        &JsValue::from_str("evaluate"),
        &js_sys::Function::new_with_args(
            "",
            "return Promise.resolve({ trusted: true, decision: 'the js smoke' });",
        ),
    )
    .expect("set the evaluate callback");

    let config = js_sys::Object::new();
    js_sys::Reflect::set(&config, &JsValue::from_str("fetch"), &scripted_fetch())
        .expect("set the fetch");
    js_sys::Reflect::set(&config, &JsValue::from_str("host"), &host).expect("set the host");
    js_sys::Reflect::set(&config, &JsValue::from_str("pdp"), &pdp).expect("set the pdp");
    js_sys::Reflect::set(
        &config,
        &JsValue::from_str("now"),
        &js_sys::Function::new_with_args("", "return 1700000000;"),
    )
    .expect("set the clock");

    WasmEngine::new(config.into()).expect("the engine builds over the mock page")
}

async fn call(engine: &WasmEngine, method: &str, params: JsValue) -> Result<JsValue, JsValue> {
    // From Rust, the wasm_bindgen async method is a plain future.
    engine.request(method.to_owned(), params).await
}

/// The session id from a session-create result.
fn session_id_of(result: &JsValue) -> String {
    let detail: serde_json::Value =
        serde_wasm_bindgen::from_value(result.clone()).unwrap_or_default();
    detail
        .pointer("/wmp/session_id")
        .and_then(|id| id.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn params(text: &str) -> JsValue {
    let parsed: serde_json::Value = serde_json::from_str(text).expect("the test params are JSON");
    serde_wasm_bindgen::to_value(&parsed).expect("the params convert")
}

#[wasm_bindgen_test]
async fn the_pre_authorized_issuance_runs_in_the_browser() {
    let engine = engine();

    // The session: the page offers the flows capability.
    let session = call(
        &engine,
        "wmp.session.create",
        params(
            r#"{
                "wmp": {"version": "0.1", "sender": "js-smoke"},
                "capabilities_offered": {"flows": {"max_concurrent": 16}},
                "security": {"mode": "tls"}
            }"#,
        ),
    )
    .await
    .map_err(|err| {
        let detail: serde_json::Value = serde_wasm_bindgen::from_value(err).unwrap_or_default();
        panic!("the session create rejected: {detail}")
    })
    .expect("the session creates");
    let session_id = session_id_of(&session);

    // The flow start: the pre-authorized issuance, end to end.
    let start = call(
        &engine,
        "wmp.flow.start",
        params(&format!(
            r#"{{
                "wmp": {{"session_id": "{session_id}", "version": "0.1"}},
                "flow_id": "flow-js-smoke-1", "flow_type": "oid4vci",
                "params": {{
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_ids": ["UniversityDegree"],
                    "grants": {{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {{
                        "pre-authorized_code": "preauth-js-smoke-1"
                    }}}}
                }}
            }}"#
        )),
    )
    .await
    .expect("the flow completes");
    let detail: serde_json::Value = serde_wasm_bindgen::from_value(start).unwrap_or_default();
    assert_eq!(
        detail
            .pointer("/flow_id")
            .and_then(|id| id.as_str())
            .unwrap_or_default(),
        "flow-js-smoke-1",
        "the flow start result was {detail}"
    );
}

#[wasm_bindgen_test]
async fn a_flow_without_the_capability_refuses_with_the_wmp_error() {
    let engine = engine();

    let session = call(
        &engine,
        "wmp.session.create",
        params(
            r#"{
                "wmp": {"version": "0.1", "sender": "js-smoke"},
                "security": {"mode": "tls"}
            }"#,
        ),
    )
    .await
    .expect("the session creates");
    let session_id = session_id_of(&session);

    // The page offered nothing: the gate refuses before the family sees
    // it, and the rejection carries the JSON-RPC error object.
    let err = engine
        .request(
            "wmp.flow.start".to_owned(),
            params(&format!(
                r#"{{
                    "wmp": {{"session_id": "{session_id}", "version": "0.1"}},
                    "flow_id": "flow-gate-js-1", "flow_type": "oid4vci",
                    "params": {{}}
                }}"#
            )),
        )
        .await
        .expect_err("the gate refuses");
    let detail: serde_json::Value = serde_wasm_bindgen::from_value(err).unwrap_or_default();
    assert_eq!(
        detail
            .get("code")
            .and_then(|code| code.as_i64())
            .unwrap_or_default(),
        -31005,
        "the gate's error was {detail}"
    );
}

/// The host-ask boundary: the raw-JSON members of an ask cross into
/// JavaScript as PLAIN OBJECTS, never `Map`s. The default
/// `serde_wasm_bindgen::to_value` keeps the Map (to preserve round-trips
/// for Rust hosts); the wasm engine's hosts are JS pages — a page reading
/// `params.dcql_query.credentials` sees `undefined` against a `Map`, and
/// `JSON.stringify(Map)` answers `{}`, so every raw-JSON member read as
/// empty (found live in the realeyes demo: the match ask's DCQL was
/// `{}`, every zkp query empty, the presentation refused).
#[wasm_bindgen_test]
async fn the_host_asks_cross_as_plain_objects_never_maps() {
    use engine_adapter_wasm::ports::JsHost;
    use engine_ports::{ClientIdScheme, Host, MatchParams, VerifierInfo};

    // The JS side records what it saw: the dcql root's constructor, the
    // credentials read, and the number member's shape. A plain object
    // stringifies itself; a Map answers "{}".
    let noop =
        js_sys::Function::new_with_args("params", "return Promise.resolve({ selections: [] })");
    let r#match = js_sys::Function::new_with_args(
        "params",
        r#"
        globalThis.__ask_ctor = params.dcql_query.constructor.name;
        globalThis.__ask_credentials = params.dcql_query.credentials
            ? JSON.stringify(params.dcql_query.credentials)
            : "(undefined)";
        globalThis.__ask_ver = JSON.stringify(
            params.dcql_query.credentials && params.dcql_query.credentials[0].params.ver,
        );
        return Promise.resolve({ selections: [] });
        "#,
    );
    let host = JsHost {
        sign: noop.clone(),
        r#match,
        consent: noop.clone(),
        tx_code: noop.clone(),
        open_authorization: noop.clone(),
        vp: noop.clone(),
        dpop_proof: noop.clone(),
        attestation: noop,
        progress: None,
        signing_key: None,
        response_encryption_key: None,
        decrypt_credential_response: None,
    };
    let dcql = serde_json::json!({
        "credentials": [ { "id": "q1", "params": { "ver": 1 } } ]
    });
    let params = MatchParams {
        flow_id: "flow-1".to_owned(),
        dcql_query: Some(dcql.clone()),
        scope: String::new(),
        verifier: VerifierInfo {
            name: "verifier".to_owned(),
            client_id: "x509_san_dns:verifier.example".to_owned(),
            client_id_scheme: ClientIdScheme::X509SanDns,
            domain: String::new(),
            logo_uri: String::new(),
            trusted: true,
            framework: String::new(),
            reason: String::new(),
            trust_context: None,
        },
        transaction_data: Vec::new(),
        client_metadata: None,
    };
    let _ = host.request_match(params).await;

    let global = js_sys::global();
    let ctor: String = js_sys::Reflect::get(&global, &JsValue::from_str("__ask_ctor"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let credentials: String =
        js_sys::Reflect::get(&global, &JsValue::from_str("__ask_credentials"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
    let ver: String = js_sys::Reflect::get(&global, &JsValue::from_str("__ask_ver"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    assert_eq!(
        ctor, "Object",
        "the raw-JSON members cross as plain objects, never Maps"
    );
    assert_eq!(
        credentials, r#"[{"id":"q1","params":{"ver":{"$serde_json::private::Number":"1"}}}]"#,
        "a JS host reads the credentials array (a Map would stringify to {{}})"
    );
    // The number member: serde_json's `arbitrary_precision` (a jose-rs
    // feature, additive across this build) still tags raw numbers as
    // `{"$serde_json::private::Number":"…"}` even through the
    // maps-as-objects serializer — the boundary's known artifact until
    // the feature goes. A JS host unwraps it (the mini-wallet's
    // fromEngineJson); the pin documents today's honest shape.
    assert!(
        ver.contains("$serde_json::private::Number"),
        "the raw number rides the arbitrary_precision tag today (documented): {ver}"
    );
}
