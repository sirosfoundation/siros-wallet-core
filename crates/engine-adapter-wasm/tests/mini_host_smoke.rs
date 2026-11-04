//! The mini host smoke: the pre-authorized issuance driven through the
//! built-in conformance host — the device key signs the proof, the
//! transaction code comes from configuration, consent is automatic —
//! and the submitted proof's signature verifies under the device key's
//! public JWK, which is what an OIDF plan's issuer checks.

use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use engine_adapter_wasm::WasmEngine;

fn params(text: &str) -> JsValue {
    let parsed: serde_json::Value = serde_json::from_str(text).expect("the test params are JSON");
    serde_wasm_bindgen::to_value(&parsed).expect("the params convert")
}

fn result_of(value: JsValue) -> serde_json::Value {
    serde_wasm_bindgen::from_value(value).unwrap_or_default()
}

/// The page's fetch: the scripted issuer the issuance drives, plus a
/// capture of the credential request so the test can verify the proof.
fn scripted_fetch() -> js_sys::Function {
    js_sys::Function::new_with_args(
        "request",
        r#"
        const bytes = (text) => Array.from(new TextEncoder().encode(text));
        if (request.url === "https://issuer.example/.well-known/openid-credential-issuer") {
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify({
                credential_issuer: "https://issuer.example",
                authorization_servers: ["https://as.example"],
                credential_configurations_supported: { MiniDegree: { scope: "openid" } }
            })) });
        }
        if (request.url === "https://as.example/.well-known/oauth-authorization-server") {
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify({
                issuer: "https://as.example", token_endpoint: "https://as.example/token"
            })) });
        }
        if (request.url === "https://as.example/token") {
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify({
                access_token: "at-mini-1", token_type: "Bearer", c_nonce: "nonce-mini-1"
            })) });
        }
        if (request.url === "https://issuer.example/credential") {
            globalThis.__mini_credential_request = request.body;
            return Promise.resolve({ status: 200, headers: [], body: bytes(JSON.stringify({
                credential: "credential-mini-1"
            })) });
        }
        if (request.url === "https://issuer.example/notification") {
            return Promise.resolve({ status: 200, headers: [], body: bytes("{}") });
        }
        return Promise.reject(new Error("unexpected fetch: " + request.url));
        "#,
    )
}

/// The captured credential request body from the scripted page: the
/// fetch sets `globalThis.__mini_credential_request`.
fn captured_credential_request() -> Vec<u8> {
    let captured = js_sys::Reflect::get(
        &js_sys::global(),
        &JsValue::from_str("__mini_credential_request"),
    );
    captured
        .ok()
        .and_then(|body| serde_wasm_bindgen::from_value(body).ok())
        .unwrap_or_default()
}

#[wasm_bindgen_test]
async fn the_mini_host_signs_the_proof_and_the_issuance_completes() {
    let config = js_sys::Object::new();
    js_sys::Reflect::set(&config, &JsValue::from_str("fetch"), &scripted_fetch())
        .expect("set the fetch");
    js_sys::Reflect::set(
        &config,
        &JsValue::from_str("host"),
        &JsValue::from_str("mini"),
    )
    .expect("select the mini host");
    js_sys::Reflect::set(
        &config,
        &JsValue::from_str("txCode"),
        &JsValue::from_str("493536"),
    )
    .expect("set the transaction code");
    let pdp = js_sys::eval("({ evaluate: () => Promise.resolve({ trusted: true }) })")
        .expect("the pdp object");
    js_sys::Reflect::set(&config, &JsValue::from_str("pdp"), &pdp).expect("set the pdp");

    let engine = WasmEngine::new(config.into()).expect("the engine builds over the mini host");

    let session = engine
        .request(
            "wmp.session.create".to_owned(),
            params(
                r#"{
                    "wmp": {"version": "0.1", "sender": "mini-smoke"},
                    "capabilities_offered": {"flows": {"max_concurrent": 16}},
                    "security": {"mode": "tls"}
                }"#,
            ),
        )
        .await
        .expect("the session creates");
    let session_id = result_of(session)
        .pointer("/wmp/session_id")
        .and_then(|id| id.as_str())
        .expect("the session id")
        .to_owned();

    let start = engine
        .request(
            "wmp.flow.start".to_owned(),
            params(&format!(
                r#"{{
                    "wmp": {{"session_id": "{session_id}", "version": "0.1"}},
                    "flow_id": "flow-mini-1", "flow_type": "oid4vci",
                    "params": {{
                        "credential_issuer": "https://issuer.example",
                        "credential_configuration_ids": ["MiniDegree"],
                        "grants": {{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {{
                            "pre-authorized_code": "preauth-mini-1",
                            "tx_code": {{"length": 6}}
                        }}}}
                    }}
                }}"#
            )),
        )
        .await
        .expect("the issuance completes");
    let start = result_of(start);
    assert_eq!(
        start.pointer("/flow_id").and_then(|id| id.as_str()),
        Some("flow-mini-1")
    );

    // The credential request the engine sent: the proof's JWT signature
    // verifies under the device key's public JWK — the same check the
    // suite's issuer performs.
    let body: Vec<u8> = captured_credential_request();
    let request: serde_json::Value = serde_json::from_slice(&body).expect("the request is JSON");
    let proof = request
        .pointer("/proofs/jwt/0")
        .and_then(|jwt| jwt.as_str())
        .expect("the proof JWT")
        .to_owned();
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "the proof is a JWS");

    // The header names ES256 and an EC key; the signature verifies under
    // the public JWK in the header itself — the wallet's device key.
    let header_json = engine_adapter_wasm::decode_b64url(parts[0]);
    let header: serde_json::Value = serde_json::from_slice(&header_json).expect("the proof header");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "openid4vci-proof+jwt");
    let device_jwk = result_of(engine.mini_public_jwk());
    assert_eq!(device_jwk["kty"], "EC", "the mini host's device key");
    let jwk: jose_rs::jwk::Jwk =
        serde_json::from_value(device_jwk).expect("the device key's public JWK");
    let verified =
        jose_rs::jws::compact::verify_with_jwk(&jwk, &proof).expect("the proof signature verifies");
    let claims: serde_json::Value = serde_json::from_slice(&verified).expect("the proof claims");
    assert_eq!(claims["aud"], "https://issuer.example");
    assert_eq!(claims["nonce"], "nonce-mini-1");
}
