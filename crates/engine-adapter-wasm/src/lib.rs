//! The browser adapter: the engine core over a JS JSON-RPC surface.
//!
//! The wallet-frontend calls `engine.request(method, params)` with the
//! same WMP messages it would send a remote engine over a WebSocket —
//! `wmp.session.create`, `wmp.flow.start`, and so on — and awaits the
//! same answers; the engine runs in the page. The sub-flows (sign,
//! match, consent, tx_code, the authorization browser, the VP
//! construction, the DPoP proofs, the attestation) are JS callbacks
//! returning Promises, the page's fetch function is the HttpClient
//! port, and the PDP is a JS callback — every environmental effect
//! the core has stays on the JS side of the boundary, exactly as the
//! sans-network design requires.
//!
//! The flow notifications (progress, complete, error) the engine
//! emits through its peer do not reach this surface: the page
//! observes through the `host.progress` callback, and the completion
//! is the resolved `wmp.flow.start`/`wmp.flow.action` answer.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

pub mod dispatch;
pub mod mini;
pub mod ports;

pub use ports::decode_b64url;

use wasm_bindgen::prelude::*;

use dispatch::Dispatcher;
use ports::{JsClock, JsFetchHttp, JsKeyValue, JsPdp, JsRng, NoTelemetry};

/// The in-browser engine.
///
/// The config object carries every callback:
///
/// - `fetch(request) -> Promise<{status, headers, body}>` — the
///   engine's HTTP; the request shape is
///   `{method, url, headers, body, purpose, maxResponseBytes,
///   redirects, allowPlaintext, timeoutMs}` (the headers and the
///   answer's headers are flat `[name, value, ...]` arrays).
/// - `host`: `{sign, match, consent, txCode, openAuthorization, vp,
///   dpopProof, attestation}` — the sub-flows, each
///   `(params) -> Promise<answer>`; and the optional `progress`
///   notification callback.
/// - `pdp`: `{evaluate(request) -> Promise<{trusted, decision?}>}`.
/// - `kv` (optional): `{get, put, del}` — the flow stash; without it
///   the stash is in-memory and the authorization-code resume does
///   not survive a page reload.
/// - `now` (optional): `() -> unix seconds` — for a fixed clock in
///   tests.
#[wasm_bindgen]
pub struct WasmEngine {
    dispatcher: Dispatcher,
    mini_public_jwk: Option<serde_json::Value>,
}

#[wasm_bindgen]
impl WasmEngine {
    /// Builds the engine over the page's callbacks.
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<WasmEngine, JsValue> {
        let fetch = required(&config, "fetch")?;
        let pdp = member(&config, "pdp")?;

        // The host: `{"host": "mini", "txCode": "…", "openAuthorization":
        // (url) => …}` selects the built-in conformance host (the device
        // key, auto-consent, the configured transaction code); anything
        // else is the page's own host object.
        let mut mini_public_jwk: Option<serde_json::Value> = None;
        let host: std::sync::Arc<dyn engine_ports::Host> = match member(&config, "host") {
            Ok(host) if host.is_string() && host.as_string().as_deref() == Some("mini") => {
                let tx_code = member(&config, "txCode")
                    .ok()
                    .and_then(|v| v.as_string())
                    .unwrap_or_default();
                let open_authorization = optional(&config, "openAuthorization");
                // A string member — `optional` is function-typed (the
                // host callbacks); the client key JWK is read raw.
                let client_key_jwk = member(&config, "clientKeyJwk")
                    .ok()
                    .and_then(|v| v.as_string());
                let mini = mini::MiniHost::new(tx_code, client_key_jwk, open_authorization)
                    .map_err(|reason| JsValue::from_str(reason.as_str()))?;
                mini_public_jwk = Some(mini.public_jwk());
                mini::arc(mini)
            }
            Ok(host) => std::sync::Arc::new(ports::JsHost {
                sign: required(&host, "sign")?,
                r#match: optional(&host, "match").unwrap_or_else(no_refuse),
                consent: optional(&host, "consent").unwrap_or_else(no_refuse),
                tx_code: optional(&host, "txCode").unwrap_or_else(no_refuse),
                open_authorization: optional(&host, "openAuthorization").unwrap_or_else(no_refuse),
                vp: optional(&host, "vp").unwrap_or_else(no_refuse),
                dpop_proof: optional(&host, "dpopProof").unwrap_or_else(no_refuse),
                attestation: optional(&host, "attestation").unwrap_or_else(no_refuse),
                progress: optional(&host, "progress"),
            }),
            Err(err) => return Err(err),
        };

        let kv_config = optional(&config, "kv");
        let (kv_get, kv_put, kv_del) = match &kv_config {
            Some(kv) => (
                optional(kv, "get"),
                optional(kv, "put"),
                optional(kv, "del"),
            ),
            None => (None, None, None),
        };

        let now = optional(&config, "now");

        let ports = std::sync::Arc::new(engine_core::Ports {
            http: std::sync::Arc::new(JsFetchHttp::new(fetch)),
            clock: std::sync::Arc::new(JsClock),
            rng: std::sync::Arc::new(JsRng),
            host,
            pdp: std::sync::Arc::new(JsPdp::new(required(&pdp, "evaluate")?)),
            kv: std::sync::Arc::new(JsKeyValue::new(kv_get, kv_put, kv_del)),
            telemetry: std::sync::Arc::new(NoTelemetry),
        });

        let clock: wmp_core::sessionservice::Clock = match now {
            Some(now) => std::sync::Arc::new(move || {
                let value = now
                    .call0(&JsValue::NULL)
                    .unwrap_or_else(|_| JsValue::from_f64(0.0));
                value.as_f64().unwrap_or_default() as i64
            }),
            None => std::sync::Arc::new(|| (js_sys::Date::now() / 1000.0) as i64),
        };

        let entropy: wmp_core::sessionservice::EntropyFn =
            std::sync::Arc::new(|bytes: &mut [u8]| js_rng_fill(bytes));
        let dispatcher =
            Dispatcher::new(ports, clock, entropy).map_err(|err| JsValue::from_str(&err))?;

        Ok(WasmEngine {
            dispatcher,
            mini_public_jwk,
        })
    }

    /// The mini host's device key, as a public JWK — for the OIDF plan's
    /// key registration and for verifying what the engine signed. `null`
    /// when the page supplied its own host.
    pub fn mini_public_jwk(&self) -> JsValue {
        self.mini_public_jwk
            .as_ref()
            .and_then(|jwk| serde_wasm_bindgen::to_value(jwk).ok())
            .unwrap_or(JsValue::NULL)
    }

    /// Handles one WMP method call: the method name and the params
    /// object exactly as the wire carries them. The Promise resolves
    /// with the method's result, or rejects with the JSON-RPC error
    /// object `{code, message, data?}`.
    pub async fn request(&self, method: String, params: JsValue) -> Result<JsValue, JsValue> {
        let params: serde_json::Value = serde_wasm_bindgen::from_value(params)
            .map_err(|err| rpc_error(wmp_core::error::ERR_INVALID_PARAMS, &err.to_string()))?;
        match self.dispatcher.request(&method, &params).await {
            // Through JSON text, not serde_wasm_bindgen's serializer:
            // it hands JS ES2015 Maps (the page reads properties) and
            // chokes on serde_json::Value's private Number type. The
            // JSON round-trip gives the page exactly the wire shape.
            Ok(result) => {
                let text = serde_json::to_string(&result).unwrap_or_default();
                js_sys::JSON::parse(&text).map_err(|_| {
                    rpc_error(wmp_core::error::ERR_INTERNAL_ERROR, "serialize the result")
                })
            }
            Err(err) => {
                // The whole RPC error — the data carries the flow's
                // reason, which the page's diagnostics need.
                let text = serde_json::to_string(&err.to_rpc()).unwrap_or_default();
                Err(js_sys::JSON::parse(&text)
                    .unwrap_or_else(|_| JsValue::from_str("flow refused")))
            }
        }
    }
}

/// A JSON-RPC error object for the rejections — plain-object shaped
/// through the same JSON round-trip.
fn rpc_error(code: i32, message: &str) -> JsValue {
    let error = serde_json::json!({ "code": code, "message": message });
    let text = serde_json::to_string(&error).unwrap_or_default();
    js_sys::JSON::parse(&text).unwrap_or_else(|_| JsValue::from_str(message))
}

/// A required member of the config, of any type (the `host` and
/// `pdp` members are objects; their members are the functions).
fn member(object: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    js_sys::Reflect::get(object, &JsValue::from_str(name))
        .map_err(|_| JsValue::from_str(&format!("the engine config is missing {name:?}")))
}

/// A required function member of the config.
fn required(object: &JsValue, name: &str) -> Result<js_sys::Function, JsValue> {
    optional(object, name)
        .ok_or_else(|| JsValue::from_str(&format!("the engine config is missing {name:?}")))
}

/// An optional function member of the config.
fn optional(object: &JsValue, name: &str) -> Option<js_sys::Function> {
    js_sys::Reflect::get(object, &JsValue::from_str(name))
        .ok()
        .and_then(|value| value.dyn_into::<js_sys::Function>().ok())
}

/// A function that never answers — the refusal shape for the host
/// callbacks the page did not provide (the engine treats the refusal
/// as the best-effort fallback it is).
fn no_refuse() -> js_sys::Function {
    js_sys::Function::new_with_args(
        "",
        "return Promise.reject(new Error('the page did not provide this host callback'))",
    )
}

/// The crypto-backed fill for the SessionService's entropy hook.
fn js_rng_fill(bytes: &mut [u8]) -> bool {
    use engine_ports::Rng;
    JsRng.fill(bytes)
}
