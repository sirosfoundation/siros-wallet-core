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
pub mod ports;

use wasm_bindgen::prelude::*;

use dispatch::Dispatcher;
use ports::{JsClock, JsFetchHttp, JsHost, JsKeyValue, JsPdp, JsRng, NoTelemetry};

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
}

#[wasm_bindgen]
impl WasmEngine {
    /// Builds the engine over the page's callbacks.
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<WasmEngine, JsValue> {
        let fetch = required(&config, "fetch")?;
        let host = member(&config, "host")?;
        let pdp = member(&config, "pdp")?;

        let js_host = JsHost {
            sign: required(&host, "sign")?,
            r#match: optional(&host, "match").unwrap_or_else(no_refuse),
            consent: optional(&host, "consent").unwrap_or_else(no_refuse),
            tx_code: optional(&host, "txCode").unwrap_or_else(no_refuse),
            open_authorization: optional(&host, "openAuthorization").unwrap_or_else(no_refuse),
            vp: optional(&host, "vp").unwrap_or_else(no_refuse),
            dpop_proof: optional(&host, "dpopProof").unwrap_or_else(no_refuse),
            attestation: optional(&host, "attestation").unwrap_or_else(no_refuse),
            progress: optional(&host, "progress"),
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
            host: std::sync::Arc::new(js_host),
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

        Ok(WasmEngine { dispatcher })
    }

    /// Handles one WMP method call: the method name and the params
    /// object exactly as the wire carries them. The Promise resolves
    /// with the method's result, or rejects with the JSON-RPC error
    /// object `{code, message, data?}`.
    pub async fn request(&self, method: String, params: JsValue) -> Result<JsValue, JsValue> {
        let params: serde_json::Value = serde_wasm_bindgen::from_value(params)
            .map_err(|err| rpc_error(wmp_core::error::ERR_INVALID_PARAMS, &err.to_string()))?;
        match self.dispatcher.request(&method, &params).await {
            Ok(result) => serde_wasm_bindgen::to_value(&result)
                .map_err(|err| rpc_error(wmp_core::error::ERR_INTERNAL_ERROR, &err.to_string())),
            Err(err) => {
                let rpc = err.to_rpc();
                Err(rpc_error(rpc.code, &rpc.message))
            }
        }
    }
}

/// A JSON-RPC error object for the rejections.
fn rpc_error(code: i32, message: &str) -> JsValue {
    let error = serde_json::json!({ "code": code, "message": message });
    serde_wasm_bindgen::to_value(&error)
        .unwrap_or_else(|_| js_sys::wasm_bindgen::JsValue::from_str(message))
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
