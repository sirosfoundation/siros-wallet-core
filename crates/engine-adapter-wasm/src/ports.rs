//! The JS-backed ports: the page's fetch behind the HttpClient port,
//! the wallet's UI callbacks behind the Host port, the PDP callback,
//! the browser clock and entropy, and a JS-optional persistence for
//! the flow stash (the authorization-code resume must survive a
//! same-tab redirect reload).
//!
//! JS futures are single-threaded — `JsFuture` holds an `Rc` — while
//! the port traits demand `Send` futures (the native SDK runs them on
//! a multithreaded executor). Every JS await goes through
//! [`via_spawn_local`]: the non-Send work runs on the JS event loop
//! via `spawn_local`, and a thread-safe oneshot channel hands the
//! answer back to the engine's executor.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use engine_ports::{
    AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
    DpopProofResult, EvaluationRequest, EvaluationResponse, Host, HostError, HttpClient, HttpError,
    HttpRequest, HttpResponse, KeyValue, KeyValueEntry, MatchParams, MatchResult, Pdp, PdpError,
    Rng, SignParams, SignResult, VpParams, VpResult,
};

/// Spawns a non-Send (JS) future on the JS event loop and hands its
/// answer back over a thread-safe channel. **A sync function, on
/// purpose**: the non-Send future is constructed in the caller's
/// frame, moved into the spawn, and gone before the caller's first
/// await — the caller's generator then holds only the Send receiver
/// across its awaits, which is what the Send-bounded port traits
/// demand. (An async wrapper would hold the JS future in its own
/// generator state and poison the whole chain.)
pub fn spawn_js<T: Send + 'static>(
    future: impl std::future::Future<Output = T> + 'static,
) -> futures::channel::oneshot::Receiver<T> {
    let (sender, receiver) = futures::channel::oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = sender.send(future.await);
    });
    receiver
}

/// Awaits a spawned JS task's answer.
pub async fn await_js<T: Send + 'static>(
    receiver: futures::channel::oneshot::Receiver<T>,
) -> Result<T, String> {
    receiver
        .await
        .map_err(|_| "the JS task was dropped".to_owned())
}

/// The JS shape of an engine HTTP request — the object the injected
/// fetch function receives.
#[derive(serde::Serialize)]
pub struct JsHttpRequest {
    /// The HTTP method.
    pub method: String,
    /// The URL.
    pub url: String,
    /// The headers, as a flat `[name, value, name, value, ...]` array.
    pub headers: Vec<String>,
    /// The body, as raw bytes.
    pub body: Vec<u8>,
    /// The fetch purpose the engine declared (for the page's
    /// logging and policy).
    pub purpose: String,
    /// The response size limit the engine declared.
    pub max_response_bytes: u64,
    /// The redirect policy the engine declared: `"none"` or
    /// `"max:N"`.
    pub redirects: String,
    /// Whether the engine allows plaintext http.
    pub allow_plaintext: bool,
    /// The timeout, in milliseconds.
    pub timeout_ms: u64,
}

/// The JS shape of the fetch answer: `{status, headers, body}`.
#[derive(serde::Deserialize)]
pub struct JsHttpResponse {
    /// The HTTP status.
    pub status: u16,
    /// The response headers, as a flat `[name, value, ...]` array.
    pub headers: Vec<String>,
    /// The body, as raw bytes.
    pub body: Vec<u8>,
}

fn js_error(reason: String) -> HttpError {
    HttpError::Transport(reason)
}

fn host_error(reason: String) -> HostError {
    HostError::Cannot(reason)
}

/// The page's fetch behind the HttpClient port. The JS side owns the
/// network — proxies, credentials and CSP workarounds are the page's.
pub struct JsFetchHttp {
    fetch: js_sys::Function,
}

impl JsFetchHttp {
    /// The port over the page's fetch function:
    /// `fetch(request) -> Promise<{status, headers, body}>`.
    pub fn new(fetch: js_sys::Function) -> Self {
        Self { fetch }
    }
}

#[async_trait::async_trait]
impl HttpClient for JsFetchHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let mut headers = Vec::with_capacity(request.headers.len() * 2);
        for (name, value) in &request.headers {
            headers.push(name.clone());
            headers.push(value.clone());
        }
        let js_request = JsHttpRequest {
            method: request.method,
            url: request.url,
            headers,
            body: request.body,
            purpose: format!("{:?}", request.purpose),
            max_response_bytes: request.max_response_bytes as u64,
            redirects: format!("{:?}", request.redirects),
            allow_plaintext: request.allow_plaintext,
            timeout_ms: request.timeout_ms,
        };
        let value = serde_wasm_bindgen::to_value(&js_request)
            .map_err(|err| js_error(format!("serialize the request: {err}")))?;

        let fetch = self.fetch.clone();
        await_js(spawn_js(async move {
            let promise = fetch
                .call1(&JsValue::NULL, &value)
                .map_err(|err| js_error(format!("the fetch call refused: {err:?}")))?;
            let answer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                .await
                .map_err(|err| js_error(format!("the fetch failed: {err:?}")))?;
            let response: JsHttpResponse =
                serde_wasm_bindgen::from_value(answer).map_err(|err| {
                    js_error(format!("the fetch answer is not the engine's shape: {err}"))
                })?;
            let mut headers = Vec::new();
            let flat = &response.headers;
            let mut index = 0;
            while index + 1 < flat.len() {
                let pair = (
                    flat.get(index).cloned().unwrap_or_default(),
                    flat.get(index + 1).cloned().unwrap_or_default(),
                );
                headers.push(pair);
                index += 2;
            }
            Ok(HttpResponse {
                status: response.status,
                headers,
                body: response.body,
            })
        }))
        .await
        .map_err(js_error)?
    }
}

/// The wallet's UI callbacks behind the Host port. Every callback
/// returns a Promise; the ask's parameters are plain JS objects of
/// the same shape the serde types serialize to.
pub struct JsHost {
    #[allow(missing_docs)]
    pub sign: js_sys::Function,
    #[allow(missing_docs)]
    pub r#match: js_sys::Function,
    #[allow(missing_docs)]
    pub consent: js_sys::Function,
    #[allow(missing_docs)]
    pub tx_code: js_sys::Function,
    #[allow(missing_docs)]
    pub open_authorization: js_sys::Function,
    #[allow(missing_docs)]
    pub vp: js_sys::Function,
    #[allow(missing_docs)]
    pub dpop_proof: js_sys::Function,
    #[allow(missing_docs)]
    pub attestation: js_sys::Function,
    #[allow(missing_docs)]
    pub progress: Option<js_sys::Function>,
}

impl JsHost {
    /// Calls a callback with the serialized ask, awaits its Promise
    /// on the JS event loop, and deserializes the answer.
    async fn call<T: serde::de::DeserializeOwned + Send + 'static>(
        function: &js_sys::Function,
        ask: &impl serde::Serialize,
    ) -> Result<T, HostError> {
        let value = serde_wasm_bindgen::to_value(ask)
            .map_err(|err| host_error(format!("serialize the ask: {err}")))?;
        let function = function.clone();
        await_js(spawn_js(async move {
            let promise = function
                .call1(&JsValue::NULL, &value)
                .map_err(|err| host_error(format!("the callback refused: {err:?}")))?;
            let answer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                .await
                .map_err(|err| host_error(format!("the callback failed: {err:?}")))?;
            serde_wasm_bindgen::from_value(answer).map_err(|err| {
                host_error(format!(
                    "the callback's answer is not the engine's shape: {err}"
                ))
            })
        }))
        .await
        .map_err(host_error)?
    }
}

#[async_trait::async_trait]
impl Host for JsHost {
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError> {
        Self::call(&self.sign, &params).await
    }

    async fn request_match(&self, params: MatchParams) -> Result<MatchResult, HostError> {
        Self::call(&self.r#match, &params).await
    }

    async fn request_consent(&self, params: ConsentParams) -> Result<ConsentResult, HostError> {
        Self::call(&self.consent, &params).await
    }

    async fn request_tx_code(&self, flow_id: &str) -> Result<String, HostError> {
        Self::call(&self.tx_code, &serde_json::json!({ "flow_id": flow_id })).await
    }

    async fn open_authorization(&self, flow_id: &str, url: &str) -> Result<(), HostError> {
        Self::call(
            &self.open_authorization,
            &serde_json::json!({ "flow_id": flow_id, "url": url }),
        )
        .await
    }

    async fn request_vp(&self, params: VpParams) -> Result<VpResult, HostError> {
        Self::call(&self.vp, &params).await
    }

    async fn request_dpop_proof(
        &self,
        params: DpopProofParams,
    ) -> Result<DpopProofResult, HostError> {
        Self::call(&self.dpop_proof, &params).await
    }

    async fn request_attestation(
        &self,
        params: AttestationParams,
    ) -> Result<AttestationResult, HostError> {
        Self::call(&self.attestation, &params).await
    }

    fn progress(&self, flow_id: &str, step: &str, detail: Option<String>) {
        if let Some(progress) = &self.progress {
            let payload = serde_json::json!({ "flow_id": flow_id, "step": step, "detail": detail });
            if let Ok(value) = serde_wasm_bindgen::to_value(&payload) {
                let _ = progress.call1(&JsValue::NULL, &value);
            }
        }
    }
}

/// The PDP behind a JS callback: `evaluate(request) ->
/// Promise<{trusted, decision?}>` — the page's trust proxy.
pub struct JsPdp {
    evaluate: js_sys::Function,
}

impl JsPdp {
    /// The PDP over the page's evaluate callback.
    pub fn new(evaluate: js_sys::Function) -> Self {
        Self { evaluate }
    }
}

#[async_trait::async_trait]
impl Pdp for JsPdp {
    async fn evaluate(&self, request: EvaluationRequest) -> Result<EvaluationResponse, PdpError> {
        let value = serde_wasm_bindgen::to_value(&request)
            .map_err(|err| PdpError::Error(format!("serialize the evaluation: {err}")))?;
        let evaluate = self.evaluate.clone();
        await_js(spawn_js(async move {
            let promise = evaluate
                .call1(&JsValue::NULL, &value)
                .map_err(|err| PdpError::Error(format!("the evaluate call refused: {err:?}")))?;
            let answer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                .await
                .map_err(|err| PdpError::Error(format!("the evaluate failed: {err:?}")))?;
            serde_wasm_bindgen::from_value(answer)
                .map_err(|err| PdpError::Error(format!("the evaluate answer is malformed: {err}")))
        }))
        .await
        .map_err(PdpError::Error)?
    }

    async fn resolve(
        &self,
        _request: engine_ports::ResolveRequest,
    ) -> Result<engine_ports::ResolveResponse, PdpError> {
        Err(PdpError::NotImplemented)
    }
}

/// The browser entropy: `crypto.getRandomValues`, through the global
/// this (browsers and Node both).
pub struct JsRng;

impl Rng for JsRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        let crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into());
        let Ok(crypto) = crypto else {
            return false;
        };
        if crypto.is_undefined() {
            return false;
        }
        let get_random_values = js_sys::Reflect::get(&crypto, &"getRandomValues".into()).ok();
        let Some(get_random_values) =
            get_random_values.and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        else {
            return false;
        };
        let array = js_sys::Uint8Array::new_with_length(buf.len() as u32);
        // The receiver is the crypto object: getRandomValues is a
        // prototype method, and Node's webcrypto refuses a NULL this
        // ("Illegal invocation").
        let filled = get_random_values
            .call1(&crypto, &array)
            .map(|value| value.is_object());
        if filled.unwrap_or(false) {
            array.copy_to(buf);
            true
        } else {
            false
        }
    }
}

/// The browser clock: `Date.now`.
pub struct JsClock;

#[async_trait::async_trait]
impl engine_ports::Clock for JsClock {
    fn now_unix(&self) -> i64 {
        (js_sys::Date::now() / 1000.0) as i64
    }

    async fn sleep(&self, duration_ms: u64) {
        // A real sleep on the JS event loop.
        let mut resolve_later = move |resolve: js_sys::Function, _: js_sys::Function| {
            web_stub_set_timeout(&resolve, duration_ms);
        };
        let promise = js_sys::Promise::new(&mut resolve_later);
        let _ = await_js(spawn_js(wasm_bindgen_futures::JsFuture::from(promise))).await;
    }
}

/// The setTimeout dance without pulling in all of web-sys: the global
/// setTimeout, available in every browser and Node.
fn web_stub_set_timeout(resolve: &js_sys::Function, duration_ms: u64) {
    let global = js_sys::global();
    let set_timeout = js_sys::Reflect::get(&global, &"setTimeout".into());
    if let Ok(set_timeout) = set_timeout {
        if let Ok(set_timeout) = set_timeout.dyn_into::<js_sys::Function>() {
            let _ = set_timeout.call2(
                &JsValue::NULL,
                resolve,
                &JsValue::from_f64(duration_ms as f64),
            );
        }
    }
}

/// The flow stash behind optional JS callbacks: `get(key) ->
/// Promise<string?>`, `put(key, value)`, `del(key)` — the
/// authorization-code resume survives a same-tab redirect when the
/// page persists (localStorage); without the callbacks the stash is
/// in-memory.
pub struct JsKeyValue {
    #[allow(missing_docs)]
    pub get: Option<js_sys::Function>,
    #[allow(missing_docs)]
    pub put: Option<js_sys::Function>,
    #[allow(missing_docs)]
    pub del: Option<js_sys::Function>,
    memory: std::sync::Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>,
}

impl JsKeyValue {
    /// The persistence over the page's optional callbacks.
    pub fn new(
        get: Option<js_sys::Function>,
        put: Option<js_sys::Function>,
        del: Option<js_sys::Function>,
    ) -> Self {
        Self {
            get,
            put,
            del,
            memory: std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
        }
    }
}

#[async_trait::async_trait]
impl KeyValue for JsKeyValue {
    async fn get(&self, key: &str) -> Option<KeyValueEntry> {
        if let Some(get) = &self.get {
            let value = serde_wasm_bindgen::to_value(&key).ok()?;
            let get = get.clone();
            let stored = await_js(spawn_js(async move {
                let promise = get.call1(&JsValue::NULL, &value).ok()?;
                let answer = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                    .await
                    .ok()?;
                let stored: Option<String> = serde_wasm_bindgen::from_value(answer).ok()?;
                Some(stored)
            }))
            .await
            .ok()??;
            return stored.map(|value| KeyValueEntry {
                value: value.into_bytes(),
                ttl_secs: None,
            });
        }
        self.memory
            .lock()
            .ok()?
            .get(key)
            .map(|value| KeyValueEntry {
                value: value.clone(),
                ttl_secs: None,
            })
    }

    async fn put(&self, key: &str, entry: KeyValueEntry) {
        if let Some(put) = &self.put {
            let key = serde_wasm_bindgen::to_value(&key);
            let value = String::from_utf8(entry.value)
                .ok()
                .and_then(|value| serde_wasm_bindgen::to_value(&value).ok());
            if let (Ok(key), Some(value)) = (key, value) {
                let put = put.clone();
                let _ = await_js(spawn_js(async move {
                    if let Ok(promise) = put.call2(&JsValue::NULL, &key, &value) {
                        let _ =
                            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                                .await;
                    }
                }))
                .await;
            }
            return;
        }
        if let Ok(mut memory) = self.memory.lock() {
            memory.insert(key.to_owned(), entry.value);
        }
    }

    async fn delete(&self, key: &str) {
        if let Some(del) = &self.del {
            let key = serde_wasm_bindgen::to_value(&key);
            if let Ok(key) = key {
                let del = del.clone();
                let _ = await_js(spawn_js(async move {
                    if let Ok(promise) = del.call1(&JsValue::NULL, &key) {
                        let _ =
                            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                                .await;
                    }
                }))
                .await;
            }
            return;
        }
        if let Ok(mut memory) = self.memory.lock() {
            memory.remove(key);
        }
    }
}

/// The no-op telemetry: the page observes through the progress
/// callback.
pub struct NoTelemetry;

impl engine_ports::Telemetry for NoTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}
