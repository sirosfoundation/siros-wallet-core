//! The step interpreter: one engine instance per vector, built from
//! `config`, running against the world built from `setup`; the script
//! of steps executes in order with the interleaving rules (the runner
//! contract).
//!
//! The engine is the real one — the runtime with both flow families
//! registered, the session service that grants the `flows` capability,
//! the peer with a recording transport — driven synchronously, exactly
//! as the in-process bridge drives it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::matchers::matches;
use crate::script::{Step, VectorFile};
use crate::world::{
    FixedClock, MemoryKv, NoTelemetry, ScriptedHost, ScriptedHttp, ScriptedPdp, SeededRng, World,
};

/// The result of one vector run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The vector passed.
    Pass,
    /// The vector failed, with the failing step and the difference.
    Fail(String),
    /// The vector was skipped, with the reason.
    Skip(String),
}

/// The summary of a whole run.
#[derive(Debug, Default)]
pub struct Report {
    /// The vectors that passed.
    pub passed: Vec<String>,
    /// The vectors that failed, with the reasons.
    pub failed: Vec<(String, String)>,
    /// The vectors skipped, with the reasons.
    pub skipped: Vec<(String, String)>,
    /// The counts by provenance.
    pub by_provenance: Vec<(String, usize)>,
}

impl Report {
    /// Records one verdict.
    pub fn record(&mut self, id: &str, provenance: &str, verdict: Verdict) {
        let mut counts: std::collections::BTreeMap<String, usize> =
            self.by_provenance.iter().cloned().collect();
        *counts.entry(provenance.to_owned()).or_insert(0) += 1;
        self.by_provenance = counts.into_iter().collect();
        match verdict {
            Verdict::Pass => self.passed.push(id.to_owned()),
            Verdict::Fail(reason) => self.failed.push((id.to_owned(), reason)),
            Verdict::Skip(reason) => self.skipped.push((id.to_owned(), reason)),
        }
    }
}

/// Runs one vector. The engine is built fresh: a peer with the session
/// service configured to grant the `flows` capability, the runtime
/// with both flow families registered, and the scripted world's ports.
pub fn run_vector(vector: &VectorFile) -> Verdict {
    // The go-observed sunset: a vector past its review date refuses to
    // gate unless it carries a written reason.
    if vector.provenance == "go-observed" {
        if let Some(review_by) = &vector.review_by {
            let today = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() / 86_400)
                .unwrap_or_default();
            if let Ok(expiry) = days_since_epoch(review_by) {
                if expiry < today && vector.review_reason.is_none() {
                    return Verdict::Skip(format!(
                        "go-observed vector past its review_by {review_by} with no review_reason"
                    ));
                }
            }
        }
    }

    let setup = vector.setup.clone().unwrap_or(Value::Null);
    let now_unix = setup
        .get("time")
        .and_then(Value::as_i64)
        .unwrap_or(1_700_000_000);
    let seed = setup
        .get("entropy_seed")
        .and_then(Value::as_u64)
        .unwrap_or(0x5eed);

    let world = World::new(vector.script.clone(), setup.clone(), now_unix);

    // The peer ↔ runtime cycle, broken with an interior-mutable slot:
    // the peer exists first (the runtime needs it for the flow
    // context), and its handler reaches the runtime once it exists —
    // the runtime the flows actually run on is the one holding the
    // REAL peer, so the flow notifications reach the recording
    // transport.
    let runtime_slot: Arc<RuntimeSlot> = Arc::new(RuntimeSlot::default());
    let store = Arc::new(wmp_core::session::MemorySessionStore::new());
    let service = match wmp_core::sessionservice::SessionService::new(
        wmp_core::sessionservice::SessionServiceConfig {
            store: Some(store.clone()),
            // The runner grants the flows capability the engine's
            // families gate on.
            supported: match flows_capability(16) {
                Ok(capabilities) => capabilities,
                Err(reason) => return Verdict::Fail(reason),
            },
            entropy: Some(Arc::new(|bytes: &mut [u8]| {
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = i as u8;
                }
                true
            })),
            ..wmp_core::sessionservice::SessionServiceConfig::default()
        },
    ) {
        Ok(service) => service,
        Err(err) => return Verdict::Fail(format!("session service config: {err}")),
    };
    let session_handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
        Arc::new(service),
        Arc::new(move || now_unix),
    ));

    let outgoing: Arc<Mutex<VecDeque<Value>>> = Arc::new(Mutex::new(VecDeque::new()));
    let handler = Arc::new(EngineHandler {
        session: session_handler,
        runtime: runtime_slot.clone(),
    });
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store)
        .transport(Arc::new(RecordingTransport {
            outgoing: outgoing.clone(),
        }))
        .build();

    // The ports and the runtime, over the real peer.
    let ports = Arc::new(engine_core::Ports {
        http: Arc::new(ScriptedHttp::new(world.clone())),
        clock: Arc::new(FixedClock::new(now_unix)),
        rng: Arc::new(SeededRng::new(seed)),
        host: Arc::new(ScriptedHost::new(world.clone())),
        pdp: Arc::new(ScriptedPdp::new(&setup)),
        kv: Arc::new(MemoryKv::new()),
        telemetry: Arc::new(NoTelemetry),
    });
    let runtime = Arc::new(engine_core::runtime::FlowRuntime::new(ports, peer.clone()));
    if let Err(err) = runtime.register(Arc::new(engine_core::oid4vci::Oid4vciFlow)) {
        return Verdict::Fail(format!("register the oid4vci family: {err}"));
    }
    if let Err(err) = runtime.register(Arc::new(engine_core::oid4vp::Oid4vpFlow)) {
        return Verdict::Fail(format!("register the oid4vp family: {err}"));
    }
    runtime_slot.set(runtime);

    // The interpreter.
    let ctx = wmp_core::context::RequestContext {
        principal: Some(wmp_core::principal::Principal::new("vector-runner", "")),
        ..wmp_core::context::RequestContext::default()
    };

    // The session: the runner's own infrastructure step, offering the
    // capabilities the flow families gate on.
    let create_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "wmp.session.create",
        "params": {
            "wmp": { "version": "0.1", "sender": "vector-runner" },
            "capabilities_offered": { "flows": { "max_concurrent": 16 } },
            "security": { "mode": "tls" }
        }
    });
    let Ok(create) = serde_json::to_vec(&create_body) else {
        return Verdict::Fail("serialize the session create".to_owned());
    };
    let session_id = match peer.handle_request_sync(&ctx, &create) {
        Ok(Some(response)) => {
            let parsed: Value = serde_json::from_slice(&response).unwrap_or(Value::Null);
            match parsed
                .pointer("/result/wmp/session_id")
                .and_then(Value::as_str)
            {
                Some(id) => id.to_owned(),
                None => {
                    return Verdict::Fail(format!(
                        "the session create answered no session: {}",
                        truncate(&parsed)
                    ))
                }
            }
        }
        _ => return Verdict::Fail("the session create failed".to_owned()),
    };

    let mut request_id = 2u64;
    let mut last_response: Option<Value> = None;

    for (index, step) in vector.script.iter().enumerate() {
        // A step that expects an event the engine never produced fails
        // before the next wmp step advances.
        if matches!(step, Step::WmpIn { .. } | Step::WmpOut { .. }) {
            if let Err(reason) = world.assert_interleaved_consumed(index) {
                return Verdict::Fail(format!("step {index} ({}) — {reason}", step_name(step)));
            }
        }

        match step {
            Step::WmpIn { wmp_in } => {
                let mut params = wmp_in.params.clone().unwrap_or(Value::Null);
                // The envelope: the runner stamps the session the
                // engine's messages belong to.
                if !params.is_object() {
                    params = json!({});
                }
                if let Some(object) = params.as_object_mut() {
                    let wmp = object.entry("wmp".to_owned()).or_insert_with(|| json!({}));
                    if let Some(envelope) = wmp.as_object_mut() {
                        envelope
                            .entry("session_id".to_owned())
                            .or_insert(json!(session_id));
                    }
                }
                // The binding references: a param value of "$path"
                // names a binding an earlier step captured (the
                // engine-generated OAuth state, the PKCE verifier),
                // so a two-call transcript asserts the SAME value
                // recurred without predicting it.
                if let Ok(bindings) = world.bindings().lock() {
                    substitute_bindings(&mut params, &bindings);
                }
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": wmp_in.method,
                    "params": params,
                });
                request_id += 1;
                let Ok(bytes) = serde_json::to_vec(&body) else {
                    return Verdict::Fail(format!("step {index}: serialize the message"));
                };
                match peer.handle_request_sync(&ctx, &bytes) {
                    Ok(Some(response)) => {
                        last_response =
                            Some(serde_json::from_slice(&response).unwrap_or(Value::Null));
                    }
                    Ok(None) => last_response = None,
                    Err(err) => {
                        // The refusal itself may be what the vector
                        // expects; record it as the response.
                        let rpc = err.to_rpc();
                        last_response = Some(json!({
                            "jsonrpc": "2.0",
                            "id": body.get("id").cloned().unwrap_or(Value::Null),
                            "error": { "code": rpc.code, "message": rpc.message }
                        }));
                    }
                }
            }
            Step::HttpOut { .. } | Step::HostAsk { .. } => {
                // Consumed by the engine during a wmp_in; nothing to do
                // at this position — the interleaving check above and
                // the world's matching do the work.
            }
            Step::WmpOut { wmp_out } => {
                if wmp_out.must_refuse.unwrap_or(false) {
                    // The refusal: the response to the last wmp_in must
                    // carry the error code.
                    let Some(response) = &last_response else {
                        return Verdict::Fail(format!(
                            "step {index}: no response to assert the refusal against"
                        ));
                    };
                    let actual = response.pointer("/error/code").and_then(Value::as_i64);
                    match (actual, wmp_out.error_code) {
                        (Some(actual), Some(expected)) if actual == expected => {
                            world.consume(index);
                        }
                        _ => {
                            return Verdict::Fail(format!(
                                "step {index}: expected the refusal {}, the response was {}",
                                wmp_out
                                    .error_code
                                    .map(|c| c.to_string())
                                    .unwrap_or_else(|| "any error".to_owned()),
                                truncate(response)
                            ))
                        }
                    }
                } else {
                    // The engine's next message out: a notification from
                    // the recording transport.
                    // The step consumes the oldest message.
                    let next = outgoing.lock().ok().and_then(|mut queue| queue.pop_front());
                    let Some(message) = next else {
                        return Verdict::Fail(format!(
                            "step {index}: the engine sent no {} message",
                            wmp_out.expect.method
                        ));
                    };
                    let method = message
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if method != wmp_out.expect.method {
                        return Verdict::Fail(format!(
                            "step {index}: expected {} the engine sent {}",
                            wmp_out.expect.method, method
                        ));
                    }
                    if let Some(expected_params) = &wmp_out.expect.params {
                        let actual_params = message.get("params").cloned().unwrap_or(Value::Null);
                        let mut bindings =
                            world.bindings().lock().unwrap_or_else(|p| p.into_inner());
                        if let Err(mismatch) =
                            matches(expected_params, &actual_params, &mut bindings)
                        {
                            return Verdict::Fail(format!("step {index}: {mismatch}"));
                        }
                    }
                    world.consume(index);
                }
            }
        }

        // The world's own failure (an unexpected request, a mismatched
        // expectation) surfaces as soon as it happened.
        if let Some(reason) = world.failure() {
            return Verdict::Fail(reason);
        }
    }

    // Every event step was satisfied.
    if let Err(reason) = world.assert_all_consumed() {
        return Verdict::Fail(reason);
    }
    Verdict::Pass
}

/// Replaces `$path` string values with the binding they name.
fn substitute_bindings(value: &mut Value, bindings: &crate::matchers::Bindings) {
    match value {
        Value::Object(object) => {
            for member in object.values_mut() {
                substitute_bindings(member, bindings);
            }
        }
        Value::Array(array) => {
            for member in array.iter_mut() {
                substitute_bindings(member, bindings);
            }
        }
        Value::String(text) => {
            if let Some(path) = text.strip_prefix('$') {
                if let Some(bound) = bindings.get(path) {
                    *value = bound.clone();
                }
            }
        }
        _ => {}
    }
}

/// The step's name, for failure messages.
fn step_name(step: &Step) -> &'static str {
    match step {
        Step::WmpIn { .. } => "wmp_in",
        Step::HttpOut { .. } => "http_out",
        Step::HostAsk { .. } => "host_ask",
        Step::WmpOut { .. } => "wmp_out",
    }
}

/// A short failure-safe view of a message.
fn truncate(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 300 {
        format!("{}…", &text[..300])
    } else {
        text
    }
}

/// Days since the epoch for a YYYY-MM-DD date (the civil-days
/// algorithm).
fn days_since_epoch(date: &str) -> Result<u64, ()> {
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let year: i64 = parts
        .first()
        .copied()
        .unwrap_or_default()
        .parse()
        .map_err(|_| ())?;
    let month: i64 = parts
        .get(1)
        .copied()
        .unwrap_or_default()
        .parse()
        .map_err(|_| ())?;
    let day: i64 = parts
        .get(2)
        .copied()
        .unwrap_or_default()
        .parse()
        .map_err(|_| ())?;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        Err(())
    } else {
        Ok(days as u64)
    }
}

/// The flows capability the runner grants.
fn flows_capability(max_concurrent: i64) -> Result<wmp_core::types::Capabilities, String> {
    serde_json::from_value(json!({ "flows": { "max_concurrent": max_concurrent } }))
        .map_err(|err| format!("the flows capability does not serialize: {err}"))
}

// ─── The engine's handler and plumbing ────────────────────────────────────

/// The runtime slot: the peer exists before the runtime does (the
/// runtime needs the peer), so the handler reaches the runtime through
/// this once it is built.
struct RuntimeSlot(Mutex<Option<Arc<engine_core::runtime::FlowRuntime>>>);

impl Default for RuntimeSlot {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl RuntimeSlot {
    fn set(&self, runtime: Arc<engine_core::runtime::FlowRuntime>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(runtime);
        }
    }

    fn get(&self) -> Option<Arc<engine_core::runtime::FlowRuntime>> {
        self.0.lock().ok().and_then(|slot| slot.clone())
    }
}

/// The engine's handler: the session methods delegate to the
/// SessionHandler, the flow methods to the runtime.
struct EngineHandler {
    session: Arc<wmp_core::sessionservice::SessionHandler>,
    runtime: Arc<RuntimeSlot>,
}

impl wmp_core::handler::Handler for EngineHandler {
    fn session_store(&self) -> Option<Arc<dyn wmp_core::session::SessionStore>> {
        self.session.session_store()
    }

    fn session_create(
        &self,
        ctx: &wmp_core::context::RequestContext,
        params: &wmp_core::methods::SessionCreateParams,
    ) -> Result<wmp_core::methods::SessionCreateResult, wmp_core::handler::HandlerError> {
        self.session.session_create(ctx, params)
    }

    fn session_resume(
        &self,
        ctx: &wmp_core::context::RequestContext,
        params: &wmp_core::methods::SessionResumeParams,
    ) -> Result<wmp_core::methods::SessionResumeResult, wmp_core::handler::HandlerError> {
        self.session.session_resume(ctx, params)
    }

    fn session_close(
        &self,
        ctx: &wmp_core::context::RequestContext,
        params: &wmp_core::methods::SessionCloseParams,
    ) {
        self.session.session_close(ctx, params)
    }

    fn flow_start(
        &self,
        ctx: &wmp_core::context::RequestContext,
        params: &wmp_core::methods::FlowStartParams,
    ) -> Result<wmp_core::methods::FlowStartResult, wmp_core::handler::HandlerError> {
        let Some(runtime) = self.runtime.get() else {
            return Err(
                wmp_core::error::RpcError::code(wmp_core::error::ERR_METHOD_NOT_FOUND).into(),
            );
        };
        let runtime = runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.start_flow(&ctx, &params).await })
        })
    }

    fn flow_action(
        &self,
        ctx: &wmp_core::context::RequestContext,
        params: &wmp_core::methods::FlowActionParams,
    ) -> Result<wmp_core::methods::FlowActionResult, wmp_core::handler::HandlerError> {
        let Some(runtime) = self.runtime.get() else {
            return Err(
                wmp_core::error::RpcError::code(wmp_core::error::ERR_METHOD_NOT_FOUND).into(),
            );
        };
        let runtime = runtime.clone();
        let ctx = ctx.clone();
        let params = params.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async move { runtime.handle_action(&ctx, &params).await })
        })
    }
}

/// The recording transport: every outgoing message is parsed and kept
/// for the wmp_out steps.
struct RecordingTransport {
    outgoing: Arc<Mutex<VecDeque<Value>>>,
}

impl wmp_core::transport::Transport for RecordingTransport {
    fn read_message(&self) -> Result<Vec<u8>, wmp_core::transport::TransportError> {
        // The runner never reads: the engine is driven synchronously.
        Ok(Vec::new())
    }

    fn write_message(&self, data: &[u8]) -> Result<(), wmp_core::transport::TransportError> {
        let parsed = serde_json::from_slice::<Value>(data).unwrap_or(Value::Null);
        if let Ok(mut outgoing) = self.outgoing.lock() {
            outgoing.push_back(parsed);
        }
        Ok(())
    }

    fn close(&self) -> Result<(), wmp_core::transport::TransportError> {
        Ok(())
    }
}
