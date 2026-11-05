//! The sub-flow lifecycle: a flow's worker requests a nested flow at a
//! simulated responder, which completes, refuses or ignores it — the mirror
//! of go-wmp's `subflow_test.go` behaviours.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use wmp_core::context::RequestContext;
use wmp_core::error::RpcError;
use wmp_core::flowcontext::AsyncFlowProfile;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::profile::{DispatchResult, PeerContext, Profile};
use wmp_core::registry::Registry;
use wmp_core::session::Session;
use wmp_core::subflow::SubFlowRequestError;
use wmp_core::types::{Metadata, VERSION};

/// How the simulated responder answers a `wmp.flow.start`.
type StartAnswer = Box<dyn Fn(&str, &Value) -> Result<Value, HandlerError> + Send + Sync>;

/// The simulated remote peer: answers calls as the test directs and claims
/// sub-flow routes like the real one does.
struct ResponderPeer {
    /// How to answer a `wmp.flow.start`, with the params it was sent.
    start_answer: Mutex<StartAnswer>,
    /// The flow ids `wmp.flow.cancel` was asked to cancel.
    cancelled: Mutex<Vec<String>>,
    registry: Arc<Registry>,
    entropy: AtomicU64,
    /// The child route this responder completes when it accepts a start:
    /// the wallet notifying `wmp.flow.complete` over the transport, played
    /// in-process through the claimed profile. Only the completing peer
    /// carries one — the refusing and ignoring peers never complete the
    /// child (their start answers are a refusal, or a bare acceptance
    /// the child never follows).
    completes: Mutex<Option<(String, Arc<dyn Profile>)>>,
    /// Whether an accepted start completes the child (completing_with
    /// only).
    completes_on_start: bool,
    /// The fire-and-forget messages the parent sent this peer — the
    /// parent's own `wmp.flow.complete` lands here, the observable
    /// completion the assertions read.
    notifications: Mutex<Vec<(String, Value)>>,
}

impl ResponderPeer {
    fn completing_with(result: Value) -> Arc<Self> {
        let result = Arc::new(result);
        Arc::new(Self {
            start_answer: Mutex::new(Box::new(move |_flow_id, _params| Ok((*result).clone()))),
            cancelled: Mutex::new(Vec::new()),
            registry: Arc::new(Registry::new()),
            entropy: AtomicU64::new(0),
            completes: Mutex::new(None),
            completes_on_start: true,
            notifications: Mutex::new(Vec::new()),
        })
    }

    fn refusing(code: i32, data: Value) -> Arc<Self> {
        let data = Arc::new(data);
        Arc::new(Self {
            start_answer: Mutex::new(Box::new(move |_flow_id, _params| {
                Err(HandlerError::Rpc(RpcError::new(
                    code,
                    Some((*data).clone()),
                )))
            })),
            cancelled: Mutex::new(Vec::new()),
            registry: Arc::new(Registry::new()),
            entropy: AtomicU64::new(0),
            completes: Mutex::new(None),
            completes_on_start: false,
            notifications: Mutex::new(Vec::new()),
        })
    }

    fn ignoring() -> Arc<Self> {
        Arc::new(Self {
            // The start is accepted but the sub-flow never completes.
            start_answer: Mutex::new(Box::new(|_flow_id, _params| Ok(json!({})))),
            cancelled: Mutex::new(Vec::new()),
            registry: Arc::new(Registry::new()),
            entropy: AtomicU64::new(0),
            completes: Mutex::new(None),
            completes_on_start: false,
            notifications: Mutex::new(Vec::new()),
        })
    }

    fn cancels(&self) -> Vec<String> {
        self.cancelled.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// The fire-and-forget messages the parent sent, as (method, params).
    fn sent(&self) -> Vec<(String, Value)> {
        self.notifications
            .lock()
            .map(|n| n.clone())
            .unwrap_or_default()
    }
}

impl PeerContext for ResponderPeer {
    fn notify(
        &self,
        _ctx: &RequestContext,
        method: &str,
        params: &Value,
    ) -> Result<(), HandlerError> {
        // Recorded, not ignored: the parent's own wmp.flow.complete is the
        // observable completion the assertions read.
        if let Ok(mut notifications) = self.notifications.lock() {
            notifications.push((method.to_owned(), params.clone()));
        }
        Ok(())
    }

    fn call(&self, _ctx: &RequestContext, method: &str, params: &Value) -> DispatchResult {
        match method {
            METHOD_FLOW_START => {
                let flow_id = params
                    .get("flow_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let answer = self
                    .start_answer
                    .lock()
                    .map(|answer| answer(&flow_id, params))
                    .unwrap_or_else(|_| Err(HandlerError::Rpc(RpcError::code(-32603))));
                // The wallet completes the child once its start is
                // accepted — `wmp.flow.complete` over the transport,
                // played in-process through the claimed profile. The
                // completion carries the fixed result as the flow's
                // result; the start answer itself is only the
                // acknowledgement the parent keeps.
                if self.completes_on_start && answer.is_ok() {
                    let route = self
                        .completes
                        .lock()
                        .ok()
                        .and_then(|mut completes| completes.take());
                    if let Some((child, profile)) = route {
                        // The fixed result as the flow's result member: the
                        // RawValue the parent's request returns.
                        let result = match &answer {
                            Ok(value) => {
                                serde_json::value::RawValue::from_string(value.to_string()).ok()
                            }
                            Err(_) => None,
                        };
                        profile.handle_complete(
                            &RequestContext::default(),
                            &FlowCompleteParams {
                                wmp: Metadata::default(),
                                flow_id: child,
                                result,
                            },
                        );
                    }
                }
                answer.map(Some)
            }
            METHOD_FLOW_CANCEL => {
                let flow_id = params
                    .get("flow_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let response = json!({
                    "wmp": { "version": VERSION },
                    "flow_id": flow_id,
                    "status": "cancelled",
                });
                if let Ok(mut cancelled) = self.cancelled.lock() {
                    cancelled.push(flow_id);
                }
                Ok(Some(response))
            }
            _ => Err(HandlerError::Rpc(RpcError::code(-32601))),
        }
    }

    fn session(&self, _id: &str) -> Option<Session> {
        None
    }

    fn claim_flow_route(
        &self,
        flow_id: &str,
        session_id: &str,
        handler: Arc<dyn Profile>,
    ) -> Option<wmp_core::profile::Claim> {
        // Keep the route: a peer that completes its child notifies the
        // completion through it, as the wallet does over the transport.
        if let Ok(mut completes) = self.completes.lock() {
            *completes = Some((flow_id.to_owned(), handler.clone()));
        }
        self.registry.claim_flow(flow_id, session_id, handler)
    }

    fn entropy(&self) -> Option<wmp_core::sessionservice::EntropyFn> {
        let counter = Arc::new(AtomicU64::new(self.entropy.load(Ordering::SeqCst)));
        Some(Arc::new(move |bytes: &mut [u8]| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (n >> (i % 8)) as u8;
            }
            true
        }))
    }
}

fn parent_flow_id() -> String {
    "flow-parent".to_owned()
}

/// A parent flow that requests a sub-flow and returns its result as its own
/// completion, through a peer that completes the child with a fixed result.
#[test]
fn sub_flow_completes() {
    let peer = ResponderPeer::completing_with(json!({ "signature": "proof-1" }));
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    profile.handle(
        "orchestrator",
        Arc::new(|_token, fc| {
            let result = fc
                .request_sub_flow(
                    "sign",
                    &json!({ "document": "doc" }),
                    Duration::from_secs(5),
                )
                .map_err(|err| {
                    HandlerError::Rpc(RpcError::new(
                        -32603,
                        Some(json!({ "reason": err.to_string() })),
                    ))
                })?;
            let Some(result) = result else {
                return Err(HandlerError::Rpc(RpcError::code(-32603)));
            };
            let signed: Value = serde_json::from_str(result.get())
                .map_err(|_| HandlerError::Rpc(RpcError::code(-32603)))?;
            fc.complete(&signed)
        }),
    );

    let started = profile
        .start_flow(
            &RequestContext::default(),
            &FlowStartParams {
                wmp: Metadata {
                    version: VERSION.to_owned(),
                    session_id: "ses-test".to_owned(),
                    ..Metadata::default()
                },
                flow_type: "orchestrator".to_owned(),
                flow_id: parent_flow_id(),
                params: None,
                timeout: None,
            },
        )
        .expect("start");
    assert_eq!(started.flow_type, "orchestrator");

    // The parent's worker exits once its sub-flow completed it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while profile.active_flows() > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        profile.active_flows(),
        0,
        "the parent must end once its sub-flow completed it"
    );

    // The completion content: the parent completed with the child's
    // fixed result as its own (the worker's fc.complete(&signed)), not
    // merely timed out and tore down.
    let sent = peer.sent();
    let completed: Vec<&(String, Value)> = sent
        .iter()
        .filter(|(method, _)| method == METHOD_FLOW_COMPLETE)
        .collect();
    assert_eq!(
        completed.len(),
        1,
        "the parent sent exactly one completion: {sent:?}"
    );
    let (_, params) = completed[0];
    assert_eq!(params["flow_id"], json!(parent_flow_id()));
    assert_eq!(params["result"], json!({ "signature": "proof-1" }));
}

/// A responder that refuses the start: the sub-flow request reports the
/// refusal with the peer's code, and the parent worker sees the error.
#[test]
fn sub_flow_refused_is_reported() {
    let peer = ResponderPeer::refusing(-31005, json!({ "unsupported": "sign" }));
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    let refusal = Arc::new(Mutex::new(None::<SubFlowRequestError>));
    let refusal_for_worker = refusal.clone();
    profile.handle(
        "orchestrator",
        Arc::new(move |_token, fc| {
            match fc.request_sub_flow("sign", &json!({}), Duration::from_secs(5)) {
                Ok(_) => panic!("the refusal should not have produced a result"),
                Err(err) => {
                    *refusal_for_worker.lock().expect("lock") = Some(err);
                }
            }
            Ok(())
        }),
    );

    profile
        .start_flow(
            &RequestContext::default(),
            &FlowStartParams {
                wmp: Metadata {
                    version: VERSION.to_owned(),
                    session_id: "ses-test".to_owned(),
                    ..Metadata::default()
                },
                flow_type: "orchestrator".to_owned(),
                flow_id: parent_flow_id(),
                params: None,
                timeout: None,
            },
        )
        .expect("start");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut seen = None;
    while std::time::Instant::now() < deadline {
        if let Some(err) = refusal.lock().ok().and_then(|mut r| r.take()) {
            seen = Some(err);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let seen = seen.expect("the worker should have reported the refusal");
    assert!(matches!(seen, SubFlowRequestError::Refused(refused) if refused.code == -31005));
}

/// A responder that accepts the start but never completes the sub-flow: the
/// request times out and asks the peer to cancel the sub-flow, so no
/// sub-flow outlives its parent.
#[test]
fn sub_flow_timeout_cancels_the_child() {
    let peer = ResponderPeer::ignoring();
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    profile.handle(
        "orchestrator",
        Arc::new(|_token, fc| {
            match fc.request_sub_flow("sign", &json!({}), Duration::from_millis(150)) {
                Ok(_) => panic!("an ignored sub-flow should not have produced a result"),
                Err(SubFlowRequestError::Timeout) => {}
                Err(other) => panic!("expected a timeout, got {other}"),
            }
            Ok(())
        }),
    );

    profile
        .start_flow(
            &RequestContext::default(),
            &FlowStartParams {
                wmp: Metadata {
                    version: VERSION.to_owned(),
                    session_id: "ses-test".to_owned(),
                    ..Metadata::default()
                },
                flow_type: "orchestrator".to_owned(),
                flow_id: parent_flow_id(),
                params: None,
                timeout: None,
            },
        )
        .expect("start");

    // The worker exits; the cancel reached the peer after the start's
    // answer, so it cannot have overtaken the start.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while profile.active_flows() > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(profile.active_flows(), 0);

    let cancel_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while peer.cancels().is_empty() && std::time::Instant::now() < cancel_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let cancels = peer.cancels();
    assert_eq!(cancels.len(), 1, "one cancel, for the child flow id");
    assert!(
        cancels[0].starts_with("flow-parent-sign-"),
        "the child id is parent-type-hex: {}",
        cancels[0]
    );
}
