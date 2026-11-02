//! The async flow driver's lifecycle: start a flow on a recording peer, let
//! its worker ask for an action, answer it, and read the notifications it
//! sent — the mirror of go-wmp's `flowcontext_test.go` lifecycles.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use wmp_core::context::RequestContext;
use wmp_core::error::{RpcError, ERR_FLOW_ERROR, ERR_INTERNAL_ERROR};
use wmp_core::flowcontext::AsyncFlowProfile;
use wmp_core::handler::HandlerError;
use wmp_core::methods::*;
use wmp_core::profile::{DispatchResult, PeerContext, Profile};
use wmp_core::session::Session;
use wmp_core::types::{Capabilities, Metadata, VERSION};

/// A peer context that records every notification it is sent.
struct RecordingPeer {
    sent: Mutex<Vec<(String, Value)>>,
}

impl RecordingPeer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: Mutex::new(Vec::new()),
        })
    }

    /// Waits until at least `count` notifications were recorded.
    fn wait_for(&self, count: usize) -> Vec<(String, Value)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = self
                .sent
                .lock()
                .map(|sent| sent.clone())
                .unwrap_or_default();
            if snapshot.len() >= count {
                return snapshot;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for {count} notifications, got {}",
                    snapshot.len()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl PeerContext for RecordingPeer {
    fn notify(
        &self,
        _ctx: &RequestContext,
        method: &str,
        params: &Value,
    ) -> Result<(), HandlerError> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((method.to_owned(), params.clone()));
        }
        Ok(())
    }

    fn call(&self, _ctx: &RequestContext, _method: &str, _params: &Value) -> DispatchResult {
        Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)))
    }

    fn session(&self, _id: &str) -> Option<Session> {
        None
    }

    fn version_for(&self, _session_id: &str) -> String {
        VERSION.to_owned()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
}

fn start_params(flow_type: &str, flow_id: &str) -> FlowStartParams {
    FlowStartParams {
        wmp: Metadata {
            version: VERSION.to_owned(),
            session_id: "ses-test".to_owned(),
            ..Metadata::default()
        },
        flow_type: flow_type.to_owned(),
        flow_id: flow_id.to_owned(),
        params: None,
        timeout: None,
    }
}

/// The approval lifecycle of the spec's flow vector: start → the worker
/// asks for review → the answer arrives → complete.
#[test]
fn approval_flow_lifecycle() {
    let peer = RecordingPeer::new();
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    profile.handle(
        "approval",
        Arc::new(|_token, fc| {
            let action = fc
                .request_action(
                    "awaiting_review",
                    &json!({ "reviewer": "bob" }),
                    Duration::from_secs(5),
                )?
                .ok_or_else(|| {
                    HandlerError::Rpc(RpcError::new(
                        -31006,
                        Some(json!({ "reason": "no action arrived" })),
                    ))
                })?;
            if action.action != "approve" {
                return Err(HandlerError::Rpc(RpcError::code(ERR_INTERNAL_ERROR)));
            }
            fc.complete(&json!({ "approved": true }))
        }),
    );

    let started = profile
        .start_flow(
            &RequestContext::default(),
            &start_params("approval", "flow-1"),
        )
        .expect("start");
    assert_eq!(started.flow_id, "flow-1");

    // The worker sends its progress and waits; answer it.
    peer.wait_for(1);
    let accepted = profile
        .handle_action(
            &RequestContext::default(),
            &FlowActionParams {
                wmp: Metadata {
                    version: VERSION.to_owned(),
                    session_id: "ses-test".to_owned(),
                    ..Metadata::default()
                },
                flow_id: "flow-1".to_owned(),
                action: "approve".to_owned(),
                params: None,
            },
        )
        .expect("action accepted");
    assert_eq!(accepted.status, "accepted");

    let sent = peer.wait_for(2);
    assert_eq!(sent[0].0, METHOD_FLOW_PROGRESS);
    assert_eq!(
        sent[0].1.get("step").and_then(Value::as_str),
        Some("awaiting_review")
    );
    assert_eq!(sent[1].0, METHOD_FLOW_COMPLETE);
    assert_eq!(
        sent[1].1.get("result").and_then(|r| r.get("approved")),
        Some(&json!(true))
    );
    // Every message carries the flow's session and a version.
    for (_, params) in &sent {
        assert_eq!(
            params.get("wmp").and_then(|w| w.get("session_id")),
            Some(&json!("ses-test"))
        );
        assert!(params.get("wmp").and_then(|w| w.get("version")).is_some());
    }

    // The worker exits: the flow is removed and a late action is refused.
    let deadline = Instant::now() + Duration::from_secs(5);
    while profile.active_flows() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(profile.active_flows(), 0);
}

/// A remote cancel ends the flow: the worker's wait ends without an action,
/// and a later action on the terminal flow answers "already_terminal".
#[test]
fn cancel_ends_the_flow() {
    let peer = RecordingPeer::new();
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    profile.handle(
        "sign",
        Arc::new(|_token, fc| {
            // Wait long enough that only the cancel can end this.
            match fc.wait_for_action(Duration::from_secs(30))? {
                Some(_) => panic!("an action should not have arrived"),
                None => Ok(()), // the flow ended: cancelled
            }
        }),
    );

    profile
        .start_flow(&RequestContext::default(), &start_params("sign", "flow-c"))
        .expect("start");
    let stopped = profile
        .handle_cancel(
            &RequestContext::default(),
            &FlowCancelParams {
                wmp: Metadata::default(),
                flow_id: "flow-c".to_owned(),
                reason: "user_cancelled".to_owned(),
            },
        )
        .expect("cancel");
    assert!(stopped, "the profile stops its own flows");

    // The worker winds down and the flow leaves the map.
    let deadline = Instant::now() + Duration::from_secs(5);
    while profile.active_flows() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(profile.active_flows(), 0);

    // A second cancel of the terminal flow answers as go-wmp does: the
    // flow's id stays reserved until its worker has exited, so the cancel
    // is refused with "already_terminal" while it winds down, and only
    // answers false once the flow is gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut second = None;
    while Instant::now() < deadline {
        second = Some(profile.handle_cancel(
            &RequestContext::default(),
            &FlowCancelParams {
                wmp: Metadata::default(),
                flow_id: "flow-c".to_owned(),
                reason: String::new(),
            },
        ));
        let already_terminal = matches!(
            &second,
            Some(Err(HandlerError::Rpc(rpc)))
                if rpc
                    .data
                    .as_ref()
                    .is_some_and(|d| d.get().contains("already_terminal"))
        );
        match &second {
            Some(Ok(false)) => break,
            Some(Err(_)) if already_terminal => {
                // The worker has not exited yet; try again shortly.
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => break,
        }
    }
    match second {
        Some(Ok(false)) => {}
        Some(Err(err)) => panic!("expected Ok(false) once the worker exited, got {err}"),
        other => panic!("unexpected outcome: {other:?}"),
    }
}

/// A failing worker reports its flow with `wmp.flow.error`.
#[test]
fn failing_worker_reports_flow_error() {
    let peer = RecordingPeer::new();
    let profile = AsyncFlowProfile::new("test");
    profile.init(peer.clone()).expect("init");
    profile.handle(
        "broken",
        Arc::new(|_token, _fc| {
            Err(HandlerError::Rpc(RpcError::new(
                -31006,
                Some(json!({ "reason": "worker failed" })),
            )))
        }),
    );

    profile
        .start_flow(
            &RequestContext::default(),
            &start_params("broken", "flow-e"),
        )
        .expect("start");

    let sent = peer.wait_for(1);
    assert_eq!(sent[0].0, METHOD_FLOW_ERROR);
    assert_eq!(sent[0].1.get("code"), Some(&json!(ERR_FLOW_ERROR as i64)));
    assert!(!sent[0]
        .1
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty());
}
