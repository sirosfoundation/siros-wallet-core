//! The JSON-RPC dispatcher: the WMP surface the browser drives — the
//! session methods and the flow methods, routed to the SessionService
//! and the FlowRuntime the same way the server adapter's EngineHandler
//! routes them, but native-async (the browser has no `block_in_place`
//! to bridge through).
//!
//! The dispatcher is plain Rust over `serde_json::Value` — no wasm
//! types — so the routing, the capability gate, and the session
//! plumbing are testable on the host target exactly as they run in the
//! browser.

use std::sync::Arc;

use wmp_core::context::RequestContext;
use wmp_core::error::RpcError;
use wmp_core::handler::{Handler, HandlerError};
use wmp_core::methods::*;
use wmp_core::session::SessionStore;
use wmp_core::sessionservice::{SessionService, SessionServiceConfig};

use engine_core::runtime::FlowRuntime;

/// The session methods' principal: the page's wallet. WMP requires an
/// authenticated principal to own a session; the browser wallet is it.
const PRINCIPAL: &str = "wasm-wallet";

/// The engine behind the JS surface: the session service, the runtime
/// with both flow families registered, and the session store they
/// share.
pub struct Dispatcher {
    sessions: Arc<wmp_core::sessionservice::SessionHandler>,
    runtime: Arc<FlowRuntime>,
    store: Arc<dyn SessionStore>,
}

impl Dispatcher {
    /// Builds the dispatcher over the given ports, with the page's
    /// clock and entropy closures (the browser's `Date.now` and
    /// `crypto.getRandomValues`; the tests inject fixed ones). The
    /// session store is the in-memory one — a page reload is a new
    /// wallet session; the resumption path is the client's to persist.
    pub fn new(
        ports: Arc<engine_core::Ports>,
        clock: wmp_core::sessionservice::Clock,
        entropy: wmp_core::sessionservice::EntropyFn,
    ) -> Result<Self, String> {
        let store: Arc<dyn SessionStore> = Arc::new(wmp_core::session::MemorySessionStore::new());

        let service = SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            // The browser wallet offers the flows capability; the
            // engine's families gate on it.
            supported: flows_capability(16)?,
            entropy: Some(entropy),
            ..SessionServiceConfig::default()
        })
        .map_err(|err| format!("the session service config: {err}"))?;

        let service = Arc::new(service);

        let session_handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
            service.clone(),
            clock.clone(),
        ));
        let peer = wmp_core::peer::PeerBuilder::new(session_handler.clone())
            .session_store(store.clone())
            .build();

        let runtime = Arc::new(FlowRuntime::new(ports, peer));
        runtime
            .register(Arc::new(engine_core::oid4vci::Oid4vciFlow))
            .map_err(|err| format!("register the oid4vci family: {err}"))?;
        runtime
            .register(Arc::new(engine_core::oid4vp::Oid4vpFlow))
            .map_err(|err| format!("register the oid4vp family: {err}"))?;

        let _ = clock.clone();
        Ok(Self {
            sessions: session_handler,
            runtime,
            store,
        })
    }

    /// Handles one JSON-RPC message: the params as the caller sends
    /// them (the `params` member of the envelope), the method name,
    /// and the raw envelope's session for the request context. The
    /// answer is the JSON-RPC result value, or the error the method
    /// refused with.
    pub async fn request(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, DispatchError> {
        let ctx = self.context_for(params);

        match method {
            "wmp.session.create" => {
                let params: SessionCreateParams = Self::typed(params)?;
                self.sessions
                    .session_create(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.session.resume" => {
                let params: SessionResumeParams = Self::typed(params)?;
                self.sessions
                    .session_resume(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.session.close" => {
                let params: SessionCloseParams = Self::typed(params)?;
                self.sessions.session_close(&ctx, &params);
                Ok(serde_json::Value::Null)
            }
            "wmp.session.authenticate" => {
                let params: SessionAuthenticateParams = Self::typed(params)?;
                self.sessions
                    .session_authenticate(&ctx, &params)
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.start" => {
                let params: FlowStartParams = Self::typed(params)?;
                self.runtime
                    .start_flow(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.action" => {
                let params: FlowActionParams = Self::typed(params)?;
                self.runtime
                    .handle_action(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            "wmp.flow.cancel" => {
                let params: FlowCancelParams = Self::typed(params)?;
                self.runtime
                    .handle_cancel(&ctx, &params)
                    .await
                    .map(|result| serde_json::to_value(&result).unwrap_or_default())
                    .map_err(DispatchError::from)
            }
            // The notifications the wallet host sends back: no result,
            // and the flow registry's hygiene (a completion, an error
            // or a cancel unregisters the flow).
            "wmp.flow.progress" => {
                let params: FlowProgressParams = Self::typed(params)?;
                self.runtime.handle_progress(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            "wmp.flow.complete" => {
                let params: FlowCompleteParams = Self::typed(params)?;
                self.runtime.handle_complete(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            "wmp.flow.error" => {
                let params: FlowErrorParams = Self::typed(params)?;
                self.runtime.handle_error(&ctx, &params).await;
                Ok(serde_json::Value::Null)
            }
            other => Err(DispatchError::MethodNotFound(other.to_owned())),
        }
    }

    /// Deserializes the typed params, refusing malformed input the way
    /// the peer does.
    fn typed<T: serde::de::DeserializeOwned>(
        params: &serde_json::Value,
    ) -> Result<T, DispatchError> {
        serde_json::from_value(params.clone())
            .map_err(|err| DispatchError::InvalidParams(err.to_string()))
    }

    /// The request context: the wallet's principal, with the session
    /// resolved from the envelope the way the peer resolves it —
    /// everything the capability gate needs.
    fn context_for(&self, params: &serde_json::Value) -> RequestContext {
        let mut ctx = RequestContext {
            principal: Some(wmp_core::principal::Principal::new(PRINCIPAL, "")),
            ..RequestContext::default()
        };
        if let Some(session_id) = params
            .get("wmp")
            .and_then(|wmp| wmp.get("session_id"))
            .and_then(|id| id.as_str())
        {
            if !session_id.is_empty() {
                if let Some(session) = self.store.get(session_id) {
                    ctx.session = Some(session);
                }
            }
        }
        ctx
    }
}

/// Why a dispatch refused.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// An unknown method.
    #[error("wmp: method not found: {0}")]
    MethodNotFound(String),
    /// Malformed params.
    #[error("wmp: invalid params: {0}")]
    InvalidParams(String),
    /// The handler refused: the WMP error to answer with.
    #[error("{0}")]
    Handler(#[from] HandlerError),
}

impl DispatchError {
    /// The JSON-RPC error object the refusal answers with.
    pub fn to_rpc(&self) -> RpcError {
        match self {
            Self::MethodNotFound(_) => RpcError::code(wmp_core::error::ERR_METHOD_NOT_FOUND),
            Self::InvalidParams(reason) => RpcError::new(
                wmp_core::error::ERR_INVALID_PARAMS,
                Some(serde_json::json!({ "reason": reason })),
            ),
            Self::Handler(err) => err.to_rpc(),
        }
    }
}

/// The flows capability the dispatcher grants.
fn flows_capability(max_concurrent: i64) -> Result<wmp_core::types::Capabilities, String> {
    serde_json::from_value(serde_json::json!({ "flows": { "max_concurrent": max_concurrent } }))
        .map_err(|err| format!("the flows capability does not serialize: {err}"))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! The dispatcher on the host target: the same routing, capability
    //! gate and session plumbing the browser runs, driven with the
    //! conformance runner's scripted world — the pre-authorized
    //! issuance, end to end, over the JSON-RPC surface.

    use super::*;
    use engine_conformance::world::{
        FixedClock, MemoryKv, NoTelemetry, ScriptedHost, ScriptedHttp, ScriptedPdp, SeededRng,
        World,
    };

    fn dispatcher(script: serde_json::Value) -> Dispatcher {
        let world = World::new(
            serde_json::from_value(script).unwrap_or_default(),
            serde_json::json!({}),
            1_700_000_000,
        );
        Dispatcher::new(
            Arc::new(engine_core::Ports {
                http: Arc::new(ScriptedHttp::new(world.clone())),
                clock: Arc::new(FixedClock::new(1_700_000_000)),
                rng: Arc::new(SeededRng::new(0x5eed)),
                host: Arc::new(ScriptedHost::new(world)),
                pdp: Arc::new(ScriptedPdp::new(&serde_json::json!({}))),
                kv: Arc::new(MemoryKv::new()),
                telemetry: Arc::new(NoTelemetry),
            }),
            Arc::new(|| 1_700_000_000),
            Arc::new(|bytes: &mut [u8]| {
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = i as u8;
                }
                true
            }),
        )
        .expect("the dispatcher builds")
    }

    #[tokio::test]
    async fn the_pre_authorized_issuance_runs_over_the_surface() {
        let script = serde_json::json!(
        [
          {
            "wmp_in": {
              "method": "wmp.flow.start",
              "params": {
                "flow_id": "flow-wasm-1",
                "flow_type": "oid4vci",
                "params": {
                  "credential_issuer": "https://issuer.example",
                  "credential_configuration_ids": [
                    "UniversityDegree"
                  ],
                  "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                      "pre-authorized_code": "preauth-wasm-1"
                    }
                  }
                }
              }
            }
          },
          {
            "http_out": {
              "expect": {
                "method": "GET",
                "url": "https://issuer.example/.well-known/openid-credential-issuer",
                "purpose": "IssuerMetadata"
              },
              "reply": {
                "status": 200,
                "body": {
                  "credential_issuer": "https://issuer.example",
                  "authorization_servers": [
                    "https://as.example"
                  ],
                  "credential_configurations_supported": {
                    "UniversityDegree": {
                      "scope": "openid"
                    }
                  }
                }
              }
            }
          },
          {
            "http_out": {
              "expect": {
                "method": "GET",
                "url": "https://as.example/.well-known/oauth-authorization-server",
                "purpose": "AsMetadata"
              },
              "reply": {
                "status": 200,
                "body": {
                  "issuer": "https://as.example",
                  "token_endpoint": "https://as.example/token"
                }
              }
            }
          },
          {
            "http_out": {
              "expect": {
                "method": "POST",
                "url": "https://as.example/token",
                "purpose": "Token",
                "form": {
                  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                  "pre-authorized_code": "preauth-wasm-1"
                }
              },
              "reply": {
                "status": 200,
                "body": {
                  "access_token": "at-wasm-1",
                  "token_type": "Bearer",
                  "c_nonce": "n-wasm-1",
                  "refresh_token": "rt-wasm-1"
                }
              }
            }
          },
          {
            "host_ask": {
              "expect": {
                "kind": "sign"
              },
              "answer": {
                "value": {
                  "signature": [
                    1,
                    2,
                    3,
                    4
                  ]
                }
              }
            }
          },
          {
            "http_out": {
              "expect": {
                "method": "POST",
                "url": "https://issuer.example/credential",
                "purpose": "Credential",
                "json": {
                  "credential_configuration_id": "UniversityDegree"
                }
              },
              "reply": {
                "status": 200,
                "body": {
                  "credential": "credential-wasm-1"
                }
              }
            }
          },
          {
            "http_out": {
              "expect": {
                "method": "POST",
                "url": "https://issuer.example/notification",
                "purpose": "Notification"
              },
              "reply": {
                "status": 200,
                "body": {}
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "offer_parsed"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "metadata_resolved"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "as_discovered"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "trust_evaluated"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "token_received"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.progress",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "step": "credential_received"
                }
              }
            }
          },
          {
            "wmp_out": {
              "expect": {
                "method": "wmp.flow.complete",
                "params": {
                  "flow_id": "flow-wasm-1",
                  "result": {
                    "credential": "credential-wasm-1",
                    "deferred": false,
                    "refresh_token": "rt-wasm-1",
                    "dpop_jwk": "*"
                  }
                }
              }
            }
          }
        ]
                );

        let dispatcher = dispatcher(script);

        // The session, then the flow start — exactly the JS calls.
        let create = dispatcher
            .request(
                "wmp.session.create",
                &serde_json::json!({
                    "wmp": {"version": "0.1", "sender": "wasm-test"},
                    "capabilities_offered": {"flows": {"max_concurrent": 16}},
                    "security": {"mode": "tls"}
                }),
            )
            .await
            .expect("the session creates");
        let session_id = create
            .get("wmp")
            .and_then(|wmp| wmp.get("session_id"))
            .and_then(|id| id.as_str())
            .expect("the session id")
            .to_owned();
        assert_eq!(create["capabilities"]["flows"]["max_concurrent"], 16);

        let start = dispatcher
            .request(
                "wmp.flow.start",
                &serde_json::json!({
                    "wmp": {"session_id": session_id, "version": "0.1"},
                    "flow_id": "flow-wasm-1", "flow_type": "oid4vci",
                    "params": {
                        "credential_issuer": "https://issuer.example",
                        "credential_configuration_ids": ["UniversityDegree"],
                        "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                            "pre-authorized_code": "preauth-wasm-1"
                        }}
                    }
                }),
            )
            .await
            .expect("the flow starts");
        assert_eq!(start["flow_id"], "flow-wasm-1");
    }

    #[tokio::test]
    async fn a_flow_without_a_negotiated_capability_refuses_31005() {
        // The session created without offering the flows capability:
        // the flow gate refuses with -31005 before the family sees it.
        let dispatcher = dispatcher(serde_json::json!([]));
        let create = dispatcher
            .request(
                "wmp.session.create",
                &serde_json::json!({
                    "wmp": {"version": "0.1", "sender": "wasm-test"},
                    "security": {"mode": "tls"}
                }),
            )
            .await
            .expect("the session creates");
        assert!(
            create.get("capabilities").is_none()
                || create["capabilities"]
                    .as_object()
                    .map(|c| c.is_empty())
                    .unwrap_or(true),
            "no capabilities were negotiated: {create}"
        );

        // No session at all: also -31005 (nothing counts as
        // negotiated).
        let err = dispatcher
            .request(
                "wmp.flow.start",
                &serde_json::json!({
                    "wmp": {"version": "0.1"},
                    "flow_id": "flow-gate-1", "flow_type": "oid4vci", "params": {}
                }),
            )
            .await
            .expect_err("the gate refuses");
        assert_eq!(
            err.to_rpc().code,
            -31005,
            "the data: {:?}",
            err.to_rpc().data
        );
    }

    #[tokio::test]
    async fn an_unknown_method_answers_32601() {
        let dispatcher = dispatcher(serde_json::json!([]));
        let err = dispatcher
            .request("wmp.unknown.method", &serde_json::json!({}))
            .await
            .expect_err("unknown methods refuse");
        assert_eq!(err.to_rpc().code, -32601);
    }
}
