//! The dispatcher on the host target: the same routing, capability
//! gate and session plumbing the browser runs, driven with the
//! conformance runner's scripted world — the pre-authorized
//! issuance, end to end, over the JSON-RPC surface.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use engine_adapter_wasm::dispatch::Dispatcher;
use engine_conformance::world::{
    FixedClock, MemoryKv, NoTelemetry, ScriptedHost, ScriptedHttp, ScriptedPdp, SeededRng, World,
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
            consent_check: engine_ports::ConsentCheckMode::Warn,
            notifications: std::sync::Arc::new(
                engine_core::oid4vci::notification::NotificationContexts::default(),
            ),
        }),
        Arc::new(|| 1_700_000_000),
        Arc::new(|bytes: &mut [u8]| {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }),
        // The host tests drop the outgoing notifications (the legacy
        // behaviour the page had before the JS forwarder).
        None,
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
              "step": "parsing_offer"
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
              "step": "fetching_metadata"
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
              "step": "metadata_fetched"
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
              "step": "evaluating_trust"
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
              "step": "exchanging_token"
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
              "step": "token_obtained"
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
              "step": "requesting_credential"
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
