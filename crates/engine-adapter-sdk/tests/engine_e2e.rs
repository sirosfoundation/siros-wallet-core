//! The in-process engine, end to end through the SDK's own surface (the
//! gap-F2 proof): `create_engine` over scripted callback
//! implementations — the same interfaces a Kotlin or Swift app
//! implements — then the WMP session create, an OID4VCI
//! pre-authorized issuance flow, the engine's asks answered through
//! the `Host` bridge, the fetches through the `HttpClient` bridge, the
//! trust through the `Pdp` bridge, and the completion read from the
//! notification channel the transport polls.

use engine_adapter_sdk::engine::{create_engine, EngineConfig, WmpEngine};
use engine_adapter_sdk::{
    AttestationParams, AttestationResult, ConsentParams, ConsentResult, CredentialSelectionParams,
    CredentialSelectionResult, EntitlementDecision, EntitlementRequest, EvaluationRequest,
    EvaluationResponse, Host, HttpClient, MatchParams, MatchResult, Pdp, ResolveRequest,
    ResolveResponse, SdkError, SignParams, SignResult, SigningKeyParams, SigningKeyResult,
    VpParams, VpResult,
};
use std::sync::Mutex;

// ─── The scripted callbacks (what a Kotlin/Swift app implements) ─────────

/// The app's HTTP: the issuer's four endpoints.
struct ScriptedHttp {
    served: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: engine_adapter_sdk::HttpRequest,
    ) -> Result<engine_adapter_sdk::HttpResponse, SdkError> {
        self.served.lock().expect("lock").push(request.url.clone());
        let body = match request.url.as_str() {
            "https://issuer.example/.well-known/openid-credential-issuer" => {
                r#"{
                "credential_issuer": "https://issuer.example",
                "credential_endpoint": "https://issuer.example/credential",
                "notification_endpoint": "https://issuer.example/notification",
                "authorization_servers": ["https://as.example"],
                "credential_configurations_supported": {
                    "UniversityDegree": {"format": "dc+sd-jwt", "vct": "https://vc.example/degree"}
                }
            }"#
            }
            "https://as.example/.well-known/oauth-authorization-server" => {
                r#"{
                "issuer": "https://as.example",
                "token_endpoint": "https://as.example/token"
            }"#
            }
            "https://as.example/token" => {
                r#"{
                "access_token": "at-issuance", "token_type": "Bearer", "expires_in": 3600,
                "c_nonce": "nonce-1"
            }"#
            }
            "https://issuer.example/credential" => {
                r#"{
                "credential": "credential-jwt-1",
                "notification_id": "nid-1"
            }"#
            }
            other => {
                return Err(SdkError::Transport(format!("no fixture for {other}")));
            }
        };
        Ok(engine_adapter_sdk::HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        })
    }
}

/// The app's wallet: every ask answered as the fixture flow needs.
struct ScriptedHost {
    progress: Mutex<Vec<(String, String)>>,
}

#[async_trait::async_trait]
impl Host for ScriptedHost {
    async fn request_sign(&self, _params: SignParams) -> Result<SignResult, SdkError> {
        // The OID4VCI proof's signature: the scripted issuer accepts
        // whatever the wallet signs.
        Ok(SignResult {
            signature: vec![1, 2, 3, 4],
        })
    }

    async fn request_match(&self, _params: MatchParams) -> Result<MatchResult, SdkError> {
        Ok(MatchResult {
            selections: Vec::new(),
            handle: None,
        })
    }

    async fn request_vp(&self, _params: VpParams) -> Result<VpResult, SdkError> {
        Err(SdkError::Cannot(
            "no presentation in the issuance test".to_owned(),
        ))
    }

    async fn request_dpop_proof(
        &self,
        _params: engine_adapter_sdk::DpopProofParams,
    ) -> Result<engine_adapter_sdk::DpopProofResult, SdkError> {
        // No client-held key: the engine's own DPoP key signs (the
        // fallback).
        Err(SdkError::Cannot("the app holds no DPoP key".to_owned()))
    }

    async fn request_consent(&self, _params: ConsentParams) -> Result<ConsentResult, SdkError> {
        Ok(ConsentResult { consented: true })
    }

    async fn request_tx_code(&self, _flow_id: String) -> Result<String, SdkError> {
        Ok("1234".to_owned())
    }

    async fn open_authorization(&self, _flow_id: String, _url: String) -> Result<(), SdkError> {
        Ok(())
    }

    async fn request_signing_key(
        &self,
        _params: SigningKeyParams,
    ) -> Result<SigningKeyResult, SdkError> {
        Err(SdkError::Cannot("no named key".to_owned()))
    }

    async fn request_attestation(
        &self,
        _params: AttestationParams,
    ) -> Result<AttestationResult, SdkError> {
        Ok(AttestationResult::default())
    }

    async fn request_credential_selection(
        &self,
        _params: CredentialSelectionParams,
    ) -> Result<CredentialSelectionResult, SdkError> {
        // The single-configuration offer auto-selects; the ask never
        // arrives.
        Err(SdkError::Cannot("no selection UI".to_owned()))
    }

    fn progress(&self, flow_id: String, step: String, _detail: Option<String>) {
        self.progress.lock().expect("lock").push((flow_id, step));
    }
}

/// The app's trust stack: the dev PDP that trusts everything and
/// evaluates no entitlement.
struct TrustingPdp;

#[async_trait::async_trait]
impl Pdp for TrustingPdp {
    async fn evaluate(&self, _request: EvaluationRequest) -> Result<EvaluationResponse, SdkError> {
        Ok(EvaluationResponse {
            trusted: true,
            decision: Some("the dev PDP trusts everything".to_owned()),
                context: None,
        })
    }

    async fn resolve(&self, _request: ResolveRequest) -> Result<ResolveResponse, SdkError> {
        Err(SdkError::Cannot("no DID resolution".to_owned()))
    }

    async fn evaluate_entitlement(
        &self,
        _request: EntitlementRequest,
    ) -> Result<EntitlementDecision, SdkError> {
        // Not implemented: the engine treats the issuer's entitlement
        // as not evaluated and proceeds (the ARF's grace).
        Err(SdkError::Cannot("no entitlement evaluation".to_owned()))
    }
}

// ─── The drive ────────────────────────────────────────────────────────────

/// One JSON-RPC request over the transport, answered as a JSON value.
fn request(
    engine: &WmpEngine,
    id: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let message = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let answer = engine
        .send(serde_json::to_vec(&message).expect("the message serializes"))
        .expect("the engine answers")
        .expect("a request answers a reply");
    let answer: serde_json::Value =
        serde_json::from_slice(&answer).expect("the answer is JSON-RPC");
    if let Some(error) = answer.get("error") {
        panic!("the engine refused {method}: {error}");
    }
    answer["result"].clone()
}

/// The full loop: the session, the issuance flow, the asks through the
/// bridges, the completion through the notification channel — the
/// local engine serving a wallet the way the SDKs drive it.
#[test]
fn the_in_process_engine_serves_an_issuance_flow() {
    let http = ScriptedHttp {
        served: Mutex::new(Vec::new()),
    };
    let host = ScriptedHost {
        progress: Mutex::new(Vec::new()),
    };
    let engine = create_engine(
        EngineConfig::default(),
        Box::new(http),
        Box::new(host),
        Some(Box::new(TrustingPdp)),
    );

    // The session: the app offers the capabilities the engine's
    // families gate on.
    let created = request(
        &engine,
        "1",
        "wmp.session.create",
        serde_json::json!({
            "wmp": { "version": "0.1" },
            "capabilities_offered": {
                "flows": { "max_concurrent": 16 },
                "credential_notification": {
                    "events": ["credential_accepted", "credential_failure"],
                    "context_ttl_seconds": 300,
                },
            },
            "security": { "mode": "tls" },
        }),
    );
    let session_id = created["wmp"]["session_id"]
        .as_str()
        .expect("the session id")
        .to_owned();
    assert!(!session_id.is_empty());
    assert!(
        created["capabilities"].get("flows").is_some(),
        "the flows capability negotiated: {}",
        created["capabilities"]
    );

    // The issuance flow: the pre-authorized offer, by value.
    let started = request(
        &engine,
        "2",
        "wmp.flow.start",
        serde_json::json!({
            "wmp": { "version": "0.1", "session_id": session_id },
            "flow_id": "flow-issuance-1",
            "flow_type": "oid4vci",
            "params": {
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "code-1"
                    }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            },
        }),
    );
    assert_eq!(started["flow_id"], "flow-issuance-1");

    // The completion arrived on the notification channel: the
    // credential, and the notification members the issuer's
    // notification_id registered (#527).
    let mut completion = None;
    let drained = engine.take_notifications();
    assert!(
        !drained.is_empty(),
        "the flow's notifications arrive on the channel the transport polls"
    );
    for raw in drained {
        let message: serde_json::Value =
            serde_json::from_slice(&raw).expect("the notification is JSON-RPC");
        if message.get("method").and_then(|m| m.as_str()) == Some("wmp.flow.complete") {
            completion = Some(message["params"]["result"].clone());
        }
    }
    let completion = completion.expect("the issuance completed");
    assert_eq!(completion["credential"], "credential-jwt-1");
    assert_eq!(completion["notification_id"], "nid-1");
    assert_eq!(
        completion["notification_endpoint"],
        "https://issuer.example/notification"
    );
}

/// An engine without a PDP fails closed: the flow refuses at the trust
/// step, exactly as the server does — the in-process engine is not a
/// permissive mode.
#[test]
fn an_engine_without_a_pdp_fails_closed() {
    let engine = create_engine(
        EngineConfig::default(),
        Box::new(ScriptedHttp {
            served: Mutex::new(Vec::new()),
        }),
        Box::new(ScriptedHost {
            progress: Mutex::new(Vec::new()),
        }),
        None,
    );
    let created = request(
        &engine,
        "1",
        "wmp.session.create",
        serde_json::json!({
            "wmp": { "version": "0.1" },
            "capabilities_offered": { "flows": { "max_concurrent": 16 } },
            "security": { "mode": "tls" },
        }),
    );
    let session_id = created["wmp"]["session_id"]
        .as_str()
        .expect("the id")
        .to_owned();

    // The refusal: the trust evaluation fails closed with no PDP.
    let message = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "2",
        "method": "wmp.flow.start",
        "params": {
            "wmp": { "version": "0.1", "session_id": session_id },
            "flow_id": "flow-issuance-2",
            "flow_type": "oid4vci",
            "params": {
                "credential_issuer": "https://issuer.example",
                "credential_configuration_ids": ["UniversityDegree"],
                "grants": {
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                        "pre-authorized_code": "code-1"
                    }
                },
                "redirect_uri": "https://wallet.example/cb",
                "client_id": "client-1"
            },
        },
    });
    let answer = engine
        .send(serde_json::to_vec(&message).expect("serializes"))
        .expect("the engine answers")
        .expect("a request answers a reply");
    let answer: serde_json::Value = serde_json::from_slice(&answer).expect("JSON-RPC");
    let error = answer.get("error").expect("the flow refuses");
    assert_eq!(
        error["code"], -31006,
        "the trust step fails closed: {error}"
    );
}
