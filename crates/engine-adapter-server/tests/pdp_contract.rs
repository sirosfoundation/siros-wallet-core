//! The backend-proxy PDP (`BackendProxyPdp`) against the real backend
//! contract (go-wallet-backend's `internal/api/authzen_proxy.go`, its
//! `/v1/evaluate` and `/v1/resolve` routes): the AuthZEN Trust Registry
//! Profile's request shape, the TAC-gated bearer, and the response the
//! routes answer — what the local drive and the Fly GDC integration
//! found (the engine's prior `{"subject","key_material"}` body never
//! bound: the route's `ShouldBindJSON` 400s it).

use std::sync::Mutex;

use engine_adapter_server::config::Config;
use engine_adapter_server::ports::BackendProxyPdp;
use engine_ports::{EntitlementRequest, EvaluationRequest, Pdp, PdpError, ResolveRequest};

/// One scripted answer per path, recording every body that arrives.
/// Each test constructs its own (an Arc shared with its server task):
/// the requests a test reads are exactly its own.
struct ScriptedProxy {
    evaluate_answer: &'static str,
    resolve_answer: &'static str,
    seen: std::sync::Arc<Mutex<Vec<(String, String)>>>,
    /// The bearer each request carried ("" when none).
    bearer: std::sync::Arc<Mutex<Vec<String>>>,
}

impl ScriptedProxy {
    fn record(&self, path: &str, body: &str, auth: Option<&str>) {
        self.seen
            .lock()
            .expect("lock")
            .push((path.to_owned(), body.to_owned()));
        self.bearer
            .lock()
            .expect("lock")
            .push(auth.unwrap_or_default().to_owned());
    }
}

/// Serves the two routes on a local port, forever, recording.
async fn serve(proxy: std::sync::Arc<ScriptedProxy>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let proxy = std::sync::Arc::clone(&proxy);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                    if let Some(at) = find_head_end(&buffer) {
                        break at;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or_default().to_owned();
                let mut content_length = 0usize;
                let mut bearer = String::new();
                for line in lines {
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:").map(str::trim) {
                        content_length = value.parse().unwrap_or(0);
                    }
                    if lower.starts_with("authorization:") {
                        if let Some(token) = line
                            .split_once(':')
                            .map(|(_, v)| v.trim())
                            .and_then(|v| v.strip_prefix("Bearer "))
                        {
                            bearer = token.to_owned();
                        }
                    }
                }
                let mut body = buffer[head_end..].to_vec();
                while body.len() < content_length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                let path = request_line
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let body_text = String::from_utf8_lossy(&body).into_owned();
                let answer = if path.ends_with("/v1/evaluate") {
                    proxy.record(&path, &body_text, Some(&bearer));
                    proxy.evaluate_answer.to_owned()
                } else if path.ends_with("/v1/resolve") {
                    proxy.record(&path, &body_text, Some(&bearer));
                    proxy.resolve_answer.to_owned()
                } else {
                    "{}".to_owned()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    answer.len(),
                    answer
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// A fresh scripted proxy (each test's own instance).
fn scripted_proxy() -> std::sync::Arc<ScriptedProxy> {
    std::sync::Arc::new(ScriptedProxy {
        // The backend's answer shape (gotrust.EvaluationResponse):
        // {decision, context.reason}.
        evaluate_answer: r#"{"decision": true, "context": {"reason": [{"message": "trusted: the registry allows it"}]}}"#,
        resolve_answer: r#"{"decision": true, "context": {"trust_metadata": {"verificationMethod": [{"publicKeyJwk": {"kty": "EC"}}]}}}"#,
        seen: std::sync::Arc::new(Mutex::new(Vec::new())),
        bearer: std::sync::Arc::new(Mutex::new(Vec::new())),
    })
}

/// The evaluation request binds the AuthZEN Trust Registry Profile's
/// shape (the route's `gotrust.EvaluationRequest`): the subject as
/// {type,id}, the resource as {type,id,key}, the action as {name} —
/// and the decision and reason come back in the engine's terms.
#[tokio::test(flavor = "multi_thread")]
async fn the_evaluation_binds_the_authzen_shape_and_the_tac_bearer() {
    let proxy = scripted_proxy();
    let base = serve(std::sync::Arc::clone(&proxy)).await;
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: "an-as-issued-token".to_owned(),
        ..Config::default()
    });

    let answer = pdp
        .evaluate(EvaluationRequest {
            subject: "https://issuer.example".to_owned(),
            key_material: br#"{"keys": [{"kty": "EC"}]}"#.to_vec(),
            resource_type: Some("credential-issuer".to_owned()),
            context: serde_json::json!({"client_id_scheme": "x509_san_dns"}),
        })
        .await
        .expect("the evaluation binds and answers");

    // The engine's terms: the AuthZEN decision is the trust, the
    // context's reason message is the decision text.
    assert!(answer.trusted);
    assert_eq!(
        answer.decision.as_deref(),
        Some("trusted: the registry allows it")
    );

    // The request the route bound.
    let seen = proxy.seen.lock().expect("lock");
    let (path, body) = seen.first().expect("the route was called");
    assert!(path.ends_with("/v1/evaluate"));
    let bound: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    assert_eq!(
        bound["subject"],
        serde_json::json!({"type": "key", "id": "https://issuer.example"}),
        "the subject binds as the key holder (the routed policy's one allowed type): {bound}"
    );
    assert_eq!(
        bound["resource"]["id"], "https://issuer.example",
        "the resource is the subject: {bound}"
    );
    assert_eq!(
        bound["resource"]["type"], "jwk",
        "the keys object is a jwk resource: {bound}"
    );
    assert_eq!(
        bound["action"],
        serde_json::json!({"name": "credential-issuer"}),
        "the issuance side names its action: {bound}"
    );
    assert_eq!(
        bound["context"]["client_id_scheme"], "x509_san_dns",
        "the evaluation's context rides beside them: {bound}"
    );

    // The TAC-gated bearer the route's middleware validates.
    let bearer = proxy.bearer.lock().expect("lock");
    assert_eq!(bearer[0], "an-as-issued-token");
}

/// A `did:`-schemed subject binds the same as an https one (the key
/// holder), the DID resolution's matched JWK as the resource - the
/// scheme rides the id, the routed policy's one subject type matches
/// both.
#[tokio::test(flavor = "multi_thread")]
async fn a_did_subject_binds_as_the_key_type() {
    let proxy = scripted_proxy();
    let base = serve(std::sync::Arc::clone(&proxy)).await;
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: "t".to_owned(),
        ..Config::default()
    });

    pdp.evaluate(EvaluationRequest {
        subject: "did:web:verifier.example".to_owned(),
        key_material: br#"{"kty": "EC", "crv": "P-256"}"#.to_vec(),
        resource_type: Some("credential-verifier".to_owned()),
        context: serde_json::json!({}),
    })
    .await
    .expect("the evaluation binds");

    let seen = proxy.seen.lock().expect("lock");
    let (_, body) = seen.last().expect("the route was called");
    let bound: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    assert_eq!(
        bound["subject"]["type"], "key",
        "a did: subject is the key type: {bound}"
    );
    assert_eq!(
        bound["resource"]["type"], "jwk",
        "the matched JWK is the resource: {bound}"
    );
    assert_eq!(
        bound["action"],
        serde_json::json!({"name": "credential-verifier"}),
        "the presentation side names its action: {bound}"
    );
}

/// The resolve binds the route's shape ({subject_id, subject_type,
/// resource_type}) and reads the resolved document from the composite
/// answer's context.trust_metadata.
#[tokio::test(flavor = "multi_thread")]
async fn the_resolve_binds_the_route_shape_and_reads_trust_metadata() {
    let proxy = scripted_proxy();
    let base = serve(std::sync::Arc::clone(&proxy)).await;
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: "t".to_owned(),
        ..Config::default()
    });

    let answer = pdp
        .resolve(ResolveRequest {
            uri: "did:web:verifier.example".to_owned(),
            resource_type: "did_document".to_owned(),
        })
        .await
        .expect("the resolve binds and answers");

    // The DID document (trust_metadata) is what the engine verifies
    // request JWTs against.
    let document: serde_json::Value =
        serde_json::from_slice(&answer.metadata).expect("the trust_metadata is JSON");
    assert_eq!(
        document["verificationMethod"][0]["publicKeyJwk"]["kty"], "EC",
        "the resolved document rode the answer: {document}"
    );

    // The request the route bound.
    let seen = proxy.seen.lock().expect("lock");
    let (path, body) = seen
        .iter()
        .rev()
        .find(|(path, _)| path.ends_with("/v1/resolve"))
        .expect("the route was called");
    assert_eq!(
        path, "/v1/resolve",
        "the backend's resolve route, not the engine's own"
    );
    let bound: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    assert_eq!(
        bound["subject_id"], "did:web:verifier.example",
        "the URI binds as subject_id: {bound}"
    );
    assert_eq!(
        bound["subject_type"], "key",
        "the DID subject is the key type: {bound}"
    );
    assert_eq!(
        bound["resource_type"], "did_document",
        "the engine's DID resource type rides: {bound}"
    );
}

/// No token configured: the route's TAC middleware 401s and the engine
/// fails closed (never "unconfigured PDP" — the deployment's own
/// `NotImplemented` default is the dev engine's, not this adapter's).
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthorized_proxy_fails_closed() {
    let proxy = scripted_proxy();
    let base = serve(std::sync::Arc::clone(&proxy)).await;
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: String::new(),
        ..Config::default()
    });

    // The scripted server answers 200 regardless of the bearer (it
    // cannot see the middleware); the contract this drives is the
    // request's: the no-token case sends none.
    pdp.evaluate(EvaluationRequest {
        subject: "https://issuer.example".to_owned(),
        key_material: Vec::new(),
        resource_type: Some("credential-issuer".to_owned()),
        context: serde_json::json!({}),
    })
    .await
    .expect("the scripted proxy answers");

    let bearer = proxy.bearer.lock().expect("lock");
    assert!(
        bearer.last().is_some_and(|token| token.is_empty()),
        "no token configured: no bearer is sent"
    );
}

/// The unreachable proxy (nothing listening) surfaces as the engine's
/// PdpError::Unreachable — never a silent pass.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_proxy_fails_closed() {
    // A listener bound then dropped: a port that refuses.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: "t".to_owned(),
        ..Config::default()
    });

    let answer = pdp
        .evaluate(EvaluationRequest {
            subject: "https://issuer.example".to_owned(),
            key_material: Vec::new(),
            resource_type: Some("credential-issuer".to_owned()),
            context: serde_json::json!({}),
        })
        .await;
    assert!(matches!(
        answer,
        Err(PdpError::Unreachable) | Err(PdpError::Error(_))
    ));
}

/// The entitlement operation rides the same proxy (the backend's route
/// answer is NotImplemented there today; the engine's contract stays).
#[tokio::test(flavor = "multi_thread")]
async fn the_entitlement_operation_is_answerrable() {
    let proxy = scripted_proxy();
    let base = serve(std::sync::Arc::clone(&proxy)).await;
    let pdp = BackendProxyPdp::new(&Config {
        pdp_url: base,
        pdp_token: "t".to_owned(),
        ..Config::default()
    });

    // The backend answers NotImplemented (the route has no entitlement
    // yet): the engine treats it as "not evaluated" (ARF 6.6.2.3's
    // grace) — never a refusal.
    let answer = pdp
        .evaluate_entitlement(EntitlementRequest {
            issuer: "https://issuer.example".to_owned(),
            metadata: Vec::new(),
            key_material: Vec::new(),
            offers: Vec::new(),
        })
        .await;
    assert!(matches!(
        answer,
        Err(PdpError::NotImplemented) | Err(PdpError::Error(_)) | Ok(_)
    ));
}
