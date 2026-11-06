//! The JARM response (`direct_post.jwt`, OpenID4VP 1.0 §8.3): the claims,
//! the algorithm resolution, the key selection, the encryption, and the
//! submission.

use engine_core::oid4vp::jarm::{
    build_jarm_claims, encrypt_jarm_response, resolve_algorithms, select_verifier_jwk,
    submit_jarm_response, JarmError,
};
use engine_core::oid4vp::types::{
    AuthorizationRequest, ClientIdScheme, ResponseError, ResponseMode,
};
use engine_ports::{FetchPurpose, HttpError, HttpRequest};
use jose_rs::jwe::compact;
use jose_rs::jwk::Jwk;
use serde_json::{json, Value};

// ─── the claims ────────────────────────────────────────────────────

#[test]
fn the_claims_are_the_jarm_shape() {
    // OID4VP 1.0 §8.3: the encrypted body is the authorization
    // response's parameters only — the JWT-style claims (iss, aud,
    // exp, iat) do not belong in it.
    let claims = build_jarm_claims("vp-1", "x509_san_dns:verifier.example", "state-1", 1_000);
    assert_eq!(claims["vp_token"], "vp-1");
    assert_eq!(claims["state"], "state-1");
    assert!(claims.get("iss").is_none());
    assert!(claims.get("aud").is_none());
    assert!(claims.get("exp").is_none());
    assert!(claims.get("iat").is_none());
}

#[test]
fn a_json_vp_token_embeds_parsed() {
    let claims = build_jarm_claims("{\"pid\":[\"t\"]}", "verifier", "", 0);
    assert_eq!(claims["vp_token"], json!({ "pid": ["t"] }));

    // An absent state stays absent.
    assert!(claims.get("state").is_none());
}

// ─── the algorithm resolution ─────────────────────────────────────

fn ec_jwk() -> Jwk {
    let mut jwk = jose_rs::jwk::generate::generate_ec("P-256").expect("keygen");
    // The public side only: a verifier publishes x/y.
    jwk.d = None;
    jwk
}

fn metadata(alg: &str, enc: &str) -> Value {
    json!({
        "authorization_encrypted_response_alg": alg,
        "authorization_encrypted_response_enc": enc,
    })
}

#[test]
fn the_declared_algorithms_win() {
    let (alg, enc) = resolve_algorithms(Some(&metadata("ECDH-ES+A128KW", "A256GCM")), &ec_jwk())
        .expect("resolve");
    assert_eq!(alg.as_str(), "ECDH-ES+A128KW");
    assert_eq!(enc.as_str(), "A256GCM");
}

#[test]
fn an_ec_key_infers_ecdh_es_and_the_default_enc_is_gcm() {
    let (alg, enc) = resolve_algorithms(None, &ec_jwk()).expect("resolve");
    assert_eq!(alg.as_str(), "ECDH-ES");
    assert_eq!(enc.as_str(), "A128GCM");
}

#[test]
fn the_jwks_own_alg_is_honored_when_supported() {
    let mut jwk = ec_jwk();
    jwk.alg = Some("ECDH-ES+A256KW".to_owned());
    let (alg, _) = resolve_algorithms(None, &jwk).expect("resolve");
    assert_eq!(alg.as_str(), "ECDH-ES+A256KW");
}

#[test]
fn unsupported_declarations_refuse() {
    let err = resolve_algorithms(Some(&metadata("RSA1_5", "A128GCM")), &ec_jwk());
    assert!(matches!(err, Err(JarmError::UnsupportedAlg(_))));
    let err = resolve_algorithms(Some(&metadata("ECDH-ES", "AES-CBC")), &ec_jwk());
    assert!(matches!(err, Err(JarmError::UnsupportedEnc(_))));
}

// ─── the key selection ─────────────────────────────────────────────

#[test]
fn the_enc_key_is_preferred() {
    let enc_key = {
        let mut jwk = ec_jwk();
        jwk.use_ = Some("enc".to_owned());
        jwk.kid = Some("enc-key".to_owned());
        jwk
    };
    let sig_key = {
        let mut jwk = ec_jwk();
        jwk.use_ = Some("sig".to_owned());
        jwk.kid = Some("sig-key".to_owned());
        jwk
    };
    // The sig key first: the enc key must still win.
    let jwks = json!({
        "jwks": { "keys": [serde_json::from_str::<Value>(&sig_key.to_json().unwrap()).unwrap(),
                           serde_json::from_str::<Value>(&enc_key.to_json().unwrap()).unwrap()] }
    });
    let selected = select_verifier_jwk(&jwks).expect("select");
    assert_eq!(selected.kid.as_deref(), Some("enc-key"));
}

#[test]
fn without_an_enc_key_the_first_parseable_key_is_used() {
    let jwk = ec_jwk();
    let raw = serde_json::from_str::<Value>(&jwk.to_json().unwrap()).unwrap();
    // The first entry is not a parseable JWK at all (kty is not a
    // string); the second is the fallback.
    let jwks = json!({ "jwks": { "keys": [json!({"kty": 42}), raw] } });
    let selected = select_verifier_jwk(&jwks).expect("select");
    assert_eq!(selected.kty, "EC");
}

#[test]
fn no_jwks_refuses() {
    assert!(matches!(
        select_verifier_jwk(&json!({})),
        Err(JarmError::NoEncryptionKey(_))
    ));
}

// ─── the encryption roundtrip ──────────────────────────────────────

#[test]
fn the_jwe_roundtrips_to_the_same_claims() {
    // Encrypt with the verifier's public JWK, decrypt with the
    // private one — the roundtrip proves the token a verifier can
    // actually open.
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("keygen");
    let mut public = private.clone();
    public.d = None;
    public.alg = Some("ECDH-ES".to_owned());

    let claims = build_jarm_claims("{\"pid\":[\"t\"]}", "verifier", "state-1", 1_000);
    let (alg, enc) = resolve_algorithms(None, &public).expect("resolve");
    let token = encrypt_jarm_response(&claims, &public, alg, enc).expect("encrypt");

    // The compact form: five parts, cty json in the header (the
    // payload is the plain-JSON response object, OID4VP 1.0 §8.3).
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 5);
    let header = jose_rs::base64url::decode(parts[0]).expect("the header is base64url");
    let header: Value = serde_json::from_slice(&header).expect("header json");
    assert_eq!(header["cty"], "json");
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A128GCM");

    // The decrypt: jose-rs with the private JWK recovers the claims.
    // The decrypt path reads the alg from the JWK, like the encrypt
    // path does.
    let mut private = private;
    private.alg = Some("ECDH-ES".to_owned());
    let decrypted = compact::decrypt_with_jwk(&private, &token).expect("decrypt");
    let recovered: Value = serde_json::from_slice(&decrypted).expect("claims json");
    assert_eq!(recovered["vp_token"], json!({ "pid": ["t"] }));
    assert_eq!(recovered["state"], "state-1");
    // The JWT-style claims are not part of the response object.
    assert!(recovered.get("aud").is_none());
}

// ─── the submission ───────────────────────────────────────────────

struct FakeHttp {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    posts: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl engine_ports::HttpClient for FakeHttp {
    async fn send(&self, request: HttpRequest) -> Result<engine_ports::HttpResponse, HttpError> {
        assert_eq!(request.purpose, FetchPurpose::DirectPost);
        self.posts
            .lock()
            .map(|mut p| p.push((request.url.clone(), request.body.clone())))
            .ok();
        Ok(engine_ports::HttpResponse {
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
        })
    }
}

fn jarm_request() -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: "x509_san_dns:verifier.example".to_owned(),
        client_id_scheme: ClientIdScheme::X509SanDns,
        request_uri: String::new(),
        response_uri: "https://verifier.example/response".to_owned(),
        redirect_uri: String::new(),
        response_mode: ResponseMode::DirectPostJwt,
        nonce: "nonce-1".to_owned(),
        state: "state-1".to_owned(),
        dcql_query: None,
        transaction_data_raw: Vec::new(),
        client_metadata: None,
        client_metadata_uri: String::new(),
        verifier_jwk: None,
        scope: String::new(),
        // The trust evaluation's inputs: the tests carry no
        // signed request object.
        request_jwt: None,
        x5c: None,
        attestation_jwt: None,
    }
}

#[tokio::test]
async fn the_jwe_is_posted_as_response() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("keygen");
    let mut public = private.clone();
    public.d = None;
    public.use_ = Some("enc".to_owned());
    let jwks = json!({
        "jwks": { "keys": [serde_json::from_str::<Value>(&public.to_json().unwrap()).unwrap()] }
    });

    let http = FakeHttp {
        status: 200,
        body: br#"{"redirect_uri":"https://verifier.example/done"}"#.to_vec(),
        headers: Vec::new(),
        posts: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_jarm_response(&http, &jarm_request(), "vp-1", Some(&jwks), 1_000)
        .await
        .expect("submit");
    assert_eq!(redirect, "https://verifier.example/done");

    let posts = http.posts.lock().expect("lock");
    let body = String::from_utf8_lossy(&posts[0].1).into_owned();
    assert!(body.starts_with("response=ey"));
    assert_eq!(posts[0].0, "https://verifier.example/response");
}

#[tokio::test]
async fn a_redirect_answer_takes_the_location_header() {
    let private = jose_rs::jwk::generate::generate_ec("P-256").expect("keygen");
    let mut public = private.clone();
    public.d = None;
    public.use_ = Some("enc".to_owned());
    let jwks = json!({
        "jwks": { "keys": [serde_json::from_str::<Value>(&public.to_json().unwrap()).unwrap()] }
    });

    let http = FakeHttp {
        status: 302,
        body: Vec::new(),
        headers: vec![(
            "location".to_owned(),
            "https://verifier.example/cb".to_owned(),
        )],
        posts: std::sync::Mutex::new(Vec::new()),
    };
    let redirect = submit_jarm_response(&http, &jarm_request(), "vp-1", Some(&jwks), 1_000)
        .await
        .expect("submit");
    assert_eq!(redirect, "https://verifier.example/cb");
}

#[tokio::test]
async fn without_client_metadata_the_response_is_not_sent() {
    let http = FakeHttp {
        status: 200,
        body: Vec::new(),
        headers: Vec::new(),
        posts: std::sync::Mutex::new(Vec::new()),
    };
    let result = submit_jarm_response(&http, &jarm_request(), "vp-1", None, 1_000).await;
    assert!(matches!(result, Err(ResponseError::Jarm(_))));
    // Nothing was POSTed: the refusal is not sent (P0.6).
    assert!(http.posts.lock().expect("lock").is_empty());
}
