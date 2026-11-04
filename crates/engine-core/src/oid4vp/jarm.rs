//! The JARM response (`direct_post.jwt`): the authorization response as a
//! JWT, JWE-encrypted to the verifier's key and POSTed as
//! `response=<jwe>` — built on jose-rs, per OpenID4VP §6.2 / JARM §4.1.
//!
//! The P0.6-verified behaviours:
//! - The claims: `iss` self-issued, `aud` the client_id, five-minute
//!   `exp`, `iat`, the `vp_token`, and `state` when the request had one.
//!   A vp_token that is itself valid JSON embeds as parsed JSON, not a
//!   string.
//! - `authorization_encrypted_response_alg` comes from the client
//!   metadata; when absent, the JWK's own `alg` is honored when it is a
//!   supported JARM algorithm, else one is inferred from the key type
//!   (EC → ECDH-ES per RFC 7518 §4.6, RSA → RSA-OAEP per §4.3 — RSA-OAEP
//!   with SHA-1 is gone from this stack, so the RSA inference is
//!   RSA-OAEP-256 and the vectors record that decision).
//! - `enc` defaults to A128GCM: CBC-HS256 is RFC 7518's first
//!   mandatory-to-implement "enc", but live verifiers reject it (the Go
//!   engine's finding against verifier.multipaz.org) and GCM has the
//!   broader real-world interop.
//! - The key comes from `client_metadata.jwks` — prefer `use: "enc"`,
//!   else the first parseable key.
//! - Most refusals around direct_post.jwt are NOT sent to the verifier
//!   (P0.6): a request that cannot be answered encrypted leaves the
//!   verifier to time out; the engine reports the flow error to the
//!   host.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::header::JoseHeader;
use jose_rs::jwe::compact;
use jose_rs::jwk::Jwk;
use serde_json::Value;

use super::types::{AuthorizationRequest, ResponseError};

/// The self-issued issuer for the JARM response (JARM §4.1).
pub const SELF_ISSUED_ISS: &str = "https://self-issued.me/v2";

/// The response lifetime: five minutes (the P0.6-verified Go behaviour).
const RESPONSE_LIFETIME_SECS: i64 = 300;

/// The default `enc` when the client metadata declares none.
pub const DEFAULT_CONTENT_ENCRYPTION: &str = "A128GCM";

/// Why the JARM response could not be built.
#[derive(Debug, thiserror::Error)]
pub enum JarmError {
    /// No usable encryption key in the client metadata's `jwks`.
    #[error("oid4vp: no verifier encryption key: {0}")]
    NoEncryptionKey(String),
    /// The declared or inferred key-management algorithm is unsupported.
    #[error("oid4vp: unsupported JARM key algorithm: {0}")]
    UnsupportedAlg(String),
    /// The declared content-encryption algorithm is unsupported.
    #[error("oid4vp: unsupported JARM content encryption: {0}")]
    UnsupportedEnc(String),
    /// No algorithm was declared and none could be inferred from the key.
    #[error(
        "oid4vp: direct_post.jwt requires authorization_encrypted_response_alg in \
         client_metadata and the key type names none"
    )]
    NoEncryptionAlg,
    /// The encryption itself failed (jose-rs).
    #[error("oid4vp: JARM encryption failed: {0}")]
    Encrypt(String),
}

/// The wire names of the supported JARM key-management algorithms
/// (the Go engine's exact set, minus SHA-1 RSA-OAEP).
pub fn map_key_algorithm(name: &str) -> Option<JweAlgorithm> {
    match name {
        "ECDH-ES" => Some(JweAlgorithm::EcdhEs),
        "ECDH-ES+A128KW" => Some(JweAlgorithm::EcdhEsA128kw),
        "ECDH-ES+A192KW" => Some(JweAlgorithm::EcdhEsA192kw),
        "ECDH-ES+A256KW" => Some(JweAlgorithm::EcdhEsA256kw),
        "RSA-OAEP-256" => Some(JweAlgorithm::RsaOaep256),
        _ => None,
    }
}

/// The wire names of the supported JARM content-encryption algorithms
/// (the Go engine's exact set).
pub fn map_content_encryption(name: &str) -> Option<JweEncryption> {
    match name {
        "A128CBC-HS256" => Some(JweEncryption::A128CbcHs256),
        "A192CBC-HS384" => Some(JweEncryption::A192CbcHs384),
        "A256CBC-HS512" => Some(JweEncryption::A256CbcHs512),
        "A128GCM" => Some(JweEncryption::A128GCM),
        "A192GCM" => Some(JweEncryption::A192GCM),
        "A256GCM" => Some(JweEncryption::A256GCM),
        _ => None,
    }
}

/// Builds the JARM claims (OpenID4VP §6.2 / JARM §4.1).
///
/// `now_unix` comes from the Clock port — the core never reads a clock
/// itself.
pub fn build_jarm_claims(vp_token: &str, _client_id: &str, state: &str, _now_unix: i64) -> Value {
    // A vp_token that is itself valid JSON embeds as parsed JSON (the
    // DCQL object, most notably); anything else stays a string.
    //
    // OID4VP 1.0 §8.3: the direct_post.jwt response is the encrypted
    // authorization-response object — its response parameters only.
    // The JWT-style claims (iss, aud, exp, iat) do not belong in it;
    // the suite's ValidateJWEBodyDoesNotIncludeIssExpAud refuses them.
    let vp_token_value: Value =
        serde_json::from_str(vp_token).unwrap_or_else(|_| Value::String(vp_token.to_owned()));

    let mut claims = serde_json::Map::new();
    claims.insert("vp_token".to_owned(), vp_token_value);
    if !state.is_empty() {
        claims.insert("state".to_owned(), Value::String(state.to_owned()));
    }
    Value::Object(claims)
}

/// The base64url SHA-256 thumbprint (RFC 7638) of the verifier's
/// encryption JWK, for `direct_post.jwt`'s OpenID4VPHandover session
/// transcript — empty for the other response modes and for any key
/// that cannot be extracted (the Go engine's
/// `computeVerifierJWKThumbprint`, which logs and continues).
pub fn verifier_jwk_thumbprint(auth_req: &super::types::AuthorizationRequest) -> String {
    if auth_req.response_mode != super::types::ResponseMode::DirectPostJwt {
        return String::new();
    }
    let Some(metadata) = auth_req.client_metadata.as_ref() else {
        return String::new();
    };
    let Ok(jwk) = select_verifier_jwk(metadata) else {
        return String::new();
    };
    jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk).unwrap_or_default()
}

/// Selects the verifier's encryption JWK from the client metadata's
/// `jwks`: prefer a key with `use: "enc"`, else the first parseable key —
/// the P0.6-verified selection.
pub fn select_verifier_jwk(client_metadata: &Value) -> Result<Jwk, JarmError> {
    // RFC 7517 §5: the jwks may carry unusable entries (unsupported
    // key types, exotic parameter sets) beside the usable key — the
    // wallet encrypts to the first key that resolves to algorithms it
    // can use, ignoring the others. The `use: "enc"` keys are
    // preferred, then any usable one.
    let keys = client_metadata
        .get("jwks")
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| JarmError::NoEncryptionKey("no jwks.keys in client_metadata".to_owned()))?;

    let mut enc_keys = Vec::new();
    let mut other_keys = Vec::new();
    for raw in keys {
        // An unparseable key is skipped, not fatal (the Go behaviour).
        let Ok(jwk) = serde_json::from_value::<Jwk>(raw.clone()) else {
            continue;
        };
        if jwk.use_.as_deref() == Some("enc") {
            enc_keys.push(jwk);
        } else {
            other_keys.push(jwk);
        }
    }
    for jwk in enc_keys.into_iter().chain(other_keys) {
        if resolve_algorithms(Some(client_metadata), &jwk).is_ok() {
            return Ok(jwk);
        }
    }

    Err(JarmError::NoEncryptionKey(
        "no usable key in jwks".to_owned(),
    ))
}

/// Resolves the JARM algorithms: the client metadata's declarations,
/// else the first of the OID4VP 1.0 `*_values_supported` lists, else
/// the JWK's own `alg` when supported, else inference from the key
/// type. `enc` defaults to A128GCM (the live-interop finding: verifiers
/// reject CBC-HS256 in practice).
pub fn resolve_algorithms(
    client_metadata: Option<&Value>,
    jwk: &Jwk,
) -> Result<(JweAlgorithm, JweEncryption), JarmError> {
    let declared_alg = client_metadata
        .and_then(|m| m.get("authorization_encrypted_response_alg"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let declared_enc = client_metadata
        .and_then(|m| m.get("authorization_encrypted_response_enc"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    // The OID4VP 1.0 §8.3 client metadata: the verifier's supported
    // algorithm lists — the JWE's headers must match one of them.
    let first_supported = |metadata: &Value, name: &str| {
        metadata
            .get(name)
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    // The content encryption: declared, else the supported list, else
    // the GCM default.
    let enc_name = if declared_enc.is_empty() {
        client_metadata
            .map(|m| first_supported(m, "encrypted_response_enc_values_supported"))
            .unwrap_or_default()
    } else {
        declared_enc.to_owned()
    };
    let enc = if enc_name.is_empty() {
        JweEncryption::A128GCM
    } else {
        map_content_encryption(&enc_name)
            .ok_or_else(|| JarmError::UnsupportedEnc(enc_name.clone()))?
    };

    // The key-management algorithm: the declared name, else the
    // supported list's first entry.
    let alg_name = if declared_alg.is_empty() {
        client_metadata
            .map(|m| first_supported(m, "encrypted_response_alg_values_supported"))
            .unwrap_or_default()
    } else {
        declared_alg.to_owned()
    };

    // The key-management algorithm: the resolved name, else the JWK's
    // own alg when it is one we support, else inferred from the key
    // type.
    if !alg_name.is_empty() {
        let alg = map_key_algorithm(&alg_name)
            .ok_or_else(|| JarmError::UnsupportedAlg(alg_name.clone()))?;
        return Ok((alg, enc));
    }

    if let Some(jwk_alg) = jwk.alg.as_deref() {
        if let Some(alg) = map_key_algorithm(jwk_alg) {
            return Ok((alg, enc));
        }
    }

    let alg = match jwk.kty.as_str() {
        "EC" => JweAlgorithm::EcdhEs,
        "OKP" if jwk.crv.as_deref() == Some("X25519") => JweAlgorithm::EcdhEs,
        "RSA" => JweAlgorithm::RsaOaep256,
        _ => return Err(JarmError::NoEncryptionAlg),
    };

    Ok((alg, enc))
}

/// Encrypts the JARM claims to the compact JWE serialization, with
/// `cty: JWT` and the JWK's `kid` when it has one.
pub fn encrypt_jarm_response(
    claims: &Value,
    jwk: &Jwk,
    alg: JweAlgorithm,
    enc: JweEncryption,
) -> Result<String, JarmError> {
    let claims_json =
        serde_json::to_vec(claims).map_err(|err| JarmError::Encrypt(err.to_string()))?;

    // The one-shot JWK API reads the alg from the JWK; the resolution
    // above owns that choice, so the clone carries it.
    let mut recipient = jwk.clone();
    recipient.alg = Some(alg.as_str().to_owned());

    let mut header = JoseHeader::for_jwe(alg, enc);
    // The payload is the plain JSON authorization response (OID4VP 1.0
    // §8.3), not a nested JWT — cty names the content's type.
    header.cty = Some("json".to_owned());
    if let Some(kid) = jwk.kid.as_deref() {
        header.kid = Some(kid.to_owned());
    }

    compact::encrypt_with_jwk_header(&recipient, header, &claims_json, enc)
        .map_err(|err| JarmError::Encrypt(err.to_string()))
}

/// Builds and submits the JARM response for a `direct_post.jwt`
/// request: the claims, the encryption to the verifier's key, and the
/// `response=<jwe>` form POST.
///
/// `now_unix` comes from the Clock port. The client metadata may be the
/// inline `client_metadata` or the fetched document — the JARM
/// parameters are read from either.
pub async fn submit_jarm_response(
    http: &dyn engine_ports::HttpClient,
    auth_req: &AuthorizationRequest,
    vp_token: &str,
    client_metadata: Option<&Value>,
    now_unix: i64,
) -> Result<String, ResponseError> {
    let endpoint = if !auth_req.response_uri.is_empty() {
        auth_req.response_uri.clone()
    } else if !auth_req.redirect_uri.is_empty() {
        auth_req.redirect_uri.clone()
    } else {
        return Err(ResponseError::NoEndpoint);
    };

    // The client metadata: the caller's resolved copy, else the inline
    // one from the request.
    let metadata = client_metadata
        .cloned()
        .or_else(|| auth_req.client_metadata.clone());

    let Some(metadata) = metadata else {
        // P0.6: an encryption contract that cannot be met is not sent;
        // the verifier times out. The flow error is the host's.
        return Err(ResponseError::Jarm(JarmError::NoEncryptionKey(
            "no client_metadata for direct_post.jwt".to_owned(),
        )));
    };

    let jwk = select_verifier_jwk(&metadata).map_err(ResponseError::Jarm)?;
    let (alg, enc) = resolve_algorithms(Some(&metadata), &jwk).map_err(ResponseError::Jarm)?;
    let claims = build_jarm_claims(vp_token, &auth_req.client_id, &auth_req.state, now_unix);
    let jwe = encrypt_jarm_response(&claims, &jwk, alg, enc).map_err(ResponseError::Jarm)?;

    // POST response=<jwe> per §6.2.
    let form = format!("response={}", super::response::url_encode(&jwe));
    let response = http
        .send(engine_ports::HttpRequest {
            method: "POST".to_owned(),
            url: endpoint,
            headers: vec![(
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: form.into_bytes(),
            purpose: engine_ports::FetchPurpose::DirectPost,
            max_response_bytes: super::response::MAX_REPLY_BYTES,
            redirects: engine_ports::RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| ResponseError::Fetch(err.to_string()))?;

    if (200..300).contains(&response.status) {
        // The verifier's answer: the redirect to hand the host, when the
        // body carries one.
        let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        if let Some(redirect) = body.get("redirect_uri").and_then(Value::as_str) {
            if !redirect.is_empty() {
                return Ok(redirect.to_owned());
            }
        }
        return Ok(String::new());
    }

    if (300..400).contains(&response.status) {
        // The redirect answer: the Location header.
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.clone());
        return Ok(location.unwrap_or_default());
    }

    Err(ResponseError::Fetch(format!(
        "JARM response submission failed with status {}",
        response.status
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::{FetchPurpose, HttpError, HttpRequest};
    use serde_json::json;

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
        let (alg, enc) =
            resolve_algorithms(Some(&metadata("ECDH-ES+A128KW", "A256GCM")), &ec_jwk())
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
        let header = crate::oid4vp::test_util::base64url_decode(parts[0].as_bytes());
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
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
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
            client_id_scheme: super::super::types::ClientIdScheme::X509SanDns,
            request_uri: String::new(),
            response_uri: "https://verifier.example/response".to_owned(),
            redirect_uri: String::new(),
            response_mode: super::super::types::ResponseMode::DirectPostJwt,
            nonce: "nonce-1".to_owned(),
            state: "state-1".to_owned(),
            dcql_query: None,
            transaction_data_raw: Vec::new(),
            client_metadata: None,
            client_metadata_uri: String::new(),
            verifier_jwk: None,
            scope: String::new(),
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
}
