//! The requests the P1 fixtures start from, each one that verifies before its fixture changes
//! one thing.

use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use siros_oid4vp::{Effect, EffectResult, IntakeState, Origin, RequestUriMethod, TrustSubject};

use crate::support::*;

pub const ORIGIN: &str = "https://verifier.example";
pub const DNS: &str = "verifier.example";
pub const ATTESTATION_ISSUER: &str = "https://attestation-issuer.example";
pub const FEDERATION: &str = "openid_federation:https://federation-verifier.example";
pub const REQUEST_URI: &str = "https://verifier.example/request/vapof4ql2i7m41m68uep";

/// How the host answers a fixture's effects.
pub type Answer = Box<dyn Fn(&Effect) -> EffectResult>;

pub fn honest(host: Host) -> Answer {
    Box::new(move |e| host.answer(e))
}

/// The parameters of a redirect request of `client_id`.
pub fn redirect_payload(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example/post",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    })
}

/// The parameters of a signed DC API request of `client_id`.
pub fn dc_api_payload(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "expected_origins": [ORIGIN],
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    })
}

/// A Request Object by value under the `client_id` parameter `outer`.
pub fn by_value(outer: &str, jws: &str) -> IntakeState {
    let uri = authorization_uri(&[("client_id", outer), ("request", jws)]);
    IntakeState::redirect(&uri, formats(), now(), &mut Rng(1))
}

/// An `x509_san_dns` request by value: `x5c` holds a certificate of `certified` naming
/// `san`, and `signer` signs.
pub fn x509_san_dns(
    san: &str,
    certified: &SigningKey,
    signer: &SigningKey,
    payload: Value,
) -> IntakeState {
    let jws = sign(
        &x5c_header(&certificate(certified, &[san])),
        &payload,
        signer,
    );
    by_value(payload["client_id"].as_str().unwrap(), &jws)
}

pub fn x509_client() -> String {
    format!("x509_san_dns:{DNS}")
}

pub fn signed_dc_api(payload: Value, origin: &str) -> IntakeState {
    let key = key(1);
    let jws = sign(&x5c_header(&certificate(&key, &[DNS])), &payload, &key);
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-signed", json!({"request": jws})),
        Origin::new(origin),
        now(),
    )
}

pub fn unsigned_dc_api(change: impl Fn(&mut Value)) -> IntakeState {
    let mut data = json!({
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    });
    change(&mut data);
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-unsigned", data),
        Origin::new(ORIGIN),
        now(),
    )
}

/// A `decentralized_identifier` request by value whose `kid` is `kid`, signed by `signer`;
/// the host resolves `did:example:123#key-1` to `key(3)`.
pub fn did(kid: &str, signer: &SigningKey) -> (IntakeState, Answer) {
    did_resolving(kid, signer, jwk(key(3).verifying_key()))
}

/// [`did`], the host resolving `did:example:123#key-1` to the JWK `resolved`.
pub fn did_resolving(kid: &str, signer: &SigningKey, resolved: Value) -> (IntakeState, Answer) {
    let client_id = "decentralized_identifier:did:example:123";
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid});
    let jws = sign(&header, &redirect_payload(client_id), signer);
    let host = Host {
        keys: vec![("did:example:123#key-1".into(), resolved)],
        ..Host::trusting()
    };
    (by_value(client_id, &jws), honest(host))
}

/// A `verifier_attestation` request by value. `issuer` signs the attestation under its `x5c`;
/// `cnf` is the attested key; `signer` signs the request.
pub fn attestation(
    sub: &str,
    exp: u64,
    issuer: &SigningKey,
    cnf: &SigningKey,
    signer: &SigningKey,
) -> IntakeState {
    attested(
        json!({"iss": ATTESTATION_ISSUER, "sub": sub, "exp": exp, "cnf": {"jwk": jwk(cnf.verifying_key())}}),
        issuer,
        signer,
    )
}

/// A `verifier_attestation` request by value whose attestation holds `claims`.
pub fn attested(claims: Value, issuer: &SigningKey, signer: &SigningKey) -> IntakeState {
    let issuer_certificate = certificate(&key(4), &["attestation-issuer.example"]);
    let attestation = sign(
        &json!({"alg": "ES256", "typ": "verifier-attestation+jwt", "x5c": [b64_padded(&issuer_certificate)]}),
        &claims,
        issuer,
    );
    let client_id = format!("verifier_attestation:{DNS}");
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "jwt": attestation});
    let jws = sign(&header, &redirect_payload(&client_id), signer);
    by_value(&client_id, &jws)
}

/// An `openid_federation` request by value signed by `signer`; the host resolves `fed-1` to
/// `key(6)`, with the Trust Chain's metadata.
pub fn federation(signer: &SigningKey) -> (IntakeState, Answer) {
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": "fed-1", "trust_chain": ["eyJ.e.s"]});
    let jws = sign(&header, &redirect_payload(FEDERATION), signer);
    let host = Host {
        keys: vec![("fed-1".into(), jwk(key(6).verifying_key()))],
        metadata: Some(json!({"vp_formats_supported": {"dc+sd-jwt": {}}})),
        ..Host::trusting()
    };
    (by_value(FEDERATION, &jws), honest(host))
}

/// An `openid4vp-v1-multisigned` request with one signature per `(dns, certified, signer)`.
pub fn multisigned(signers: &[(&str, &SigningKey, &SigningKey)], payload: Value) -> IntakeState {
    let payload_b64 = b64(payload.to_string().as_bytes());
    let signatures: Vec<Value> = signers
        .iter()
        .map(|(dns, certified, signer)| {
            let mut protected = x5c_header(&certificate(certified, &[dns]));
            protected["client_id"] = format!("x509_san_dns:{dns}").into();
            signature_object(&protected, &payload_b64, signer)
        })
        .collect();
    let data = json!({"request": {"payload": payload_b64, "signatures": signatures}});
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-multisigned", data),
        Origin::new(ORIGIN),
        now(),
    )
}

pub fn multisigned_payload() -> Value {
    let mut payload = dc_api_payload("");
    payload.as_object_mut().unwrap().remove("client_id");
    payload
}

/// A host that trusts only the Client Identifier `trusted`.
pub fn trusting_only(trusted: &'static str) -> Answer {
    Box::new(move |effect| match effect {
        Effect::Trust(trust) => {
            let yes = matches!(trust.subject(), TrustSubject::Client(c) if c.as_str() == trusted);
            EffectResult::Trusted(siros_oid4vp::TrustAnswer::new(yes.into(), None, None))
        }
        Effect::RequestObject(_) => panic!("no Request Object"),
    })
}

/// What a Request Object by reference holds as `wallet_nonce`.
#[derive(Clone, Copy)]
pub enum Echo {
    /// The nonce a `post` sent; none after a `get`.
    Sent,
    /// None.
    Omitted,
    /// Another nonce.
    Altered,
}

/// An `x509_san_dns` request by reference at `request_uri`, with `request_uri_method` when
/// given. The host answers with the Request Object of the request, its `wallet_nonce` per
/// `echo`, and trusts every subject.
pub fn by_reference(request_uri: &str, method: Option<&str>, echo: Echo) -> (IntakeState, Answer) {
    let client_id = x509_client();
    let mut params = vec![
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri),
    ];
    params.extend(method.map(|method| ("request_uri_method", method)));
    let state = IntakeState::redirect(&authorization_uri(&params), formats(), now(), &mut Rng(1));
    let host = Host::trusting();
    let answer: Answer = Box::new(move |effect| match effect {
        Effect::RequestObject(request) => {
            let mut payload = redirect_payload(&x509_client());
            let sent = match request.method() {
                RequestUriMethod::Get => None,
                RequestUriMethod::Post(parameters) => Some(parameters.wallet_nonce().as_str()),
            };
            match (echo, sent) {
                (Echo::Sent, Some(nonce)) => payload["wallet_nonce"] = nonce.into(),
                (Echo::Altered, _) => payload["wallet_nonce"] = "qPmxiNFCR3QTm19POc8u".into(),
                (Echo::Sent, None) | (Echo::Omitted, _) => {}
            }
            let key = key(1);
            let jws = sign(&x5c_header(&certificate(&key, &[DNS])), &payload, &key);
            EffectResult::RequestObject(request_object(&jws))
        }
        Effect::Trust(_) => host.answer(effect),
    });
    (state, answer)
}
