//! B.2.6.2's DC API handover example bytes and §5.9's audience, RFC 8037 A.3's OKP thumbprint,
//! and §8.3's choice of the response encryption.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use siros_explain::AllOf;
use siros_openid4vp::boxes::Card;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, FormatHost, PresentError, Presentation, Usable,
};
use siros_openid4vp::ids::{ClientId, FormatId, Nonce};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Fault, FindingData, Format, FormatQuery, Member, Members, NoCandidate, OptionIndex,
    OptionItems, Registry, Shown,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{AgreeableKey, Query, thumbprint};
use siros_openid4vp::resolve::ResponseData;
use siros_openid4vp::rows::Env;
use siros_openid4vp::session::{Endpoint, Handover, Session};
use siros_openid4vp::wallet::{Credential, Wallet};
use siros_testkit::FAULT;
use siros_testkit::{Binds, TestFormat, TestHost};

use crate::common::{Held, env, parameters, registry, request_of, test_queries, unsigned};

use super::{answer, hex};

/// A format whose presentation is the session phase 2 hands it.
#[derive(Clone)]
struct Recorder(TestFormat);

struct RecorderQuery<'q, H>(Box<dyn AnsweredQuery<H> + 'q>);

/// An option whose presentation records the session.
struct RecorderOption(OptionIndex);

impl Format for Recorder {
    fn id(&self) -> FormatId<'_> {
        self.0.id()
    }

    fn reserved(&self) -> &[Member] {
        self.0.reserved()
    }

    fn wallet_formats(
        &self,
    ) -> Result<siros_openid4vp::json::Node<'static>, siros_openid4vp::plugins::Fault> {
        Ok(siros_openid4vp::json::Node::Object(
            siros_openid4vp::json::Object::default(),
        ))
    }

    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        self.0.query(query, context)
    }
}

impl<H: 'static> FormatHost<H> for Recorder {
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        Ok(Box::new(RecorderQuery(FormatHost::<H>::answer(
            &self.0, query, context,
        )?)))
    }
}

impl<H> FormatQuery for RecorderQuery<'_, H> {
    fn options(&self) -> &[OptionItems] {
        self.0.options()
    }

    fn admits(
        &self,
        credential: &Credential<'_>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        self.0.admits(credential, keys)
    }

    fn answerable(
        &self,
        credential: &Credential<'_>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        self.0.answerable(credential, env, provided)
    }

    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<bool, Fault> {
        self.0.carries(credential, members)
    }

    fn draw(
        &self,
        credential: &Credential<'_>,
        shown: Shown<'_>,
        env: &Env,
    ) -> Result<Card, Fault> {
        self.0.draw(credential, shown, env)
    }
}

impl<H> AnsweredQuery<H> for RecorderQuery<'_, H> {
    fn choose<'a>(
        &'a self,
        credential: Usable<'a>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault> {
        Ok(self
            .0
            .choose(credential, env, provided)?
            .into_iter()
            .map(|option| {
                Box::new(RecorderOption(option.option())) as Box<dyn AnsweredOption<H> + 'a>
            })
            .collect())
    }
}

impl<H> AnsweredOption<H> for RecorderOption {
    fn option(&self) -> OptionIndex {
        self.0
    }

    fn revalidate(&self, _: &Session<'_>, _: &H) -> Result<Option<Box<dyn FindingData>>, Fault> {
        Ok(None)
    }

    fn present(
        &self,
        _: &Members,
        session: &Session<'_>,
        _: &H,
    ) -> Result<Presentation, PresentError> {
        let Handover::DcApi {
            origin,
            nonce,
            thumbprint,
        } = session.handover
        else {
            return Err(Fault::new(FAULT, detail!("a redirect handover")).into());
        };
        let text = serde_json::json!({"aud": session.audience(), "handover": [origin.as_str(), nonce.as_str(), thumbprint.map(|t| hex(&t.0))]});
        Ok(serde_json::value::to_raw_value(&text)
            .map(Presentation)
            .map_err(|e| Fault::caused(FAULT, detail!("recorded"), e))?)
    }
}

fn cbor(value: &Value) -> String {
    let mut written = Vec::new();
    ciborium::into_writer(value, &mut written).expect("cbor");
    hex(&written)
}

#[test]
fn the_dc_api_handover_reproduces_the_b_2_6_2_example() {
    let jwk = r#"{"kty": "EC", "crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES", "kid": "1"}"#;
    let mut builder = Registry::<TestHost>::builder();
    builder.format(Recorder(TestFormat::new().expect("format")));
    let registry = builder.build().expect("registry");
    let holder = Held::answering("c", &["q"], &[]);
    let wallet = Wallet::new(vec![holder.credential()]).expect("wallet");
    let env = env("en");
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA","client_metadata":{{"jwks":{{"keys":[{jwk}]}}}},"dcql_query":{}}}"#,
        test_queries(&["q"])
    );
    let origin = siros_openid4vp::ids::Origin::parse("https://example.com").expect("origin");
    let received = siros_openid4vp::arrival::Received::dc_api(
        "openid4vp-v1-unsigned",
        &text,
        origin,
        &siros_openid4vp::arrival::DcApiProtocols::ALL,
    )
    .expect("received");
    let encrypted = request_of(&received).expect("request");
    let response = answer(&encrypted, &wallet, &registry, &env);
    let recorded: Json = serde_json::from_str(&response.vp_token.json()).expect("vp_token");
    let session = &recorded["q"][0];
    let (origin, nonce, key) = (
        session["handover"][0].as_str().expect("origin"),
        session["handover"][1].as_str().expect("nonce"),
        session["handover"][2].as_str().expect("thumbprint"),
    );
    let key: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16).expect("hex"))
        .collect();
    let info = cbor(&Value::Array(vec![
        Value::Text(origin.to_owned()),
        Value::Text(nonce.to_owned()),
        Value::Bytes(key),
    ]));
    let info_bytes: Vec<u8> = (0..info.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&info[i..i + 2], 16).expect("hex"))
        .collect();
    let digest = Sha256::digest(&info_bytes);
    let handover = Value::Array(vec![
        Value::Text("OpenID4VPDCAPIHandover".to_owned()),
        Value::Bytes(digest.to_vec()),
    ]);
    let transcript = cbor(&Value::Array(vec![
        Value::Null,
        Value::Null,
        handover.clone(),
    ]));
    // The spec's hex: OpenID4VPDCAPIHandoverInfo, OpenID4VPDCAPIHandover, SessionTranscript.
    assert_eq!(
        info,
        "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c486847777174415820\
         4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
    );
    assert_eq!(
        cbor(&handover),
        "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
    );
    assert_eq!(
        transcript,
        "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
    );
    assert_eq!(
        session["aud"], "origin:https://example.com",
        "Annex A: the audience is the Origin prefixed with origin:"
    );
    // §5.9: a redirect-based request's audience is its Client Identifier, prefix included.
    let client_id = ClientId::parse("x509_san_dns:client.example.org").expect("client_id");
    let nonce = Nonce::parse("n-0S6_WzA2Mj").expect("nonce");
    let redirect = Session {
        handover: Handover::Redirect {
            client_id: &client_id,
            nonce: &nonce,
            thumbprint: None,
            endpoint: Endpoint::ResponseUri("https://client.example.org/post"),
        },
        keys: &[],
    };
    assert_eq!(redirect.audience(), "x509_san_dns:client.example.org");
    // dc_api: the handover holds no thumbprint.
    let plain = parameters(&test_queries(&["q"]), "");
    let received = unsigned(&plain).expect("received");
    let request = request_of(&received).expect("request");
    let recorded: Json =
        serde_json::from_str(&answer(&request, &wallet, &registry, &env).vp_token.json())
            .expect("vp_token");
    assert_eq!(recorded["q"][0]["handover"][2], Json::Null);
}

#[test]
fn an_okp_thumbprint_follows_rfc_8037_a_3() {
    let digest = thumbprint(
        "OKP",
        "Ed25519",
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        None,
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(digest),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

#[test]
fn dc_api_jwt_encrypts_under_the_key_rule() {
    let p256 = r#""crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc""#;
    let keys = format!(
        r#"[{{"kty": "RSA", "kid": "r", "n": "n", "e": "AQAB"}}, {{"kty": "EC", {}, "kid": "p384", "alg": "ECDH-ES+A128KW"}}, {{"kty": "EC", {p256}, "alg": "ECDH-ES", "kid": "2"}}]"#,
        p256.replace("P-256", "P-384")
    );
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"n-0S6_WzA2Mj","client_metadata":{{"jwks":{{"keys":{keys}}},"encrypted_response_enc_values_supported":["XC20P","A128CBC-HS256","A256GCM"]}},"dcql_query":{}}}"#,
        test_queries(&["q"])
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let holder = Held::answering("c", &["q"], &[]);
    let wallet = Wallet::new(vec![holder.credential()]).expect("wallet");
    let response = answer(&request, &wallet, &registry(Binds::First), &env("en"));
    let ResponseData::Encrypted(jwe) = &response.data else {
        panic!("an encrypted response")
    };
    let header: Json = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwe.as_str().split('.').next().expect("header"))
            .expect("base64url"),
    )
    .expect("json");
    assert_eq!(
        header,
        serde_json::json!({"alg": "ECDH-ES", "enc": "A256GCM", "kid": "2"})
    );
    assert!(
        response.data.json().starts_with(r#"{"response":"#),
        "data holds `response` alone"
    );
    // The B.2.6.2 key's thumbprint is the example's.
    let jwk = format!("{{\"kty\": \"EC\", {p256}, \"kid\": \"1\"}}");
    let key = Node::parse(&jwk).expect("jwk");
    assert_eq!(
        hex(&AgreeableKey::of(&key).expect("agreeable").thumbprint()),
        "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
    );
}

#[test]
fn the_wallet_agrees_keys_on_every_curve_it_implements() {
    use siros_openid4vp::request::{Curve, KeyAgreement};
    // RFC 7518 §6.2 and RFC 8037: EC keys carry x and y, OKP keys x; use and alg, when present,
    // are enc and an ECDH-ES key agreement.
    let cases: [(&str, Option<(Curve, KeyAgreement)>); 10] = [
        (
            r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "x", "y": "y"}"#,
            Some((Curve::P256, KeyAgreement::EcdhEs)),
        ),
        (
            r#"{"kty": "EC", "crv": "P-384", "kid": "k", "x": "x", "y": "y", "alg": "ECDH-ES+A192KW"}"#,
            Some((Curve::P384, KeyAgreement::EcdhEsA192Kw)),
        ),
        (
            r#"{"kty": "EC", "crv": "P-521", "kid": "k", "x": "x", "y": "y", "alg": "ECDH-ES+A256KW"}"#,
            Some((Curve::P521, KeyAgreement::EcdhEsA256Kw)),
        ),
        (
            r#"{"kty": "OKP", "crv": "X25519", "kid": "k", "x": "x"}"#,
            Some((Curve::X25519, KeyAgreement::EcdhEs)),
        ),
        (
            r#"{"kty": "OKP", "crv": "X448", "kid": "k", "x": "x", "use": "enc"}"#,
            Some((Curve::X448, KeyAgreement::EcdhEs)),
        ),
        (
            r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "x"}"#,
            None,
        ),
        (
            r#"{"kty": "EC", "crv": "X25519", "kid": "k", "x": "x", "y": "y"}"#,
            None,
        ),
        (
            r#"{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "x"}"#,
            None,
        ),
        (
            r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "x", "y": "y", "use": "sig"}"#,
            None,
        ),
        (
            r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "x", "y": "y", "alg": "RSA-OAEP"}"#,
            None,
        ),
    ];
    for (jwk, want) in cases {
        let node = Node::parse(jwk).expect("jwk");
        let key = AgreeableKey::of(&node);
        assert_eq!(key.map(|key| (key.curve, key.alg)), want, "{jwk}");
        // The thumbprint covers the curve by the crv the key states.
        if let Some(key) = key {
            assert_eq!(
                Some(key.curve.name()),
                node.get("crv").and_then(Node::as_str),
                "{jwk}"
            );
        }
    }
    // An OKP key's thumbprint covers crv, kty and x alone.
    let x25519 = Node::parse(r#"{"kty": "OKP", "crv": "X25519", "kid": "k", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#).expect("jwk");
    let key = AgreeableKey::of(&x25519).expect("agreeable");
    assert_eq!(
        key.thumbprint(),
        thumbprint(
            "OKP",
            "X25519",
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            None
        )
    );
    assert_eq!(
        hex(&key.thumbprint()),
        hex(&Sha256::digest(
            br#"{"crv":"X25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        ))
    );
}
