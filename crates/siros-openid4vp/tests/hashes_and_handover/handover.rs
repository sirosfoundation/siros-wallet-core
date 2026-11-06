//! The session phase 2 binds (B.2.6.2's example request) and §5.9's audience, and §8.3's choice
//! of the response encryption and the JWE the core seals.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value as Json;
use siros_explain::AllOf;
use siros_openid4vp::authenticate::PrefixName;
use siros_openid4vp::consent::Card;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, FormatHost, PresentError, Presentation, Usable,
};
use siros_openid4vp::host::{Haip, Platform, RequestDecryption};
use siros_openid4vp::ids::FormatId;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Carriage, Fault, FindingData, Format, FormatQuery, Member, Members, NoCandidate, OptionIndex,
    Options, Registry, Shown,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{AgreeableKey, Query};
use siros_openid4vp::resolve::Delivery;
use siros_openid4vp::rows::Env;
use siros_openid4vp::session::{Session, SessionBinding};
use siros_openid4vp::wallet::{Credential, Wallet};
use siros_testkit::FAULT;
use siros_testkit::probe::{Redirect, read_redirect_session};
use siros_testkit::{
    Binds, JweHaip, TestChoice, TestFormat, TestHost, TestPlatform, TestRequestDecryption,
};

use crate::common::{Held, env, parameters, registry, request_of, test_queries, unsigned};

use super::answer;

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

    fn placement(&self) -> Option<siros_openid4vp::wallet_metadata::Placement> {
        self.0.placement()
    }

    fn additions<'c>(
        &self,
        credential: &'c siros_openid4vp::wallet::Credential<'c>,
    ) -> Result<Box<dyn siros_openid4vp::plugins::ViewAdditions + 'c>, Fault> {
        self.0.additions(credential)
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
    fn options(&self) -> &Options {
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

    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<Carriage, Fault> {
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
        let SessionBinding::DcApi { origin } = session.binding() else {
            return Err(Fault::new(FAULT, detail!("a redirect binding")).into());
        };
        let sealed = session
            .encrypted_to()
            .map(|key| [key.key().kid().as_str(), key.enc().as_str()]);
        let text = serde_json::json!({"aud": session.audience().as_str(), "origin": origin.as_str(), "nonce": session.nonce().as_str(), "sealed": sealed});
        Ok(Presentation::object(&text.to_string())
            .map_err(|e| Fault::caused(FAULT, detail!("recorded"), e))?)
    }
}

#[test]
fn a_dc_api_session_binds_the_origin_the_nonce_and_the_key_the_core_sealed_to() {
    let jwk = r#"{"kty": "EC", "crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0", "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES", "kid": "1"}"#;
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
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
    let recorded: Json = serde_json::from_str(&response.vp_token).expect("vp_token");
    let session = &recorded["q"][0];
    // The session binds the Origin, the nonce, and B.2.6.2's key, to which the core sealed with
    // A128GCM, the Verifier listing no enc (§5.1).
    assert_eq!(
        (&session["origin"], &session["nonce"], &session["sealed"]),
        (
            &Json::from("https://example.com"),
            &Json::from("exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"),
            &serde_json::json!(["1", "A128GCM"])
        )
    );
    assert_eq!(
        session["aud"], "origin:https://example.com",
        "Annex A: the audience is the Origin prefixed with origin:"
    );
    // §5.9: a redirect-based request's audience is its Client Identifier, prefix included.
    let audience = read_redirect_session(
        Redirect {
            client_id: "x509_san_dns:client.example.org",
            response_uri: "https://client.example.org/post",
            nonce: "n-0S6_WzA2Mj",
            client_metadata: "{}",
        },
        siros_explain::checked!(PrefixName, "x509_san_dns"),
        TestChoice::Plain,
        |redirect| redirect.audience(),
    )
    .expect("the route of a redirect-based request");
    assert_eq!(audience.as_str(), "x509_san_dns:client.example.org");
    // dc_api: the session is sealed to no key.
    let plain = parameters(&test_queries(&["q"]), "");
    let received = unsigned(&plain).expect("received");
    let request = request_of(&received).expect("request");
    let recorded: Json = serde_json::from_str(&answer(&request, &wallet, &registry, &env).vp_token)
        .expect("vp_token");
    assert_eq!(recorded["q"][0]["sealed"], Json::Null);
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
    let (registry, env) = (registry(Binds::First), env("en"));
    let response = answer(&request, &wallet, &registry, &env);
    let Delivery::DcApi(data) = &response.delivery else {
        panic!("a DC API delivery")
    };
    let data: Json = serde_json::from_str(data.as_str()).expect("data");
    let jwe = data["response"].as_str().expect("an encrypted response");
    assert_eq!(
        data.as_object().map(serde_json::Map::len),
        Some(1),
        "data holds `response` alone"
    );
    let header: Json = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwe.split('.').next().expect("header"))
            .expect("base64url"),
    )
    .expect("json");
    assert_eq!(
        header,
        serde_json::json!({"alg": "ECDH-ES", "enc": "A256GCM", "kid": "2"})
    );
}

/// §8.3's example key with its private `d`, which decrypts the example response.
const SECTION_8_3_KEY: &str = r#"{"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
    "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
    "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
    "d":"Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"}"#;

/// §8.3's example request's `client_metadata`: four keys, A128GCM and A128CBC-HS256.
const SECTION_8_3_METADATA: &str = r#"{"jwks":{"keys":[
    {"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
     "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk","y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"},
    {"kty":"OKP","kid":"jc","use":"enc","crv":"X25519","alg":"ECDH-ES",
     "x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"},
    {"kty":"EC","kid":"lc","use":"enc","crv":"P-384","alg":"ECDH-ES",
     "x":"iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV",
     "y":"MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"},
    {"kty":"OKP","kid":"bc","use":"enc","crv":"X448","alg":"ECDH-ES",
     "x":"pK5IRpLlX-8XcsRYWHejpzkfsHoDOmAYuBzAC7aTpewWOw_QFHSa64t9p2kuommI8JQQLohS2AIA"}]},
    "encrypted_response_enc_values_supported":["A128GCM","A128CBC-HS256"]}"#;

siros_testkit::test_host! {
    /// A host whose `Haip` encrypts.
    #[derive(Default)]
    struct Sealing {
        handles { platform: TestPlatform => Platform }
        zero_sized { JweHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional {}
        lacks {}
    }
}

/// KA6 and KA13: §8.3's request answered in `dc_api.jwt`; jose-rs decrypts the core's JWE under
/// §8.3's key to §8.1's object, the Authorization Response delivered, sealed with the `enc` and to the `kid` the key
/// rule chose.
#[test]
fn the_core_seals_section_8_3s_answer_to_the_key_the_rule_chose() {
    let key = jose_rs::jwk::Jwk::from_json(SECTION_8_3_KEY).expect("§8.3's key");
    let decrypt = |jwe: &str| -> Json {
        let plaintext = jose_rs::jwe::decrypt_with_jwk(&key, jwe).expect("decrypts");
        serde_json::from_slice(&plaintext).expect("a JSON payload")
    };
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"xyz123ltcaccescbwc777","dcql_query":{},"client_metadata":{SECTION_8_3_METADATA}}}"#,
        test_queries(&["q"])
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let held = Held::answering("c", &["q"], &[]);
    let wallet = Wallet::new(vec![held.credential()]).expect("wallet");
    let mut builder = Registry::<Sealing>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("format"));
    let registry = builder.build().expect("registry");
    let env = env("en");
    let built = answer(&request, &wallet, &registry, &env);
    let Delivery::DcApi(data) = &built.delivery else {
        panic!("a DC API delivery")
    };
    let data: Json = serde_json::from_str(data.as_str()).expect("data");
    let jwe = data["response"].as_str().expect("{\"response\": JWE}");
    let protected = jwe.split('.').next().expect("a compact JWE");
    let header: Json =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).expect("base64url"))
            .expect("a header");
    assert_eq!(
        (&header["enc"], &header["kid"]),
        (&Json::from("A128GCM"), &Json::from("ac"))
    );
    let payload = decrypt(jwe);
    let names = |object: &Json| -> Vec<String> {
        object
            .as_object()
            .map(|members| members.keys().cloned().collect())
            .unwrap_or_default()
    };
    assert_eq!(names(&payload), ["vp_token"], "§8.1, no state requested");
    assert_eq!(names(&payload["vp_token"]), ["q"], "§8.1: by query id");
    assert_eq!(payload["vp_token"]["q"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        payload,
        serde_json::from_str::<Json>(&built.json).expect("the response")
    );
}

/// RFC 7517 §4 and RFC 7518 §6.2, RFC 8037 §2: a JWK names its key type, curve and
/// coordinates, base64url; an EC key carries `y`; `use`, when present, is `enc` for a key the
/// wallet agrees with; `crv` and `alg` are registry names, which the agreeing module and the key
/// rule judge. One fixture per refusal.
#[test]
fn an_agreeable_key_reads_its_jwk_members() {
    use siros_openid4vp::request::KeyAgreement;
    let accepted: [(&str, &str, Option<&str>); 4] = [
        (
            r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "AA", "y": "AQ"}"#,
            "P-256",
            None,
        ),
        (
            r#"{"kty": "EC", "crv": "P-384", "kid": "k", "x": "AA", "y": "AQ", "alg": "ECDH-ES+A192KW"}"#,
            "P-384",
            Some("ECDH-ES+A192KW"),
        ),
        (
            r#"{"kty": "OKP", "crv": "X25519", "kid": "k", "x": "AA", "use": "enc"}"#,
            "X25519",
            None,
        ),
        (
            r#"{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "AA"}"#,
            "Ed25519",
            None,
        ),
    ];
    for (jwk, curve, alg) in accepted {
        let node = Node::parse(jwk).expect("jwk");
        let key = AgreeableKey::of(&node).expect(jwk);
        assert_eq!(
            (key.curve().as_str(), key.alg().map(KeyAgreement::as_str)),
            (curve, alg),
            "{jwk}"
        );
        assert_eq!(key.point().x(), [0], "{jwk}");
    }
    let refused = [
        r#"{"crv": "P-256", "kid": "k", "x": "AA", "y": "AQ"}"#,
        r#"{"kty": "EC", "kid": "k", "x": "AA", "y": "AQ"}"#,
        r#"{"kty": "EC", "crv": "P 256", "kid": "k", "x": "AA", "y": "AQ"}"#,
        r#"{"kty": "EC", "crv": "P-256", "kid": "k", "y": "AQ"}"#,
        r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "A", "y": "AQ"}"#,
        r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "AA"}"#,
        r#"{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AQ"}"#,
        r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "AA", "y": "AQ", "use": "sig"}"#,
        r#"{"kty": "EC", "crv": "P-256", "kid": "k", "x": "AA", "y": "AQ", "alg": ""}"#,
    ];
    for jwk in refused {
        let node = Node::parse(jwk).expect("jwk");
        assert!(AgreeableKey::of(&node).is_none(), "{jwk}");
    }
}
