//! I2: every Authorization Response goes to the authenticated endpoint, whatever mode carries it;
//! every error goes to it, to the platform, to a `response_uri` a `Framework` binding vouches
//! for, or through an `Unverified` route in the plain form; every URI endpoint is an absolute
//! `https` URI with a host; every sealed answer and error is sealed by the core to the session's
//! `RouteKey`, and the mode of a sealed route receives no plaintext. A property over generated
//! DC API and URI requests, accepted and refused, with tampered signatures and endpoints, run
//! once per registered mode: the core's four and `TestMode` with bodies of either channel and
//! key choices the sealing statement admits and refuses. I5: the same arrival, answers and host
//! give the same `Delivery` bytes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::Value;
use siros_openid4vp::arrival::{DcApiProtocols, Received};
use siros_openid4vp::authenticate::{Authenticated, BoundEndpoint};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::ids::Origin;
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::modes::{DcApi, DcApiJwt, DirectPost, DirectPostJwt};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::recourse::{DcApiErrors, ErrorTarget, Rejected, Reply};
use siros_openid4vp::request::{ContentEncryption, Request};
use siros_openid4vp::resolve::{Delivery, Outcome, Prepared, Route, RouteBreach};
use siros_openid4vp::routing::{ChannelKind, ModeName, VpToken};
use siros_openid4vp::uri::{Fetch, FetchAnswer, RequestObjectFetch};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{B26_KEY, CLIENT_ID, REQUEST_OBJECT_HEADER, first_selection};
use siros_testkit::jose::{VERIFIER_SECRET, compact_jws};
use siros_testkit::{
    Published, TestBody, TestChoice, TestFormat, TestHost, TestMode, TestPrefix, TestTrust,
};

use super::common::{Held, env, test_queries};
use super::config;

/// The test Verifier's endpoints.
const RESPONSE_URI: &str = "https://verifier.example/post";
const ORIGIN: &str = "https://verifier.example";
const TEST_MODE: ModeName = siros_explain::checked!(ModeName, "test.mode");

/// How a mode under test registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Registration {
    /// `mode`: answers in the clear.
    Clear,
    /// `jwe_mode`: answers the core seals.
    Jwe,
}

/// A registered mode under test.
#[derive(Debug, Clone)]
enum Under {
    DcApi,
    DcApiJwt,
    DirectPostJwt,
    DirectPost,
    Test(TestMode, Registration),
}

impl Under {
    fn name(&self) -> &'static str {
        match self {
            Self::DcApi => "dc_api",
            Self::DcApiJwt => "dc_api.jwt",
            Self::DirectPostJwt => "direct_post.jwt",
            Self::DirectPost => "direct_post",
            Self::Test(..) => TEST_MODE.as_str(),
        }
    }

    fn channel(&self) -> ChannelKind {
        match self {
            Self::DcApi | Self::DcApiJwt => ChannelKind::DcApi,
            Self::DirectPostJwt | Self::DirectPost => ChannelKind::Uri,
            Self::Test(mode, _) => mode.channel,
        }
    }

    /// The registry: `vp_token`, the test format and prefix, and the mode, a URI mode for its
    /// errors too.
    fn registry(&self) -> Registry<TestHost> {
        let mut builder = Registry::<TestHost>::builder();
        builder.response_type(VpToken);
        builder.format(TestFormat::new().expect("the test format"));
        builder.client_prefix(TestPrefix::Request);
        match self.clone() {
            Self::DcApi => builder.mode(DcApi),
            Self::DcApiJwt => builder.jwe_mode(DcApiJwt),
            Self::DirectPostJwt => {
                builder.jwe_mode(DirectPostJwt);
                builder.error_mode(DirectPostJwt);
            }
            Self::DirectPost => builder.error_mode(DirectPost),
            Self::Test(mode, registration) => {
                if mode.channel == ChannelKind::Uri {
                    builder.error_mode(mode.clone());
                }
                match registration {
                    Registration::Clear => builder.mode(mode),
                    Registration::Jwe => builder.jwe_mode(mode),
                }
            }
        }
        builder.build().expect("the registry")
    }
}

/// The core's four modes, and `TestMode` on each channel with each body, under each registration
/// with choices the statement admits (B.2.6's key, A128GCM, which a Verifier listing none takes)
/// and refuses (A256GCM unlisted, a key of other metadata, a key on a clear route, no key on a
/// sealed one).
fn modes() -> Vec<Under> {
    let mut modes = vec![
        Under::DcApi,
        Under::DcApiJwt,
        Under::DirectPostJwt,
        Under::DirectPost,
    ];
    let key = |enc| TestChoice::Key { place: 0, enc };
    let choices = [
        (Registration::Clear, TestChoice::Plain),
        (Registration::Jwe, key(ContentEncryption::A128GCM)),
        (Registration::Jwe, key(ContentEncryption::A256GCM)),
        (
            Registration::Jwe,
            TestChoice::Foreign {
                enc: ContentEncryption::A128GCM,
            },
        ),
        (Registration::Clear, key(ContentEncryption::A128GCM)),
        (Registration::Jwe, TestChoice::Plain),
    ];
    for channel in [ChannelKind::DcApi, ChannelKind::Uri] {
        for body in [TestBody::Own, TestBody::Other] {
            for (registration, choice) in choices {
                let mode = TestMode {
                    choice,
                    body,
                    ..TestMode::new(TEST_MODE, channel)
                };
                modes.push(Under::Test(mode, registration));
            }
        }
    }
    modes
}

/// A rule a generated request breaks after authentication.
#[derive(Debug, Clone, Copy)]
enum Break {
    /// None.
    Nothing,
    /// `dcql_query` absent.
    Query,
    /// `client_metadata` no object (C6).
    Metadata,
    /// `state` not URL-safe (P6, by URI).
    State,
    /// A mode no error mode carries (C5).
    Mode,
}

/// Where a URI request sends its answers.
#[derive(Debug, Clone, Copy)]
enum Endpoint {
    /// The test Verifier's Response URI.
    Own,
    /// Another host's.
    Other,
    /// The Response URI by `http` (A13).
    Http,
}

/// One generated request.
#[derive(Debug, Clone)]
struct Case {
    signed: bool,
    forged: bool,
    listed: bool,
    endpoint: Endpoint,
    keys: Vec<&'static str>,
    encs: Option<&'static [&'static str]>,
    broken: Break,
    held: bool,
}

/// A key the rule refuses: B.2.6's coordinates under RSA-OAEP.
const RSA: &str = r#"{"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"RSA-OAEP","kid":"rsa"}"#;
/// A second key the rule accepts.
const SECOND: &str = r#"{"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0","y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"ECDH-ES","kid":"2"}"#;

impl Case {
    fn draw(rng: &mut ChaCha8Rng) -> Self {
        let keys: &[&[&'static str]] =
            &[&[], &[B26_KEY], &[RSA], &[RSA, SECOND], &[B26_KEY, SECOND]];
        let encs: &[Option<&'static [&'static str]>] = &[
            None,
            Some(&["A256GCM"]),
            Some(&["A128CBC-HS256"]),
            Some(&["A128GCM", "A256GCM"]),
        ];
        let breaks = [
            Break::Nothing,
            Break::Nothing,
            Break::Nothing,
            Break::Query,
            Break::Metadata,
            Break::State,
            Break::Mode,
        ];
        let endpoints = [
            Endpoint::Own,
            Endpoint::Own,
            Endpoint::Other,
            Endpoint::Http,
        ];
        Self {
            signed: rng.random_bool(0.5),
            forged: rng.random_bool(0.15),
            listed: rng.random_bool(0.3),
            endpoint: endpoints[rng.random_range(0..endpoints.len())],
            keys: keys[rng.random_range(0..keys.len())].to_vec(),
            encs: encs[rng.random_range(0..encs.len())],
            broken: breaks[rng.random_range(0..breaks.len())],
            held: rng.random_bool(0.8),
        }
    }

    /// The request's parameters for the mode on its channel.
    fn parameters(&self, under: &Under, k: usize) -> String {
        let mode = match self.broken {
            Break::Mode => "fragment",
            _ => under.name(),
        };
        let mut members = vec![
            r#""response_type":"vp_token""#.to_owned(),
            format!(r#""response_mode":"{mode}""#),
            r#""nonce":"n-0S6_WzA2Mj""#.to_owned(),
        ];
        if !matches!(self.broken, Break::Query) {
            members.push(format!(r#""dcql_query":{}"#, test_queries(&["q"])));
        }
        let encs = self.encs.map_or_else(String::new, |encs| {
            let listed: Vec<String> = encs.iter().map(|enc| format!(r#""{enc}""#)).collect();
            format!(
                r#","encrypted_response_enc_values_supported":[{}]"#,
                listed.join(",")
            )
        });
        members.push(match self.broken {
            Break::Metadata => r#""client_metadata":5"#.to_owned(),
            _ => format!(
                r#""client_metadata":{{"jwks":{{"keys":[{}]}}{encs}}}"#,
                self.keys.join(",")
            ),
        });
        match under.channel() {
            ChannelKind::DcApi => {
                if self.signed {
                    members.push(format!(r#""client_id":"{CLIENT_ID}""#));
                    members.push(format!(r#""expected_origins":["{ORIGIN}"]"#));
                }
            }
            ChannelKind::Uri => {
                let endpoint = self.response_uri();
                let state = match self.broken {
                    Break::State => "a b".to_owned(),
                    _ => format!("s-{k}"),
                };
                members.push(format!(r#""client_id":"{CLIENT_ID}""#));
                members.push(format!(r#""response_uri":"{endpoint}""#));
                members.push(format!(r#""state":"{state}""#));
            }
        }
        format!("{{{}}}", members.join(","))
    }

    /// The `response_uri` a URI request names.
    const fn response_uri(&self) -> &'static str {
        match self.endpoint {
            Endpoint::Own => RESPONSE_URI,
            Endpoint::Other => "https://other.example/post",
            Endpoint::Http => "http://verifier.example/post",
        }
    }

    /// The Request Object of the parameters, signed by the test Verifier's key or, forged, by
    /// another's.
    fn object(&self, parameters: &str) -> String {
        let key = if self.forged {
            [7u8; 32]
        } else {
            VERIFIER_SECRET
        };
        compact_jws(&key, REQUEST_OBJECT_HEADER, parameters).expect("signs")
    }

    /// The trust service, listing the test Verifier's Response URI when `listed`.
    fn trust(&self) -> TestTrust {
        TestTrust {
            endpoints: self.listed.then(|| vec![RESPONSE_URI.to_owned()]),
            ..TestTrust::default()
        }
    }
}

/// What a mode's encryption comes to on a request's route.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// No answering route: C6 or the mode's C7 refuses, or no registered mode answers.
    Unanswered,
    /// Answers in the clear.
    Clear,
    /// Answers sealed to the key of the `kid`, under the `enc`.
    Sealed(String, String),
    /// The core refuses the mode's choice.
    Breach(RouteBreach),
}

impl Verdict {
    /// The verdict of a `TestMode`'s choice, from its registration, the request's keys and listed
    /// `enc`s, and the sealing statement of the test `Haip` (P-256 `ECDH-ES` with A128GCM or
    /// A256GCM); `None` for the core's modes, which never breach.
    fn expected(under: &Under, case: &Case) -> Option<Self> {
        let Under::Test(mode, registration) = under else {
            return None;
        };
        if matches!(case.broken, Break::Metadata | Break::Mode) {
            return Some(Self::Unanswered);
        }
        let sealed = *registration == Registration::Jwe;
        Some(match (mode.choice, sealed) {
            (TestChoice::Plain, false) => Self::Clear,
            (TestChoice::Plain, true) => Self::Breach(RouteBreach::NoKey),
            (TestChoice::Key { place, .. }, _) if place >= case.keys.len() => Self::Unanswered,
            (TestChoice::Key { .. } | TestChoice::Foreign { .. }, false) => {
                Self::Breach(RouteBreach::KeyInTheClear)
            }
            (TestChoice::Foreign { .. }, true) => Self::Breach(RouteBreach::Foreign),
            (TestChoice::Key { place, enc }, true) => {
                let key: Value = serde_json::from_str(case.keys[place]).expect("a JWK");
                let listed = case.encs.map_or(enc == ContentEncryption::A128GCM, |encs| {
                    encs.contains(&enc.as_str())
                });
                if key["crv"] != "P-256" || key["alg"] != "ECDH-ES" {
                    Self::Breach(RouteBreach::Unstated)
                } else if !listed {
                    Self::Breach(RouteBreach::Unlisted)
                } else {
                    let kid = key["kid"].as_str().expect("a kid").to_owned();
                    Self::Sealed(kid, enc.as_str().to_owned())
                }
            }
        })
    }

    /// The verdict a route came to, or the breach its fault names.
    fn of(route: &Result<Route<'_, TestHost>, Outcome>) -> Option<Self> {
        match route {
            Ok(route) => Some(match route.answering() {
                None => Self::Unanswered,
                Some(_) => {
                    session_key(route).map_or(Self::Clear, |(kid, enc)| Self::Sealed(kid, enc))
                }
            }),
            Err(Outcome::Fault(fault)) => std::error::Error::source(fault)
                .and_then(|cause| cause.downcast_ref::<RouteBreach>())
                .map(|breach| Self::Breach(*breach)),
            Err(_) => None,
        }
    }
}

/// What the property saw: each outcome's count, and each violation of I2.
#[derive(Debug, Default)]
struct Seen {
    counts: Vec<(&'static str, usize)>,
    violations: Vec<String>,
}

impl Seen {
    fn add(&mut self, kind: &'static str) {
        match self.counts.iter_mut().find(|(known, _)| *known == kind) {
            Some((_, count)) => *count += 1,
            None => self.counts.push((kind, 1)),
        }
    }

    fn violate(&mut self, what: String) {
        self.violations.push(what);
    }

    fn count(&self, kind: &str) -> usize {
        self.counts
            .iter()
            .find(|(known, _)| *known == kind)
            .map_or(0, |(_, count)| *count)
    }
}

/// The header and plaintext of the test `Haip`'s JWE, which keeps its plaintext readable.
fn opened(jwe: &str) -> Option<(Value, Value)> {
    let parts: Vec<&str> = jwe.split('.').collect();
    let [header, "", "", plaintext, ""] = parts.as_slice() else {
        return None;
    };
    let read = |part: &str| -> Option<Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    Some((read(header)?, read(plaintext)?))
}

/// The pairs of a form, in order.
fn form(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    serde_urlencoded::from_bytes(bytes).ok()
}

/// The JWE a body carries alone: `{"response": JWE}` over the DC API, `response=<JWE>` by URI.
fn sealed_body(delivery: &Delivery) -> Option<String> {
    match delivery {
        Delivery::DcApi(data) => {
            let data: Value = serde_json::from_str(data.as_str()).ok()?;
            let object = data.as_object()?;
            (object.len() == 1).then(|| object.get("response")?.as_str().map(str::to_owned))?
        }
        Delivery::Post { body, .. } => match form(body.bytes())?.as_slice() {
            [(name, jwe)] if name == "response" => Some(jwe.clone()),
            _ => None,
        },
    }
}

/// Whether a URI endpoint is an absolute `https` URI with a host.
fn https(endpoint: &str) -> bool {
    endpoint.strip_prefix("https://").is_some_and(|rest| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|host| !host.is_empty())
    })
}

/// I2 over one delivery of the route: its channel's, to the authenticated endpoint, sealed to
/// the key the session holds with the plaintext `plaintext` checks, else in the clear.
fn check_routed(
    seen: &mut Seen,
    at: &str,
    delivery: &Delivery,
    endpoint: Option<&str>,
    key: Option<&(String, String)>,
    plaintext: &dyn Fn(&Value) -> bool,
) {
    match (delivery, endpoint) {
        (Delivery::DcApi(_), None) => {}
        (Delivery::Post { endpoint: to, .. }, Some(bound)) => {
            if to.as_str() != bound || !https(to.as_str()) {
                seen.violate(format!("{at}: posted to {} for {bound}", to.as_str()));
            }
        }
        (other, _) => seen.violate(format!("{at}: a delivery off its channel: {other:?}")),
    }
    match (key, sealed_body(delivery)) {
        (Some((kid, enc)), Some(jwe)) => match opened(&jwe) {
            Some((header, inner))
                if header["kid"] == kid.as_str() && header["enc"] == enc.as_str() =>
            {
                if !plaintext(&inner) {
                    seen.violate(format!("{at}: another plaintext sealed: {inner}"));
                }
            }
            _ => seen.violate(format!("{at}: sealed to another key than ({kid}, {enc})")),
        },
        (Some(key), None) => seen.violate(format!(
            "{at}: a sealed route's body in the clear for {key:?}"
        )),
        (None, Some(_)) => seen.violate(format!("{at}: a JWE on a route without a key")),
        (None, None) => {}
    }
}

/// A rejection's reply: over the DC API A.4's error; by URI the plain form to the `https`
/// `response_uri` the request names, as `Listed` only when the trust service lists it, or nothing.
fn check_rejected(seen: &mut Seen, at: &str, case: &Case, rejected: &Rejected<'_>) {
    match rejected.reply(DcApiErrors::Respond) {
        Ok(Reply::Cancel) => seen.add("rejections answering the End-User alone"),
        Ok(Reply::Deliver(Delivery::DcApi(data))) => {
            let data: Value = serde_json::from_str(data.as_str()).unwrap_or(Value::Null);
            if data
                .as_object()
                .is_none_or(|object| object.len() != 1 || !object.contains_key("error"))
            {
                seen.violate(format!("{at}: a DC API rejection writes {data}"));
            }
            seen.add("rejections answered on the DC API");
        }
        Ok(Reply::Deliver(Delivery::Post { endpoint, body })) => {
            let vouched = case.listed && matches!(case.endpoint, Endpoint::Own);
            let routed = endpoint.as_str() == case.response_uri()
                && match rejected.route().map(|route| route.target()) {
                    Some(ErrorTarget::Listed(_)) => vouched,
                    Some(ErrorTarget::Unverified(_)) => true,
                    _ => false,
                };
            let plain = form(body.bytes()).is_some_and(|pairs| {
                pairs.first().is_some_and(|(name, _)| name == "error")
                    && !pairs.iter().any(|(name, _)| name == "response")
            });
            if !routed || !plain || !https(endpoint.as_str()) {
                seen.violate(format!("{at}: a rejection posted to {}", endpoint.as_str()));
            }
            seen.add("rejections posted plain to their route");
        }
        Err(fault) => seen.violate(format!("{at}: a rejection's reply faults: {fault}")),
    }
}

/// A.4 over the DC API: the error's data is `{"error": code}` alone.
fn check_a4(seen: &mut Seen, at: &str, delivery: &Delivery, code: &str) {
    if let Delivery::DcApi(data) = delivery {
        let data: Value = serde_json::from_str(data.as_str()).unwrap_or(Value::Null);
        if data != serde_json::json!({ "error": code }) {
            seen.violate(format!("{at}: A.4's error is {data}"));
        }
    }
}

/// The key the session of the route binds, as (`kid`, `enc`).
fn session_key(route: &Route<'_, TestHost>) -> Option<(String, String)> {
    route.answering().and_then(|answering| {
        answering
            .session()
            .encrypted_to()
            .map(|key| (key.key().kid().to_string(), key.enc().as_str().to_owned()))
    })
}

/// The authenticated endpoint of a URI request; `None` over the DC API.
fn bound(authenticated: &Authenticated<'_>) -> Option<String> {
    match authenticated.verifier().endpoint() {
        BoundEndpoint::DcApi => None,
        BoundEndpoint::ResponseUri { uri, .. } => Some(uri.as_str().to_owned()),
    }
}

/// One case through the core under the mode: arrival, authentication, the route, the request's
/// rules, phase 1, phase 2, each delivery checked.
fn run(seen: &mut Seen, under: &Under, registry: &Registry<TestHost>, case: &Case, k: usize) {
    let at = format!("{} case {k} {case:?}", under.name());
    let host = TestHost::default();
    let parameters = case.parameters(under, k);
    let object;
    let data;
    let link =
        "openid4vp://?client_id=test%3Averifier&request_uri=https%3A%2F%2Fverifier.example%2Fr";
    let received = match under.channel() {
        ChannelKind::DcApi => {
            let (protocol, body) = if case.signed {
                data = format!(r#"{{"request":"{}"}}"#, case.object(&parameters));
                ("openid4vp-v1-signed", data.as_str())
            } else {
                ("openid4vp-v1-unsigned", parameters.as_str())
            };
            let origin = Origin::parse(ORIGIN).expect("the Origin");
            match Received::dc_api(protocol, body, origin, &DcApiProtocols::ALL) {
                Ok(received) => received,
                Err(cause) => {
                    check_rejected(seen, &at, case, &Rejected::dc_api(cause));
                    return;
                }
            }
        }
        ChannelKind::Uri => {
            let fetch = Fetch::of(link, registry, &host).expect("a fetch");
            assert!(matches!(fetch.request(), RequestObjectFetch::Get(_)));
            object = case.object(&parameters);
            match fetch.resume(FetchAnswer::Body(&object), registry, &host) {
                Ok(received) => received,
                Err(rejected) => {
                    check_rejected(seen, &at, case, &rejected);
                    return;
                }
            }
        }
    };
    let envelope = match Envelope::parse(&received, registry) {
        Ok(envelope) => envelope,
        Err(cause) => {
            check_rejected(seen, &at, case, &Rejected::unreadable(&received, cause));
            return;
        }
    };
    let trust = case.trust();
    let authenticated = match envelope
        .questions(registry, &config(), &host)
        .and_then(|pending| {
            pending.authenticate(|evaluation| trust.decide(evaluation), &config(), &host)
        }) {
        Ok(authenticated) => authenticated,
        Err(rejected) => {
            check_rejected(seen, &at, case, &rejected);
            return;
        }
    };
    let routed = Route::new(&authenticated, registry, &host);
    // C5 by URI: the request's mode names no registered error mode.
    let unroutable = under.channel() == ChannelKind::Uri && matches!(case.broken, Break::Mode);
    if unroutable != matches!(routed, Err(Outcome::Unroutable(_))) {
        seen.violate(format!(
            "{at}: unroutable {unroutable}: {:?}",
            routed.as_ref().err()
        ));
        return;
    }
    let verdict = Verdict::of(&routed);
    let expected = Verdict::expected(under, case);
    match (&expected, &verdict) {
        _ if unroutable => {}
        (Some(expected), got) if got.as_ref() != Some(expected) => {
            seen.violate(format!("{at}: the route came to {got:?} for {expected:?}"));
            return;
        }
        (None, Some(Verdict::Breach(_)) | None) => {
            seen.violate(format!(
                "{at}: the core's mode faults: {:?}",
                routed.as_ref().err()
            ));
            return;
        }
        _ => {}
    }
    let route = match routed {
        Ok(route) => route,
        Err(Outcome::Unroutable(_)) => {
            seen.add("URI requests no error mode carries");
            return;
        }
        Err(_) => {
            seen.add("routes refused for a mode that breaks its registration");
            return;
        }
    };
    let endpoint = bound(&authenticated);
    let key = session_key(&route);
    // Over the DC API every error is A.4's, in the clear (A.4); by URI the route's key seals it.
    let error_key = endpoint.as_ref().and(key.as_ref());
    let is_error = |code: &'static str| {
        move |inner: &Value| inner["error"] == code && inner.get("vp_token").is_none()
    };
    let refused = match Request::parse(authenticated.envelope()) {
        Err(refused) => Some(refused),
        Ok(request) => Accepted::new(&request, registry).err(),
    };
    if let Some(refused) = refused {
        let code = refused
            .refusals()
            .first()
            .map(|refusal| refusal.code().as_str())
            .unwrap_or_default();
        match route.refusal(&refused, DcApiErrors::Respond, &host) {
            Ok(Reply::Deliver(delivery)) => {
                check_routed(
                    seen,
                    &at,
                    &delivery,
                    endpoint.as_deref(),
                    error_key,
                    &|inner| inner["error"] == code,
                );
                check_a4(seen, &at, &delivery, code);
                seen.add(if error_key.is_some() {
                    "refusals sealed on their route"
                } else {
                    "refusals in the clear on their route"
                });
            }
            Ok(Reply::Cancel) => seen.violate(format!("{at}: Respond cancels")),
            Err(fault) => seen.violate(format!("{at}: a refusal's error faults: {fault}")),
        }
        return;
    }
    let request = Request::parse(authenticated.envelope()).expect("an accepted request");
    let held = if case.held {
        vec![Held::answering("c", &["q"], &[])]
    } else {
        vec![Held::answering("c", &[], &[])]
    };
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("a wallet");
    let env = env("en");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let Ok(ids) = first_selection(&request, &wallet, registry, &env, &rendering) else {
        match route.unmet(
            siros_openid4vp::matching::UnmetCode::AccessDenied,
            DcApiErrors::Respond,
            &host,
        ) {
            Ok(Reply::Deliver(delivery)) => {
                check_routed(
                    seen,
                    &at,
                    &delivery,
                    endpoint.as_deref(),
                    error_key,
                    &is_error("access_denied"),
                );
                check_a4(seen, &at, &delivery, "access_denied");
                seen.add("unmet requests answered on their route");
            }
            Ok(Reply::Cancel) => seen.violate(format!("{at}: Respond cancels")),
            Err(fault) => seen.violate(format!("{at}: an unmet request's error faults: {fault}")),
        }
        return;
    };
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let built = Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        registry,
        &env,
        &rendering,
        &host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), &host));
    // A `TestMode` answers on its route, writes its own channel's body or breaches with the other
    // channel's, and is refused under its C7; the core's modes answer or refuse.
    let wants = match (&expected, under) {
        (Some(Verdict::Unanswered), _) => Some("refused"),
        (Some(_), Under::Test(mode, _)) if mode.body == TestBody::Other => Some("breach"),
        (Some(_), _) => Some("answer"),
        (None, _) => None,
    };
    let got = match &built {
        Ok(_) => "answer",
        Err(Outcome::Refused(_)) => "refused",
        Err(Outcome::Fault(fault))
            if std::error::Error::source(fault)
                .and_then(|cause| cause.downcast_ref::<RouteBreach>())
                == Some(&RouteBreach::BodyChannel) =>
        {
            "breach"
        }
        Err(_) => "other",
    };
    if wants.is_some_and(|wants| wants != got) {
        seen.violate(format!("{at}: phase 2 came to {got} for {wants:?}"));
        return;
    }
    match built {
        Ok(built) => {
            let json = built.response().json();
            let response: Value = serde_json::from_str(&json).expect("§8.1's object");
            check_routed(
                seen,
                &at,
                built.delivery(),
                endpoint.as_deref(),
                key.as_ref(),
                &|inner| *inner == response,
            );
            if key.is_none() && sealed_body(built.delivery()).is_some() {
                seen.violate(format!("{at}: a clear route's answer holds a JWE"));
            }
            seen.add(if key.is_some() {
                "answers sealed to the session's key"
            } else {
                "answers in the clear"
            });
        }
        Err(Outcome::Refused(_)) => seen.add("answers refused under the sealing statement"),
        Err(Outcome::Fault(fault)) => {
            if expected.is_none() {
                seen.violate(format!("{at}: phase 2 faults: {fault}"));
            }
            seen.add("answers refused for a mode that breaks its registration");
        }
        Err(other) => seen.violate(format!("{at}: phase 2: {other}")),
    }
}

/// I2 over `per_mode` generated requests for each registered mode, from `seed`.
fn property(seed: u64, per_mode: usize) -> Seen {
    let mut seen = Seen::default();
    for (m, under) in modes().iter().enumerate() {
        let registry = under.registry();
        let mut rng =
            ChaCha8Rng::seed_from_u64(seed ^ (u64::try_from(m).expect("a mode's place") << 32));
        for k in 0..per_mode {
            let case = Case::draw(&mut rng);
            run(&mut seen, under, &registry, &case, k);
        }
    }
    seen
}

/// The outcomes each run must reach, so the property checks what it states.
const REACHED: [&str; 7] = [
    "answers sealed to the session's key",
    "answers in the clear",
    "refusals sealed on their route",
    "refusals in the clear on their route",
    "rejections posted plain to their route",
    "rejections answered on the DC API",
    "routes refused for a mode that breaks its registration",
];

fn assert_holds(seen: &Seen) {
    assert!(
        seen.violations.is_empty(),
        "I2: {} violation(s), the first: {:#?}",
        seen.violations.len(),
        seen.violations.iter().take(5).collect::<Vec<_>>()
    );
    for kind in REACHED {
        assert!(seen.count(kind) > 0, "I2 reaches {kind}: {:?}", seen.counts);
    }
}

#[test]
fn every_answer_and_error_goes_where_its_route_sends_it() {
    assert_holds(&property(1, 24));
}

#[test]
#[ignore = "the model's size: 1,500 requests per mode, minutes unoptimized; run per merge"]
fn every_answer_and_error_goes_where_its_route_sends_it_at_the_models_size() {
    for seed in 1..=3 {
        let seen = property(seed, 1500);
        assert_holds(&seen);
        println!("I2 seed {seed}: {:?}", seen.counts);
    }
}

/// I5: the same arrival, answers and host give the same `Delivery` bytes, `runs` times, over a
/// sealed URI route and a DC API route.
fn replay(runs: usize) -> usize {
    let mut differences = 0;
    for under in [Under::DirectPostJwt, Under::DcApiJwt] {
        let registry = under.registry();
        let case = Case {
            signed: true,
            forged: false,
            listed: true,
            endpoint: Endpoint::Own,
            keys: vec![B26_KEY],
            encs: None,
            broken: Break::Nothing,
            held: true,
        };
        let mut first: Option<Vec<u8>> = None;
        for _ in 0..runs {
            let bytes = delivery_bytes(&under, &registry, &case);
            match &first {
                None => first = Some(bytes),
                Some(first) if *first != bytes => differences += 1,
                Some(_) => {}
            }
        }
    }
    differences
}

/// The bytes of the case's delivery: its endpoint and body, or its DC API data.
fn delivery_bytes(under: &Under, registry: &Registry<TestHost>, case: &Case) -> Vec<u8> {
    let host = TestHost::default();
    let parameters = case.parameters(under, 0);
    let object = case.object(&parameters);
    let data = format!(r#"{{"request":"{object}"}}"#);
    let link =
        "openid4vp://?client_id=test%3Averifier&request_uri=https%3A%2F%2Fverifier.example%2Fr";
    let received = match under.channel() {
        ChannelKind::DcApi => Received::dc_api(
            "openid4vp-v1-signed",
            &data,
            Origin::parse(ORIGIN).expect("the Origin"),
            &DcApiProtocols::ALL,
        )
        .expect("received"),
        ChannelKind::Uri => Fetch::of(link, registry, &host)
            .expect("a fetch")
            .resume(FetchAnswer::Body(&object), registry, &host)
            .expect("received"),
    };
    let envelope = Envelope::parse(&received, registry).expect("an envelope");
    let trust = case.trust();
    let authenticated = envelope
        .questions(registry, &config(), &host)
        .and_then(|pending| {
            pending.authenticate(|evaluation| trust.decide(evaluation), &config(), &host)
        })
        .expect("authenticated");
    let request = Request::parse(authenticated.envelope()).expect("a request");
    let held = [Held::answering("c", &["q"], &[])];
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("a wallet");
    let env = env("en");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let ids = first_selection(&request, &wallet, registry, &env, &rendering).expect("a selection");
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let built = Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        registry,
        &env,
        &rendering,
        &host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), &host))
    .expect("an answer");
    match built.delivery() {
        Delivery::DcApi(data) => data.as_str().as_bytes().to_vec(),
        Delivery::Post { endpoint, body } => {
            let mut bytes = endpoint.as_str().as_bytes().to_vec();
            bytes.extend_from_slice(body.media_type().to_string().as_bytes());
            bytes.extend_from_slice(body.bytes());
            bytes
        }
    }
}

#[test]
fn a_replayed_arrival_delivers_the_same_bytes() {
    assert_eq!(replay(50), 0, "I5");
}

#[test]
#[ignore = "I5 at 1,000 runs per route; run per merge"]
fn a_replayed_arrival_delivers_the_same_bytes_a_thousand_times() {
    assert_eq!(replay(1000), 0, "I5");
}
