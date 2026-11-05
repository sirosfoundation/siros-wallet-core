//! The SD-JWT VC presentation (OpenID4VP 1.0 B.3.6, RFC 9901 §4): a Key Binding JWT whenever the
//! credential has a key; the transaction's members as its claims after its own (B.3.3.1's hashes
//! computed here over the entry as received); the bindings a Verifier checks, over seeded random
//! credentials, options, members and sessions; and what the plug-in refuses to present.

use siros_openid4vp::detail;
use siros_testkit::FAULT;
use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use siros_openid4vp::host::{AuthenticationNeed, FormatHost, ProfileHost, Timestamp, Usable};
use siros_openid4vp::ids::{Nonce, Origin, TransactionType};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{JsonText, Member, MemberValue, Members, OptionIndex, Registry};
use siros_openid4vp::request::ClientMetadata;
use siros_openid4vp::routing::VerifierMetadata;
use siros_openid4vp::session::{Session, SessionBinding};
use siros_openid4vp::wallet::{Holder, Wallet};
use siros_sdjwt::SdJwtVc;
use siros_testkit::fixtures::{
    Held, NONCE, ORIGIN, answer_first, dc_api_context, env, parameters, present_option, request_of,
    unsigned,
};
use siros_testkit::{Binds, TestHost, TestProfile, verifier};

const VIEW: &str = r#""metadata": {}, "jwt": "eyJhbGciOiJFUzI1NiJ9.c.sig", "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256""#;

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hex8(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn registry(binds: Binds) -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(SdJwtVc::new().expect("format"));
    let profile = builder.profile(TestProfile::new(binds));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

/// The presentation the first selection gives, as JSON text.
fn presented(dcql: &str, extra: &str, held: &[Held], registry: &Registry<TestHost>) -> String {
    let text = parameters(dcql, extra);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("credential"))
            .collect(),
    )
    .expect("wallet");
    let token = answer_first(
        &request,
        &wallet,
        registry,
        &env(&["en"], Vec::new()).expect("env"),
        &TestHost::default(),
    )
    .expect("response");
    let token = Node::parse(&token).expect("vp_token");
    token
        .get("q")
        .and_then(Node::as_array)
        .and_then(|presentations| presentations.first())
        .expect("presentation")
        .python_compact()
        .to_string()
}

fn names(node: &Node<'_>) -> Vec<String> {
    node.as_object()
        .expect("object")
        .names()
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_key_binding_jwt_whenever_the_credential_has_a_key() {
    // B.3: a query that waives holder binding may take an SD-JWT without a Key Binding JWT; the
    // plug-in adds one whenever the credential has a key.
    let waived = r#"{"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["t"]}, "require_cryptographic_holder_binding": false}]}"#;
    let mut held = Held::new(
        "c",
        "dc+sd-jwt",
        format!(r#"{{"type": "t", "values": {{}}, {VIEW}}}"#),
    );
    let bound = presented(
        waived,
        "",
        std::slice::from_ref(&held),
        &registry(Binds::First),
    );
    held.holder = Holder::Unbound;
    let unbound = presented(waived, "", &[held], &registry(Binds::First));
    let keys = |text: &str| names(&Node::parse(text).expect("presentation"));
    assert_eq!(keys(&bound), ["sd_jwt", "kb_jwt"]);
    assert_eq!(keys(&unbound), ["sd_jwt"]);
}

#[test]
fn the_key_binding_jwt_holds_the_transactions_hashes_after_its_own_claims() {
    // OpenID4VP B.3.3.1 through the every-entry test profile: one hash per entry the
    // presentation authorizes, over the strings as received, sha-256 when no entry lists
    // algorithms.
    let first =
        verifier::encode(r#"{"type": "t1", "credential_ids": ["q"], "n": 1}"#).expect("entry");
    let second =
        verifier::encode(r#"{"type": "t1", "credential_ids": ["q"], "n": 2}"#).expect("entry");
    let mut held = Held::new(
        "c",
        "dc+sd-jwt",
        format!(r#"{{"type": "t", "values": {{"given_name": "Erika"}}, {VIEW}}}"#),
    );
    held.documents = vec![(
        "test".to_owned(),
        r#"{"supports": ["t1"], "nonconforming": []}"#.as_bytes().to_vec(),
    )];
    let text = presented(
        r#"{"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["t"]}, "claims": [{"path": ["given_name"]}]}]}"#,
        &format!(r#""transaction_data":["{first}","{second}"]"#),
        &[held],
        &registry(Binds::Every),
    );
    let presentation = Node::parse(&text).expect("presentation");
    let sd_jwt = presentation
        .get("sd_jwt")
        .and_then(Node::as_str)
        .expect("sd_jwt");
    let payload = presentation
        .get("kb_jwt")
        .and_then(|kb| kb.get("payload"))
        .expect("payload");
    assert_eq!(
        names(payload),
        ["iat", "aud", "nonce", "sd_hash", "transaction_data_hashes"]
    );
    let hashes: Vec<Node<'_>> = [&first, &second]
        .iter()
        .map(|entry| Node::String(Cow::Owned(b64url(&Sha256::digest(entry.as_bytes())))))
        .collect();
    let want = [
        (
            "iat",
            Node::integer(i128::from(TestHost::default().platform.now.0)),
        ),
        ("aud", Node::String(format!("origin:{ORIGIN}").into())),
        ("nonce", Node::String(NONCE.into())),
        (
            "sd_hash",
            Node::String(b64url(&Sha256::digest(sd_jwt.as_bytes())).into()),
        ),
        ("transaction_data_hashes", Node::Array(hashes)),
    ];
    for (name, value) in want {
        assert_eq!(payload.get(name), Some(&value), "{name}");
    }
}

/// A random JSON value without objects of more than one member, so its text has one order.
fn value(rng: &mut ChaCha8Rng, depth: u8) -> String {
    match rng.random_range(0..if depth > 1 { 5 } else { 7 }) {
        0 => format!("\"s{}\"", rng.random_range(0..100)),
        1 => rng.random_range(-1000..1000).to_string(),
        2 => "true".to_owned(),
        3 => "null".to_owned(),
        4 => "\"Grüße \\\"q\\\" \\n\"".to_owned(),
        5 => format!("[{}, {}]", value(rng, depth + 1), value(rng, depth + 1)),
        _ => format!("{{\"k\": {}}}", value(rng, depth + 1)),
    }
}

#[test]
fn every_presentation_binds_what_it_shows() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let format = SdJwtVc::new().expect("format");
    let names = ["a", "b", "c", "d"];
    for case in 0..200 {
        let mut held_values: Vec<(&str, String)> = Vec::new();
        for name in names {
            if rng.random_bool(0.75) {
                held_values.push((name, value(&mut rng, 0)));
            }
        }
        let values: Vec<String> = held_values
            .iter()
            .map(|(name, value)| format!("\"{name}\": {value}"))
            .collect();
        let claims: Vec<String> = names
            .iter()
            .map(|name| format!(r#"{{"id": "{name}", "path": ["{name}"]}}"#))
            .collect();
        if held_values.is_empty() {
            held_values.push(("a", value(&mut rng, 0)));
        }
        // Phase 2 presents an option the credential answers: claims it holds.
        let option: Vec<&str> = held_values
            .iter()
            .map(|(name, _)| *name)
            .filter(|_| rng.random_bool(0.6))
            .collect();
        let option = if option.is_empty() {
            vec![held_values[0].0]
        } else {
            option
        };
        let quoted: Vec<String> = option.iter().map(|name| format!("\"{name}\"")).collect();
        let dcql = format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["t"]}}, "claims": [{}], "claim_sets": [[{}]]}}]}}"#,
            claims.join(", "),
            quoted.join(", ")
        );
        let text = parameters(&dcql, "");
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let query = FormatHost::<TestHost>::answer(
            &format,
            &request.queries()[0],
            dc_api_context(&request, None),
        )
        .map_err(|r| format!("{r:?}"))
        .expect("query");
        let id = format!("c{case}");
        let mut held = Held::new(
            &id,
            "dc+sd-jwt",
            format!(
                r#"{{"type": "t", "values": {{{}}}, {VIEW}}}"#,
                values.join(", ")
            ),
        );
        let bound = rng.random_bool(0.8);
        held.holder = if bound {
            Holder::Bound
        } else {
            Holder::Unbound
        };
        let members: Vec<(Member, MemberValue)> = if bound {
            (0..rng.random_range(0..3))
                .map(|k| {
                    let value = if rng.random_bool(0.5) {
                        MemberValue::Text(format!("m{k}"))
                    } else {
                        MemberValue::Json(JsonText::parse(&value(&mut rng, 0)).expect("json"))
                    };
                    (Member::Claim(Cow::Owned(format!("member_{k}"))), value)
                })
                .collect()
        } else {
            Vec::new()
        };
        let origin = Origin::parse(ORIGIN).expect("origin");
        let nonce = Nonce::parse(format!("n{case}")).expect("nonce");
        let none = ClientMetadata::parse(None).expect("metadata");
        let none = VerifierMetadata::new(&none);
        let session = Session::new(
            SessionBinding::DcApi { origin: &origin },
            &nonce,
            None,
            none.keys(),
        );
        let credential = held.credential().expect("credential");
        let now = Timestamp(1_785_000_000 + case);
        let presentation = present_option(
            query.as_ref(),
            Usable::checked(&credential),
            OptionIndex(0),
            &Members::new(members.clone()).expect("members"),
            &session,
            &TestHost::at(now),
        )
        .expect("presentation");
        let presentation = Node::parse(presentation.as_str()).expect("json");
        let sd_jwt = presentation
            .get("sd_jwt")
            .and_then(Node::as_str)
            .expect("sd_jwt");
        // RFC 9901 §4: the Issuer-signed JWT, then each disclosure, each followed by `~`.
        let parts: Vec<&str> = sd_jwt.split('~').collect();
        assert_eq!(parts.first(), Some(&"eyJhbGciOiJFUzI1NiJ9.c.sig"));
        assert_eq!(parts.last(), Some(&""));
        // The disclosures: the option's claims the credential holds, in claim order, each the
        // array [salt, name, value] (RFC 9901 §4.2.1).
        let disclosed: Vec<(String, Node<'static>)> = parts[1..parts.len() - 1]
            .iter()
            .map(|disclosure| {
                let bytes = URL_SAFE_NO_PAD.decode(disclosure).expect("base64url");
                let text = String::from_utf8(bytes).expect("utf-8");
                let array = Node::parse(&text).expect("json").into_owned();
                let [salt, name, value] = array.as_array().expect("array") else {
                    panic!("a disclosure of three elements");
                };
                assert_eq!(salt.as_str().map(str::len), Some(22));
                (name.as_str().expect("name").to_owned(), value.clone())
            })
            .collect();
        let want: Vec<(String, Node<'static>)> = names
            .iter()
            .filter(|name| option.contains(name))
            .filter_map(|name| {
                held_values
                    .iter()
                    .find(|(held, _)| held == name)
                    .map(|(_, value)| {
                        (
                            (*name).to_owned(),
                            Node::parse(value).expect("value").into_owned(),
                        )
                    })
            })
            .collect();
        assert_eq!(disclosed, want, "case {case}");
        let Some(kb) = presentation.get("kb_jwt") else {
            assert!(
                !bound,
                "a Key Binding JWT whenever the credential has a key"
            );
            continue;
        };
        assert!(bound);
        let header = kb.get("header").expect("header");
        let payload = kb.get("payload").expect("payload");
        assert_eq!(
            header,
            &Node::parse(r#"{"typ": "kb+jwt", "alg": "ES256"}"#).expect("header")
        );
        let own = [
            ("iat", Node::integer(i128::from(now.0))),
            ("aud", Node::String(format!("origin:{ORIGIN}").into())),
            ("nonce", Node::String(nonce.as_str().to_owned().into())),
            (
                "sd_hash",
                Node::String(b64url(&Sha256::digest(sd_jwt.as_bytes())).into()),
            ),
        ];
        let payload_members = payload.as_object().expect("payload").members();
        assert_eq!(payload_members.len(), own.len() + members.len());
        for (member, (name, value)) in payload_members.iter().zip(own) {
            assert_eq!((member.name.as_ref(), &member.value), (name, &value));
        }
        for (member, (name, value)) in payload_members[4..].iter().zip(&members) {
            let want = match value {
                MemberValue::Text(text) => Node::String(text.clone().into()),
                MemberValue::Json(json) => Node::parse(json.as_str()).expect("json").into_owned(),
                MemberValue::Bytes(_) | MemberValue::Cbor(_) => {
                    panic!("no byte string or CBOR data item")
                }
            };
            assert_eq!(
                (member.name.as_ref(), &member.value),
                (name.to_string().as_str(), &want)
            );
        }
        // The signature covers the header and payload as presented.
        let signing_input = format!(
            "{}.{}",
            b64url(header.python_compact().to_string().as_bytes()),
            b64url(payload.python_compact().to_string().as_bytes())
        );
        assert_eq!(
            kb.get("signature").and_then(Node::as_str),
            Some(format!("sig:{id}:{}", hex8(signing_input.as_bytes())).as_str())
        );
    }
}

#[test]
fn what_cannot_be_presented_is_a_fault() {
    let format = SdJwtVc::new().expect("format");
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["t"]}, "claims": [{"path": ["a"]}]}]}"#,
        "",
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = FormatHost::<TestHost>::answer(
        &format,
        &request.queries()[0],
        dc_api_context(&request, None),
    )
    .map_err(|r| format!("{r:?}"))
    .expect("query");
    let origin = Origin::parse(ORIGIN).expect("origin");
    let nonce = Nonce::parse(NONCE).expect("nonce");
    let none = ClientMetadata::parse(None).expect("metadata");
    let none = VerifierMetadata::new(&none);
    let session = Session::new(
        SessionBinding::DcApi { origin: &origin },
        &nonce,
        None,
        none.keys(),
    );
    let good = format!(r#"{{"type": "t", "values": {{"a": 1}}, {VIEW}}}"#);
    let jwt = |jwt: &str| good.replace("eyJhbGciOiJFUzI1NiJ9.c.sig", jwt);
    let claim = |name: &'static str, value: MemberValue| (Member::claim(name), value);
    let text_member = || MemberValue::Text("x".to_owned());
    // (view, holder, members, why it is presented or refused).
    type Case = (String, Holder, Vec<(Member, MemberValue)>, &'static str);
    let cases: Vec<Case> = vec![
        (good.clone(), Holder::Bound, Vec::new(), "presented"),
        // The Issuer-signed JWT is a JWS in compact serialization.
        (jwt("eyJ.c"), Holder::Bound, Vec::new(), "two parts"),
        (jwt("eyJ..sig"), Holder::Bound, Vec::new(), "an empty part"),
        (
            jwt("eyJ.c~d.sig"),
            Holder::Bound,
            Vec::new(),
            "a ~ in the JWT",
        ),
        (
            good.replace(r#""jwt": "eyJhbGciOiJFUzI1NiJ9.c.sig", "#, ""),
            Holder::Bound,
            Vec::new(),
            "no jwt",
        ),
        (
            good.replace(r#""key_alg": "ES256", "#, ""),
            Holder::Bound,
            Vec::new(),
            "no holder key algorithm",
        ),
        // The members: claims of text or JSON, none of the Key Binding JWT's own, and only with
        // a Key Binding JWT.
        (
            good.clone(),
            Holder::Bound,
            vec![claim("x", MemberValue::Bytes(vec![1]))],
            "a byte string",
        ),
        (
            good.clone(),
            Holder::Bound,
            vec![(Member::element("ns", "x"), text_member())],
            "a data element",
        ),
        (
            good.clone(),
            Holder::Bound,
            vec![claim("aud", text_member())],
            "the Key Binding JWT's own claim",
        ),
        (
            good.clone(),
            Holder::Unbound,
            vec![claim("x", text_member())],
            "a member without a key",
        ),
        // The view is the kit's.
        (
            good.replace(r#""type": "t", "#, ""),
            Holder::Bound,
            Vec::new(),
            "no type",
        ),
        ("[]".to_owned(), Holder::Bound, Vec::new(), "no object"),
    ];
    for (view, holder, members, why) in cases {
        let mut held = Held::new("c", "dc+sd-jwt", view);
        held.holder = holder;
        let credential = held.credential().expect("credential");
        let result = present_option(
            query.as_ref(),
            Usable::checked(&credential),
            OptionIndex(0),
            &Members::new(members).expect("members"),
            &session,
            &TestHost::default(),
        );
        assert_eq!(result.is_ok(), why == "presented", "{why}");
    }
}

/// A profile writing these members in every format, judged at registration alone.
#[derive(Clone)]
struct Writes(Vec<Member>);

impl siros_openid4vp::plugins::Profile for Writes {
    type Finding = ();

    fn refusals(
        &self,
        _request: &siros_openid4vp::request::Request<'_>,
        _entries: &[siros_openid4vp::request::EntryIndex],
    ) -> Vec<siros_openid4vp::refusal::Refusal> {
        Vec::new()
    }

    fn members(
        &self,
        _placement: siros_openid4vp::wallet_metadata::Placement,
    ) -> Option<&[Member]> {
        Some(&self.0)
    }

    fn bind(
        &self,
        _binding: siros_openid4vp::plugins::Binding<'_>,
        _env: &siros_openid4vp::rows::Env,
    ) -> Result<siros_openid4vp::plugins::Bound, siros_openid4vp::plugins::NoCandidate> {
        Err(
            siros_openid4vp::plugins::Fault::new(FAULT, detail!("judged at registration alone"))
                .into(),
        )
    }
}

impl<H> ProfileHost<H> for Writes {
    fn wanted(
        &self,
        _record: siros_openid4vp::plugins::Answered<'_>,
    ) -> Result<Vec<siros_openid4vp::rows::HttpsUrl>, siros_openid4vp::plugins::Fault> {
        Err(siros_openid4vp::plugins::Fault::new(
            FAULT,
            detail!("judged at registration alone"),
        ))
    }

    fn informed(&self, _findings: &[&()]) -> Self {
        self.clone()
    }

    fn authentication(
        &self,
        _: siros_openid4vp::plugins::Answered<'_>,
    ) -> Result<AuthenticationNeed, siros_openid4vp::plugins::Fault> {
        Ok(AuthenticationNeed::Presence)
    }

    fn revalidate(
        &self,
        _record: siros_openid4vp::plugins::FetchedRecord<'_>,
        _host: &H,
    ) -> Result<Option<()>, siros_openid4vp::plugins::Fault> {
        Err(siros_openid4vp::plugins::Fault::new(
            FAULT,
            detail!("judged at registration alone"),
        ))
    }

    fn respond(
        &self,
        _record: siros_openid4vp::plugins::Answered<'_>,
        _host: &H,
        _authentication: &siros_openid4vp::host::Authentication,
    ) -> Result<Members, siros_openid4vp::plugins::Fault> {
        Err(siros_openid4vp::plugins::Fault::new(
            FAULT,
            detail!("judged at registration alone"),
        ))
    }
}

#[test]
fn no_profile_writes_a_key_binding_jwts_own_claim() {
    // RFC 9901 §4.3, OpenID4VP B.3.6: the Key Binding JWT's own claims are iat, aud, nonce and
    // sd_hash; the registry refuses a profile that would write one into an SD-JWT VC.
    let registered = |name: &'static str| {
        let mut builder = Registry::<TestHost>::builder();
        siros_testkit::fixtures::openid4vp(&mut builder);
        builder.format(SdJwtVc::new().expect("format"));
        let profile = builder.profile(Writes(vec![Member::claim(name)]));
        builder.exact(TransactionType::parse("t1").expect("type"), profile);
        builder.build().map(drop)
    };
    for own in ["iat", "aud", "nonce", "sd_hash"] {
        assert!(
            matches!(
                registered(own),
                Err(siros_openid4vp::plugins::RegistryError::MemberTwice { .. })
            ),
            "{own}"
        );
    }
    assert!(registered("transaction_data_hashes").is_ok());
}
