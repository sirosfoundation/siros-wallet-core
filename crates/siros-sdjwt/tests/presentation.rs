//! The SD-JWT VC presentation (OpenID4VP 1.0 B.3.6, RFC 9901 §4): a Key Binding JWT whenever the
//! credential has a key; the transaction's members as its claims after its own (B.3.3.1's hashes
//! computed here over the entry as received); the bindings a Verifier checks, over seeded random
//! credentials, options, members and sessions; and what the plug-in refuses to present.

use siros_openid4vp::detail;
use std::borrow::Cow;
use std::error::Error as _;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::host::{
    AuthenticationNeed, FormatHost, PresentError, Presentation, ProfileHost, Timestamp, Usable,
};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::plugins::{JsonText, Member, MemberValue, Members, Registry};
use siros_openid4vp::wallet::{Holder, Wallet};
use siros_sdjwt::{IssuerJwtFault, KeyBindingError, ParseError, PresentFault, SdJwtVc};
use siros_testkit::fixtures::{
    Held, NONCE, ORIGIN, answer_first, env, parameters, present_option, request_of, unsigned,
};
use siros_testkit::probe::{dc_api, read_phase_two};
use siros_testkit::render::Language;
use siros_testkit::sd_jwt_issuer;
use siros_testkit::sd_jwt_reading::{Read, read};
use siros_testkit::{Binds, TestChoice, TestHost, TestProfile, verifier};

/// The presentation of a registration for the first query of the request parameters, its first
/// option, over the context and the session phase 2 gives the format under `dc_api` in the clear.
fn presented_over(
    text: &str,
    held: &Held,
    members: Members,
    host: &TestHost,
) -> Result<Presentation, PresentError> {
    let received = unsigned(text).expect("received");
    let held = held.clone();
    read_phase_two(
        &received,
        "dc+sd-jwt",
        dc_api(TestChoice::Plain),
        host,
        move |phase_two| {
            let format = SdJwtVc::new().expect("format");
            let query = FormatHost::<TestHost>::answer(&format, phase_two.query, phase_two.context)
                .map_err(|r| format!("{r:?}"))
                .expect("query");
            let credential = held.credential().expect("credential");
            present_option(
                query.as_ref(),
                Usable::checked(&credential),
                0,
                &members,
                phase_two.session,
                phase_two.host,
            )
        },
    )
    .expect("the flow reaches the format")
}

const VIEW: &str =
    r#""metadata": {}, "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256""#;

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

/// The presentation the first selection gives.
fn presented(dcql: &str, extra: &str, held: &[Held], registry: &Registry<TestHost>) -> Read {
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
        Language::English.shared().expect("the test app"),
        &TestHost::default(),
    )
    .expect("response");
    let token = Node::parse(&token).expect("vp_token");
    let text = token
        .get("q")
        .and_then(Node::as_array)
        .and_then(|presentations| presentations.first())
        .and_then(Node::as_str)
        .expect("a presentation that is a string (OpenID4VP §8.1)");
    read(text).expect("a presentation a Verifier takes")
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
    let held = |holder| {
        let mut held = Held::new(
            "c",
            "dc+sd-jwt",
            format!(r#"{{"type": "t", "values": {{}}, {VIEW}}}"#),
        );
        held.holder = holder;
        held.with_issued().expect("issued")
    };
    let bound = presented(waived, "", &[held(Holder::Bound)], &registry(Binds::First));
    let unbound = presented(
        waived,
        "",
        &[held(Holder::Unbound)],
        &registry(Binds::First),
    );
    assert!(bound.key_binding.is_some());
    assert!(unbound.key_binding.is_none());
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
    )
    .with_issued()
    .expect("issued");
    held.documents.push((
        "test".to_owned(),
        r#"{"supports": ["t1"], "nonconforming": []}"#.as_bytes().to_vec(),
    ));
    let presentation = presented(
        r#"{"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["t"]}, "claims": [{"path": ["given_name"]}]}]}"#,
        &format!(r#""transaction_data":["{first}","{second}"]"#),
        &[held],
        &registry(Binds::Every),
    );
    let payload = &presentation
        .key_binding
        .as_ref()
        .expect("a key binding")
        .payload;
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
            Node::String(b64url(&Sha256::digest(presentation.sent.as_bytes())).into()),
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

/// The members and elements below a value, each selectively disclosable.
fn descendants(value: &Node<'_>) -> usize {
    match value {
        Node::Object(object) => object
            .members()
            .iter()
            .map(|member| 1 + descendants(&member.value))
            .sum(),
        Node::Array(items) => items.iter().map(|item| 1 + descendants(item)).sum(),
        _ => 0,
    }
}

#[test]
fn every_presentation_binds_what_it_shows() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
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
        let held = held.with_issued().expect("issued");
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
        let nonce = format!("n{case}");
        let text = text.replace(NONCE, &nonce);
        let now = Timestamp(1_785_000_000 + case);
        let presentation = presented_over(
            &text,
            &held,
            Members::new(members.clone()).expect("members"),
            &TestHost::at(now),
        )
        .expect("presentation");
        let text = Node::parse(presentation.as_str()).expect("json");
        let read = read(text.as_str().expect("a string")).expect("a Verifier takes it");
        let issued = std::str::from_utf8(&held.documents[0].1).expect("text");
        assert_eq!(issued.split('~').next(), Some(read.issuer_jwt.as_str()));
        // S3: the option's claims in its order, each with one disclosure per node of its value.
        let shown: Vec<&str> = read
            .disclosures
            .iter()
            .filter_map(|disclosure| disclosure.name.as_deref())
            .filter(|name| names.contains(name))
            .collect();
        assert_eq!(shown, option, "case {case}");
        let nodes: usize = option
            .iter()
            .filter_map(|name| held_values.iter().find(|(held, _)| held == name))
            .map(|(_, value)| 1 + descendants(&Node::parse(value).expect("value")))
            .sum();
        assert_eq!(read.disclosures.len(), nodes, "case {case}");
        // The claims a Verifier reads: the option's, each with its whole value, and no other.
        for name in names {
            let want = option
                .contains(&name)
                .then(|| held_values.iter().find(|(held, _)| *held == name))
                .flatten()
                .map(|(_, value)| Node::parse(value).expect("value").into_owned());
            assert_eq!(read.claims.get(name), want.as_ref(), "case {case}: {name}");
        }
        let Some(kb) = &read.key_binding else {
            assert!(
                !bound,
                "a Key Binding JWT whenever the credential has a key"
            );
            continue;
        };
        assert!(bound);
        let (header, payload) = (&kb.header, &kb.payload);
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
                Node::String(b64url(&Sha256::digest(read.sent.as_bytes())).into()),
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
        // The signature covers the header and payload as sent.
        assert_eq!(
            kb.signature,
            format!("sig:{id}:{}", hex8(kb.signing_input.as_bytes())).into_bytes()
        );
    }
}

#[test]
fn what_cannot_be_presented_is_a_fault() {
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "dc+sd-jwt", "meta": {"vct_values": ["t"]}, "claims": [{"path": ["a"]}]}]}"#,
        "",
    );
    let good = format!(r#"{{"type": "t", "values": {{"a": 1}}, {VIEW}}}"#);
    let written = Node::parse(&good).expect("view");
    let keyed = sd_jwt_issuer::issue(&written).expect("issued");
    let keyless =
        sd_jwt_issuer::issue(&sd_jwt_issuer::without_key(&written).expect("view")).expect("issued");
    let claim = |name: &'static str, value: MemberValue| (Member::claim(name), value);
    let text_member = || MemberValue::Text("x".to_owned());
    /// Why a case ends as it does.
    enum Why {
        Presented,
        /// The plug-in's own cause.
        Plugin(PresentFault),
        /// A fault of this crate's domain with no typed cause: the view's reading.
        Reading,
    }
    // (name, view, document, holder, members, why).
    type Case = (
        &'static str,
        String,
        Option<String>,
        Holder,
        Vec<(Member, MemberValue)>,
        Why,
    );
    let document = || Some(keyed.clone());
    let own_claim = KeyBindingError::Repeated(JsonError::DuplicateMember {
        member: "aud".to_owned(),
    });
    let cases: Vec<Case> = vec![
        (
            "presented",
            good.clone(),
            document(),
            Holder::Bound,
            Vec::new(),
            Why::Presented,
        ),
        // The document: an SD-JWT holding what the view states.
        (
            "no document",
            good.clone(),
            None,
            Holder::Bound,
            Vec::new(),
            Why::Plugin(PresentFault::NoDocument),
        ),
        (
            "a document of two parts",
            good.clone(),
            Some("eyJ.c~".to_owned()),
            Holder::Bound,
            Vec::new(),
            Why::Plugin(PresentFault::Document(ParseError::IssuerJwt(
                IssuerJwtFault::Segments { count: 2 },
            ))),
        ),
        (
            "a view the document contradicts",
            good.replace(r#""a": 1"#, r#""a": 2"#),
            document(),
            Holder::Bound,
            Vec::new(),
            Why::Plugin(PresentFault::View),
        ),
        (
            "facts of no key over a document with a key",
            good.clone(),
            document(),
            Holder::Unbound,
            Vec::new(),
            Why::Plugin(PresentFault::Holder),
        ),
        (
            "facts of a key over a document without one",
            good.clone(),
            Some(keyless.clone()),
            Holder::Bound,
            Vec::new(),
            Why::Plugin(PresentFault::Holder),
        ),
        (
            "no holder key algorithm",
            good.replace(r#""key_alg": "ES256", "#, ""),
            document(),
            Holder::Bound,
            Vec::new(),
            Why::Reading,
        ),
        (
            "a holder key algorithm of none",
            good.replace(r#""key_alg": "ES256""#, r#""key_alg": "none""#),
            document(),
            Holder::Bound,
            Vec::new(),
            Why::Plugin(PresentFault::KeyAlg),
        ),
        // The members: claims of text or JSON, none of the Key Binding JWT's own, and only with
        // a Key Binding JWT.
        (
            "a byte string",
            good.clone(),
            document(),
            Holder::Bound,
            vec![claim("x", MemberValue::Bytes(vec![1]))],
            Why::Plugin(PresentFault::Binary {
                member: "x".to_owned(),
            }),
        ),
        (
            "a data element",
            good.clone(),
            document(),
            Holder::Bound,
            vec![(Member::element("ns", "x"), text_member())],
            Why::Plugin(PresentFault::NoClaim {
                member: Member::element("ns", "x").to_string(),
            }),
        ),
        (
            "the Key Binding JWT's own claim",
            good.clone(),
            document(),
            Holder::Bound,
            vec![claim("aud", text_member())],
            Why::Plugin(PresentFault::KeyBinding(own_claim)),
        ),
        (
            "a member without a key",
            good.clone(),
            Some(keyless.clone()),
            Holder::Unbound,
            vec![claim("x", text_member())],
            Why::Plugin(PresentFault::NoKeyForMember {
                member: Member::claim("x").to_string(),
            }),
        ),
    ];
    for (name, view, document, holder, members, why) in cases {
        let mut held = Held::new("c", "dc+sd-jwt", view);
        held.holder = holder;
        if let Some(document) = document {
            held.documents
                .push((sd_jwt_issuer::DOCUMENT.to_owned(), document.into_bytes()));
        }
        let result = presented_over(
            &text,
            &held,
            Members::new(members).expect("members"),
            &TestHost::default(),
        );
        let fault = match (result, why) {
            (Ok(_), Why::Presented) => continue,
            (Err(PresentError::Fault(fault)), why) => (fault, why),
            (other, _) => panic!("{name}: {:?}", other.map(|p| p.as_str().to_owned())),
        };
        let (fault, why) = fault;
        let cause = fault
            .source()
            .and_then(|cause| cause.downcast_ref::<PresentFault>());
        match why {
            Why::Presented => panic!("{name}: {fault}"),
            Why::Plugin(want) => assert_eq!(cause, Some(&want), "{name}"),
            Why::Reading => {
                assert_eq!(cause, None, "{name}");
                assert_eq!(fault.id(), "err.sdjwt.fault", "{name}");
            }
        }
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
        _context: &siros_i18n::Context,
    ) -> Result<siros_openid4vp::plugins::Bound, siros_openid4vp::plugins::NoCandidate> {
        Err(siros_testkit::fault(detail!("judged at registration alone")).into())
    }
}

impl<H> ProfileHost<H> for Writes {
    fn wanted(
        &self,
        _record: siros_openid4vp::plugins::Answered<'_>,
        _host: &H,
    ) -> Result<Vec<siros_openid4vp::rows::HttpsUrl>, siros_openid4vp::plugins::Fault> {
        Err(siros_testkit::fault(detail!(
            "judged at registration alone"
        )))
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
        Err(siros_testkit::fault(detail!(
            "judged at registration alone"
        )))
    }

    fn respond(
        &self,
        _record: siros_openid4vp::plugins::Answered<'_>,
        _host: &H,
        _authentication: &siros_openid4vp::host::Authentication,
    ) -> Result<Members, siros_openid4vp::plugins::Fault> {
        Err(siros_testkit::fault(detail!(
            "judged at registration alone"
        )))
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
