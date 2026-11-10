//! Matching SD-JWT VCs: `vct_values` (B.3.5), the format's request rules with their error codes,
//! the Verifier's algorithms (B.3.4, RFC 9864), and the carriage of response members.

use std::error::Error;

use siros_openid4vp::claims::kit::{KitRule, QueryRule};
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::matching::{Accepted, Match};
use siros_openid4vp::plugins::{Format, Member, Registry};
use siros_openid4vp::refusal::{ErrorCode, Refusal};
use siros_openid4vp::request::Request;
use siros_openid4vp::wallet::{Holder, Wallet};
use siros_sdjwt::{HolderBindingWaived, SdJwtRule, SdJwtVc};
use siros_testkit::TestHost;
use siros_testkit::fixtures::{Held, env, parameters, request_of, unsigned};
use siros_testkit::render::Language;
use siros_testkit::{Binds, TestProfile, verifier};

/// An SD-JWT VC of a type and values, ES256 on P-256, its key ES256 on P-256.
fn sd_jwt(id: &str, vct: &str, values: &str) -> Held {
    Held::new(
        id,
        "dc+sd-jwt",
        format!(
            r#"{{"type": "{vct}", "metadata": {{}}, "values": {values}, "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}}"#
        ),
    )
}

/// The SD-JWT VC plug-in, and the test profile for the type `t1`.
fn registry() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(SdJwtVc::new().expect("format"));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

/// Each query's id with its candidates, each (credential, the options it answers).
type Answers = Vec<(String, Vec<(String, Vec<usize>)>)>;

/// The exclusions, each (query, credential, clause).
type Exclusions = Vec<(String, String, String)>;

/// Each query's candidates with the options they answer, and the exclusions.
fn matched(request: &Request<'_>, held: &[Held]) -> (Answers, Exclusions) {
    let registry = registry();
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("credential"))
            .collect(),
    )
    .expect("wallet");
    let accepted = Accepted::new(request, &registry).expect("accepted");
    let matched = Match::run(
        &accepted,
        &wallet,
        &env(&["en"], Vec::new()).expect("env"),
        Language::English.shared().expect("the test app"),
    )
    .expect("match");
    let answers = request
        .indexed_queries()
        .map(|(index, query)| {
            let found = matched
                .candidates(index)
                .iter()
                .map(|c| {
                    (
                        c.credential.id.to_string(),
                        c.options.iter().map(|o| o.position()).collect(),
                    )
                })
                .collect();
            (query.id().to_string(), found)
        })
        .collect();
    let excluded = matched
        .excluded()
        .iter()
        .map(|x| {
            (
                request.query(x.query).expect("query").id().to_string(),
                x.credential.id.to_string(),
                x.exclude.clause().to_string(),
            )
        })
        .collect();
    (answers, excluded)
}

#[test]
fn vct_values_match_a_type_the_credential_inherits_from() {
    // B.3.5: "The Wallet MAY return Credentials that inherit from any of the specified types";
    // SD-JWT VC §6.4: a type's chain, the type it extends first.
    let (own, parent, root) = (
        "https://bank.example/sca/card",
        "https://bank.example/sca",
        "https://eudi.example/sca",
    );
    let mut card = sd_jwt("card", own, "{}");
    card.view = card
        .view
        .replacen('{', &format!(r#"{{"extends": ["{parent}", "{root}"], "#), 1);
    let format = SdJwtVc::new().expect("format");
    let credential = card.credential().expect("credential");
    let additions = format.additions(&credential).expect("additions");
    let types: Vec<&str> = additions.types().iter().map(|kind| kind.as_str()).collect();
    assert_eq!(types, [own, parent, root]);
    for (vct, want) in [(own, true), (root, true), ("https://other.example", false)] {
        let text = parameters(
            &format!(
                r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["{vct}"]}}}}]}}"#
            ),
            "",
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let (found, _) = matched(&request, std::slice::from_ref(&card));
        assert_eq!(!found[0].1.is_empty(), want, "{vct}");
    }
    // An `extends` that is no array of types is no view the format reads.
    let mut broken = sd_jwt("broken", own, "{}");
    broken.view = broken.view.replacen('{', r#"{"extends": "x", "#, 1);
    let credential = broken.credential().expect("credential");
    assert!(format.additions(&credential).is_err());
}

/// A rule of the format, or of the kit under it.
#[derive(Debug, PartialEq)]
enum Rule {
    VctValues,
    VpFormats,
    HolderBinding,
}

fn rule(refusal: &Refusal) -> Rule {
    let rule: &dyn Error = refusal.rule();
    if rule.downcast_ref::<HolderBindingWaived>().is_some() {
        return Rule::HolderBinding;
    }
    match rule
        .downcast_ref::<QueryRule<KitRule>>()
        .map(|rule| &rule.rule)
    {
        Some(KitRule::VpFormats) => Rule::VpFormats,
        Some(KitRule::Meta(meta)) => {
            let meta: &dyn Error = meta.as_ref();
            assert_eq!(meta.downcast_ref(), Some(&SdJwtRule::VctValues));
            Rule::VctValues
        }
        other => panic!("{other:?}"),
    }
}

/// The rules the request breaks, each with its code.
fn refusals(dcql: &str, extra: &str) -> Vec<(Rule, ErrorCode)> {
    let text = parameters(dcql, extra);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry();
    match Accepted::new(&request, &registry) {
        Ok(_) => Vec::new(),
        Err(refused) => refused
            .refusals()
            .iter()
            .map(|refusal| (rule(refusal), refusal.code()))
            .collect(),
    }
}

#[test]
fn each_format_rule_refuses_with_its_code() {
    let query = |members: &str| {
        format!(r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt"{members}}}]}}"#)
    };
    // B.3.5: meta.vct_values is a non-empty array of strings.
    for meta in [
        "",
        r#", "meta": {}"#,
        r#", "meta": {"vct_values": []}"#,
        r#", "meta": {"vct_values": [5]}"#,
    ] {
        assert_eq!(
            refusals(&query(meta), ""),
            [(Rule::VctValues, ErrorCode::INVALID_REQUEST)],
            "{meta}"
        );
    }
    // B.3.4: a JWS algorithm identifier is a string.
    let meta = r#", "meta": {"vct_values": ["t"]}"#;
    assert_eq!(
        refusals(
            &query(meta),
            r#""client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":[-7]}}}"#
        ),
        [(Rule::VpFormats, ErrorCode::INVALID_REQUEST)]
    );
    // B.3.3: transaction data needs holder binding.
    let entry = verifier::encode(r#"{"type": "t1", "credential_ids": ["q"]}"#).expect("entry");
    let entries = format!(r#""transaction_data":["{entry}"]"#);
    assert_eq!(
        refusals(
            &query(&format!(
                r#"{meta}, "require_cryptographic_holder_binding": false"#
            )),
            &entries
        ),
        [(Rule::HolderBinding, ErrorCode::INVALID_TRANSACTION_DATA)]
    );
    assert_eq!(refusals(&query(meta), &entries), [], "with holder binding");
}

#[test]
fn the_verifiers_algorithms_admit_the_credentials_they_list() {
    let clause = "OpenID4VP B.3 vp_formats_supported";
    let view = |alg: &str, curve: &str| {
        format!(
            r#"{{"type": "t", "metadata": {{}}, "values": {{}}, "alg": "{alg}", "curve": "{curve}", "key_alg": "ES256", "key_curve": "P-256"}}"#
        )
    };
    // (supported, holder binding required, credential bound to a key, its alg and curve, the
    // exclusion's clause).
    type Admission = (
        &'static str,
        bool,
        bool,
        (&'static str, &'static str),
        Option<&'static str>,
    );
    let cases: [Admission; 9] = [
        (
            r#"{"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}"#,
            true,
            true,
            ("ES256", "P-256"),
            None,
        ),
        (
            r#"{"sd-jwt_alg_values": ["Ed25519"]}"#,
            true,
            true,
            ("ES256", "P-256"),
            Some(clause),
        ),
        (
            r#"{"kb-jwt_alg_values": ["ES384"]}"#,
            true,
            true,
            ("ES256", "P-256"),
            Some(clause),
        ),
        // kb-jwt_alg_values applies whenever the credential has a key, holder binding waived or not.
        (
            r#"{"kb-jwt_alg_values": ["ES384"]}"#,
            false,
            true,
            ("ES256", "P-256"),
            Some(clause),
        ),
        (
            r#"{"kb-jwt_alg_values": ["ES384"]}"#,
            false,
            false,
            ("ES256", "P-256"),
            None,
        ),
        // RFC 9864: EdDSA on a curve is the fully-specified algorithm of the curve, and EdDSA.
        (
            r#"{"sd-jwt_alg_values": ["Ed25519"]}"#,
            true,
            true,
            ("EdDSA", "Ed25519"),
            None,
        ),
        (
            r#"{"sd-jwt_alg_values": ["Ed448"]}"#,
            true,
            true,
            ("EdDSA", "Ed448"),
            None,
        ),
        (
            r#"{"sd-jwt_alg_values": ["Ed25519"]}"#,
            true,
            true,
            ("EdDSA", "Ed448"),
            Some(clause),
        ),
        (
            r#"{"sd-jwt_alg_values": ["EdDSA"]}"#,
            true,
            true,
            ("EdDSA", "Ed25519"),
            None,
        ),
    ];
    for (supported, binding, bound, (alg, curve), want) in cases {
        let dcql = format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["t"]}}, "require_cryptographic_holder_binding": {binding}}}]}}"#
        );
        let text = parameters(
            &dcql,
            &format!(r#""client_metadata":{{"vp_formats_supported":{{"dc+sd-jwt":{supported}}}}}"#),
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let mut held = Held::new("c", "dc+sd-jwt", view(alg, curve));
        held.holder = if bound {
            Holder::Bound
        } else {
            Holder::Unbound
        };
        let (answers, excluded) = matched(&request, &[held]);
        let got = excluded.first().map(|(_, _, clause)| clause.as_str());
        assert_eq!(got, want, "{supported} {binding} {bound} {alg} {curve}");
        assert_eq!(answers[0].1.is_empty(), want.is_some());
    }
}

#[test]
fn a_key_binding_jwt_carries_claims_alone() {
    let carried = |binding: bool, holder: Holder, members: &[Member]| {
        let dcql = format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["t"]}}, "require_cryptographic_holder_binding": {binding}}}]}}"#
        );
        let text = parameters(&dcql, "");
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let members = members.to_vec();
        siros_testkit::probe::read_parsed(
            &request,
            &request.queries()[0],
            SdJwtVc::new().expect("format"),
            move |query| {
                let mut held = sd_jwt("c", "t", "{}");
                held.holder = holder;
                query
                    .carries(&held.credential().expect("credential"), &members)
                    .expect("carries")
                    == siros_openid4vp::plugins::Carriage::Carried
            },
        )
        .expect("the query")
    };
    let claim = [Member::claim("transaction_data_hashes")];
    assert!(carried(true, Holder::Bound, &claim));
    assert!(
        !carried(false, Holder::Bound, &claim),
        "holder binding waived"
    );
    assert!(!carried(false, Holder::Unbound, &claim), "no key");
    assert!(
        !carried(
            true,
            Holder::Bound,
            &[Member::element("urn:paso:sca:1", "jti")]
        ),
        "a data element is no claim"
    );
}
