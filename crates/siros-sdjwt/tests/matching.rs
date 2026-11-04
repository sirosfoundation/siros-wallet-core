//! Matching SD-JWT VCs: OpenID4VP 1.0's DCQL examples (`siros-openid4vp/tests/data/spec_vectors`,
//! verbatim copies of `1.0/examples/query_lang`), the format's request rules with their error
//! codes, the Verifier's algorithms (B.3.4, RFC 9864), the carriage of response members, and the
//! consent's shapes of the reference model's check.py through SD-JWT VC credentials.

use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::{Accepted, Consent, Match, Offered, flatten};
use siros_openid4vp::plugins::{Format, Member, Registry};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::request::Request;
use siros_openid4vp::wallet::{Holder, Wallet};
use siros_sdjwt::SdJwtVc;
use siros_testkit::TestHost;
use siros_testkit::fixtures::{Held, env, parameters, request_of, unsigned};
use siros_testkit::{Binds, TestProfile, verifier};

const IDC: &str = "https://credentials.example.com/identity_credential";

/// An SD-JWT VC of a type and values, ES256 on P-256, its key ES256 on P-256.
fn sd_jwt(id: &str, vct: &str, values: &str) -> Held {
    Held::new(
        id,
        "dc+sd-jwt",
        format!(
            r#"{{"type": "{vct}", "metadata": {{}}, "values": {values}, "jwt": "eyJhbGciOiJFUzI1NiJ9.{id}.sig", "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}}"#
        ),
    )
}

fn vector(name: &str) -> String {
    let path = format!(
        "{}/../siros-openid4vp/tests/data/spec_vectors/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).expect("vector")
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
    let matched =
        Match::run(&accepted, &wallet, &env(&["en"], Vec::new()).expect("env")).expect("match");
    let answers = request
        .indexed_queries()
        .map(|(index, query)| {
            let found = matched
                .candidates(index)
                .iter()
                .map(|c| {
                    (
                        c.credential.id.to_string(),
                        c.options.iter().map(|o| o.0).collect(),
                    )
                })
                .collect();
            (query.id.to_string(), found)
        })
        .collect();
    let excluded = matched
        .excluded()
        .iter()
        .map(|x| {
            (
                request.query(x.query).expect("query").id.to_string(),
                x.credential.id.to_string(),
                x.exclude.clause().to_string(),
            )
        })
        .collect();
    (answers, excluded)
}

fn answers(name: &str, held: &[Held]) -> Vec<(String, Vec<usize>)> {
    let text = parameters(&vector(name), "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let (mut answers, _) = matched(&request, held);
    answers.remove(0).1
}

#[test]
fn the_dcql_examples_match_the_credentials_their_values_satisfy() {
    let everything = r#""family_name": "Doe", "postal_code": "90210", "locality": "Berlin", "region": "BE", "date_of_birth": "1990-01-01""#;
    let without = |name: &str| {
        let kept: Vec<&str> = everything
            .split(", ")
            .filter(|member| !member.starts_with(&format!("\"{name}\"")))
            .collect();
        format!("{{{}}}", kept.join(", "))
    };
    // §6.4.1 claim_sets [a, c, d, e] or [a, b, e]: each holder answers the options its values
    // satisfy; one answering none, or of another vct, is no candidate.
    assert_eq!(
        answers(
            "claims_alternatives",
            &[
                sd_jwt("full", IDC, &format!("{{{everything}}}")),
                sd_jwt("no-locality", IDC, &without("locality")),
                sd_jwt("no-postal", IDC, &without("postal_code")),
                sd_jwt("no-name", IDC, &without("family_name")),
                sd_jwt(
                    "other-type",
                    "https://other.example/x",
                    &format!("{{{everything}}}")
                ),
            ]
        ),
        [
            ("full".to_owned(), vec![0, 1]),
            ("no-locality".to_owned(), vec![1]),
            ("no-postal".to_owned(), vec![0])
        ]
    );
    // §6.3 values: equality of type and value.
    let doe = r#""given_name": "J", "address": {"street_address": "1 Way"}"#;
    assert_eq!(
        answers(
            "value_matching_simple",
            &[
                sd_jwt(
                    "doe",
                    IDC,
                    &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": "90211"}}"#)
                ),
                sd_jwt(
                    "smith",
                    IDC,
                    &format!(r#"{{"family_name": "Smith", {doe}, "postal_code": "90211"}}"#)
                ),
                sd_jwt(
                    "elsewhere",
                    IDC,
                    &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": "10115"}}"#)
                ),
                sd_jwt(
                    "number",
                    IDC,
                    &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": 90211}}"#)
                ),
            ]
        ),
        [("doe".to_owned(), vec![0])]
    );
    // A JSON boolean is no integer: true does not match 1.
    let flag = parameters(
        &format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["{IDC}"]}}, "claims": [{{"path": ["age_over_18"], "values": [1]}}]}}]}}"#
        ),
        "",
    );
    let received = unsigned(&flag).expect("received");
    let request = request_of(&received).expect("request");
    let (found, _) = matched(
        &request,
        &[
            sd_jwt("boolean", IDC, r#"{"age_over_18": true}"#),
            sd_jwt("integer", IDC, r#"{"age_over_18": 1}"#),
        ],
    );
    assert_eq!(found[0].1, [("integer".to_owned(), vec![0])]);
    // §6.1.1: a value of one of the query's types; another type's value does not count.
    let trusted = parameters(
        &format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["{IDC}"]}}, "trusted_authorities": [{{"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]}}]}}]}}"#
        ),
        "",
    );
    let received = unsigned(&trusted).expect("received");
    let request = request_of(&received).expect("request");
    let mut listed = sd_jwt("listed", IDC, "{}");
    listed.authorities = vec![(
        "aki".to_owned(),
        vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y".to_owned()],
    )];
    let mut other = sd_jwt("other", IDC, "{}");
    other.authorities = vec![
        ("aki".to_owned(), vec!["x".to_owned()]),
        (
            "etsi_tl".to_owned(),
            vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y".to_owned()],
        ),
    ];
    let (found, _) = matched(&request, &[listed, other, sd_jwt("unknown", IDC, "{}")]);
    assert_eq!(found[0].1, [("listed".to_owned(), vec![0])]);
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
    assert_eq!(additions.types(), [own, parent, root]);
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

/// The rules the request breaks, as (text, code).
fn refusals(dcql: &str, extra: &str) -> Vec<(String, ErrorCode)> {
    let text = parameters(dcql, extra);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry();
    match Accepted::new(&request, &registry) {
        Ok(_) => Vec::new(),
        Err(refused) => refused
            .refusals()
            .iter()
            .map(|refusal| (refusal.text(), refusal.code()))
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
            [(
                "dc+sd-jwt q: meta.vct_values is not a non-empty array of strings (B.3.5)"
                    .to_owned(),
                ErrorCode::INVALID_REQUEST
            )],
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
        [(
            "dc+sd-jwt q: vp_formats_supported is not an object of non-empty algorithm arrays"
                .to_owned(),
            ErrorCode::INVALID_REQUEST
        )]
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
        [(
            "dc+sd-jwt q: transaction data on a query without holder binding (B.3.3)".to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
        )]
    );
    assert_eq!(refusals(&query(meta), &entries), [], "with holder binding");
}

#[test]
fn the_verifiers_algorithms_admit_the_credentials_they_list() {
    let clause = "OpenID4VP B.3 vp_formats_supported";
    let view = |alg: &str, curve: &str| {
        format!(
            r#"{{"type": "t", "metadata": {{}}, "values": {{}}, "jwt": "eyJ.c.sig", "alg": "{alg}", "curve": "{curve}", "key_alg": "ES256", "key_curve": "P-256"}}"#
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
    let format = SdJwtVc::new().expect("format");
    let carried = |binding: bool, holder: Holder, members: &[Member]| {
        let dcql = format!(
            r#"{{"credentials": [{{"id": "q", "format": "dc+sd-jwt", "meta": {{"vct_values": ["t"]}}, "require_cryptographic_holder_binding": {binding}}}]}}"#
        );
        let text = parameters(&dcql, "");
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let query = format
            .query(
                &request.queries()[0],
                siros_testkit::fixtures::query_context(&request, false, None),
            )
            .map_err(|r| format!("{r:?}"))
            .expect("query");
        let mut held = sd_jwt("c", "t", "{}");
        held.holder = holder;
        query
            .carries(&held.credential().expect("credential"), members)
            .expect("carries")
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

/// The first set of the flattened offer, each entry (query, credential, option) or "none".
fn shape(dcql: &str, held: &[Held]) -> Vec<Vec<Vec<String>>> {
    let text = parameters(dcql, "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry();
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("credential"))
            .collect(),
    )
    .expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched =
        Match::run(&accepted, &wallet, &env(&["en"], Vec::new()).expect("env")).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    flatten(&matched, &consent)
        .iter()
        .map(|set| {
            set.iter()
                .map(|slot| {
                    slot.iter()
                        .map(|offered| match offered {
                            Offered::Nothing => "none".to_owned(),
                            Offered::Pick(pick) => format!(
                                "{} {} {}",
                                request.query(pick.query).expect("query").id,
                                matched
                                    .candidate(pick.query, pick.candidate)
                                    .expect("candidate")
                                    .credential
                                    .id,
                                pick.option.0
                            ),
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn set(slots: &[&[&str]]) -> Vec<Vec<String>> {
    slots
        .iter()
        .map(|slot| slot.iter().map(|entry| (*entry).to_owned()).collect())
        .collect()
}

#[test]
fn the_consent_takes_the_shapes_check_py_states() {
    // credentials_alternatives: the coupled option is a set of its own with two slots.
    let vector = vector("credentials_alternatives");
    let values = r#"{"given_name": "a", "family_name": "b", "address": {"street_address": "c"}, "postal_code": "d", "locality": "e", "region": "f", "rewards_number": "g"}"#;
    let parsed = Node::parse(&vector).expect("vector");
    let ids: Vec<(&str, &str)> = parsed
        .get("credentials")
        .and_then(Node::as_array)
        .expect("credentials")
        .iter()
        .map(|query| {
            let id = query.get("id").and_then(Node::as_str).expect("id");
            let vct = query
                .get("meta")
                .and_then(|meta| meta.get("vct_values"))
                .and_then(Node::as_array)
                .and_then(|values| values.first())
                .and_then(Node::as_str)
                .expect("vct");
            (id, vct)
        })
        .collect();
    let held: Vec<Held> = ids
        .iter()
        .map(|(id, vct)| sd_jwt(id, vct, values))
        .collect();
    assert_eq!(
        shape(&vector, &held),
        [
            set(&[
                &["pid pid 0", "other_pid other_pid 0"],
                &["nice_to_have nice_to_have 0", "none"]
            ]),
            set(&[
                &["pid_reduced_cred_1 pid_reduced_cred_1 0"],
                &["pid_reduced_cred_2 pid_reduced_cred_2 0"],
                &["nice_to_have nice_to_have 0", "none"]
            ])
        ]
    );
    // multiple: every non-empty subset once, by its first member.
    let multiple = format!(
        r#"{{"credentials": [{{"id": "m", "format": "dc+sd-jwt", "multiple": true, "meta": {{"vct_values": ["{IDC}"]}}}}]}}"#
    );
    let held: Vec<Held> = (0..3)
        .map(|k| sd_jwt(&format!("x{k}"), IDC, "{}"))
        .collect();
    assert_eq!(
        shape(&multiple, &held),
        [
            set(&[&["m x0 0"], &["m x1 0", "none"], &["m x2 0", "none"]]),
            set(&[&["m x1 0"], &["m x2 0", "none"]]),
            set(&[&["m x2 0"]])
        ]
    );
    // [c, b], [a, d], [c, d], [a, b] factor into {c, a} and {b, d}; without b, d comes next.
    let queries: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|id| {
            format!(r#"{{"id": "{id}", "format": "dc+sd-jwt", "meta": {{"vct_values": ["{IDC}"]}}, "claims": [{{"path": ["{id}"]}}]}}"#)
        })
        .collect();
    let dcql = format!(
        r#"{{"credentials": [{}], "credential_sets": [{{"options": [["c", "b"], ["a", "d"], ["c", "d"], ["a", "b"]]}}]}}"#,
        queries.join(", ")
    );
    let held: Vec<Held> = ["a", "c", "d"]
        .iter()
        .map(|id| sd_jwt(id, IDC, &format!(r#"{{"{id}": "v"}}"#)))
        .collect();
    assert_eq!(
        shape(&dcql, &held),
        [set(&[&["c c 0", "a a 0"], &["d d 0"]])]
    );
}
