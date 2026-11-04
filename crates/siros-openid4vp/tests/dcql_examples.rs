//! The OpenID4VP DCQL examples (`data/spec_vectors`, verbatim copies of `1.0/examples/query_lang`)
//! and PaSO Core Annex A.5 and A.6, with what their texts state: the independent choices each
//! request factors into, and the options a credential's values answer.

mod common;

use siros_openid4vp::claims::kit::ClaimsQuery;
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::{Accepted, Match};
use siros_openid4vp::plugins::OptionIndex;
use siros_openid4vp::request::{Request, factor, project};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::Binds;

use common::{ClaimsTest, Held, PASO_A5, env, parameters, registry, request_of, unsigned, vector};

/// Each block with its options, as sorted query ids.
fn shape(request: &Request<'_>) -> Vec<(Vec<String>, Vec<Vec<String>>)> {
    let names = |set: siros_openid4vp::request::QuerySet| {
        let mut ids: Vec<String> = set
            .iter()
            .filter_map(|q| request.query(q))
            .map(|q| q.id.to_string())
            .collect();
        ids.sort();
        ids
    };
    let alternatives = request.alternative_sets();
    factor(&alternatives, request.query_order())
        .into_iter()
        .map(|block| {
            (
                names(block),
                project(&alternatives, block)
                    .into_iter()
                    .map(names)
                    .collect(),
            )
        })
        .collect()
}

/// A block's query ids with its options' query ids.
type Shape<'s> = [(&'s [&'s str], &'s [&'s [&'s str]])];

fn owned(shape: &Shape<'_>) -> Vec<(Vec<String>, Vec<Vec<String>>)> {
    let strings = |items: &[&str]| -> Vec<String> {
        let mut out: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
        out.sort();
        out
    };
    shape
        .iter()
        .map(|(block, options)| (strings(block), options.iter().map(|o| strings(o)).collect()))
        .collect()
}

#[test]
fn the_dcql_examples_factor_into_their_stated_choices() {
    let cases: [(&str, &Shape<'_>); 4] = [
        ("simple", &[(&["my_credential"], &[&["my_credential"]])]),
        (
            "multi_credentials",
            &[(&["pid"], &[&["pid"]]), (&["mdl"], &[&["mdl"]])],
        ),
        // Not transposable: one option fills two queries.
        (
            "credentials_alternatives",
            &[
                (
                    &[
                        "pid",
                        "other_pid",
                        "pid_reduced_cred_1",
                        "pid_reduced_cred_2",
                    ],
                    &[
                        &["pid"],
                        &["other_pid"],
                        &["pid_reduced_cred_1", "pid_reduced_cred_2"],
                    ],
                ),
                (&["nice_to_have"], &[&["nice_to_have"], &[]]),
            ],
        ),
        (
            "complex_mdoc",
            &[
                (
                    &["mdl-id", "photo_card-id"],
                    &[&["mdl-id"], &["photo_card-id"]],
                ),
                (
                    &["mdl-address", "photo_card-address"],
                    &[&["mdl-address"], &["photo_card-address"], &[]],
                ),
            ],
        ),
    ];
    for (name, want) in cases {
        let text = parameters(&vector(name), "");
        assert_eq!(
            shape(&request_of(&unsigned(&text).expect("received")).expect("request")),
            owned(want),
            "{name}"
        );
    }
}

#[test]
fn paso_core_annex_a_5_and_a_6_factor_as_stated() {
    let a5 = parameters(PASO_A5, "");
    assert_eq!(
        shape(&request_of(&unsigned(&a5).expect("received")).expect("request")),
        owned(&[
            (
                &["sca_card", "sca_account"],
                &[&["sca_card"], &["sca_account"]]
            ),
            (&["pid"], &[&["pid"], &[]])
        ])
    );
    let a6 = parameters(
        r#"{"credentials": [{"id": "sca_card", "format": "x"}, {"id": "pid_1", "format": "x"}, {"id": "pid_2", "format": "x"}, {"id": "loyalty", "format": "x"}],
            "credential_sets": [{"options": [["sca_card", "pid_1"], ["sca_card", "pid_2"], ["sca_card"]]}]}"#,
        "",
    );
    assert_eq!(
        shape(&request_of(&unsigned(&a6).expect("received")).expect("request")),
        owned(&[
            (&["sca_card"], &[&["sca_card"]]),
            (&["pid_1", "pid_2"], &[&["pid_1"], &["pid_2"], &[]])
        ])
    );
}

/// The options each credential's values answer, for the DCQL query's first Credential Query.
fn answered(
    dcql: &str,
    member: &'static str,
    credentials: &[(&str, &str, &str)],
) -> Vec<(String, Vec<usize>)> {
    let text = parameters(dcql, "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let format = ClaimsTest {
        member,
        label: "label",
    };
    let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
    credentials
        .iter()
        .filter_map(|(id, kind, values)| {
            let view_text =
                format!(r#"{{"type": "{kind}", "metadata": {{}}, "values": {values}}}"#);
            let view = Node::parse(&view_text).expect("view");
            let options: Vec<usize> = query
                .answerable(&format, &view, &[])
                .expect("the view's types")
                .into_iter()
                .map(|o| o.0)
                .collect();
            (!options.is_empty()).then(|| ((*id).to_owned(), options))
        })
        .collect()
}

#[test]
fn claims_and_claim_sets_answer_the_options_a_credentials_values_satisfy() {
    let idc = "https://credentials.example.com/identity_credential";
    // [a, c, d, e] or [a, b, e]; a holder answering none, or of another vct, is no candidate.
    let answered_options = answered(
        &vector("claims_alternatives"),
        "vct_values",
        &[
            (
                "full",
                idc,
                r#"{"family_name": "Doe", "postal_code": "90210", "locality": "Berlin", "region": "BE", "date_of_birth": "1990-01-01"}"#,
            ),
            (
                "no-locality",
                idc,
                r#"{"family_name": "Doe", "postal_code": "90210", "region": "BE", "date_of_birth": "1990-01-01"}"#,
            ),
            (
                "no-postal",
                idc,
                r#"{"family_name": "Doe", "locality": "Berlin", "region": "BE", "date_of_birth": "1990-01-01"}"#,
            ),
            (
                "no-name",
                idc,
                r#"{"postal_code": "90210", "locality": "Berlin", "region": "BE", "date_of_birth": "1990-01-01"}"#,
            ),
            (
                "other-type",
                "https://other.example/x",
                r#"{"family_name": "Doe", "postal_code": "90210", "locality": "Berlin", "region": "BE", "date_of_birth": "1990-01-01"}"#,
            ),
        ],
    );
    assert_eq!(
        answered_options,
        [
            ("full".to_owned(), vec![0, 1]),
            ("no-locality".to_owned(), vec![1]),
            ("no-postal".to_owned(), vec![0])
        ]
    );
    // Values match by equality of type and value.
    let doe = r#""given_name": "J", "address": {"street_address": "1 Way"}"#;
    let matching = answered(
        &vector("value_matching_simple"),
        "vct_values",
        &[
            (
                "doe",
                idc,
                &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": "90211"}}"#),
            ),
            (
                "smith",
                idc,
                &format!(r#"{{"family_name": "Smith", {doe}, "postal_code": "90211"}}"#),
            ),
            (
                "elsewhere",
                idc,
                &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": "10115"}}"#),
            ),
            (
                "number",
                idc,
                &format!(r#"{{"family_name": "Doe", {doe}, "postal_code": 90211}}"#),
            ),
        ],
    );
    assert_eq!(matching, [("doe".to_owned(), vec![0])]);
    // The doctype_value decides; claims are [namespace, element].
    let holder =
        r#"{"org.iso.7367.1": {"vehicle_holder": "J"}, "org.iso.18013.5.1": {"given_name": "J"}}"#;
    let mdoc = answered(
        &vector("simple_mdoc"),
        "doctype_value",
        &[
            ("car", "org.iso.7367.1.mVRC", holder),
            ("mdl", "org.iso.18013.5.1.mDL", holder),
        ],
    );
    assert_eq!(mdoc, [("car".to_owned(), vec![0])]);
    // PaSO Core Annex A.5: the SCA card's query names no claim, so its one option holds none and
    // a credential of its type answers it (§6.4.1).
    let sca = answered(
        PASO_A5,
        "vct_values",
        &[
            ("card", "https://bank.example/sca/card", "{}"),
            ("account", "https://bank.example/sca/account", "{}"),
        ],
    );
    assert_eq!(sca, [("card".to_owned(), vec![0])]);
}

#[test]
fn a_json_boolean_is_no_integer() {
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "x", "meta": {"vct_values": ["t"]}, "claims": [{"path": ["age_over_18"], "values": [1]}]}]}"#,
        "",
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
    let answers = |values: &str| {
        let view = format!(r#"{{"type": "t", "values": {values}}}"#);
        query
            .answerable(&format, &Node::parse(&view).expect("view"), &[])
            .expect("the view's types")
    };
    assert_eq!(
        answers(r#"{"age_over_18": true}"#),
        Vec::<OptionIndex>::new()
    );
    assert_eq!(answers(r#"{"age_over_18": 1}"#), vec![OptionIndex(0)]);
    // A query without its format's meta is refused by the format.
    let bare = parameters(
        r#"{"credentials": [{"id": "q", "format": "x", "claims": []}]}"#,
        "",
    );
    let received = unsigned(&bare).expect("received");
    let bare = request_of(&received).expect("request");
    let refusals = ClaimsQuery::parse(&format, &bare.queries()[0], None).expect_err("refused");
    assert_eq!(refusals.items()[0].text(), "x q: meta.vct_values is absent");
}

#[test]
fn trusted_authorities_take_a_value_of_one_of_the_querys_types() {
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "test", "trusted_authorities": [{"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]}]}]}"#,
        "",
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let mut listed = Held::answering("listed", &["q"], &[]);
    listed.authorities = vec![("aki", vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y"])];
    let mut other = Held::answering("other", &["q"], &[]);
    other.authorities = vec![
        ("aki", vec!["x"]),
        ("etsi_tl", vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]),
    ];
    let unknown = Held::answering("unknown", &["q"], &[]);
    let wallet = Wallet::new(vec![
        listed.credential(),
        other.credential(),
        unknown.credential(),
    ])
    .expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env("en")).expect("match");
    let ids: Vec<&str> = matched
        .candidates(request.indexed_queries().next().expect("q").0)
        .iter()
        .map(|c| c.credential.id.as_str())
        .collect();
    assert_eq!(ids, ["listed"]);
}

#[test]
fn credential_sets_and_entries_parse_as_written() {
    let json = r#"{"type": "t1", "credential_ids": ["pid"], "x": null, "y": true}"#;
    let text = parameters(
        &vector("credentials_alternatives"),
        &format!(r#""transaction_data":["{}"]"#, common::entry(json)),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let id =
        |q: &siros_openid4vp::request::QueryIndex| request.query(*q).expect("query").id.to_string();
    let sets: Vec<(Vec<Vec<String>>, bool)> = request
        .sets()
        .expect("credential sets")
        .iter()
        .map(|set| {
            (
                set.options
                    .iter()
                    .map(|o| o.iter().map(id).collect())
                    .collect(),
                set.required,
            )
        })
        .collect();
    let owned = |options: &[&[&str]]| {
        options
            .iter()
            .map(|o| o.iter().map(|q| (*q).to_owned()).collect())
            .collect::<Vec<Vec<String>>>()
    };
    assert_eq!(
        sets,
        [
            (
                owned(&[
                    &["pid"],
                    &["other_pid"],
                    &["pid_reduced_cred_1", "pid_reduced_cred_2"]
                ]),
                true
            ),
            (owned(&[&["nice_to_have"]]), false)
        ]
    );
    let [entry] = request.entries() else {
        panic!("one entry")
    };
    assert_eq!(
        (entry.kind().as_str(), entry.credential_ids()),
        ("t1", &["pid".to_owned()][..])
    );
    // The entry decodes to the JSON text the Verifier encoded, its members as written.
    assert_eq!(entry.decoded(), json);
    assert_eq!(
        (entry.members().get("x"), entry.members().get("y")),
        (Some(&Node::Null), Some(&Node::Bool(true)))
    );
}
