//! The type's rules (OpenID4VP §5.1 `invalid_transaction_data`): one fixture per rule, and per
//! way of breaking it, each a change to §7.1.2's entry with the refusal qes.py writes for it.

mod common;

use siros_openid4vp::matching::Accepted;
use siros_openid4vp::refusal::ErrorCode;
use siros_qes::QesProfile;

use common::fixtures::{accepted, naming_twice, rule_table};
use common::{QUERY_7_1_2, entry, parameters, registry, request_of, unsigned};

/// The refusals of a request of entries for §7.1.2's query: each one's text and code.
fn refusals(entries: &[String]) -> Vec<(String, ErrorCode)> {
    let encoded: Vec<String> = entries.iter().map(|json| entry(json)).collect();
    let text = parameters(QUERY_7_1_2, &encoded);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Some(QesProfile::default()));
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
fn each_rule_of_the_type_refuses_its_entry() {
    // Catches a rule of qes.py's `problems` the port leaves out, words otherwise or codes
    // otherwise, and the order the rules run in.
    for (json, problems) in rule_table() {
        let want: Vec<(String, ErrorCode)> = problems
            .iter()
            .map(|problem| {
                (
                    format!("QES entry 0: {problem}"),
                    ErrorCode::InvalidTransactionData,
                )
            })
            .collect();
        assert_eq!(refusals(std::slice::from_ref(&json)), want, "{json}");
    }
}

#[test]
fn one_presentation_approves_one_request() {
    // Catches two entries of the type naming one query passing, or a refusal per pair.
    assert_eq!(
        refusals(&naming_twice())
            .into_iter()
            .filter(|(text, _)| text.starts_with("QES"))
            .collect::<Vec<_>>(),
        [(
            "QES entries [0, 1, 2] name xyz123: one presentation approves one request".to_owned(),
            ErrorCode::InvalidTransactionData
        )]
    );
}

#[test]
fn the_examples_keep_the_rules() {
    // Catches a rule refusing an entry the specification's examples write.
    for json in accepted() {
        let refused = refusals(std::slice::from_ref(&json));
        assert!(refused.is_empty(), "{json}: {refused:?}");
    }
}
