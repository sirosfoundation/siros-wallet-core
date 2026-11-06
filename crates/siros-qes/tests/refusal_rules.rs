//! The type's rules (OpenID4VP §5.1 `invalid_transaction_data`): one fixture per rule, each a
//! change to §7.1.2's entry.

mod common;

use siros_openid4vp::matching::Accepted;
use siros_openid4vp::refusal::ErrorCode;
use siros_qes::{QesProfile, QesRule};

use common::fixtures::{accepted, naming_twice, rule_table};
use common::{QUERY_7_1_2, entry, parameters, registry, request_of, unsigned};

/// The refusals of a request of entries for §7.1.2's query: each one's rule when it is the
/// profile's, and its code.
fn refusals(entries: &[String]) -> Vec<(Option<QesRule>, ErrorCode)> {
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
            .map(|refusal| {
                let rule: &dyn std::error::Error = refusal.rule();
                (rule.downcast_ref::<QesRule>().cloned(), refusal.code())
            })
            .collect(),
    }
}

#[test]
fn each_rule_of_the_type_refuses_its_entry() {
    for (json, broken) in rule_table() {
        let got = refusals(std::slice::from_ref(&json));
        let [(Some(QesRule::Entry { entry, problem }), code)] = got.as_slice() else {
            panic!("{json}: {got:?}")
        };
        assert_eq!(entry.get(), 0, "{json}");
        assert_eq!(*code, ErrorCode::INVALID_TRANSACTION_DATA, "{json}");
        assert!(broken(problem), "{json}: {problem:?}");
    }
}

#[test]
fn one_presentation_approves_one_request() {
    // Catches two entries of the type naming one query passing, or a refusal per pair.
    let named: Vec<(Vec<usize>, String, ErrorCode)> = refusals(&naming_twice())
        .into_iter()
        .filter_map(|(rule, code)| match rule {
            Some(QesRule::OneRequest { entries, query }) => Some((
                entries.entries().iter().map(|at| at.get()).collect(),
                query,
                code,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        named,
        [(
            vec![0, 1, 2],
            "xyz123".to_owned(),
            ErrorCode::INVALID_TRANSACTION_DATA
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
