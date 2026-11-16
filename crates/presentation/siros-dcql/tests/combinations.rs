//! Combination enumeration over the selection rules of OpenID4VP 1.0 §6.4: the sets of
//! credentials that answer a request together, their purposes, `multiple`, and the bound on
//! their count.

mod support;

use serde_json::{json, Value};
use siros_dcql::{execute, Dropped, ExactFormat};
use support::{pid, query, satisfiable, JsonCredential};

/// With no `credential_sets`, every query must be answered, so a combination
/// spans all of them (§6.4).
#[test]
fn a_combination_spans_every_query_when_no_sets_are_given() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"b","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["family_name"]}]}]}"#,
    );
    let creds = [pid(
        json!({"given_name": "Erika", "family_name": "Mustermann"}),
    )];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.dropped(), Dropped::Exact(0));
    assert_eq!(combos.combinations().len(), 1);

    let members = &combos.combinations()[0].members();
    assert_eq!(members.len(), 2, "both queries in one combination");
    assert_eq!(members[0].0, "a");
    assert_eq!(members[1].0, "b");
}

/// Alternatives are separate combinations — the user picks one.
#[test]
fn each_alternative_credential_is_its_own_combination() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new("pid-1", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("pid-2", "dc+sd-jwt", json!({"given_name": "Max"})),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    let ids: Vec<_> = combos
        .combinations()
        .iter()
        .map(|c| c.members()[0].1.credential_id().to_owned())
        .collect();
    assert_eq!(ids, ["pid-1", "pid-2"]);
}

/// Each option of a required set is a distinct way to satisfy it, and a
/// multi-member option produces one combination covering both queries.
#[test]
fn each_satisfiable_option_becomes_a_combination() {
    let q = query(
        r#"{"credentials":[{"id":"full","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"part1","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["family_name"]}]},
                           {"id":"part2","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["birth_date"]}]}],
            "credential_sets":[{"options":[["full"],["part1","part2"]]}]}"#,
    );
    let creds = [pid(json!({
        "given_name": "Erika", "family_name": "Mustermann", "birth_date": "1979-04-12"
    }))];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.combinations().len(), 2, "one per satisfiable option");

    let sizes: Vec<_> = combos
        .combinations()
        .iter()
        .map(|c| c.members().len())
        .collect();
    assert_eq!(sizes, [1, 2], "the second option needs both credentials");
}

/// An option the wallet cannot satisfy is not offered, but a sibling option
/// that it can satisfy still is.
#[test]
fn unsatisfiable_options_are_left_out() {
    let q = query(
        r#"{"credentials":[{"id":"have","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"lack","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["lack"],["have"]]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.combinations().len(), 1);
    assert_eq!(combos.combinations()[0].members()[0].0, "have");
}

/// Optional sets are not enumerated: the wallet MAY include them, so offering
/// one is a UI decision rather than a matching one, and folding them in would
/// multiply the count for choices the verifier said it can do without.
#[test]
fn optional_sets_do_not_multiply_the_combinations() {
    let q = query(
        r#"{"credentials":[{"id":"need","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"nice","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["family_name"]}]}],
            "credential_sets":[{"options":[["need"]]},
                               {"options":[["nice"]],"required":false}]}"#,
    );
    let creds = [pid(
        json!({"given_name": "Erika", "family_name": "Mustermann"}),
    )];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.combinations().len(), 1);
    assert_eq!(combos.combinations()[0].members()[0].0, "need");
}

/// The count is a product, so it has to be bounded — and whatever is dropped
/// is counted. A picker showing the first few of many is telling the user
/// those are the only options they have.
#[test]
fn the_combination_count_is_bounded_and_the_remainder_is_counted() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds: Vec<_> = (0..10)
        .map(|i| {
            JsonCredential::new(
                &format!("pid-{i}"),
                "dc+sd-jwt",
                json!({"given_name": "Erika"}),
            )
        })
        .collect();

    let combos = execute(&q, &creds, &ExactFormat).combinations(4);
    assert_eq!(combos.combinations().len(), 4);
    assert_eq!(
        combos.dropped(),
        Dropped::Exact(6),
        "the remainder must be reported, not hidden"
    );
}

/// An unsatisfiable request yields no combinations — §6.4 says the wallet
/// must not return any credential, so there is nothing to offer.
#[test]
fn an_unsatisfiable_request_yields_no_combinations() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"b","format":"mso_mdoc","meta":{}}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let result = execute(&q, &creds, &ExactFormat);
    assert!(!satisfiable(&result));
    assert!(result.combinations(16).combinations().is_empty());
}

/// Every set optional means nothing is required, so there is no combination to
/// enumerate. Returning one empty combination would hand the picker an option
/// containing no credentials at all.
#[test]
fn all_optional_sets_produce_no_combination_rather_than_an_empty_one() {
    let q = query(
        r#"{"credentials":[{"id":"nice","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}],
            "credential_sets":[{"options":[["nice"]],"required":false}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let result = execute(&q, &creds, &ExactFormat);
    assert!(satisfiable(&result), "an optional set imposes nothing");

    let combos = result.combinations(16);
    assert!(
        combos.combinations().is_empty(),
        "expected no combinations, got {:?}",
        combos.combinations()
    );
}

/// The product is computed, not built: asking for two of a thousand
/// possibilities must not materialise a thousand.
#[test]
fn only_the_requested_number_of_combinations_is_built() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"b","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]}],
            "credential_sets":[{"options":[["a","b"]]}]}"#,
    );
    let creds: Vec<_> = (0..40)
        .map(|i| {
            JsonCredential::new(
                &format!("pid-{i}"),
                "dc+sd-jwt",
                json!({"given_name": "Erika"}),
            )
        })
        .collect();

    // 40 candidates for each of two queries: 1600 possibilities.
    let combos = execute(&q, &creds, &ExactFormat).combinations(2);
    assert_eq!(combos.combinations().len(), 2);
    assert_eq!(
        combos.dropped(),
        Dropped::Exact(1598),
        "the rest are counted, not built"
    );

    // The two built are distinct, so the bound does not collapse them.
    assert_ne!(combos.combinations()[0], combos.combinations()[1]);
    for combination in combos.combinations() {
        assert_eq!(combination.members().len(), 2);
    }
}

/// §6.2 `purpose` reaches the combination it explains, not just the query.
///
/// A request with two required sets offers combinations that satisfy both, so
/// both reasons belong to each one. Shown beside the wrong option, a purpose
/// misinforms the person consenting.
#[test]
fn a_combination_carries_the_purposes_of_the_sets_it_satisfies() {
    let q = query(
        r#"{"credentials":[{"id":"name","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"age","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["birth_date"]}]}],
            "credential_sets":[
              {"options":[["name"]],"purpose":"Addressing you correctly"},
              {"options":[["age"]],"purpose":{"id":7,"name":"Age check"}}]}"#,
    );
    let creds = [pid(
        json!({"given_name": "Erika", "birth_date": "1979-04-12"}),
    )];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.combinations().len(), 1);
    let purposes = &combos.combinations()[0].purposes();
    assert_eq!(
        purposes.len(),
        2,
        "one per required set the combination satisfies"
    );
    assert_eq!(
        purposes[0],
        Value::String("Addressing you correctly".into())
    );
    assert_eq!(
        purposes[1].get("name"),
        Some(&Value::String("Age check".into())),
        "a non-string purpose is carried whole, not stringified here"
    );
}

/// A set with no `purpose` contributes nothing rather than a placeholder, so a
/// caller can tell "no reason given" from "a reason that renders as empty".
#[test]
fn a_set_without_a_purpose_contributes_none() {
    let q = query(
        r#"{"credentials":[{"id":"name","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]}],
            "credential_sets":[{"options":[["name"]]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert!(combos.combinations()[0].purposes().is_empty());
}

/// Without `credential_sets` there is no set to carry a reason, so there is no
/// reason — the implicit group §6.4 defines is the engine's, not the
/// verifier's.
#[test]
fn no_credential_sets_means_no_purposes() {
    let q = query(
        r#"{"credentials":[{"id":"name","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert!(combos.combinations()[0].purposes().is_empty());
}

/// §6.1 `multiple` — "multiple Credentials can be returned for this Credential
/// Query". A query that sets it is answered by every matching credential at
/// once, which is the reading under which the flag does anything at all.
#[test]
fn a_multiple_query_is_answered_by_every_matching_credential() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},"multiple":true,
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new("a", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("b", "dc+sd-jwt", json!({"given_name": "Max"})),
        JsonCredential::new("c", "dc+sd-jwt", json!({"given_name": "Ada"})),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(
        combos.combinations().len(),
        1,
        "one option holding all three, not three alternatives"
    );
    let ids: Vec<_> = combos.combinations()[0]
        .members()
        .iter()
        .map(|(query_id, candidate)| (query_id.as_str(), candidate.credential_id().as_str()))
        .collect();
    assert_eq!(ids, [("c", "a"), ("c", "b"), ("c", "c")]);
}

/// Without `multiple` the same wallet yields one alternative per credential —
/// the default is `false`, and §6.4 then permits at most one per query.
#[test]
fn without_multiple_each_credential_is_its_own_alternative() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new("a", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("b", "dc+sd-jwt", json!({"given_name": "Max"})),
        JsonCredential::new("c", "dc+sd-jwt", json!({"given_name": "Ada"})),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.combinations().len(), 3);
    for combination in combos.combinations() {
        assert_eq!(
            combination.members().len(),
            1,
            "at most one per query (§6.4)"
        );
    }
}

/// `multiple` collapses the product rather than multiplying it: two queries
/// with three candidates each is nine combinations normally, and one when both
/// take everything.
#[test]
fn multiple_collapses_the_combination_count() {
    let q = query(
        r#"{"credentials":[{"id":"names","format":"dc+sd-jwt","meta":{},"multiple":true,
                            "claims":[{"path":["given_name"]}]},
                           {"id":"dates","format":"dc+sd-jwt","meta":{},"multiple":true,
                            "claims":[{"path":["birth_date"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new(
            "a",
            "dc+sd-jwt",
            json!({"given_name": "Erika", "birth_date": "1979-04-12"}),
        ),
        JsonCredential::new(
            "b",
            "dc+sd-jwt",
            json!({"given_name": "Max", "birth_date": "1985-01-02"}),
        ),
        JsonCredential::new(
            "c",
            "dc+sd-jwt",
            json!({"given_name": "Ada", "birth_date": "1990-11-30"}),
        ),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(64);
    assert_eq!(combos.combinations().len(), 1);
    assert_eq!(combos.combinations()[0].members().len(), 6, "3 per query");
    assert_eq!(combos.dropped(), Dropped::Exact(0));
}

/// A `multiple` query with nothing matching is still unsatisfied. Width one
/// applies to a query answered by everything, and there is no "everything"
/// when the wallet holds none of it.
#[test]
fn a_multiple_query_with_no_candidates_is_not_satisfied() {
    let q = query(r#"{"credentials":[{"id":"c","format":"mso_mdoc","meta":{},"multiple":true}]}"#);
    let creds = [pid(json!({"given_name": "Erika"}))];

    let result = execute(&q, &creds, &ExactFormat);
    assert!(!satisfiable(&result));
    assert!(result.combinations(16).combinations().is_empty());
}

/// The finding this type exists for: a product that overflows `usize` reports
/// a bound, not a number.
///
/// Before, `dropped` was `total - take` where `total` had saturated, so a
/// wallet asking about 500 credential queries was told 18446744073709551551
/// combinations had been dropped — a figure precise enough to be believed and
/// wrong enough to discredit everything beside it.
#[test]
fn an_overflowing_product_reports_a_bound_rather_than_a_number() {
    // Two candidates per query across enough queries that 2^n leaves `usize`
    // far behind. Nothing is mis-offered — the cap is what keeps enumeration
    // bounded — but the count of what was skipped is unknowable.
    let queries: Vec<String> = (0..200)
        .map(|i| {
            format!(
                r#"{{"id":"q{i}","format":"dc+sd-jwt","meta":{{}},
                     "claims":[{{"path":["given_name"]}}]}}"#
            )
        })
        .collect();
    let q = query(&format!(r#"{{"credentials":[{}]}}"#, queries.join(",")));
    let creds = [
        JsonCredential::new("a", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("b", "dc+sd-jwt", json!({"given_name": "Max"})),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(32);
    assert_eq!(
        combos.combinations().len(),
        32,
        "the limit is still honoured"
    );
    assert!(
        !combos.dropped().is_exact(),
        "2^200 combinations cannot be counted in a usize, and claiming \
         otherwise is the bug: got {:?}",
        combos.dropped()
    );
    assert!(combos.dropped().any());
    assert!(
        matches!(combos.dropped(), Dropped::AtLeast(n) if n == usize::MAX - 32),
        "the bound is what is left of the clamp: got {:?}",
        combos.dropped()
    );
}

/// A count that fits stays exact, so the distinction is not merely always-on.
#[test]
fn a_product_that_fits_stays_exact() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"b","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new("x", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("y", "dc+sd-jwt", json!({"given_name": "Max"})),
        JsonCredential::new("z", "dc+sd-jwt", json!({"given_name": "Ada"})),
    ];

    // 3 x 3 = 9 combinations, of which 4 are built.
    let combos = execute(&q, &creds, &ExactFormat).combinations(4);
    assert_eq!(combos.combinations().len(), 4);
    assert_eq!(combos.dropped(), Dropped::Exact(5));
    assert!(combos.dropped().is_exact());
}

/// Nothing dropped is exactly zero, not an unknown — a picker showing every
/// option there is should say so with confidence.
#[test]
fn nothing_dropped_is_an_exact_zero() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let combos = execute(&q, &creds, &ExactFormat).combinations(16);
    assert_eq!(combos.dropped(), Dropped::Exact(0));
    assert!(!combos.dropped().any());
}

/// Summing dropped counts must not manufacture exactness either.
///
/// Two required credential sets each drop a bounded number, and the total is
/// still a bound. Reported as exact, that would be the same overstatement one
/// layer up from the product — so it is checked across the group loop, not
/// only inside it.
#[test]
fn a_bound_stays_a_bound_across_several_credential_sets() {
    // Two required sets, each over enough queries that its own product
    // overflows, so both contribute an `AtLeast` that then has to be summed.
    let mut queries = Vec::new();
    for group in 0..2 {
        for i in 0..100 {
            queries.push(format!(
                r#"{{"id":"g{group}q{i}","format":"dc+sd-jwt","meta":{{}},
                     "claims":[{{"path":["given_name"]}}]}}"#
            ));
        }
    }
    let options: Vec<String> = (0..2)
        .map(|group| {
            let ids: Vec<String> = (0..100).map(|i| format!(r#""g{group}q{i}""#)).collect();
            format!(r#"{{"options":[[{}]]}}"#, ids.join(","))
        })
        .collect();
    let q = query(&format!(
        r#"{{"credentials":[{}],"credential_sets":[{}]}}"#,
        queries.join(","),
        options.join(",")
    ));
    let creds = [
        JsonCredential::new("a", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("b", "dc+sd-jwt", json!({"given_name": "Max"})),
    ];

    let combos = execute(&q, &creds, &ExactFormat).combinations(32);
    assert!(
        !combos.dropped().is_exact(),
        "a sum of bounds is a bound: got {:?}",
        combos.dropped()
    );
}
