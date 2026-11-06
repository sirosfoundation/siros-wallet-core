//! First match (Core §7.4.2) through the profile's binding, with PaSO Core A.5 and A.7.

use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Binding, Carriage, NoCandidate, Profile};
use siros_paso::PasoProfile;

use crate::common::{CUSTOM, Card, ExcludedBy, PAY, annex, en, member, parameters};

/// A binding of the request's entries naming the query `q` for the card.
pub(super) fn bind(
    entries: &[&str],
    card: &Card,
    carriage: Carriage,
) -> Result<Vec<usize>, ExcludedBy> {
    let parameters = parameters(&crate::common::one_query("dc+sd-jwt"), entries, "");
    siros_testkit::signed_request!(let request = &parameters);
    let query = &request.queries()[0];
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let credential = card.credential();
    let additions = crate::common::additions(&credential);
    let binding = Binding {
        request: &request,
        query,
        credential: &credential,
        entries: &offered,
        placement: crate::common::placement(&credential.format),
        additions: &*additions,
        carriage,
    };
    match PasoProfile::default().bind(binding, &en()) {
        Ok(bound) => Ok(bound.entries.entries().iter().map(|e| e.get()).collect()),
        Err(NoCandidate::Excluded(exclude)) => Err(ExcludedBy::of(&exclude)),
        Err(NoCandidate::Fault(fault)) => panic!("{fault}"),
    }
}

#[test]
pub(super) fn first_match_binds_the_first_entry_that_renders_and_stops_at_a_locale_failure() {
    let ok = r#"{"claims": [{"path": ["transaction_id"]}, {"path": ["n"], "display": [{"locale": "en", "name": "N"}]}]}"#;
    let german = r#"{"claims": [{"path": ["transaction_id"]}, {"path": ["n"], "display": [{"locale": "de", "name": "N"}]}]}"#;
    let custom = |kind: &str, n: &str| {
        format!(
            r#"{{"type": "{kind}", "credential_ids": ["q"], "payload": {{"transaction_id": "t", "n": "{n}"}}}}"#
        )
    };
    // An entry that is not compatible gives way to the next (Core §7.4.2 step 2).
    let card = Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {ok}}}"#));
    assert_eq!(
        bind(
            &[&custom(CUSTOM, "a\\u202e"), &custom(CUSTOM, "a")],
            &card,
            Carriage::Carried
        ),
        Ok(vec![1])
    );
    // A locale failure excludes the credential; the next entry is never tried (View §4).
    let other = format!("{CUSTOM}x");
    let card = Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {german}, "{other}": {ok}}}"#));
    assert_eq!(
        bind(
            &[&custom(CUSTOM, "a"), &custom(&other, "a")],
            &card,
            Carriage::Carried
        ),
        Err(ExcludedBy::Locale)
    );
    // A presentation that cannot carry the SCA response claims supports no PaSO type.
    assert_eq!(
        bind(
            &[&custom(CUSTOM, "a")],
            &Card::sd_jwt(&format!(r#"{{"{CUSTOM}": {ok}}}"#)),
            Carriage::Uncarried
        ),
        Err(ExcludedBy::Carriage)
    );
    assert_eq!(
        bind(&[&custom(CUSTOM, "a\\u202e")], &card, Carriage::Carried),
        Err(ExcludedBy::NoEntry)
    );
}

#[test]
pub(super) fn core_a5_and_a7_bind_the_entries_their_text_states() {
    let pay_meta = member(&annex("Payment.md", "A.1")[1], PAY);
    // A.5: each entry names its own query; the card binds entry 0, the account entry 1.
    let a5 = annex("paso-core.md", "A.5");
    let dcql = member(&a5[0], "dcql_query");
    let entries: Vec<String> = Node::parse(&a5[1])
        .expect("entries")
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| e.json_spaced().to_string())
        .collect();
    let parameters = parameters(
        &dcql,
        &entries.iter().map(String::as_str).collect::<Vec<_>>(),
        "",
    );
    siros_testkit::signed_request!(let request = &parameters);
    let card = Card::sd_jwt(&format!(r#"{{"{PAY}": {pay_meta}}}"#));
    for (query, want) in [("sca_card", 0), ("sca_account", 1)] {
        let (index, query) = request
            .indexed_queries()
            .find(|(_, q)| q.id().as_str() == query)
            .expect("query");
        let naming = request.entries_naming(index);
        let credential = card.credential();
        let additions = crate::common::additions(&credential);
        let bound = PasoProfile::default()
            .bind(
                Binding {
                    request: &request,
                    query,
                    credential: &credential,
                    entries: &naming,
                    placement: crate::common::placement(&credential.format),
                    additions: &*additions,
                    carriage: Carriage::Carried,
                },
                &en(),
            )
            .expect("binds");
        assert_eq!(
            bound
                .entries
                .entries()
                .iter()
                .map(|e| e.get())
                .collect::<Vec<_>>(),
            [want]
        );
    }
    // A.7: a credential supporting v2 takes the v2 entry; one supporting v1 alone falls back.
    let a7_text = annex("paso-core.md", "A.7").remove(0);
    let a7 = Node::parse(&a7_text).expect("entries");
    let entries: Vec<String> = a7
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| e.json_spaced().to_string())
        .collect();
    let kinds: Vec<String> = a7
        .as_array()
        .expect("an array")
        .iter()
        .map(|e| {
            e.get("type")
                .and_then(Node::as_str)
                .expect("type")
                .to_owned()
        })
        .collect();
    let a7_meta = |points: bool| {
        let reward = if points {
            r#", {"path": ["reward_points"], "display": [{"locale": "en", "name": "Reward points"}]}"#
        } else {
            ""
        };
        format!(
            r#"{{"claims": [{{"path": ["transaction_id"]}}, {{"path": ["amount"], "value_type": "iso_currency_amount", "display": [{{"locale": "en", "name": "Amount"}}]}}, {{"path": ["payee", "name"], "display": [{{"locale": "en", "name": "Payee"}}]}}, {{"path": ["payee", "id"]}}{reward}]}}"#
        )
    };
    let entry_texts: Vec<&str> = entries.iter().map(String::as_str).collect();
    let rebound = |card: &Card| {
        let parameters = crate::common::parameters(
            &crate::common::one_query("dc+sd-jwt").replace("\"q\"", "\"sca\""),
            &entry_texts,
            "",
        );
        siros_testkit::signed_request!(let request = &parameters);
        let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
        let credential = card.credential();
        let additions = crate::common::additions(&credential);
        PasoProfile::default()
            .bind(
                Binding {
                    request: &request,
                    query: &request.queries()[0],
                    credential: &credential,
                    entries: &offered,
                    placement: crate::common::placement(&credential.format),
                    additions: &*additions,
                    carriage: Carriage::Carried,
                },
                &en(),
            )
            .expect("binds")
            .entries
            .entries()
            .iter()
            .map(|e| e.get())
            .collect::<Vec<_>>()
    };
    let newer = Card::sd_jwt(&format!(
        r#"{{"{}": {}, "{}": {}}}"#,
        kinds[1],
        a7_meta(false),
        kinds[0],
        a7_meta(true)
    ));
    let older = Card::sd_jwt(&format!(r#"{{"{}": {}}}"#, kinds[1], a7_meta(false)));
    assert_eq!((rebound(&newer), rebound(&older)), (vec![0], vec![1]));
}
