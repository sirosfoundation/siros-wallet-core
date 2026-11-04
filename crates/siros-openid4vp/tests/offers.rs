//! Credential Manager's sets for the wallet's choices, and the choices inside a candidate, as the
//! DCQL examples, PaSO Core §7.4.1 and zkp_req §2.1 state them.

mod common;

use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::matching::{
    Accepted, Consent, Match, Offered, answer_slots, offer, option_items, option_of,
};
use siros_openid4vp::plugins::OptionIndex;
use siros_openid4vp::request::{Item, ItemSet, Request};
use siros_openid4vp::rows::{Amounts, Choice, Env};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::Binds;

use common::{Held, PASO_A5, env, parameters, registry, request_of, unsigned, vector};

/// The sets a wallet configured with the choice offers, as (query, credential, option) or
/// "none".
fn sets(text: &str, held: &[Held], choice: Choice) -> Vec<Vec<Vec<String>>> {
    let received = unsigned(text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let env = Env::new(
        [LocaleTag::parse("en").expect("tag")],
        Vec::new(),
        Amounts::Formatted,
        choice,
    )
    .expect("env");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    offer(&matched, &consent, env.choice())
        .iter()
        .map(|set| {
            set.iter()
                .map(|slot| {
                    slot.iter()
                        .map(|offered| match offered {
                            Offered::Nothing => "none".to_owned(),
                            Offered::Pick(p) => format!(
                                "{}/{}/{}",
                                request.query(p.query).expect("query").id,
                                matched
                                    .candidate(p.query, p.candidate)
                                    .expect("candidate")
                                    .credential
                                    .id,
                                p.option.0
                            ),
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn texts(sets: &[&[&[&str]]]) -> Vec<Vec<Vec<String>>> {
    sets.iter()
        .map(|set| {
            set.iter()
                .map(|slot| slot.iter().map(|e| (*e).to_owned()).collect())
                .collect()
        })
        .collect()
}

#[test]
fn credential_manager_sets_follow_the_requests_order() {
    let a5 = parameters(&PASO_A5.replace("dc+sd-jwt", "test"), "");
    let held = [
        Held::answering("card", &["sca_card"], &[]),
        Held::answering("account", &["sca_account"], &[]),
        Held::answering("pid", &["pid"], &[]),
    ];
    assert_eq!(
        sets(&a5, &held, Choice::First),
        texts(&[&[
            &["sca_card/card/0", "sca_account/account/0"],
            &["pid/pid/0", "none"]
        ]])
    );
    // Letting the user choose: the request's alternatives, in its order.
    assert_eq!(
        sets(&a5, &held, Choice::LetChoose),
        texts(&[
            &[&["sca_card/card/0"], &["pid/pid/0"]],
            &[&["sca_card/card/0"], &["none"]],
            &[&["sca_account/account/0"], &["pid/pid/0"]],
            &[&["sca_account/account/0"], &["none"]],
        ])
    );
    // credentials_alternatives: the coupled option is its own set with two slots.
    let alternatives = parameters(
        &vector("credentials_alternatives").replace("dc+sd-jwt", "test"),
        "",
    );
    let ids = [
        "pid",
        "other_pid",
        "pid_reduced_cred_1",
        "pid_reduced_cred_2",
        "nice_to_have",
    ];
    let held: Vec<Held> = ids
        .iter()
        .map(|id| Held::answering(id, &[id], &[]))
        .collect();
    assert_eq!(
        sets(&alternatives, &held, Choice::First),
        texts(&[
            &[
                &["pid/pid/0", "other_pid/other_pid/0"],
                &["nice_to_have/nice_to_have/0", "none"]
            ],
            &[
                &["pid_reduced_cred_1/pid_reduced_cred_1/0"],
                &["pid_reduced_cred_2/pid_reduced_cred_2/0"],
                &["nice_to_have/nice_to_have/0", "none"]
            ],
        ])
    );
    // The alternatives [c, b], [a, d], [c, d], [a, b] factor into the slots {c, a} and {b, d}; the
    // wallet holds no b. Each slot in the request's order, its default the first alternative's
    // selection the wallet holds, else the next (PaSO Core §7.4.1; OpenID4VP §6.4.2).
    let coupled = parameters(
        r#"{"credentials": [{"id": "a", "format": "test"}, {"id": "b", "format": "test"}, {"id": "c", "format": "test"}, {"id": "d", "format": "test"}],
            "credential_sets": [{"options": [["c", "b"], ["a", "d"], ["c", "d"], ["a", "b"]]}]}"#,
        "",
    );
    let held: Vec<Held> = ["a", "c", "d"]
        .iter()
        .map(|id| Held::answering(id, &[id], &[]))
        .collect();
    assert_eq!(
        sets(&coupled, &held, Choice::First),
        texts(&[&[&["c/c/0", "a/a/0"], &["d/d/0"]]])
    );
    // multiple: every non-empty subset once, by its first member; the first set holds every candidate.
    let multiple = parameters(
        r#"{"credentials": [{"id": "m", "format": "test", "multiple": true}]}"#,
        "",
    );
    let held: Vec<Held> = ["x0", "x1", "x2"]
        .iter()
        .map(|id| Held::answering(id, &["m"], &[]))
        .collect();
    assert_eq!(
        sets(&multiple, &held, Choice::First),
        texts(&[
            &[&["m/x0/0"], &["m/x1/0", "none"], &["m/x2/0", "none"]],
            &[&["m/x1/0"], &["m/x2/0", "none"]],
            &[&["m/x2/0"]]
        ])
    );
}

fn items(numbers: &[usize]) -> ItemSet {
    ItemSet::of(numbers.iter().map(|n| Item::new(*n).expect("item")))
}

/// A candidate's choices as the wallet lists them: each choice's items, then each option's.
fn listed(slots: Vec<(ItemSet, Vec<ItemSet>)>) -> Vec<(Vec<usize>, Vec<Vec<usize>>)> {
    let numbers = |set: ItemSet| set.iter().map(Item::get).collect();
    slots
        .into_iter()
        .map(|(block, options)| (numbers(block), options.into_iter().map(numbers).collect()))
        .collect()
}

#[test]
fn a_candidates_options_factor_like_the_credential_sets() {
    let env = env("en");
    let registry = registry(Binds::First);
    let run = |options: &str, held: &[Held], check: &dyn Fn(&Request<'_>, &Match<'_>)| {
        let text = parameters(
            &format!(
                r#"{{"credentials": [{{"id": "q", "format": "test", "options": {options}}}]}}"#
            ),
            "",
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let matched = Match::run(&accepted, &wallet, &env).expect("match");
        check(&request, &matched);
    };
    let mut stale = Held::answering("stale", &["q"], &[]);
    stale.view = r#"{"answers": ["q"], "answerable": {"q": [1]}, "alg": "A"}"#.to_owned();
    // zkp_req §2.1 [[0, 1], [0]]: item 0 always, item 1 optional; choosing 1 answers option 0.
    run(
        "[[0, 1], [0]]",
        &[Held::answering("both", &["q"], &[]), stale],
        &|request, matched| {
            let q = request.indexed_queries().next().expect("q").0;
            let options = matched.accepted().options(q);
            let both = &matched.candidates(q)[0];
            assert_eq!(
                listed(answer_slots(options, both)),
                [(vec![0], vec![vec![0]]), (vec![1], vec![vec![1], vec![]])]
            );
            assert_eq!(
                (
                    option_of(options, both, items(&[0, 1])),
                    option_of(options, both, items(&[0]))
                ),
                (Some(OptionIndex(0)), Some(OptionIndex(1)))
            );
            assert_eq!(
                option_items(options, &both.options, OptionIndex(0)),
                (
                    vec![Item::new(0).expect("item")],
                    vec![Item::new(1).expect("item")]
                ),
                "item 0 is general, item 1 chosen"
            );
        },
    );
    // The choices follow the order the Verifier lists the items in.
    run(
        "[[1, 0], [1]]",
        &[Held::answering("both", &["q"], &[])],
        &|request, matched| {
            let q = request.indexed_queries().next().expect("q").0;
            let both = &matched.candidates(q)[0];
            assert_eq!(
                listed(answer_slots(matched.accepted().options(q), both)),
                [(vec![1], vec![vec![1]]), (vec![0], vec![vec![0], vec![]])]
            );
        },
    );
    // Item 1 in or out gives two entries of the credential in one slot.
    let member = parameters(
        r#"{"credentials": [{"id": "member", "format": "test", "options": [[0, 1], [0]]}]}"#,
        "",
    );
    let mut stale = Held::answering("stale", &["member"], &[]);
    stale.view = r#"{"answers": ["member"], "answerable": {"member": [1]}, "alg": "A"}"#.to_owned();
    assert_eq!(
        sets(
            &member,
            &[Held::answering("both", &["member"], &[]), stale],
            Choice::First
        ),
        texts(&[&[&["member/both/0", "member/both/1", "member/stale/1"]]])
    );
    // A system missing one combination couples the choices; a complete
    // one leaves two independent choices.
    let mut partial = Held::answering("partial", &["q"], &[]);
    partial.view = r#"{"answers": ["q"], "answerable": {"q": [0, 1, 2]}, "alg": "A"}"#.to_owned();
    run(
        "[[0, 2], [0, 3], [1, 2], [1, 3]]",
        &[partial, Held::answering("all", &["q"], &[])],
        &|request, matched| {
            let q = request.indexed_queries().next().expect("q").0;
            let options = matched.accepted().options(q);
            let [partial, complete] = matched.candidates(q) else {
                panic!("two candidates")
            };
            assert_eq!(
                listed(answer_slots(options, partial)),
                [(vec![0, 1, 2, 3], vec![vec![0, 2], vec![0, 3], vec![1, 2]])]
            );
            assert_eq!(
                listed(answer_slots(options, complete)),
                [
                    (vec![0, 1], vec![vec![0], vec![1]]),
                    (vec![2, 3], vec![vec![2], vec![3]])
                ]
            );
        },
    );
}

#[test]
fn a_record_id_reads_back_as_the_json_of_its_fields() {
    use siros_openid4vp::ids::CredentialId;
    use siros_openid4vp::matching::{Record, ReturnedRecord};
    use siros_openid4vp::plugins::Attested;
    let text = parameters(
        &common::test_queries(&["q"]),
        &format!(
            r#""transaction_data":["{0}","{0}","{0}"]"#,
            common::entry(r#"{"type": "t1", "credential_ids": ["q"]}"#)
        ),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let entries: Vec<_> = request
        .indexed_entries()
        .map(|(index, _)| index)
        .skip(1)
        .collect();
    let credential = CredentialId::parse("c \"1\" \\ \u{1} é").expect("id");
    let attested = Attested::new(vec![
        ("display_locale".to_owned(), "de\n".to_owned()),
        ("x".to_owned(), "é".to_owned()),
    ])
    .expect("attested");
    let query = &request.queries()[0].id;
    let record = Record::new(
        query,
        &credential,
        OptionIndex(2),
        &entries,
        Some(&attested),
        request.digest(),
    );
    assert!(ReturnedRecord::parse(record.id().as_str()).is_ok());
    let read: serde_json::Value = serde_json::from_str(record.id().as_str()).expect("json");
    assert_eq!(
        read,
        serde_json::json!(["q", "c \"1\" \\ \u{1} é", 2, [1, 2], {"display_locale": "de\n", "x": "é"}, request.digest().as_str()])
    );
    // An id is a record in that shape only: each of these breaks it in one field.
    for malformed in [
        r#"[1, "c", 0, [], {}, "d"]"#,
        r#"["q", 1, 0, [], {}, "d"]"#,
        r#"["q", "c", -1, [], {}, "d"]"#,
        r#"["q", "c", 0, [1.5], {}, "d"]"#,
        r#"["q", "c", 0, [], {"a": 1}, "d"]"#,
        r#"["q", "c", 0, [], {}, 1]"#,
        r#"["q", "c", 0, [], {}]"#,
    ] {
        assert!(ReturnedRecord::parse(malformed).is_err(), "{malformed}");
    }
    assert!(ReturnedRecord::parse(r#"["q", "c", 0, [], {}, "d"]"#).is_ok());
}

#[test]
fn a_profile_overlay_draws_over_the_formats_card() {
    use siros_openid4vp::boxes::{Card, EntryBox, Overlay, PaymentHeader};
    use siros_openid4vp::rows::{Icon, Label, Row};
    let row = |label: &str| Row::full_text(Label::text(label));
    let card = || Card {
        icon: Icon::DEFAULT,
        title: "Card".to_owned(),
        subtitle: Some("Issuer".to_owned()),
        rows: vec![row("claim")],
    };
    // No transaction: the card itself.
    let EntryBox::Standard(plain) = EntryBox::compose(card(), None) else {
        panic!("a Standard entry")
    };
    assert_eq!(
        (
            plain.title.as_str(),
            plain.subtitle.as_deref(),
            plain.warning.as_deref(),
            plain.rows.len()
        ),
        ("Card", Some("Issuer"), None, 1)
    );
    // A Standard presentation (PaSO Generic and Mandate, QES, the test profile's t1): the card stays
    // the identity, the transaction's rows come first, the hint is the warning.
    let standard = Overlay {
        rows: vec![row("Reference")],
        payment: None,
        hint: Some("Check the payee".to_owned()),
    };
    let EntryBox::Standard(shown) = EntryBox::compose(card(), Some(&standard)) else {
        panic!("a Standard entry")
    };
    assert_eq!(
        (
            shown.title.as_str(),
            shown.subtitle.as_deref(),
            shown.warning.as_deref(),
            &shown.icon
        ),
        (
            "Card",
            Some("Issuer"),
            Some("Check the payee"),
            &Icon::DEFAULT
        )
    );
    assert_eq!(shown.rows, [row("Reference"), row("claim")]);
    // A payment (PaSO Payment, the test profile's t2): merchant and amount from the header, whose
    // rows the box leaves out; the card is the payment method; the hint the additional info.
    let header = PaymentHeader {
        merchant: "Shop".to_owned(),
        amount: "€1.00".to_owned(),
        rows: vec![row("Payee"), row("Amount")],
    };
    let payment = Overlay {
        rows: vec![row("Payee logo")],
        payment: Some(header),
        hint: None,
    };
    let EntryBox::Payment(paid) = EntryBox::compose(card(), Some(&payment)) else {
        panic!("a Payment entry")
    };
    assert_eq!(
        (
            paid.merchant.as_str(),
            paid.amount.as_str(),
            paid.method_name.as_str(),
            paid.method_subtitle.as_deref(),
            paid.additional_info.as_deref()
        ),
        ("Shop", "€1.00", "Card", Some("Issuer"), None)
    );
    assert_eq!(paid.rows, [row("Payee logo"), row("claim")]);
    // Either kind: the overlay's rows then the card's, and the card's icon.
    for (overlay, first) in [(&standard, "Reference"), (&payment, "Payee logo")] {
        let composed = EntryBox::compose(card(), Some(overlay));
        assert_eq!(
            (composed.rows(), composed.icon()),
            (&[row(first), row("claim")][..], &Icon::DEFAULT)
        );
    }
}

#[test]
fn a_transaction_binds_its_entry_through_the_record_into_the_response() {
    use siros_openid4vp::matching::{Views, display};
    use siros_openid4vp::resolve::Prepared;
    use siros_testkit::{Published, TestHost};
    let text = parameters(
        &common::test_queries(&["q"]),
        &format!(
            r#""transaction_data":["{}"]"#,
            common::entry(r#"{"type": "t1", "credential_ids": ["q"]}"#)
        ),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let held = Held::answering("c", &["q"], &["t1"]);
    let wallet = Wallet::new(vec![held.credential()]).expect("wallet");
    let env = env("en");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    let views = Views::of(&matched, &env).expect("views");
    let sets = offer(&matched, &consent, Choice::First);
    let shown = display(&sets, &views, &[]).expect("display");
    let id = shown.sets()[0][0][0].id().to_owned();
    let selection = shown.select(0, &[&id]).expect("selection");
    // The record names the entry and attests what the profile attests; the header is the
    // transaction's.
    assert!(id.contains(r#",[0],{"entries":"0"},"#), "{id}");
    assert_eq!(selection.header(&env).title.text, "entries 0");
    let response = Prepared::prepare(&request, &[&id], &wallet, &registry, &env)
        .and_then(|prepared| {
            prepared.respond(
                |resource| Published::default().answer(resource),
                &TestHost::default(),
            )
        })
        .expect("response");
    // dc_api answers with the response parameters as the DigitalCredential's data (Annex A).
    let data: serde_json::Value = serde_json::from_str(&response.data.json()).expect("data");
    assert_eq!(data.as_object().map(serde_json::Map::len), Some(1));
    assert_eq!(data["vp_token"]["q"][0]["proof"]["binding"], "0");
}

#[test]
fn multiple_offers_one_transaction_bearing_credential_per_selection() {
    // A query transaction data names binds every candidate: each fill holds one of them, so the
    // consent offers them as one slot of alternatives.
    let text = parameters(
        r#"{"credentials": [{"id": "m", "format": "test", "multiple": true}]}"#,
        &format!(
            r#""transaction_data":["{}"]"#,
            common::entry(r#"{"type": "t1", "credential_ids": ["m"]}"#)
        ),
    );
    let held: Vec<Held> = ["b1", "b2"]
        .iter()
        .map(|id| Held::answering(id, &["m"], &["t1"]))
        .collect();
    assert_eq!(
        sets(&text, &held, Choice::First),
        texts(&[&[&["m/b1/0", "m/b2/0"]]])
    );
    assert_eq!(
        sets(&text, &held, Choice::LetChoose),
        texts(&[&[&["m/b1/0"]], &[&["m/b2/0"]]])
    );
}

#[test]
fn a_selection_is_read_back_only_from_its_sets_entries() {
    use siros_openid4vp::matching::{CandidateIndex, Pick, SelectionError, Views, display};
    let text = parameters(&common::test_queries(&["q", "r"]), "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Binds::First);
    let held = [
        Held::answering("c", &["q"], &[]),
        Held::answering("d", &["r"], &[]),
    ];
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let env = env("en");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    let views = Views::of(&matched, &env).expect("views");
    let sets = offer(&matched, &consent, Choice::First);
    let shown = display(&sets, &views, &[]).expect("display");
    let ids: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
    assert_eq!(shown.select(0, &ids).expect("selection").ids(), ids);
    assert_eq!(
        shown.select(1, &ids).err(),
        Some(SelectionError::NoSet { set: 1, sets: 1 })
    );
    assert_eq!(
        shown.select(0, &ids[..1]).err(),
        Some(SelectionError::Length {
            set: 0,
            ids: 1,
            slots: 2
        })
    );
    let swapped = [ids[1], ids[0]];
    assert!(matches!(
        shown.select(0, &swapped),
        Err(SelectionError::NotAChoice {
            set: 0,
            slot: 0,
            ..
        })
    ));
    // One confirmation carries one transaction: a display offering two transaction-bearing
    // entries in one set, which no offer makes, refuses choosing both.
    let text = parameters(
        r#"{"credentials": [{"id": "m", "format": "test", "multiple": true}]}"#,
        &format!(
            r#""transaction_data":["{}"]"#,
            common::entry(r#"{"type": "t1", "credential_ids": ["m"]}"#)
        ),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let held = [
        Held::answering("b1", &["m"], &["t1"]),
        Held::answering("b2", &["m"], &["t1"]),
    ];
    let wallet = Wallet::new(held.iter().map(Held::credential).collect()).expect("wallet");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
    let views = Views::of(&matched, &env).expect("views");
    let m = request.indexed_queries().next().expect("m").0;
    let pick = |k: usize| {
        Offered::Pick(Pick {
            query: m,
            candidate: CandidateIndex(k),
            option: OptionIndex(0),
        })
    };
    let both = [vec![vec![pick(0)], vec![pick(1)]]];
    let shown = display(&both, &views, &[]).expect("display");
    let ids: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
    assert_eq!(
        shown.select(0, &ids).err(),
        Some(SelectionError::TwoTransactions)
    );
}
