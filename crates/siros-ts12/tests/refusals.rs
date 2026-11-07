//! Section 8.2's siros-ts12 fixtures, one per rule: the request rules T1 to T6, the values a typed
//! payload refuses, what leaves a type unsupported for a credential, and the constructors.

mod common;

use common::{
    BASE, CS12_IBAN, TESTBED_IBAN, bound, bound_entry, bound_of, bound_with, credential, document,
    env, parameters, profile, with_signed, with_unsigned,
};
use siros_explain::{Entry, Keyed};
use siros_openid4vp::hash::HashesAlgRule;
use siros_openid4vp::ids::{QueryId, TransactionType};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Bound, Carriage, Member, NoCandidate, Profile};
use siros_openid4vp::refusal::{ErrorCode, Refusal};
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::rows::HttpsUrl;
use siros_openid4vp::wallet_metadata::Placement;
use siros_paso::metadata::UiKey;
use siros_paso::outcome::Outcome;
use siros_ts12::{
    ComposeError, DataUrl, DateForm, Expected, FetchedDocument, FieldPath, Integrity,
    PayloadRefusal, Ts12Document, Ts12Excluded, Ts12Payload, Ts12Rule, Ts12Type, Ts12Unsupported,
    TwinnedMember,
};

const PAYMENT: &str = "urn:eudi:sca:payment:1";

fn entry(kind: &str, ids: &str, alg: &str, payload: &str) -> String {
    format!(r#"{{"type": "{kind}", "credential_ids": [{ids}]{alg}{payload}}}"#)
}

const ALG: &str = r#", "transaction_data_hashes_alg": ["sha-256"]"#;
const GOOD: &str = r#", "payload": {"transaction_id": "t", "payee": {"name": "P", "id": "i"}, "currency": "EUR", "amount": 1}"#;

fn refused(request: &Request<'_>) -> Vec<Refusal> {
    let entries: Vec<EntryIndex> = request.indexed_entries().map(|(index, _)| index).collect();
    profile().refusals(request, &entries)
}

fn holds(refusals: &[Refusal], code: ErrorCode, rule: &Ts12Rule) -> bool {
    refusals.iter().any(|refusal| {
        let read: &dyn std::error::Error = refusal.rule();
        refusal.code() == code && read.downcast_ref::<Ts12Rule>() == Some(rule)
    })
}

#[test]
fn the_request_rules_each_refuse_with_their_code() {
    use ErrorCode as C;
    let good = entry(PAYMENT, r#""sca""#, ALG, GOOD);
    with_signed(&parameters(&[&good], ""), |request| {
        assert!(refused(request).is_empty(), "{:?}", refused(request));
    });
    let no_alg = entry(PAYMENT, r#""sca""#, "", GOOD);
    let no_payload = entry(PAYMENT, r#""sca""#, ALG, "");
    let two_ids = entry(PAYMENT, r#""sca","sca""#, ALG, GOOD);
    let other = entry("urn:eudi:sca:emandate:1", r#""sca""#, ALG, GOOD);
    let alg_string = entry(
        PAYMENT,
        r#""sca""#,
        r#", "transaction_data_hashes_alg": "sha-256""#,
        GOOD,
    );
    type Rule = fn(EntryIndex) -> Ts12Rule;
    let table: [(&[&str], usize, Rule); 6] = [
        (&[&no_alg], 0, |entry| Ts12Rule::NoHashes { entry }),
        (&[&no_payload], 0, |entry| Ts12Rule::NoPayload { entry }),
        (&[&good, &good], 1, |entry| Ts12Rule::Second { entry }),
        (&[&two_ids], 0, |entry| Ts12Rule::CredentialIds { entry }),
        (&[&other], 0, |entry| Ts12Rule::Type {
            entry,
            kind: TransactionType::parse("urn:eudi:sca:emandate:1").expect("a type"),
        }),
        (&[&alg_string], 0, |entry| Ts12Rule::Hashes {
            entry,
            rule: HashesAlgRule::NotArray,
        }),
    ];
    for (entries, at, rule) in table {
        with_signed(&parameters(entries, ""), |request| {
            let (index, _) = request.indexed_entries().nth(at).expect("the entry");
            let rule = rule(index);
            let refusals = refused(request);
            assert!(
                holds(&refusals, C::INVALID_TRANSACTION_DATA, &rule),
                "{rule}: {refusals:?}"
            );
        });
    }
    with_unsigned(&parameters(&[&good], ""), |request| {
        assert!(holds(
            &refused(request),
            C::INVALID_REQUEST,
            &Ts12Rule::Unsigned
        ));
    });
    with_signed(&parameters(&[&good], r#","multiple":true"#), |request| {
        let rule = Ts12Rule::Multiple {
            query: QueryId::parse("sca").expect("an id"),
        };
        assert!(holds(&refused(request), C::INVALID_REQUEST, &rule));
    });
}

fn parsed(kind: Ts12Type, payload: &str) -> Result<Ts12Payload, PayloadRefusal> {
    Ts12Payload::parse(kind, &Node::parse(payload).expect("JSON"))
}

/// A payment payload with `amount`'s text and `more` members.
fn payment(amount: &str, more: &str) -> String {
    format!(
        r#"{{"transaction_id": "t", "payee": {{"name": "P", "id": "i"{payee}}}, "currency": "EUR", "amount": {amount}{rest}}}"#,
        payee = more.strip_prefix('@').map_or("", |payee| payee),
        rest = if more.starts_with('@') { "" } else { more },
    )
}

#[test]
fn the_values_each_refuse_by_their_rule() {
    use PayloadRefusal as R;
    let path = |path: &str| FieldPath::parse(path).expect("a field of TS12's tables");
    let table: [(String, R); 11] = [
        (
            r#"{"transaction_id": "t", "payee": {"name": "P", "id": "i"}, "amount": 1}"#.to_owned(),
            R::Required {
                path: path("currency"),
            },
        ),
        (
            r#"{"transaction_id": "t", "payee": {"name": "P", "id": "i"}, "currency": "eur", "amount": 1}"#.to_owned(),
            R::Currency {
                value: "eur".to_owned(),
            },
        ),
        (
            payment("1", r#","recurrence":{"frequency":"DAILY"}"#),
            R::Frequency {
                value: "DAILY".to_owned(),
            },
        ),
        (
            payment("10.125", ""),
            R::Digits {
                path: path("amount"),
            },
        ),
        (
            payment("-1", ""),
            R::Negative {
                path: path("amount"),
            },
        ),
        (
            payment("1", r#","extra":1"#),
            R::Member {
                within: path("payload"),
                name: "extra".to_owned(),
            },
        ),
        (
            payment("1", r#"@,"nested":1"#),
            R::Member {
                within: path("payee"),
                name: "nested".to_owned(),
            },
        ),
        (
            payment(
                "1",
                r#","execution_date":"2026-11-01","recurrence":{"frequency":"MNTH"}"#,
            ),
            R::ExecutionAndRecurrence,
        ),
        (
            payment("1", r#","execution_date":"2026-11-01T10:00:00Z""#),
            R::Date {
                path: path("execution_date"),
                form: DateForm::Calendar,
            },
        ),
        (
            payment("1", r#"@,"logo":"https://example.com/logo.png""#),
            R::LogoIntegrity,
        ),
        (
            payment("1", r#","recurrence":{"frequency":"MNTH","number":1.5}"#),
            R::Kind {
                path: path("recurrence.number"),
                kind: Expected::Integer,
            },
        ),
    ];
    for (payload, rule) in table {
        assert_eq!(parsed(Ts12Type::Payment, &payload), Err(rule), "{payload}");
    }
}

/// TS12's schemas' `maxLength`s, counted in characters (JSON Schema §6.3.1), and `transaction_id`'s
/// `minLength`.
#[test]
fn the_schemas_lengths_bound_their_strings() {
    let login = |field: &str, text: &str| {
        let member = |name: &str, default: &str| {
            format!(
                r#""{name}": "{}""#,
                if field == name { text } else { default }
            )
        };
        format!(
            "{{{}, {}, {}}}",
            member("transaction_id", "t"),
            member("service", "s"),
            member("action", "a")
        )
    };
    let pay = |_: &str, text: &str| {
        format!(
            r#"{{"transaction_id": "{text}", "payee": {{"name": "P", "id": "i"}}, "currency": "EUR", "amount": 1}}"#
        )
    };
    type Written<'a> = &'a dyn Fn(&str, &str) -> String;
    let table: [(Ts12Type, Written<'_>, &str, usize); 4] = [
        (Ts12Type::Payment, &pay, "transaction_id", 36),
        (Ts12Type::LoginRisk, &login, "transaction_id", 36),
        (Ts12Type::LoginRisk, &login, "service", 100),
        (Ts12Type::LoginRisk, &login, "action", 140),
    ];
    for (kind, written, field, max) in table {
        let at = |length: usize| parsed(kind, &written(field, &"\u{e9}".repeat(length)));
        assert!(at(max).is_ok(), "{field} at {max}");
        let refused = at(max + 1);
        assert!(
            matches!(
                &refused,
                Err(PayloadRefusal::Length { path, max: stated })
                    if path.as_str() == field && stated.get() == max
            ),
            "{field} past {max}: {refused:?}"
        );
    }
    assert!(matches!(
        parsed(Ts12Type::Payment, &pay("transaction_id", "")),
        Err(PayloadRefusal::Length { .. })
    ));
}

/// TS12 §4.3.1's amounts as the Values table reads them: the exact decimal value as written.
#[test]
fn an_amount_takes_its_exact_value_with_its_currencys_digits() {
    for (written, code, shown) in [
        ("42.5", "EUR", "42.50 EUR"),
        ("129.95", "EUR", "129.95 EUR"),
        ("1.2e1", "EUR", "12.00 EUR"),
        ("1250e-2", "EUR", "12.50 EUR"),
        ("0", "EUR", "0.00 EUR"),
        ("0.10", "EUR", "0.10 EUR"),
        ("10.0", "JPY", "10 JPY"),
        ("1.234", "KWD", "1.234 KWD"),
    ] {
        let payload = format!(
            r#"{{"transaction_id": "t", "payee": {{"name": "P", "id": "i"}}, "currency": "{code}", "amount": {written}}}"#
        );
        let read = parsed(Ts12Type::Payment, &payload).expect(written);
        let paso = read.paso_payload();
        assert_eq!(paso.get("amount").and_then(Node::as_str), Some(shown));
    }
    assert!(matches!(
        parsed(Ts12Type::Payment, &payment("1e400", "")),
        Err(PayloadRefusal::Digits { .. })
    ));
}

/// The rule that excludes the credential.
fn excluded(result: Result<Bound, NoCandidate>) -> Ts12Excluded {
    match result {
        Err(NoCandidate::Excluded(excluded)) => {
            let rule: &dyn std::error::Error = excluded.rule();
            rule.downcast_ref::<Ts12Excluded>()
                .expect("a TS12 exclusion")
                .clone()
        }
        other => panic!("an exclusion: {other:?}"),
    }
}

fn unsupported(result: Result<Bound, NoCandidate>) -> Ts12Unsupported {
    match excluded(result) {
        Ts12Excluded::Unsupported(unsupported) => unsupported,
        other => panic!("unsupported: {other:?}"),
    }
}

#[test]
fn the_metadata_each_leaves_the_type_unsupported() {
    let good = entry(PAYMENT, r#""sca""#, ALG, GOOD);
    let locales = env(&["en"]);
    let bind = |own: &str| {
        with_signed(&parameters(&[&good], ""), |request| {
            bound(request, &document(own), &locales)
        })
    };
    let replaced = |from: &str, to: &str| {
        assert!(TESTBED_IBAN.contains(from), "{from}");
        TESTBED_IBAN.replace(from, to)
    };
    assert!(bind(CS12_IBAN).is_ok(), "the base offers it");
    // No `ts12` document.
    let none = with_signed(&parameters(&[&good], ""), |request| {
        let credential = siros_openid4vp::wallet::Credential::new(
            siros_openid4vp::ids::CredentialId::parse("card").expect("id"),
            siros_openid4vp::ids::FormatId::parse("dc+sd-jwt").expect("format"),
            b"{}",
            Vec::new(),
            siros_openid4vp::wallet::Facts::new(siros_openid4vp::wallet::Holder::Bound, Vec::new())
                .expect("facts"),
        )
        .expect("credential");
        bound_with(request, &credential, &locales, &[BASE], Carriage::Carried)
    });
    assert_eq!(unsupported(none), Ts12Unsupported::NoDocument);
    let claim = |claim: &str| replaced(r#""claims": ["#, &format!(r#""claims": [{claim},"#));
    let path = |field: &str| FieldPath::parse(field).expect("a field of TS12's tables");
    let labels = |field: &str| Ts12Unsupported::Labels { field: path(field) };
    let table: [(String, Ts12Unsupported); 12] = [
        (
            replaced(r#""category": "urn:eu:europa:ec:eudi:sua:sca","#, ""),
            Ts12Unsupported::Category,
        ),
        (
            replaced(
                r#""urn:eudi:sca:payment:1": {"#,
                r#""urn:eudi:sca:other:1": {"#,
            ),
            Ts12Unsupported::NotListed {
                kind: TransactionType::parse(PAYMENT).expect("a type"),
            },
        ),
        (
            replaced(
                r#""schema": "urn:eudi:sca:payment:1""#,
                r#""schema_uri": "https://example.com/schema.json""#,
            ),
            Ts12Unsupported::Schema {
                schema: "https://example.com/schema.json".to_owned(),
            },
        ),
        (
            replaced(r#""schema": "urn:eudi:sca:payment:1","#, ""),
            Ts12Unsupported::NoSchema,
        ),
        (
            replaced("affirmative_action_label", "other_label"),
            Ts12Unsupported::Affirmative,
        ),
        (
            replaced(
                "\"payload\",\n            \"amount\"",
                "\"payload\",\n            \"date_time\"",
            ),
            labels("amount"),
        ),
        // TS12 §3.3.1: level 1, or no level (3), without the parameter name's labels.
        (
            claim(r#"{"path": ["payload", "date_time"], "visualisation": 1}"#),
            labels("date_time"),
        ),
        (
            claim(r#"{"path": ["payload", "payee", "id"]}"#),
            labels("payee.id"),
        ),
        (
            claim(r#"{"path": ["payload", "unlisted"], "display": []}"#),
            Ts12Unsupported::ClaimPath {
                path: r#"["payload","unlisted"]"#.to_owned(),
            },
        ),
        // TS12 §3.3.1 lists levels 1 to 4.
        (
            claim(r#"{"path": ["payload", "date_time"], "visualisation": 5}"#),
            Ts12Unsupported::Level {
                field: path("date_time"),
            },
        ),
        // TS12 §3.3.2: a `display` entry holds `lang` and `label`; §3.3.3: a UI label `lang` and
        // `value`.
        (
            claim(r#"{"path": ["payload", "date_time"], "display": [{"label": "When"}]}"#),
            Ts12Unsupported::ClaimLabels {
                field: path("date_time"),
            },
        ),
        (
            replaced(
                r#""ui_labels": {"#,
                r#""ui_labels": {"security_hint": [{"value": "Check"}],"#,
            ),
            Ts12Unsupported::UiLabels {
                element: UiKey::SecurityHint,
            },
        ),
    ];
    for (own, rule) in table {
        assert_eq!(unsupported(bind(&own)), rule, "{own}");
    }
    let other_type = with_signed(&parameters(&[&good], ""), |request| {
        bound_of(
            request,
            &document(TESTBED_IBAN),
            &locales,
            &["https://example.com/other"],
        )
    });
    assert_eq!(unsupported(other_type), Ts12Unsupported::AttestationType);
    // TS12 §3.3.3: a UI element identifier outside the catalogue is the wallet's to ignore.
    assert!(
        bind(&replaced(
            r#""ui_labels": {"#,
            r#""ui_labels": {"x_extra": "text","#
        ))
        .is_ok()
    );
}

/// TS12 §3.3.1 over CS-12 §7.2's metadata: an optional field the Relying Party sends, which the
/// metadata leaves without a level (3: displayed) or labels, ceases; a labelled one shows, and
/// level 4 hides it.
#[test]
fn a_held_field_without_labels_ceases() {
    let locales = ["en"];
    let bind = |own: &str, more: &str| {
        let payload = format!(
            r#", "payload": {{"transaction_id": "t", "payee": {{"name": "P", "id": "i"{payee}}}, "currency": "EUR", "amount": 1{rest}}}"#,
            payee = more.strip_prefix('@').unwrap_or_default(),
            rest = if more.starts_with('@') { "" } else { more },
        );
        bound_entry(own, &entry(PAYMENT, r#""sca""#, ALG, &payload), &locales)
    };
    for (more, field) in [
        (
            r#","recurrence":{"frequency":"MNTH"}"#,
            "recurrence.frequency",
        ),
        (
            r#","recurrence":{"frequency":"MNTH","mit_options":{"total_amount":1000000}}"#,
            "recurrence.frequency",
        ),
        (r#","amount_estimated":true"#, "amount_estimated"),
        (r#","amount_earmarked":true"#, "amount_earmarked"),
        (r#","sct_inst":true"#, "sct_inst"),
        (r#","execution_date":"2026-12-01""#, "execution_date"),
        (
            r#","pisp":{"legal_name":"L","brand_name":"B","domain_name":"d.example"}"#,
            "pisp.legal_name",
        ),
        (r#"@,"website":"https://payee.example""#, "payee.website"),
    ] {
        assert_eq!(
            unsupported(bind(CS12_IBAN, more)),
            Ts12Unsupported::Labels {
                field: FieldPath::parse(field).expect("a field of TS12's tables")
            },
            "{more}"
        );
    }
    let recurring = r#","recurrence":{"frequency":"MNTH"}"#;
    let with_frequency = |level: u8| {
        CS12_IBAN.replacen(
            r#""claims": ["#,
            &format!(
                r#""claims": [{{"path": ["payload", "recurrence", "frequency"], "visualisation": {level}, "display": [{{"lang": "en", "label": "Frequency"}}]}},"#
            ),
            1,
        )
    };
    let rows = |own: &str| bind(own, recurring).expect("offered").overlay.rows.len();
    assert_eq!(
        rows(&with_frequency(2)),
        bind(CS12_IBAN, "").expect("offered").overlay.rows.len() + 1
    );
    assert_eq!(
        rows(&with_frequency(4)),
        bind(CS12_IBAN, "").expect("offered").overlay.rows.len()
    );
}

/// TS12 §3.3.3's 30, 30, 50 and 250 and Proof Metadata §3.3's 60 for a claim's label, in extended
/// grapheme clusters.
#[test]
fn the_label_limits_bound_each_label() {
    let payment = entry(PAYMENT, r#""sca""#, ALG, GOOD);
    let replaced = |from: &str, to: &str| {
        assert!(TESTBED_IBAN.contains(from), "{from}");
        TESTBED_IBAN.replacen(from, to, 1)
    };
    let added = |name: &str, text: &str| {
        replaced(
            r#""ui_labels": {"#,
            &format!(r#""ui_labels": {{"{name}": [{{"lang": "en-GB", "value": "{text}"}}],"#),
        )
    };
    type Labelled<'a> = &'a dyn Fn(&str) -> String;
    let table: [(Labelled<'_>, usize); 5] = [
        (&|text| replaced("Confirm payment", text), 30),
        (
            &|text| replaced(r#""value": "Cancel""#, &format!(r#""value": "{text}""#)),
            30,
        ),
        (&|text| added("transaction_title", text), 50),
        (&|text| added("security_hint", text), 250),
        (
            &|text| replaced(r#""label": "Payee""#, &format!(r#""label": "{text}""#)),
            60,
        ),
    ];
    for (labelled, max) in table {
        let at =
            |length: usize| bound_entry(&labelled(&"e\u{301}".repeat(length)), &payment, &["en"]);
        assert!(at(max).is_ok(), "{max}: {:?}", at(max).err());
        assert!(
            matches!(
                excluded(at(max + 1)),
                Ts12Excluded::Rendering(Outcome::Unsupported(_))
            ),
            "{:?}",
            at(max + 1).err()
        );
    }
}

/// TS12 §1.2, §3.6: the binding exists as Key Binding JWT claims alone, so a presentation that
/// cannot carry them excludes the credential.
#[test]
fn ts12s_claims_exist_in_a_key_binding_jwt_alone() {
    let claims = [
        "jti",
        "response_mode",
        "amr",
        "transaction_data_hashes",
        "transaction_data_hashes_alg",
    ]
    .map(Member::claim);
    assert_eq!(profile().members(Placement::Claims), Some(&claims[..]));
    assert!(profile().members(Placement::NameSpaces).is_none());
    let good = entry(PAYMENT, r#""sca""#, ALG, GOOD);
    let held = document(TESTBED_IBAN);
    let result = with_signed(&parameters(&[&good], ""), |request| {
        bound_with(
            request,
            &credential(&held),
            &env(&["en"]),
            &[BASE],
            Carriage::Uncarried,
        )
    });
    assert_eq!(excluded(result), Ts12Excluded::Carriage);
}

/// TS12 §4.1: a member or its `_uri` twin, the twin replaced by the document fetched.
#[test]
fn the_composition_replaces_each_uri_member_or_refuses() {
    let url = "https://example.com/labels.json";
    let own = |labels: &str| {
        format!(
            r#"{{"transaction_data_types": {{"{PAYMENT}": {{"schema_uri": "{PAYMENT}", {labels}}}}}}}"#
        )
    };
    let fetched = Keyed::new(vec![Entry::new(
        HttpsUrl::parse(url).expect("a URL"),
        FetchedDocument::parse(
            br#"{"affirmative_action_label": [{"lang": "en", "value": "Pay"}]}"#,
        )
        .expect("JSON"),
    )])
    .expect("one URL");
    let composed = |own: &str| {
        Ts12Document::compose(&Node::parse(own).expect("JSON"), &fetched).map(|composed| {
            let text = std::str::from_utf8(composed.content().as_bytes()).expect("UTF-8");
            let node = Node::parse(text).expect("JSON").into_owned();
            node.get("transaction_data_types")
                .and_then(|types| types.get(PAYMENT))
                .and_then(|entry| entry.get("ui_labels"))
                .and_then(|labels| labels.get("affirmative_action_label"))
                .is_some()
        })
    };
    assert_eq!(
        composed(&own(&format!(r#""ui_labels_uri": "{url}""#))),
        Ok(true)
    );
    assert_eq!(
        composed(&own(&format!(
            r#""ui_labels": {{}}, "ui_labels_uri": "{url}""#
        ))),
        Err(ComposeError::Both {
            member: TwinnedMember::UiLabels
        })
    );
    let elsewhere = "https://example.com/elsewhere.json";
    assert_eq!(
        composed(&own(&format!(r#""claims_uri": "{elsewhere}""#))),
        Err(ComposeError::Unfetched {
            uri: elsewhere.to_owned()
        })
    );
    assert_eq!(composed("{}"), Err(ComposeError::Types));
}

#[test]
fn the_constructors_refuse_outside_their_grammar() {
    assert_eq!(DataUrl::parse("image/png;base64,AAAA".to_owned()), None);
    assert!(DataUrl::parse("data:image/png;base64,AAAA".to_owned()).is_some());
    // W3C SRI: sha256's digest is 32 octets, 44 characters of base64.
    let short = format!("sha256-{}", "A".repeat(40));
    assert_eq!(Integrity::parse(short), None);
    let exact = format!("sha256-{}=", "A".repeat(43));
    assert!(Integrity::parse(exact).is_some());
}
