//! Section 8.2's siros-ts12 fixtures, one per rule: the request rules T1 to T6, the values a typed
//! payload refuses, what leaves a type unsupported for a credential, and the constructors.

mod common;

use common::{
    BASE, CS12_IBAN, TESTBED_IBAN, bound, bound_of, document, env, parameters, profile,
    with_signed, with_unsigned,
};
use siros_explain::{Entry, Keyed};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{NoCandidate, Profile};
use siros_openid4vp::refusal::{ErrorCode, Refusal};
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::rows::HttpsUrl;
use siros_ts12::{
    ComposeError, DataUrl, Integrity, PayloadRefusal, Ts12Document, Ts12Payload, Ts12Rule,
    Ts12Type, Ts12Unsupported,
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
    let table: [(&[&str], &str, Ts12Rule, C); 5] = [
        (
            &[&no_alg],
            "",
            Ts12Rule::NoHashes { entry: 0 },
            C::INVALID_TRANSACTION_DATA,
        ),
        (
            &[&no_payload],
            "",
            Ts12Rule::NoPayload { entry: 0 },
            C::INVALID_TRANSACTION_DATA,
        ),
        (
            &[&good, &good],
            "",
            Ts12Rule::Second { entry: 1 },
            C::INVALID_TRANSACTION_DATA,
        ),
        (
            &[&two_ids],
            "",
            Ts12Rule::CredentialIds { entry: 0 },
            C::INVALID_TRANSACTION_DATA,
        ),
        (
            &[&other],
            "",
            Ts12Rule::Type {
                entry: 0,
                kind: "urn:eudi:sca:emandate:1".to_owned(),
            },
            C::INVALID_TRANSACTION_DATA,
        ),
    ];
    for (entries, extra, rule, code) in table {
        with_signed(&parameters(entries, extra), |request| {
            let refusals = refused(request);
            assert!(holds(&refusals, code, &rule), "{rule}: {refusals:?}");
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
            query: "sca".to_owned(),
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
    let path = |path: &str| path.to_owned();
    let table: [(String, R); 8] = [
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
                path: path("extra"),
            },
        ),
        (
            payment("1", r#"@,"nested":1"#),
            R::Member {
                path: path("payee.nested"),
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
                form: "calendar date",
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
                kind: "integer",
            },
        ),
    ];
    for (payload, rule) in table {
        assert_eq!(parsed(Ts12Type::Payment, &payload), Err(rule), "{payload}");
    }
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
        let paso = read.paso_payload().expect("the payload");
        assert_eq!(paso.get("amount").and_then(Node::as_str), Some(shown));
    }
    assert!(matches!(
        parsed(Ts12Type::Payment, &payment("1e400", "")),
        Err(PayloadRefusal::Digits { .. })
    ));
}

fn unsupported(result: Result<siros_openid4vp::plugins::Bound, NoCandidate>) -> String {
    match result {
        Err(NoCandidate::Excluded(excluded)) => excluded.rule().to_string(),
        other => panic!("an exclusion: {other:?}"),
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
        common::bound_without_document(request, &credential, &locales)
    });
    assert_eq!(unsupported(none), Ts12Unsupported::NoDocument.to_string());
    let table: [(String, Ts12Unsupported); 5] = [
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
                kind: PAYMENT.to_owned(),
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
            replaced("affirmative_action_label", "other_label"),
            Ts12Unsupported::Affirmative,
        ),
        (
            replaced(
                "\"payload\",\n            \"amount\"",
                "\"payload\",\n            \"date_time\"",
            ),
            Ts12Unsupported::Labels {
                field: "amount".to_owned(),
            },
        ),
    ];
    for (own, rule) in table {
        assert_eq!(unsupported(bind(&own)), rule.to_string());
    }
    let other_type = with_signed(&parameters(&[&good], ""), |request| {
        bound_of(
            request,
            &document(TESTBED_IBAN),
            &locales,
            "https://example.com/other",
        )
    });
    assert_eq!(
        unsupported(other_type),
        Ts12Unsupported::AttestationType.to_string()
    );
    assert_ne!(BASE, "https://example.com/other");
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
        br#"{"affirmative_action_label": [{"lang": "en", "value": "Pay"}]}"#.to_vec(),
    )])
    .expect("one URL");
    let composed = |own: &str| {
        Ts12Document::compose(&Node::parse(own).expect("JSON"), &fetched).map(|bytes| {
            let text = String::from_utf8(bytes).expect("UTF-8");
            let node = Node::parse(&text).expect("JSON").into_owned();
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
            member: "ui_labels".to_owned()
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
