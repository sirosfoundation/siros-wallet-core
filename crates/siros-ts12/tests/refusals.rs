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
    ComposeError, DataUrl, DateForm, Expected, FetchedDocument, Integrity, PayloadRefusal,
    Ts12Document, Ts12Excluded, Ts12Payload, Ts12Rule, Ts12Type, Ts12Unsupported, TwinnedMember,
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

/// A refusal rule as a predicate over the refusal.
macro_rules! rule {
    ($($pattern:tt)+) => {
        |refused| matches!(refused, $($pattern)+)
    };
}

#[test]
fn the_values_each_refuse_by_their_rule() {
    use PayloadRefusal as R;
    const SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let number =
        |written: &str| format!(r#","recurrence":{{"frequency":"MNTH","number":{written}}}"#);
    let apr = |written: &str| {
        format!(r#","recurrence":{{"frequency":"MNTH","mit_options":{{"apr":{written}}}}}"#)
    };
    let table: [(String, fn(&R) -> bool); 21] = [
        (
            r#"{"transaction_id": "t", "payee": {"name": "P", "id": "i"}, "amount": 1}"#.to_owned(),
            rule!(R::Required { path } if path.as_str() == "currency"),
        ),
        (
            r#"{"transaction_id": "t", "payee": {"name": "P", "id": "i"}, "currency": "eur", "amount": 1}"#.to_owned(),
            rule!(R::Currency { value } if value == "eur"),
        ),
        (
            payment("1", r#","recurrence":{"frequency":"DAILY"}"#),
            rule!(R::Frequency { value } if value == "DAILY"),
        ),
        (
            payment("10.125", ""),
            rule!(R::Digits { path } if path.as_str() == "amount"),
        ),
        (
            payment("-1", ""),
            rule!(R::Negative { path } if path.as_str() == "amount"),
        ),
        (
            payment("1", r#","extra":1"#),
            rule!(R::Member { within, name } if within.as_str() == "payload" && name == "extra"),
        ),
        (
            payment("1", r#"@,"nested":1"#),
            rule!(R::Member { within, name } if within.as_str() == "payee" && name == "nested"),
        ),
        (
            payment(
                "1",
                r#","execution_date":"2026-11-01","recurrence":{"frequency":"MNTH"}"#,
            ),
            rule!(R::ExecutionAndRecurrence),
        ),
        (
            payment("1", r#","execution_date":"2026-11-01T10:00:00Z""#),
            rule!(R::Date { path, form: DateForm::Calendar } if path.as_str() == "execution_date"),
        ),
        (
            payment("1", r#"@,"logo":"https://example.com/logo.png""#),
            rule!(R::LogoIntegrity),
        ),
        // TS12 §4.3.1's `date_time`: a date alone is no date and time.
        (
            payment("1", r#","date_time":"2026-11-01""#),
            rule!(R::Date { path, form: DateForm::DateTime } if path.as_str() == "date_time"),
        ),
        // View §3 `image`: `payee.logo#integrity` belongs to an https logo.
        (
            payment(
                "1",
                &format!(r#"@,"logo":"data:image/png;base64,AAAA","logo#integrity":"{SRI}""#),
            ),
            rule!(R::Member { within, name } if within.as_str() == "payee" && name == "logo#integrity"),
        ),
        (
            payment("1", &format!(r#"@,"logo#integrity":"{SRI}""#)),
            rule!(R::Member { within, name } if within.as_str() == "payee" && name == "logo#integrity"),
        ),
        // View §3: `url` and `image` take https alone.
        (
            payment("1", r#"@,"website":"http://payee.example""#),
            rule!(R::Kind { path, kind: Expected::HttpsUrl } if path.as_str() == "payee.website"),
        ),
        (
            payment("1", r#"@,"logo":"http://payee.example/logo.png""#),
            rule!(
                R::Kind { path, kind: Expected::DataOrHttpsUrl } if path.as_str() == "payee.logo"
            ),
        ),
        (
            payment("1", r#"@,"logo":"data:image/png""#),
            rule!(R::Kind { path, kind: Expected::DataUrl } if path.as_str() == "payee.logo"),
        ),
        (
            payment("1", &number("1.5")),
            rule!(
                R::Kind { path, kind: Expected::Integer } if path.as_str() == "recurrence.number"
            ),
        ),
        (
            payment("1", &number("-1")),
            rule!(
                R::Kind { path, kind: Expected::Integer } if path.as_str() == "recurrence.number"
            ),
        ),
        // 2^64.
        (
            payment("1", &number("18446744073709551616")),
            rule!(
                R::Kind { path, kind: Expected::Integer } if path.as_str() == "recurrence.number"
            ),
        ),
        (
            payment("1", &apr("-1")),
            rule!(
                R::Kind { path, kind: Expected::Decimal }
                    if path.as_str() == "recurrence.mit_options.apr"
            ),
        ),
        (
            payment("1", &apr("1e400")),
            rule!(
                R::Kind { path, kind: Expected::Decimal }
                    if path.as_str() == "recurrence.mit_options.apr"
            ),
        ),
    ];
    for (payload, holds) in table {
        let refused = parsed(Ts12Type::Payment, &payload).expect_err(&payload);
        assert!(holds(&refused), "{payload}: {refused:?}");
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
    // View §3: an exact decimal holds 38 digits, its currency's minor-unit digits among them.
    for (code, whole) in [("EUR", 36), ("JPY", 38)] {
        let at = |digits: usize| {
            let payload = format!(
                r#"{{"transaction_id": "t", "payee": {{"name": "P", "id": "i"}}, "currency": "{code}", "amount": {}}}"#,
                "1".repeat(digits)
            );
            parsed(Ts12Type::Payment, &payload)
        };
        assert!(at(whole).is_ok(), "{code} at {whole} digits");
        assert!(
            matches!(at(whole + 1), Err(PayloadRefusal::Digits { .. })),
            "{code} past {whole} digits"
        );
    }
    assert!(matches!(
        parsed(Ts12Type::Payment, &payment("1e400", "")),
        Err(PayloadRefusal::Digits { .. })
    ));
}

/// `apr` is a JSON number (RFC 8259 §6) shown as its decimal value, up to View §3's 38 digits.
#[test]
fn an_apr_takes_its_exact_value() {
    let read = |written: &str| {
        let payload = payment(
            "1",
            &format!(r#","recurrence":{{"frequency":"MNTH","mit_options":{{"apr":{written}}}}}"#),
        );
        let paso = parsed(Ts12Type::Payment, &payload)?.paso_payload();
        let shown = paso
            .get("recurrence")
            .and_then(|recurrence| recurrence.get("mit_options"))
            .and_then(|options| options.get("apr"))
            .and_then(Node::as_str)
            .expect("the apr");
        Ok::<_, PayloadRefusal>(shown.to_owned())
    };
    let whole = format!("1{}", "0".repeat(37));
    let fraction = format!("0.{}", "1".repeat(38));
    for (written, shown) in [
        ("6.5", "6.5"),
        ("6.50", "6.5"),
        ("0", "0"),
        ("1e1", "10"),
        ("1.5E1", "15"),
        ("125e-2", "1.25"),
        (&whole, &whole),
        (&fraction, &fraction),
    ] {
        assert_eq!(read(written).as_deref(), Ok(shown), "{written}");
    }
    assert!(read(&format!("{whole}0")).is_err());
    assert!(read(&format!("{fraction}1")).is_err());
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

/// Whether a type is unsupported for this field's labels.
fn labels_of(refused: &Ts12Unsupported, wanted: &str) -> bool {
    matches!(refused, Ts12Unsupported::Labels { field } if field.as_str() == wanted)
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
    type Rule = fn(&Ts12Unsupported) -> bool;
    use Ts12Unsupported as U;
    let table: [(String, Rule); 16] = [
        (
            replaced(r#""category": "urn:eu:europa:ec:eudi:sua:sca","#, ""),
            rule!(U::Category),
        ),
        (
            replaced(
                r#""urn:eudi:sca:payment:1": {"#,
                r#""urn:eudi:sca:other:1": {"#,
            ),
            rule!(U::NotListed { kind } if kind.as_str() == PAYMENT),
        ),
        (
            replaced(
                r#""schema": "urn:eudi:sca:payment:1""#,
                r#""schema_uri": "https://example.com/schema.json""#,
            ),
            rule!(U::Schema { schema } if schema == "https://example.com/schema.json"),
        ),
        (
            replaced(r#""schema": "urn:eudi:sca:payment:1","#, ""),
            rule!(U::NoSchema),
        ),
        // TS12 §4.1 writes `schema` as a string.
        (
            replaced(
                r#""schema": "urn:eudi:sca:payment:1""#,
                r#""schema": {"type": "object"}"#,
            ),
            rule!(U::SchemaForm),
        ),
        (
            replaced("affirmative_action_label", "other_label"),
            rule!(U::Affirmative),
        ),
        // TS12 §3.3.2 writes `claims` as an array, §3.3.3 `ui_labels` as an object.
        (
            replaced(r#""claims": ["#, r#""claims": 5, "x_claims": ["#),
            rule!(U::ClaimsForm),
        ),
        (
            replaced(r#""ui_labels": {"#, r#""ui_labels": 5, "x_ui_labels": {"#),
            rule!(U::CatalogueForm),
        ),
        (
            replaced(
                "\"payload\",\n            \"amount\"",
                "\"payload\",\n            \"date_time\"",
            ),
            |refused| labels_of(refused, "amount"),
        ),
        // TS12 §3.3.1: level 1, or no level (3), without the parameter name's labels.
        (
            claim(r#"{"path": ["payload", "date_time"], "visualisation": 1}"#),
            |refused| labels_of(refused, "date_time"),
        ),
        (
            claim(r#"{"path": ["payload", "payee", "id"]}"#),
            |refused| labels_of(refused, "payee.id"),
        ),
        (claim(r#"{"visualisation": 1}"#), rule!(U::NoClaimPath)),
        (
            claim(r#"{"path": ["payload", "unlisted"], "display": []}"#),
            rule!(U::ClaimPath { path } if path == r#"["payload","unlisted"]"#),
        ),
        // TS12 §3.3.1 lists levels 1 to 4.
        (
            claim(r#"{"path": ["payload", "date_time"], "visualisation": 5}"#),
            rule!(U::Level { field } if field.as_str() == "date_time"),
        ),
        // TS12 §3.3.2: a `display` entry holds `lang` and `label`; §3.3.3: a UI label `lang` and
        // `value`.
        (
            claim(r#"{"path": ["payload", "date_time"], "display": [{"label": "When"}]}"#),
            rule!(U::ClaimLabels { field } if field.as_str() == "date_time"),
        ),
        (
            replaced(
                r#""ui_labels": {"#,
                r#""ui_labels": {"security_hint": [{"value": "Check"}],"#,
            ),
            rule!(U::UiLabels {
                element: UiKey::SecurityHint
            }),
        ),
    ];
    for (own, holds) in table {
        let refused = unsupported(bind(&own));
        assert!(holds(&refused), "{own}: {refused:?}");
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

/// A type's metadata labelling these fields, each without a level.
fn labelled(kind: &str, fields: &[&str]) -> String {
    let claims: Vec<String> = fields
        .iter()
        .map(|field| {
            let steps: Vec<String> = field
                .split('.')
                .map(|step| format!(r#""{step}""#))
                .collect();
            format!(
                r#"{{"path": ["payload", {}], "display": [{{"lang": "en", "label": "{field}"}}]}}"#,
                steps.join(", ")
            )
        })
        .collect();
    format!(
        r#"{{"vct": "{BASE}", "category": "urn:eu:europa:ec:eudi:sua:sca",
           "transaction_data_types": {{"{kind}": {{"schema": "{kind}", "claims": [{}],
           "ui_labels": {{"affirmative_action_label": [{{"lang": "en", "value": "Yes"}}]}}}}}}}}"#,
        claims.join(", ")
    )
}

/// TS12 §3.3.1 and CS-12 §7.3 item 5: a leaf without claim metadata takes level 3, which displays,
/// and a parameter name unavailable ceases. Every field of TS12 §4.3.1 and §4.3.2 falls under it
/// but `transaction_id`, `date_time`, `payee.id` and `currency`, which CS-12 §7.2 and its test bed
/// send without metadata. The field labelled, its row shows.
#[test]
fn a_held_field_without_claim_metadata_ceases() {
    const PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    const LOGIN: &str = "urn:eudi:sca:login_risk_transaction:1";
    let header = ["amount", "payee.name"];
    let frequency = "recurrence.frequency";
    let recurring = |member: &str| format!(r#","recurrence":{{"frequency":"MNTH","{member}}}"#);
    let mit = |member: &str| recurring(&format!(r#"mit_options":{{"{member}}}"#));
    let pisp = r#","pisp":{"legal_name":"L","brand_name":"B","domain_name":"d.example"}"#;
    let logo = format!(r#"@,"logo":"{PNG}""#);
    let table: [(&str, String, &[&str]); 20] = [
        ("payee.logo", logo, &[]),
        (
            "payee.website",
            r#"@,"website":"https://payee.example""#.to_owned(),
            &[],
        ),
        (
            "pisp.legal_name",
            pisp.to_owned(),
            &["pisp.brand_name", "pisp.domain_name"],
        ),
        (
            "pisp.brand_name",
            pisp.to_owned(),
            &["pisp.legal_name", "pisp.domain_name"],
        ),
        (
            "pisp.domain_name",
            pisp.to_owned(),
            &["pisp.legal_name", "pisp.brand_name"],
        ),
        (
            "execution_date",
            r#","execution_date":"2026-12-01""#.to_owned(),
            &[],
        ),
        (
            "amount_estimated",
            r#","amount_estimated":true"#.to_owned(),
            &[],
        ),
        (
            "amount_earmarked",
            r#","amount_earmarked":true"#.to_owned(),
            &[],
        ),
        ("sct_inst", r#","sct_inst":true"#.to_owned(), &[]),
        (
            "recurrence.frequency",
            r#","recurrence":{"frequency":"MNTH"}"#.to_owned(),
            &[],
        ),
        (
            "recurrence.start_date",
            recurring(r#"start_date":"2026-12-01""#),
            &[frequency],
        ),
        (
            "recurrence.end_date",
            recurring(r#"end_date":"2027-12-01""#),
            &[frequency],
        ),
        (
            "recurrence.number",
            recurring(r#"number":12"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.amount_variable",
            mit(r#"amount_variable":true"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.min_amount",
            mit(r#"min_amount":1"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.max_amount",
            mit(r#"max_amount":2"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.total_amount",
            mit(r#"total_amount":3"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.initial_amount",
            mit(r#"initial_amount":4"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.initial_amount_number",
            mit(r#"initial_amount_number":5"#),
            &[frequency],
        ),
        (
            "recurrence.mit_options.apr",
            mit(r#"apr":6.5"#),
            &[frequency],
        ),
    ];
    let bind = |own: &str, kind: &str, payload: &str| {
        let payload = format!(r#", "payload": {payload}"#);
        bound_entry(own, &entry(kind, r#""sca""#, ALG, &payload), &["en"])
    };
    for (field, held, also) in &table {
        let payload = payment("1", held);
        let others = [&header[..], also].concat();
        let refused = unsupported(bind(&labelled(PAYMENT, &others), PAYMENT, &payload));
        assert!(labels_of(&refused, field), "{field}: {refused:?}");
        let all = [&others[..], &[field]].concat();
        let bound = bind(&labelled(PAYMENT, &all), PAYMENT, &payload).expect(field);
        assert_eq!(bound.overlay.rows.len(), also.len() + 1, "{field}");
    }
    // TS12 §4.3.2's optional field; `action` in the rows, as the type has no header.
    let login = r#"{"transaction_id": "t", "service": "S", "action": "A"}"#;
    let refused = unsupported(bind(&labelled(LOGIN, &["action"]), LOGIN, login));
    assert!(labels_of(&refused, "service"), "{refused:?}");
    let bound = bind(&labelled(LOGIN, &["action", "service"]), LOGIN, login).expect("offered");
    assert_eq!(bound.overlay.rows.len(), 2);
    // The four named fields, held without metadata, stay internal.
    let payload = payment("1", r#","date_time":"2026-10-01T12:30:15.123Z""#);
    let bound = bind(&labelled(PAYMENT, &header), PAYMENT, &payload).expect("offered");
    assert!(bound.overlay.rows.is_empty());
    // TS12 §3.3.1: level 4 omits the field, labelled or not.
    let hidden = labelled(PAYMENT, &header).replacen(
        r#""claims": ["#,
        r#""claims": [{"path": ["payload", "sct_inst"], "visualisation": 4},"#,
        1,
    );
    let payload = payment("1", r#","sct_inst":true"#);
    let bound = bind(&hidden, PAYMENT, &payload).expect("offered");
    assert!(bound.overlay.rows.is_empty());
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

/// RFC 2397's grammar, its own examples among the accepted; W3C SRI's: sha256's digest is 32 octets,
/// 44 characters of base64.
#[test]
fn the_constructors_refuse_outside_their_grammar() {
    for (written, holds) in [
        ("data:,A%20brief%20note", true),
        ("data:text/plain;charset=iso-8859-7,%be%fg%be", true),
        ("data:image/gif;base64,R0lGODdh", true),
        ("image/png;base64,AAAA", false),
        ("data:image/png;base64", false),
        ("data:image/png;base64,@@@@", false),
        ("data:image/png;base64,AAA", false),
        ("data:image;base64,AAAA", false),
        ("data:image/png;charset,AAAA", false),
        ("data:,caf\u{e9}", false),
    ] {
        assert_eq!(
            DataUrl::parse(written.to_owned()).is_some(),
            holds,
            "{written}"
        );
    }
    let short = format!("sha256-{}", "A".repeat(40));
    assert_eq!(Integrity::parse(short), None);
    let exact = format!("sha256-{}=", "A".repeat(43));
    assert!(Integrity::parse(exact).is_some());
}
