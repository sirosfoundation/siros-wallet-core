//! The payload fixtures: one per rule of the four TS12 schemas and of TS12's prose (Sections
//! 4.3.1 to 4.3.4), and the payloads accepted at their edges. The refusal table and the schema
//! differential read the same list.

use serde_json::{json, Value};

use siros_codec::json::MAX_DEPTH;

use crate::common::{payment, with, ACCESS, LOGIN, MANDATE, PAYMENT};

pub struct Payload {
    pub case: &'static str,
    pub transaction_type: &'static str,
    /// The JSON text of the payload.
    pub payload: String,
    /// `Ok`, or the code of the refusal.
    pub expected: Result<(), &'static str>,
    /// The prose rule the payload breaks when its schema accepts it.
    pub prose: Option<&'static str>,
}

const MISSING: &str = "transaction_data_member_missing";
const WRONG_TYPE: &str = "transaction_data_member_wrong_type";
const INVALID: &str = "transaction_data_member_invalid";
const UNKNOWN: &str = "transaction_data_member_unknown";
const NOT_ALLOWED: &str = "transaction_data_member_not_allowed";

/// A payload both its schema and the parser accept.
fn accepted(case: &'static str, transaction_type: &'static str, payload: String) -> Payload {
    Payload {
        case,
        transaction_type,
        payload,
        expected: Ok(()),
        prose: None,
    }
}

/// A payload its schema refuses, refused with `code`.
fn schema(
    case: &'static str,
    transaction_type: &'static str,
    payload: String,
    code: &'static str,
) -> Payload {
    Payload {
        case,
        transaction_type,
        payload,
        expected: Err(code),
        prose: None,
    }
}

/// A payload its schema accepts, refused with `code` for the prose rule `rule`.
fn prose(
    case: &'static str,
    transaction_type: &'static str,
    payload: String,
    code: &'static str,
    rule: &'static str,
) -> Payload {
    Payload {
        case,
        transaction_type,
        payload,
        expected: Err(code),
        prose: Some(rule),
    }
}

/// The JSON text of a payment with `changes`.
fn pay(changes: Value) -> String {
    with(payment(), changes).to_string()
}

/// The JSON text of a payment with the JSON text `amount` as its amount in `currency`.
fn pay_amount(currency: &str, amount: &str) -> String {
    format!(
        r#"{{"transaction_id":"tx-0001","payee":{{"name":"Shop AB","id":"SE1"}},"currency":"{currency}","amount":{amount}}}"#
    )
}

/// `depth` arrays, each inside the one before.
fn nested(depth: usize) -> Value {
    (1..depth).fold(json!([]), |inner, _| json!([inner]))
}

fn chars(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

/// The fixtures, at the time `2026-10-26T12:00:00Z` of [`crate::common::now`].
pub fn payloads() -> Vec<Payload> {
    let mut payloads = payments();
    payloads.extend(others());
    payloads
}

fn payments() -> Vec<Payload> {
    let party =
        json!({"legal_name": "PISP Ltd", "brand_name": "Pisp", "domain_name": "pisp.example"});
    vec![
        accepted("a payment", PAYMENT, payment().to_string()),
        accepted(
            "a recurring payment with every member",
            PAYMENT,
            pay(json!({
                "date_time": "2025-11-13T20:20:39+00:00",
                "payee": {"name": "Shop AB", "id": "SE1", "logo": "https://shop.example/logo.png",
                          "website": "https://shop.example"},
                "pisp": party,
                "amount_estimated": true,
                "amount_earmarked": false,
                "sct_inst": true,
                "recurrence": {
                    "start_date": "2026-11-01", "end_date": "2027-11-01", "number": 12,
                    "frequency": "MNTH",
                    "mit_options": {"amount_variable": true, "min_amount": 1, "max_amount": 100.25,
                                    "total_amount": 1000, "initial_amount": 5,
                                    "initial_amount_number": 2, "apr": 3.9}
                }
            })),
        ),
        accepted(
            "a payment executed later",
            PAYMENT,
            pay(json!({"execution_date": "2026-12-01"})),
        ),
        accepted(
            "a payment executed today",
            PAYMENT,
            pay(json!({"execution_date": "2026-10-26"})),
        ),
        accepted(
            "a payee logo in a data URL",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1",
                                 "logo": "data:image/png;base64,iVBORw0KGgo="}})),
        ),
        accepted(
            "a date_time with a fraction and an offset",
            PAYMENT,
            pay(json!({"date_time": "2025-11-13T20:20:39.250-05:00"})),
        ),
        accepted(
            "members the nested schemas leave open",
            PAYMENT,
            pay(json!({
                "payee": {"name": "Shop AB", "id": "SE1", "tags": ["a", null], "branch": {"city": "Malmö"}},
                "recurrence": {"frequency": "YEAR", "note": 1, "mit_options": {"cap": false}}
            })),
        ),
        accepted(
            "an open member nesting to MAX_DEPTH in the entry",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1", "x": nested(MAX_DEPTH - 3)}})),
        ),
        accepted(
            "a recurrence number written with a zero fraction",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "number": 12.0}})),
        ),
        accepted(
            "a transaction_id of 36 characters outside the BMP",
            PAYMENT,
            pay(json!({"transaction_id": chars('\u{1f600}', 36)})),
        ),
        accepted("a negative amount", PAYMENT, pay_amount("EUR", "-10.50")),
        accepted("an amount in yen", PAYMENT, pay_amount("JPY", "100")),
        accepted("an amount in dinar", PAYMENT, pay_amount("BHD", "1.250")),
        accepted("an amount without a fraction", PAYMENT, pay_amount("EUR", "49")),
        schema(
            "a payment without transaction_id",
            PAYMENT,
            pay(json!({"transaction_id": null})),
            MISSING,
        ),
        schema(
            "an empty transaction_id",
            PAYMENT,
            pay(json!({"transaction_id": ""})),
            INVALID,
        ),
        schema(
            "a transaction_id of 37 characters",
            PAYMENT,
            pay(json!({"transaction_id": chars('t', 37)})),
            INVALID,
        ),
        schema("a payment without payee", PAYMENT, pay(json!({"payee": null})), MISSING),
        schema("a payee that is a string", PAYMENT, pay(json!({"payee": "Shop"})), WRONG_TYPE),
        schema(
            "a payee without id",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB"}})),
            MISSING,
        ),
        schema("an amount that is a string", PAYMENT, pay(json!({"amount": "49.99"})), WRONG_TYPE),
        schema("a payment without amount", PAYMENT, pay(json!({"amount": null})), MISSING),
        schema("a currency in lower case", PAYMENT, pay(json!({"currency": "eur"})), INVALID),
        schema("a currency of four letters", PAYMENT, pay(json!({"currency": "EURO"})), INVALID),
        schema(
            "a null date_time",
            PAYMENT,
            r#"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"date_time":null}"#
                .to_owned(),
            WRONG_TYPE,
        ),
        schema(
            "an amount_estimated that is a string",
            PAYMENT,
            pay(json!({"amount_estimated": "true"})),
            WRONG_TYPE,
        ),
        schema(
            "a pisp without domain_name",
            PAYMENT,
            pay(json!({"pisp": {"legal_name": "PISP Ltd", "brand_name": "Pisp"}})),
            MISSING,
        ),
        schema(
            "a recurrence without frequency",
            PAYMENT,
            pay(json!({"recurrence": {"number": 3}})),
            MISSING,
        ),
        schema(
            "a frequency outside the enumeration",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "MONTHLY"}})),
            INVALID,
        ),
        schema(
            "a recurrence number with a fraction",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "number": 2.5}})),
            WRONG_TYPE,
        ),
        schema(
            "a mit_options amount that is a string",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "WEEK", "mit_options": {"min_amount": "1"}}})),
            WRONG_TYPE,
        ),
        schema(
            "a payment member its schema does not define",
            PAYMENT,
            pay(json!({"note": "x"})),
            UNKNOWN,
        ),
        prose(
            "a date_time that is no date and time",
            PAYMENT,
            pay(json!({"date_time": "yesterday"})),
            INVALID,
            "4.3.1 date_time: an ISO 8601 date and time",
        ),
        prose(
            "a date_time without a UTC offset",
            PAYMENT,
            pay(json!({"date_time": "2025-11-13T20:20:39"})),
            INVALID,
            "4.3.1 date_time: an ISO 8601 date and time",
        ),
        prose(
            "an execution_date in the past",
            PAYMENT,
            pay(json!({"execution_date": "2026-10-25"})),
            INVALID,
            "4.3.1 execution_date: MUST NOT lie in the past",
        ),
        prose(
            "an execution_date with a time",
            PAYMENT,
            pay(json!({"execution_date": "2026-12-01T10:00:00Z"})),
            INVALID,
            "4.3.1 execution_date: an ISO 8601 date",
        ),
        prose(
            "an execution_date beside a recurrence",
            PAYMENT,
            pay(json!({"execution_date": "2026-12-01", "recurrence": {"frequency": "MNTH"}})),
            NOT_ALLOWED,
            "4.3.1 execution_date: MUST NOT be present when recurrence is present",
        ),
        prose(
            "a recurrence start_date that is no date",
            PAYMENT,
            pay(json!({"recurrence": {"frequency": "MNTH", "start_date": "next month"}})),
            INVALID,
            "4.3.1 recurrence.start_date: an ISO 8601 date",
        ),
        prose(
            "a currency outside ISO 4217",
            PAYMENT,
            pay(json!({"currency": "ABC"})),
            INVALID,
            "4.3.1 currency: an ISO 4217 Alpha-3 code",
        ),
        prose(
            "an amount in euro with one fraction digit",
            PAYMENT,
            pay_amount("EUR", "49.9"),
            INVALID,
            "4.3.1 amount: the fraction digits of the currency's ISO 4217 minor unit",
        ),
        prose(
            "an amount in yen with a fraction",
            PAYMENT,
            pay_amount("JPY", "100.5"),
            INVALID,
            "4.3.1 amount: the fraction digits of the currency's ISO 4217 minor unit",
        ),
        prose(
            "an amount in exponent form",
            PAYMENT,
            pay_amount("EUR", "1e2"),
            INVALID,
            "4.3.1 amount: major units, and an optional decimal point and minor units",
        ),
        prose(
            "a mit_options amount with three fraction digits in euro",
            PAYMENT,
            r#"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"recurrence":{"frequency":"MNTH","mit_options":{"min_amount":1.505}}}"#
                .to_owned(),
            INVALID,
            "4.3.1 mit_options.min_amount: formatted as amount",
        ),
        prose(
            "a payee website that is no URL",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1", "website": "shop.example"}})),
            INVALID,
            "4.3.1 payee.website: a resolvable URL",
        ),
        prose(
            "a payee logo that is no URL",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1", "logo": "logo.png"}})),
            INVALID,
            "4.3.1 payee.logo: a resolvable or data URL",
        ),
        prose(
            "a payee logo in a data URL whose base64 does not decode",
            PAYMENT,
            pay(json!({"payee": {"name": "Shop AB", "id": "SE1", "logo": "data:image/png;base64,*"}})),
            INVALID,
            "4.3.1 payee.logo: a resolvable or data URL (RFC 2397)",
        ),
        prose(
            "a pisp domain_name that is no domain name",
            PAYMENT,
            pay(json!({"pisp": {"legal_name": "PISP Ltd", "brand_name": "Pisp",
                                "domain_name": "pisp example"}})),
            INVALID,
            "4.3.1 pisp.domain_name: a domain name",
        ),
    ]
}

fn others() -> Vec<Payload> {
    let party =
        json!({"legal_name": "AISP Ltd", "brand_name": "Aisp", "domain_name": "aisp.example"});
    let mandate = |extra: Value| {
        with(
            json!({"transaction_id": "t", "purpose": "Pay monthly bill"}),
            extra,
        )
        .to_string()
    };
    vec![
        accepted(
            "a login",
            LOGIN,
            json!({"transaction_id": "t", "date_time": "2025-11-13T20:20:39+00:00",
                   "service": "Superbank Online Banking", "action": "Log in"})
            .to_string(),
        ),
        schema(
            "a login without action",
            LOGIN,
            json!({"transaction_id": "t"}).to_string(),
            MISSING,
        ),
        schema(
            "a login without transaction_id",
            LOGIN,
            json!({"action": "Log in"}).to_string(),
            MISSING,
        ),
        schema(
            "an action of 141 characters",
            LOGIN,
            json!({"transaction_id": "t", "action": chars('a', 141)}).to_string(),
            INVALID,
        ),
        schema(
            "a service of 101 characters",
            LOGIN,
            json!({"transaction_id": "t", "action": "Log in", "service": chars('s', 101)})
                .to_string(),
            INVALID,
        ),
        schema(
            "a login member its schema does not define",
            LOGIN,
            json!({"transaction_id": "t", "action": "Log in", "amount": 1}).to_string(),
            UNKNOWN,
        ),
        prose(
            "a login date_time that is no date and time",
            LOGIN,
            json!({"transaction_id": "t", "action": "Log in", "date_time": "2025-13-01T00:00:00Z"})
                .to_string(),
            INVALID,
            "4.3.2 date_time: an ISO 8601 date and time",
        ),
        accepted(
            "an account access",
            ACCESS,
            json!({"transaction_id": "t"}).to_string(),
        ),
        accepted(
            "an account access through an AISP",
            ACCESS,
            json!({"transaction_id": "t", "aisp": party, "description": "Read the balance"})
                .to_string(),
        ),
        schema(
            "an account access without transaction_id",
            ACCESS,
            json!({}).to_string(),
            MISSING,
        ),
        schema(
            "an aisp without brand_name",
            ACCESS,
            json!({"transaction_id": "t", "aisp": {"legal_name": "A", "domain_name": "a.example"}})
                .to_string(),
            MISSING,
        ),
        schema(
            "a description of 141 characters",
            ACCESS,
            json!({"transaction_id": "t", "description": chars('d', 141)}).to_string(),
            INVALID,
        ),
        prose(
            "an aisp domain_name with an underscore",
            ACCESS,
            json!({"transaction_id": "t", "aisp": {"legal_name": "A", "brand_name": "A",
                                                   "domain_name": "a_isp.example"}})
            .to_string(),
            INVALID,
            "4.3.3 aisp.domain_name: a domain name",
        ),
        accepted(
            "a mandate",
            MANDATE,
            mandate(json!({"start_date": "2026-01-01", "end_date": "2027-01-01",
                           "reference_number": "A-98765", "creditor_id": "FR14ZZZ001122334455"})),
        ),
        accepted(
            "a mandate valid from a date and time",
            MANDATE,
            mandate(json!({"start_date": "2026-11-01T00:00:00Z"})),
        ),
        accepted(
            "a mandate with a payment and no purpose",
            MANDATE,
            json!({"transaction_id": "t", "payment_payload": payment()}).to_string(),
        ),
        schema(
            "a mandate without transaction_id",
            MANDATE,
            json!({"purpose": "p"}).to_string(),
            MISSING,
        ),
        schema(
            "a mandate whose payment has a lower-case currency",
            MANDATE,
            mandate(json!({"payment_payload": with(payment(), json!({"currency": "eur"}))})),
            INVALID,
        ),
        schema(
            "a mandate whose payment has a member its schema does not define",
            MANDATE,
            mandate(json!({"payment_payload": with(payment(), json!({"note": "x"}))})),
            UNKNOWN,
        ),
        schema(
            "an empty reference_number",
            MANDATE,
            mandate(json!({"reference_number": ""})),
            INVALID,
        ),
        schema(
            "a creditor_id of 51 characters",
            MANDATE,
            mandate(json!({"creditor_id": chars('c', 51)})),
            INVALID,
        ),
        schema(
            "a purpose of 1001 characters",
            MANDATE,
            mandate(json!({"purpose": chars('p', 1001)})),
            INVALID,
        ),
        prose(
            "a mandate without purpose or payment",
            MANDATE,
            json!({"transaction_id": "t"}).to_string(),
            MISSING,
            "4.3.4 purpose: REQUIRED when payment is not present",
        ),
        prose(
            "a mandate end_date that is no date",
            MANDATE,
            mandate(json!({"end_date": "soon"})),
            INVALID,
            "4.3.4 end_date: an ISO 8601 date or date and time",
        ),
        prose(
            "a mandate whose payment executes in the past",
            MANDATE,
            mandate(
                json!({"payment_payload": with(payment(), json!({"execution_date": "2026-01-01"}))}),
            ),
            INVALID,
            "4.3.1 execution_date: MUST NOT lie in the past",
        ),
    ]
}
