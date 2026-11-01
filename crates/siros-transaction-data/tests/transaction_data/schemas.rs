//! The payload parsers against the TS12 schemas of `tests/ts12-schemas` (see
//! `tests/ts12-schemas/SOURCE`). On every payload fixture, a payload the parser accepts is one
//! its schema accepts. A payload the schema accepts and the parser refuses breaks a rule of
//! TS12's prose, which the fixture names. The refusals are those the fixtures expect.

use crate::common::{ts12_payload, ACCESS, LOGIN, MANDATE, PAYMENT};
use crate::fixtures::payloads;
use jsonschema::{Resource, Validator};
use serde_json::Value;

const PAYMENT_SCHEMA: &str =
    include_str!("../ts12-schemas/ts12-urn-eudi-sca-payment-1-data-model.json");

/// The validator of the schema `text`. The e-mandate schema's `$ref` names the payment schema
/// by its file name, relative to the default base URI.
fn validator(text: &str) -> Validator {
    let schema: Value = serde_json::from_str(text).unwrap();
    let payment: Value = serde_json::from_str(PAYMENT_SCHEMA).unwrap();
    jsonschema::options()
        .should_validate_formats(false)
        .with_resource(
            "json-schema:///ts12-urn-eudi-sca-payment-1-data-model.json",
            Resource::from_contents(payment),
        )
        .build(&schema)
        .unwrap()
}

#[test]
fn the_parsers_accept_only_what_the_schemas_accept() {
    let schemas = [
        (PAYMENT, validator(PAYMENT_SCHEMA)),
        (
            LOGIN,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-login_risk_transaction-1-data-model.json"
            )),
        ),
        (
            ACCESS,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-account_access-1-data-model.json"
            )),
        ),
        (
            MANDATE,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-emandate-1-data-model.json"
            )),
        ),
    ];
    for fixture in payloads() {
        let (_, schema) = schemas
            .iter()
            .find(|(t, _)| *t == fixture.transaction_type)
            .unwrap();
        let payload: Value = serde_json::from_str(&fixture.payload).unwrap();
        let schema_accepts = schema.is_valid(&payload);
        let parser_accepts = ts12_payload(fixture.transaction_type, &fixture.payload).is_ok();
        let case = fixture.case;
        assert_eq!(
            ts12_payload(fixture.transaction_type, &fixture.payload),
            fixture.expected,
            "{case}"
        );
        assert!(
            schema_accepts || !parser_accepts,
            "{case}: accepted, schema refuses"
        );
        assert_eq!(
            schema_accepts && !parser_accepts,
            fixture.prose.is_some(),
            "{case}: the prose rule named is {:?}",
            fixture.prose
        );
    }
}
