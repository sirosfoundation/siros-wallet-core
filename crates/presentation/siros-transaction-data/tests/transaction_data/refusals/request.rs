//! The rules of an entry (T1; OpenID4VP 1.0, Section 5.1 and B.3) and of the request as a whole:
//! credential sets (PaSO Core, Section 7.4.1) and the signed request of a PaSO type (Section 3).

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_codec::json::MAX_DEPTH;
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_dcql::{DcqlQuery, QueryId};
use siros_oid4vp::RequestSignature;
use siros_transaction_data::{
    check_request, Entry, EntryMember, EntryPosition, EntryRefusal, HashesAlgFault, SetPosition,
    SetsFault, TransactionDataError,
};

use crate::common::{encode, entries, item};

/// `pay` and `card` ask for SD-JWT VCs with holder binding, `unbound` for one without, `mdl` for
/// an mdoc.
fn query() -> DcqlQuery {
    DcqlQuery::from_json(
        &json!({"credentials": [
            {"id": "pay", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pay.example"]}},
            {"id": "card", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pay.example"]}},
            {"id": "unbound", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pay.example"]},
             "require_cryptographic_holder_binding": false},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
        ]})
        .to_string(),
    )
    .unwrap()
}

/// An honest PaSO entry.
fn honest() -> Value {
    json!({"type": "urn:paso:sca:global:payment:1", "credential_ids": ["pay"],
           "payload": {"amount": "1.00 EUR", "payee": {"name": "Shop", "id": "1"}}})
}

/// The honest entry with `changes`; a `null` change removes the member.
fn changed(changes: Value) -> String {
    let mut entry = honest();
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            entry.as_object_mut().unwrap().remove(name);
        } else {
            entry[name] = change.clone();
        }
    }
    encode(&entry.to_string())
}

/// What a row expects: acceptance, a refusal, or a refusal by the code of a cause that carries
/// a library's position.
enum Expect {
    Accepted,
    Refused(EntryRefusal),
    Code(&'static str),
}

fn member(member: EntryMember, fault: MemberFault) -> Expect {
    Expect::Refused(EntryRefusal::Member(member, fault))
}

#[test]
fn each_entry_rule_is_refused_alone() {
    let text = |text: &str| encode(text);
    let honest_text = honest().to_string();
    let deep = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    let unpadded = encode(&honest_text);
    let padded = format!("{unpadded}{}", "=".repeat((4 - unpadded.len() % 4) % 4));
    assert_ne!(padded, unpadded);
    let alg = |value: Value| changed(json!({"transaction_data_hashes_alg": value}));
    let rows: Vec<(&str, String, Expect)> = vec![
        ("an honest PaSO entry", unpadded.clone(), Expect::Accepted),
        (
            "base64url with padding",
            padded,
            Expect::Code("transaction_data_not_base64url"),
        ),
        (
            "a character outside base64url",
            format!("{unpadded}+"),
            Expect::Code("transaction_data_not_base64url"),
        ),
        (
            "bytes that are not UTF-8",
            base64url::encode(&[0x7b, 0xff, 0x7d]).into(),
            Expect::Code("transaction_data_not_json_object"),
        ),
        (
            "text that is not JSON",
            text("{type}"),
            Expect::Code("transaction_data_not_json_object"),
        ),
        (
            "a JSON array",
            text("[1]"),
            Expect::Refused(EntryRefusal::NotJsonObject),
        ),
        (
            "a repeated member name",
            text(&honest_text.replacen('{', r#"{"type":"x","#, 1)),
            Expect::Code("transaction_data_duplicate_key"),
        ),
        (
            "nesting deeper than MAX_DEPTH",
            text(&honest_text.replacen('{', &format!(r#"{{"deep":{deep},"#), 1)),
            Expect::Code("transaction_data_too_deep"),
        ),
        (
            "no type",
            changed(json!({"type": null})),
            member(EntryMember::Type, MemberFault::Absent),
        ),
        (
            "a type that is no string",
            changed(json!({"type": 1})),
            member(EntryMember::Type, MemberFault::WrongType),
        ),
        (
            "an empty type",
            changed(json!({"type": ""})),
            Expect::Refused(EntryRefusal::TypeEmpty),
        ),
        (
            "no credential_ids",
            changed(json!({"credential_ids": null})),
            member(EntryMember::CredentialIds, MemberFault::Absent),
        ),
        (
            "credential_ids that is no array",
            changed(json!({"credential_ids": "pay"})),
            member(EntryMember::CredentialIds, MemberFault::WrongType),
        ),
        (
            "empty credential_ids",
            changed(json!({"credential_ids": []})),
            Expect::Refused(EntryRefusal::CredentialIdsEmpty),
        ),
        (
            "a credential_ids element that is no string",
            changed(json!({"credential_ids": ["pay", 1]})),
            member(EntryMember::CredentialIds, MemberFault::WrongType),
        ),
        (
            "credential_ids naming no Credential Query",
            changed(json!({"credential_ids": ["pay", "nope"]})),
            Expect::Refused(EntryRefusal::CredentialIdUnknown("nope".to_owned())),
        ),
        (
            "a Credential Query without holder binding (B.3)",
            changed(json!({"credential_ids": ["unbound"]})),
            Expect::Refused(EntryRefusal::HolderBindingNotRequired(
                QueryId::parse("unbound").unwrap(),
            )),
        ),
        (
            "an mdoc Credential Query, which supports no type",
            changed(json!({"credential_ids": ["mdl"]})),
            Expect::Accepted,
        ),
        (
            "no payload",
            changed(json!({"payload": null})),
            member(EntryMember::Payload, MemberFault::Absent),
        ),
        (
            "a payload that is no object",
            changed(json!({"payload": "x"})),
            member(EntryMember::Payload, MemberFault::WrongType),
        ),
        (
            "metadata that is no string",
            changed(json!({"metadata": 1})),
            member(EntryMember::Metadata, MemberFault::WrongType),
        ),
        (
            "a member no specification defines",
            changed(json!({"note": "x"})),
            Expect::Refused(EntryRefusal::MemberUnknown("note".to_owned())),
        ),
        // `transaction_data_hashes_alg` (B.3.3.1; CS-12, Section 8.1).
        (
            "an array of algorithms",
            alg(json!(["md5", "sha-512"])),
            Expect::Accepted,
        ),
        (
            "CS-12's one string",
            alg(json!("sha-256")),
            Expect::Accepted,
        ),
        (
            "an empty array",
            alg(json!([])),
            Expect::Refused(EntryRefusal::HashesAlg(HashesAlgFault::Empty)),
        ),
        (
            "an element that is no string",
            alg(json!(["sha-256", 256])),
            Expect::Refused(EntryRefusal::HashesAlg(HashesAlgFault::Element(
                ArrayIndex::new(1),
            ))),
        ),
        (
            "no algorithm the wallet computes",
            alg(json!(["md5"])),
            Expect::Refused(EntryRefusal::HashesAlg(HashesAlgFault::Unsupported)),
        ),
        (
            "an object",
            alg(json!({})),
            Expect::Refused(EntryRefusal::HashesAlg(HashesAlgFault::WrongType)),
        ),
    ];
    let query = query();
    for (case, raw, expected) in rows {
        let read = Entry::parse(EntryPosition::new(0), &item(&raw), &query).map(drop);
        match expected {
            Expect::Accepted => assert_eq!(read, Ok(()), "{case}"),
            Expect::Refused(refusal) => assert_eq!(read, Err(refusal), "{case}"),
            Expect::Code(code) => assert_eq!(read.map_err(|e| e.code()), Err(code), "{case}"),
        }
    }
}

#[test]
fn each_request_rule_is_refused_alone() {
    let sets = |sets: Value| {
        DcqlQuery::from_json(
            &json!({"credentials": [
                {"id": "pay", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pay.example"]}},
                {"id": "card", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pay.example"]}},
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://pid.example"]}}
            ], "credential_sets": sets})
            .to_string(),
        )
        .unwrap()
    };
    let targeting = |ids: Value| {
        let mut entry = honest();
        entry["credential_ids"] = ids;
        entry.to_string()
    };
    let id = |id: &str| QueryId::parse(id).unwrap();
    // (case, credential sets, the entries' credential_ids, signature, expected)
    let rows = vec![
        (
            "every targeted query in one set",
            json!([{"options": [["pay", "pid"], ["card", "pid"]]}]),
            vec![json!(["pay"]), json!(["card"])],
            RequestSignature::Signed,
            Ok(()),
        ),
        (
            "targeted queries in two sets",
            json!([{"options": [["pay"]]}, {"options": [["card"]]}]),
            vec![json!(["pay"]), json!(["card"])],
            RequestSignature::Signed,
            Err(TransactionDataError::CredentialSets(SetsFault::Split(id(
                "card",
            )))),
        ),
        (
            "a targeted query in no set",
            json!([{"options": [["pid"]]}]),
            vec![json!(["pay"])],
            RequestSignature::Signed,
            Err(TransactionDataError::CredentialSets(SetsFault::Split(id(
                "pay",
            )))),
        ),
        (
            "a targeted query in a second set",
            json!([{"options": [["pay"], ["card"]]}, {"options": [["pay", "pid"]], "required": false}]),
            vec![json!(["pay", "card"])],
            RequestSignature::Signed,
            Err(TransactionDataError::CredentialSets(SetsFault::Repeated(
                id("pay"),
            ))),
        ),
        (
            "alternatives coupled across slots",
            json!([{"options": [["pay", "pid"], ["card"]]}]),
            vec![json!(["pay", "card"])],
            RequestSignature::Signed,
            Err(TransactionDataError::CredentialSets(
                SetsFault::NotTransposable(SetPosition::new(0)),
            )),
        ),
        (
            "a PaSO entry in an unsigned request (PaSO Core, Section 3)",
            json!([{"options": [["pay"]]}]),
            vec![json!(["pay"])],
            RequestSignature::Unsigned,
            Err(TransactionDataError::Unsigned(EntryPosition::new(0))),
        ),
    ];
    for (case, credential_sets, ids, signature, expected) in rows {
        let query = sets(credential_sets);
        let texts: Vec<String> = ids.into_iter().map(targeting).collect();
        let entries = entries(&texts, &query);
        assert_eq!(
            check_request(&entries, &query, signature),
            expected,
            "{case}"
        );
    }
}
