//! The advanced profile of PaSO Core, Section 7.4, on its examples A.5 to A.7: the outcome each
//! example states.

use serde_json::{json, Value};
use siros_dcql::DcqlQuery;
use siros_oid4vp::RequestSignature;
use siros_transaction_data::{
    check_request, Entry, EntryPosition, SetPosition, SetsFault, TransactionDataError,
};

use crate::common::{configured, credential, elements, entries, taken, Host};

/// The `transaction_data_types` entry of `urn:paso:sca:global:payment:1` of Proof Metadata,
/// Annex A.2.
fn payment_definition() -> Value {
    let payload: Value =
        serde_json::from_str(include_str!("../vectors/paso/metadata-a2-payload.json")).unwrap();
    payload["credential_metadata"]["transaction_data_types"]["urn:paso:sca:global:payment:1"]
        .clone()
}

/// The entries of `entries` that target the Credential Query `id`, in array order.
fn targeting<'e>(entries: &'e [Entry], id: &str) -> Vec<&'e Entry> {
    entries
        .iter()
        .filter(|entry| entry.credential_ids().iter().any(|q| q.as_str() == id))
        .collect()
}

/// A.5: the card takes the entry that names `sca_card`, the account the one that names
/// `sca_account`; the four alternatives decompose into two slots.
#[test]
fn a5_each_credential_takes_its_entry() {
    let request: Value =
        serde_json::from_str(include_str!("../vectors/paso/core-a5-request.json")).unwrap();
    let query = DcqlQuery::from_json(&request["dcql_query"].to_string()).unwrap();
    let entries = entries(
        &elements(include_str!("../vectors/paso/core-a5-entries.json")),
        &query,
    );
    check_request(&entries, &query, RequestSignature::Signed).unwrap();
    let card = "https://bank.example/sca/card";
    let account = "https://bank.example/sca/account";
    let mut host = Host::new(json!([
        configured("urn:paso:sca:global:payment:1", card, &payment_definition()),
        configured(
            "urn:paso:sca:global:payment:1",
            account,
            &payment_definition()
        )
    ]));
    // The issuer publishes no Type Metadata: the configuration serves the cards.
    host.absent = vec![card.to_owned(), account.to_owned()];
    for (id, vct, entry) in [("sca_card", card, 0), ("sca_account", account, 1)] {
        let selection = host
            .select(&targeting(&entries, id), &credential(vct, &[]))
            .unwrap();
        assert_eq!(taken(&selection).entry(), EntryPosition::new(entry), "{id}");
    }
}

/// A.6: the transposable options are accepted, the counterexample refused, and the six
/// combinations that repair it accepted.
#[test]
fn a6_transposability() {
    let dcql = |options: &Value| {
        let credentials = ["sca_card", "pid_1", "pid_2", "loyalty"].map(|id| {
            json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": ["https://bank.example/sca/card"]}})
        });
        let query = json!({"credentials": credentials, "credential_sets": [{"options": options}]});
        DcqlQuery::from_json(&query.to_string()).unwrap()
    };
    let entry = json!({"type": "urn:paso:sca:global:payment:1", "credential_ids": ["sca_card"],
                       "payload": {"amount": "1.00 EUR", "payee": {"name": "S", "id": "1"}}});
    // The options of Annex A.6, as written there.
    let cases = [
        (
            json!([["sca_card", "pid_1"], ["sca_card", "pid_2"], ["sca_card"]]),
            Ok(()),
        ),
        (
            json!([
                ["sca_card", "pid_1"],
                ["sca_card", "pid_2", "loyalty"],
                ["sca_card"]
            ]),
            Err(TransactionDataError::CredentialSets(
                SetsFault::NotTransposable(SetPosition::new(0)),
            )),
        ),
        (
            json!([
                ["sca_card", "pid_1", "loyalty"],
                ["sca_card", "pid_1"],
                ["sca_card", "pid_2", "loyalty"],
                ["sca_card", "pid_2"],
                ["sca_card", "loyalty"],
                ["sca_card"]
            ]),
            Ok(()),
        ),
    ];
    for (options, expected) in cases {
        let query = dcql(&options);
        let entries = entries(&[entry.to_string()], &query);
        assert_eq!(
            check_request(&entries, &query, RequestSignature::Signed),
            expected,
            "{options}"
        );
    }
}

/// A.7: a credential that supports version 2 takes the first entry; one that supports version
/// 1 alone skips it and takes the second.
#[test]
fn a7_versioned_transaction_data() {
    let texts = elements(include_str!("../vectors/paso/core-a7-entries.json"));
    let query = crate::common::query(&["sca"], "https://bank.example/sca/card");
    let entries = entries(&texts, &query);
    check_request(&entries, &query, RequestSignature::Signed).unwrap();
    let v1 = payment_definition();
    let mut v2 = v1.clone();
    v2["claims"].as_array_mut().unwrap().push(
        json!({"path": ["reward_points"], "display": [{"locale": "en", "name": "Reward points"}]}),
    );
    let (new, old) = (
        "https://bank.example/sca/new",
        "https://bank.example/sca/old",
    );
    let mut host = Host::new(json!([
        configured("urn:paso:sca:com.example.pay:transaction:2", new, &v2),
        configured("urn:paso:sca:com.example.pay:transaction:1", new, &v1),
        configured("urn:paso:sca:com.example.pay:transaction:1", old, &v1)
    ]));
    host.absent = vec![new.to_owned(), old.to_owned()];
    let all: Vec<&Entry> = entries.iter().collect();
    for (vct, entry) in [(new, 0), (old, 1)] {
        let selection = host.select(&all, &credential(vct, &[])).unwrap();
        assert_eq!(
            taken(&selection).entry(),
            EntryPosition::new(entry),
            "{vct}"
        );
    }
}
