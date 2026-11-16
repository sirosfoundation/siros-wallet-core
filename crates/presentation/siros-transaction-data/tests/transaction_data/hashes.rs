//! The hash vectors of `tests/vectors/transaction-data-hashes.json` (see `tests/vectors/SOURCE`):
//! each `transaction_data` string hashed as received (OpenID4VP 1.0, B.3.3.1), and the KB-JWT
//! claims of an entry that carries `transaction_data_hashes_alg` as an array or as CS-12's
//! string.

use std::convert::Infallible;

use serde_json::{json, Value};
use siros_oid4vp::TransactionDataItem;
use siros_transaction_data::{Binding, Entry, EntryPosition, HashAlg, KbJwtInputs, Rulebook};

use crate::common::{query, CARD};

#[test]
fn each_entry_is_hashed_as_received() {
    let document: Value =
        serde_json::from_str(include_str!("../vectors/transaction-data-hashes.json")).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let raw = vector["raw"].as_str().unwrap();
        for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let expected = vector["hashes"][alg.identifier()].as_str().unwrap();
            assert_eq!(
                alg.hash(&TransactionDataItem::new(raw.to_owned())),
                expected,
                "{} {}",
                vector["name"],
                alg.identifier()
            );
        }
    }
    // (vector, the algorithm the entry's list takes first)
    for (name, alg) in [
        ("hash_alg_array", "sha-256"),
        ("hash_alg_string", "sha-384"),
    ] {
        let vector = vectors.iter().find(|v| v["name"] == name).unwrap();
        let raw = TransactionDataItem::new(vector["raw"].as_str().unwrap().to_owned());
        let entry = Entry::parse(EntryPosition::new(0), &raw, &query(&["pay"], CARD)).unwrap();
        let claims = Binding::new(&entry, Rulebook::Generic)
            .kb_jwt_claims(|| -> Result<KbJwtInputs, Infallible> { unreachable!() })
            .unwrap();
        let expected: Vec<(String, Value)> = vec![
            (
                "transaction_data_hashes".to_owned(),
                json!([vector["hashes"][alg]]),
            ),
            ("transaction_data_hashes_alg".to_owned(), json!(alg)),
        ];
        assert_eq!(claims, expected, "{name}");
    }
}
