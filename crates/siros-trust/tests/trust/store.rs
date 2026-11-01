//! TR1: the trust store record, one refusal per rule, each by its reason.

use serde_json::json;
use siros_codec::json::JsonFault;
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;
use siros_dcql::AuthorityType;
use siros_trust::{CertificateError, CertificateIndex, EntryError, StoreError, TrustStore};
use x509_cert::der::Decode;

use crate::support::{base64, record, Cert, Key};

/// The outcome of a parse, comparable: the entry and its error, the member name an object
/// repeats, or the record's error code.
#[derive(Debug, PartialEq)]
enum Verdict {
    Parsed,
    Record(&'static str),
    RepeatedMember(String),
    Entry(usize, EntryError),
    Repeated(usize),
}

fn verdict(record: &str) -> Verdict {
    match TrustStore::parse(record) {
        Ok(_) => Verdict::Parsed,
        Err(StoreError::Entry { entry, error }) => Verdict::Entry(entry.value(), error),
        Err(StoreError::Repeated(entry)) => Verdict::Repeated(entry.value()),
        Err(StoreError::Json(JsonFault::RepeatedMember(name))) => Verdict::RepeatedMember(name),
        Err(error) => Verdict::Record(error.code()),
    }
}

#[test]
fn each_rule_of_tr1() {
    let iaca = Cert::root("Test IACA", Key::p256(0x51));
    let certificate = base64(&iaca.der());
    let entry = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut entry = json!({"type": "etsi_tl", "value": "https://tl.example/eu",
            "certificates": [certificate]});
        edit(&mut entry);
        json!([entry]).to_string()
    };
    let first = CertificateIndex::new(0);
    let base64url_text = certificate.replace('+', "-").replace('/', "_");
    let cases = [
        ("an honest record", entry(&|_| {}), Verdict::Parsed),
        (
            "not JSON",
            "[".to_owned(),
            Verdict::Record("trust_store_json"),
        ),
        (
            "not an array",
            json!({"entries": []}).to_string(),
            Verdict::Record("trust_store_not_array"),
        ),
        (
            "an entry that is not an object",
            json!(["etsi_tl"]).to_string(),
            Verdict::Entry(0, EntryError::NotObject),
        ),
        (
            "an unknown member",
            entry(&|e| e["status"] = json!("granted")),
            Verdict::Entry(0, EntryError::UnknownMember("status".to_owned())),
        ),
        (
            "no string type",
            entry(&|e| e["type"] = json!(1)),
            Verdict::Entry(0, EntryError::Type(MemberFault::WrongType)),
        ),
        (
            "an unknown type",
            entry(&|e| e["type"] = json!("aki")),
            Verdict::Entry(0, EntryError::UnknownType(AuthorityType::new("aki"))),
        ),
        (
            "no string value",
            entry(&|e| e["value"] = json!(["https://tl.example/eu"])),
            Verdict::Entry(0, EntryError::Value(MemberFault::WrongType)),
        ),
        (
            "no certificate",
            entry(&|e| e["certificates"] = json!([])),
            Verdict::Entry(0, EntryError::Certificates(MemberFault::Empty)),
        ),
        (
            "a certificate that is not a string",
            entry(&|e| e["certificates"] = json!([1])),
            Verdict::Entry(0, EntryError::CertificateNotString(first)),
        ),
        (
            "a certificate in base64url",
            entry(&|e| e["certificates"] = json!([base64url_text])),
            Verdict::Entry(
                0,
                EntryError::Encoding {
                    certificate: first,
                    error: Base64Error::Alphabet(base64url_text.find(['-', '_']).unwrap()),
                },
            ),
        ),
        (
            "a certificate that does not parse",
            entry(&|e| e["certificates"] = json!([base64(b"not a certificate")])),
            Verdict::Entry(
                0,
                EntryError::Certificate {
                    certificate: first,
                    error: CertificateError::Der(
                        x509_cert::Certificate::from_der(b"not a certificate").unwrap_err(),
                    ),
                },
            ),
        ),
        (
            "a repeated member",
            format!(
                r#"[{{"type":"openid_federation","type":"etsi_tl","value":"https://tl.example/eu","certificates":["{certificate}"]}}]"#
            ),
            Verdict::RepeatedMember("type".to_owned()),
        ),
        (
            "a repeated type and value",
            record(&[
                ("etsi_tl", "https://tl.example/eu", &[&iaca]),
                ("etsi_tl", "https://tl.example/eu", &[&iaca]),
            ]),
            Verdict::Repeated(1),
        ),
    ];
    assert!(
        certificate.contains('+') || certificate.contains('/'),
        "the base64url case needs a certificate whose base64 differs from its base64url"
    );
    let failures: Vec<String> = cases
        .into_iter()
        .filter_map(|(name, record, expected)| {
            let got = verdict(&record);
            (got != expected).then(|| format!("{name}: got {got:?}, want {expected:?}"))
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
