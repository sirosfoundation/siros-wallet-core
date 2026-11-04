//! The fixtures the tests assert and the differential gives the model: changes to the CSC
//! examples, the documents' contents, and the type's rule table.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest;
use siros_openid4vp::json::quote;

use super::{Fields, csc, items, string};

/// §7.1.2's document links, in array order.
pub const HREFS: [&str; 3] = [
    "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
    "https://public.rp-cdn.example/terms-and-conditions.pdf",
    "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
];

/// check_qes.py's example contract.
pub const CONTRACT: &[u8] = b"%PDF-1.7 example contract";

/// W3C SRI metadata of content with sha256, written from the definition.
pub fn sri(content: &[u8]) -> String {
    format!("sha256-{}", STANDARD.encode(sha2::Sha256::digest(content)))
}

/// §7.1.2's entry.
pub fn approval() -> Fields {
    Fields::of(&csc("csc-7.1.2-entry"))
}

/// §7.1.2's entry with these documents.
pub fn with_documents(documents: &[String]) -> String {
    approval()
        .set("documentInfos", &format!("[{}]", documents.join(", ")))
        .json()
}

/// §7.1.2's second document with the checksum of [`CONTRACT`], with or without its label.
pub fn terms(labelled: bool) -> String {
    let documents = items(approval().get("documentInfos").expect("documentInfos"));
    let fields = Fields::of(&documents[1]).set("checksum", &quote(&sri(CONTRACT)));
    if labelled {
        fields
    } else {
        fields.without("label")
    }
    .json()
}

/// The digest by the algorithm an object identifier names in NIST CSOR's hashAlgs arc.
pub fn nist(oid: &str, data: &[u8]) -> Vec<u8> {
    match oid.strip_prefix("2.16.840.1.101.3.4.2.") {
        Some("1") => sha2::Sha256::digest(data).to_vec(),
        Some("2") => sha2::Sha384::digest(data).to_vec(),
        Some("3") => sha2::Sha512::digest(data).to_vec(),
        Some("4") => sha2::Sha224::digest(data).to_vec(),
        Some("5") => sha2::Sha512_224::digest(data).to_vec(),
        Some("6") => sha2::Sha512_256::digest(data).to_vec(),
        Some("7") => sha3::Sha3_224::digest(data).to_vec(),
        Some("8") => sha3::Sha3_256::digest(data).to_vec(),
        Some("9") => sha3::Sha3_384::digest(data).to_vec(),
        Some("10") => sha3::Sha3_512::digest(data).to_vec(),
        _ => panic!("no hashAlgs OID: {oid}"),
    }
}

/// What phase 2 fetches of a document: its content, or nothing.
pub type Published = Vec<(String, Vec<u8>)>;

/// §7.1.2's entry hashed by the OID, each document's checksum the SRI of "%PDF-1.7 {label}"; and
/// what is published: each document as it is, those `altered` with a byte more, those `missing`
/// not at all.
pub fn known(oid: &str, altered: &[usize], missing: &[usize]) -> (String, Published) {
    let mut documents = Vec::new();
    let mut published = Vec::new();
    for (k, item) in items(approval().get("documentInfos").expect("documentInfos"))
        .iter()
        .enumerate()
    {
        let mut content = format!("%PDF-1.7 {}", string(item, "label")).into_bytes();
        documents.push(
            Fields::of(item)
                .set("checksum", &quote(&sri(&content)))
                .json(),
        );
        if altered.contains(&k) {
            content.push(b'!');
        }
        if !missing.contains(&k) {
            published.push((HREFS[k].to_owned(), content));
        }
    }
    let json = Fields::of(&with_documents(&documents))
        .set("hashAlgorithmOID", &quote(oid))
        .json();
    (json, published)
}

/// The content of the document at `k` as [`known`] publishes it.
pub fn published(k: usize) -> Vec<u8> {
    let documents = items(approval().get("documentInfos").expect("documentInfos"));
    format!("%PDF-1.7 {}", string(&documents[k], "label")).into_bytes()
}

/// Each way to break a rule of the type, as a change to §7.1.2's entry, with the problems qes.py
/// finds in it, in order.
pub fn rule_table() -> Vec<(String, Vec<&'static str>)> {
    let document = r#"{"hash": "h", "hashType": "sodr"}"#;
    let documents = |docs: &str| approval().set("documentInfos", docs);
    let count = "numSignatures is not a positive integer";
    let no_hash = "hashAlgorithmOID is absent: §7.2 identifies the approval's hash with it";
    let empty = "documentInfos is not a non-empty array";
    let not_a_document = "documentInfos[0] is not a document with hash and hashType";
    let otp = "documentInfos[0]: an OTP access without its oneTimePassword";
    let locations = "locations is not an array of strings";
    let table: Vec<(Fields, Vec<&'static str>)> = vec![
        (
            approval().set("signAlgo", r#""1.2.840.113549.1.1.1""#),
            vec!["unknown member signAlgo"],
        ),
        (approval().set("numSignatures", "0"), vec![count]),
        (approval().set("numSignatures", "-1"), vec![count]),
        (approval().set("numSignatures", "1.0"), vec![count]),
        (approval().set("numSignatures", "true"), vec![count]),
        (approval().set("numSignatures", r#""2""#), vec![count]),
        (approval().without("numSignatures"), vec![count]),
        (
            approval().set("signatureQualifier", r#""za_ecta_aes""#),
            vec!["signatureQualifier 'za_ecta_aes' is not one this wallet renders"],
        ),
        (
            approval().without("signatureQualifier"),
            vec!["signatureQualifier None is not one this wallet renders"],
        ),
        (
            approval().set("signatureQualifier", "5"),
            vec!["signatureQualifier 5 is not one this wallet renders"],
        ),
        (approval().without("hashAlgorithmOID"), vec![no_hash]),
        (approval().set("hashAlgorithmOID", "null"), vec![no_hash]),
        (approval().set("hashAlgorithmOID", "1"), vec![no_hash]),
        (
            approval().set("hashAlgorithmOID", r#""1.2.840.113549.2.5""#),
            vec!["hashAlgorithmOID 1.2.840.113549.2.5 names no hash this wallet computes"],
        ),
        (documents("[]"), vec![empty]),
        (documents("{}"), vec![empty]),
        (approval().without("documentInfos"), vec![empty]),
        (documents(r#"[{"label": "x"}]"#), vec![not_a_document]),
        (documents(r#"[{"hash": "h"}]"#), vec![not_a_document]),
        (documents("[5]"), vec![not_a_document]),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "label": 5}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": 1, "hashType": "sodr"}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": ["sodr"]}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "access": "OTP"}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "href": null}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "checksum": 1}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "signAlgo": "x"}]"#),
            vec![not_a_document],
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "access": {"type": "OTP"}}]"#),
            vec![otp],
        ),
        (
            documents(
                r#"[{"hash": "h", "hashType": "sodr", "access": {"type": "OTP", "oneTimePassword": 51623}}]"#,
            ),
            vec![otp],
        ),
        (
            documents(&format!(r#"[{document}, {{"hash": "h"}}]"#)),
            vec!["documentInfos[1] is not a document with hash and hashType"],
        ),
        (
            approval().set("locations", r#""https://rsp.example""#),
            vec![locations],
        ),
        (
            approval().set("locations", r#"["https://rsp.example", 1]"#),
            vec![locations],
        ),
        (
            approval()
                .set("locations", "[]")
                .set("x", "1")
                .set("numSignatures", "0")
                .set("signatureQualifier", "null")
                .set("hashAlgorithmOID", r#""x""#)
                .set("documentInfos", &format!(r#"[{{}}, {document}, 5]"#))
                .set("y", "2"),
            vec![
                "unknown member x",
                "unknown member y",
                count,
                "signatureQualifier None is not one this wallet renders",
                "hashAlgorithmOID x names no hash this wallet computes",
                not_a_document,
                "documentInfos[2] is not a document with hash and hashType",
            ],
        ),
    ];
    table
        .into_iter()
        .map(|(fields, problems)| (fields.json(), problems))
        .collect()
}

/// Three approvals naming `xyz123`, the third also `abc`.
pub fn naming_twice() -> Vec<String> {
    let third = approval()
        .set("credential_ids", r#"["xyz123", "abc"]"#)
        .json();
    vec![approval().json(), approval().json(), third]
}

/// The entries the specification's examples write: §7.1.2's, §7.3's, check.py's entry of the
/// required members alone, and §7.1.2's with `locations` (§7.1.1).
pub fn accepted() -> Vec<String> {
    let minimal = r#"{"type": "https://cloudsignatureconsortium.org/2025/qes-approval", "credential_ids": ["xyz123"], "numSignatures": 1, "signatureQualifier": "eu_eidas_qes", "documentInfos": [{"hash": "aA==", "hashType": "sodr"}], "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"}"#;
    vec![
        approval().json(),
        csc("csc-7.3-entry"),
        minimal.to_owned(),
        approval()
            .set("locations", r#"["https://rsp.example/csc/v2"]"#)
            .json(),
    ]
}

/// §7.1.2's documents with a `data:` link, which §6.2.1 makes signature applications support, and
/// without a checksum.
pub fn embedded() -> String {
    with_documents(&[
        r#"{"label": "Example Configuration", "hash": "h", "hashType": "sodr", "href": "data:application/json;base64,eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K"}"#.to_owned(),
        r#"{"hash": "h", "hashType": "sodr", "href": "https://rp.example/a.pdf"}"#.to_owned(),
    ])
}
