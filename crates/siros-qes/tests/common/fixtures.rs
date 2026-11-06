//! The fixtures the tests assert and the differential gives the model: changes to the CSC
//! examples, the documents' contents, and the type's rule table.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest;
use siros_openid4vp::json::quote;
use siros_qes::Problem;

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

/// Whether a refusal is the one a fixture expects.
pub type Refuses = fn(&Problem) -> bool;

/// One fixture per rule of the type: §7.1.2's entry changed to break it, and the check of the
/// rule's refusal.
pub fn rule_table() -> Vec<(String, Refuses)> {
    let documents = |docs: &str| approval().set("documentInfos", docs);
    let table: Vec<(Fields, Refuses)> = vec![
        (
            approval().set("signAlgo", r#""1.2.840.113549.1.1.1""#),
            |p| matches!(p, Problem::UnknownMember(member) if member == "signAlgo"),
        ),
        (approval().set("numSignatures", "0"), |p| {
            matches!(p, Problem::SignatureCount)
        }),
        (
            approval().set("signatureQualifier", r#""za_ecta_aes""#),
            |p| matches!(p, Problem::SignatureQualifier(_)),
        ),
        (approval().without("hashAlgorithmOID"), |p| {
            matches!(p, Problem::NoHashAlgorithm)
        }),
        (
            approval().set("hashAlgorithmOID", r#""1.2.840.113549.2.5""#),
            |p| matches!(p, Problem::UnknownHashAlgorithm(oid) if oid == "1.2.840.113549.2.5"),
        ),
        (documents("[]"), |p| matches!(p, Problem::NoDocuments)),
        (
            documents(r#"[{"label": "x"}]"#),
            |p| matches!(p, Problem::NotADocument(at) if at.get() == 0),
        ),
        (
            documents(r#"[{"hash": "h", "hashType": "sodr", "access": {"type": "OTP"}}]"#),
            |p| matches!(p, Problem::OtpWithoutPassword(at) if at.get() == 0),
        ),
        (
            approval().set("locations", r#""https://rsp.example""#),
            |p| matches!(p, Problem::Locations),
        ),
    ];
    table
        .into_iter()
        .map(|(fields, rule)| (fields.json(), rule))
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
