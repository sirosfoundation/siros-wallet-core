//! What the host holds for transaction data in the tests: issuer metadata, documents and
//! records of absence; and the text of a label.

use serde_json::json;
use siros_display::{DisplayCache, IssuerMetadata};
use siros_oid4vp::HttpsUrl;
use siros_transaction_data::{HeldDocument, HeldMetadata, Segment, ShownLabel};

use super::wallet::VCT;

/// The display metadata of the wallet's credentials: the issuer metadata of the configuration
/// `example` of `https://issuer.example`, without a `credential_metadata_uri`.
pub fn issuer_display() -> DisplayCache {
    let issuer = json!({
        "credential_issuer": "https://issuer.example",
        "credential_configurations_supported": {"example": {"format": "dc+sd-jwt", "vct": VCT}}
    });
    let metadata = IssuerMetadata::merge(&issuer, "example", None).unwrap();
    DisplayCache::new(vec![metadata], Vec::new()).unwrap()
}

/// The metadata of the host's records that the documents of `urls` are absent.
pub fn holding_absent(urls: &[&str]) -> HeldMetadata {
    let documents = urls
        .iter()
        .map(|url| HeldDocument::absent(HttpsUrl::parse(url).unwrap()))
        .collect();
    HeldMetadata::new(Vec::new(), documents).unwrap()
}

/// The metadata of the documents `documents`, each the body its URL served.
pub fn holding(documents: Vec<(&str, Vec<u8>)>) -> HeldMetadata {
    let documents = documents
        .into_iter()
        .map(|(url, body)| HeldDocument::new(HttpsUrl::parse(url).unwrap(), body))
        .collect();
    HeldMetadata::new(Vec::new(), documents).unwrap()
}

/// The text of `label`, each value as the payload writes it.
pub fn label_text(label: &ShownLabel) -> String {
    label
        .segments()
        .iter()
        .map(|segment| match segment {
            Segment::Text(text) => text.clone(),
            Segment::Value(value) => value.text(),
        })
        .collect()
}
