//! PaSO Credentials and the `transaction_data` entries that target them.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde_json::{json, Value};
use siros_display::{DisplayCache, IssuerMetadata};
use siros_oid4vp::HttpsUrl;
use siros_transaction_data::{HeldDocument, HeldJwt, HeldMetadata};
use siros_trust::TrustStore;
use siros_wallet_state::{ConfigurationId, IssuerIdentifier};
use siros_zkp_req_nym_auth::testing::Issuer;

use super::verifier::{b64, NOW};
use super::wallet::{base64, sd_jwt_x5c, Held, Wallet, VCT};

pub const APPROVAL: &str = "urn:paso:sca:com.example:approval:1";
pub const METADATA_URI: &str = "https://issuer.example/metadata/pid";

/// The definition of [`APPROVAL`]: one mandatory claim and the affirmative action label.
pub fn approval() -> Value {
    json!({
        "claims": [{"path": ["what"], "mandatory": true,
                    "display": [{"locale": "en", "name": "What"}]}],
        "ui_labels": {"affirmative_action_label": [{"locale": "en", "value": "Approve"}]}
    })
}

/// A `transaction_data` entry of `type_id` naming the query `query`, with `payload`, as the
/// verifier sends it.
pub fn entry(type_id: &str, query: &str, payload: Value) -> String {
    let entry = json!({"type": type_id, "credential_ids": [query], "payload": payload});
    b64(entry.to_string().as_bytes())
}

/// The signed credential metadata JWT of [`VCT`] (PaSO Proof Metadata, Section 4) defining
/// `types`, which `signer` signs.
pub fn credential_metadata(signer: &Issuer, types: &Value) -> String {
    let header =
        json!({"alg": "ES256", "typ": "credential-metadata+jwt", "x5c": [base64(&signer.der)]});
    let claims = json!({
        "iss": "https://issuer.example", "sub": VCT, "format": "dc+sd-jwt",
        "iat": NOW - 86_400, "exp": NOW + 86_400, "credential_metadata_uri": METADATA_URI,
        "credential_metadata": {"transaction_data_types": types}
    });
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature: Signature = signer.key.sign(input.as_bytes());
    format!("{input}.{}", b64(&signature.to_bytes()))
}

/// A wallet holding one PID of a Document Signer under a trusted root, whose issuer metadata
/// names [`METADATA_URI`], and whose host holds the credential metadata that defines `types`,
/// which the Document Signer signs.
pub fn paso_wallet(types: Value) -> Wallet {
    let root = Issuer::root(0x71, "Bank root");
    let signer = root.sign_child(0x72, "Bank Document Signer");
    let claims = [("given_name", json!("Erika"))];
    let mut wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt_x5c(VCT, &claims, &[&signer.der]),
    )]);
    let anchors = json!([{"type": "etsi_tl", "value": "https://tl.example/eu",
                          "certificates": [base64(&root.der)]}]);
    wallet.trust = TrustStore::parse(&anchors.to_string()).unwrap();
    let issuer = json!({
        "credential_issuer": "https://issuer.example",
        "credential_configurations_supported": {"example": {
            "format": "dc+sd-jwt", "vct": VCT, "credential_metadata_uri": METADATA_URI
        }}
    });
    let metadata = IssuerMetadata::merge(&issuer, "example", None).unwrap();
    wallet.display = DisplayCache::new(vec![metadata], Vec::new()).unwrap();
    let jwt = HeldJwt::new(
        IssuerIdentifier::parse("https://issuer.example").unwrap(),
        ConfigurationId::parse("example").unwrap(),
        credential_metadata(&signer, &types),
        HttpsUrl::parse(METADATA_URI).unwrap(),
    );
    let absent = HeldDocument::absent(HttpsUrl::parse(VCT).unwrap());
    wallet.metadata = HeldMetadata::new(vec![jwt], vec![absent]).unwrap();
    wallet
}
