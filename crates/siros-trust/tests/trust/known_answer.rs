//! The `aki` example of OpenID4VP 1.0, Section 6.1.1.1, against a certificate whose
//! AuthorityKeyIdentifier carries the bytes the value encodes.

use serde_json::json;
use siros_openid4vp::wallet::Holder;
use siros_trust::{AdmittedIssuer, ChainRefusal, IssuerFacts, TrustStore};

use crate::support::{at, base64, chain, chain_of, over_query, store, Cert, Key, NOW};

/// The specification's example value.
const AKI: &str = "s9tIpPmhxdiuNkHMEWNpYim8S8Y";

/// The bytes of [`AKI`], decoded by Python's `base64.urlsafe_b64decode`.
const KEY_IDENTIFIER: [u8; 20] = [
    0xb3, 0xdb, 0x48, 0xa4, 0xf9, 0xa1, 0xc5, 0xd8, 0xae, 0x36, 0x41, 0xcc, 0x11, 0x63, 0x69, 0x62,
    0x29, 0xbc, 0x4b, 0xc6,
];

/// [`AKI`] with the lowest bit of its last byte flipped, `0xc6` to `0xc7`.
const FLIPPED: &str = "s9tIpPmhxdiuNkHMEWNpYim8S8c";

/// The Document Signer of ISO/IEC 18013-5, Annex D.
const ANNEX_D_DOCUMENT_SIGNER: &[u8] = include_bytes!("vectors/annex_d_document_signer.der");

/// Its Authority Key Identifier as `openssl x509 -text` prints it,
/// 54:FA:23:83:A0:4C:28:E0:D9:30:79:22:61:C8:0C:48:81:D2:C0:0B, encoded by Python's
/// `base64.urlsafe_b64encode` without its padding.
const ANNEX_D_AKI: &str = "VPojg6BMKODZMHkiYcgMSIHSwAs";

const LIST: &str = "https://tl.example/eu";

#[test]
fn the_spec_aki_value_admits_its_key_and_a_flipped_bit_does_not() {
    let iaca = Cert::root("Test IACA", Key::p256(0x21));
    let document_signer =
        Cert::issued_by("Test Document Signer", Key::p256(0x22), &iaca).aki(&KEY_IDENTIFIER);
    let chain = chain(&[&document_signer]);
    let store = store(&[]);
    let resolve = |value: &str| {
        over_query(json!([{"type": "aki", "values": [value]}]), |query| {
            AdmittedIssuer::resolve(query, Some(&chain), &store, at(NOW))
        })
    };

    assert_eq!(resolve(AKI).unwrap().leaf(), Some(chain.leaf()));
    assert_eq!(
        resolve(FLIPPED).unwrap_err().refusals(),
        [ChainRefusal::KeyIdentifierAbsent]
    );
}

/// The registered facts admit Annex D's Document Signer by its `aki` and by the store entry that
/// lists it, in its validity; the matcher's rule and the witness's agree.
#[test]
fn annex_d_document_signer_is_admitted_by_its_aki_and_by_a_store_entry() {
    let chain = chain_of(ANNEX_D_DOCUMENT_SIGNER, &[]);
    let store = TrustStore::parse(
        &json!([{"type": "etsi_tl", "value": LIST,
            "certificates": [base64(ANNEX_D_DOCUMENT_SIGNER)]}])
        .to_string(),
    )
    .unwrap();
    let time = at("2021-01-01T00:00:00Z");
    let facts = IssuerFacts::at(Some(&chain), &store, time).facts(Holder::Bound);
    for (authorities, admitted) in [
        (json!([{"type": "aki", "values": [ANNEX_D_AKI]}]), true),
        (json!([{"type": "etsi_tl", "values": [LIST]}]), true),
        (json!([{"type": "aki", "values": [AKI]}]), false),
        (
            json!([{"type": "etsi_tl", "values": ["https://tl.example/other"]}]),
            false,
        ),
    ] {
        over_query(authorities, |query| {
            assert_eq!(
                facts.admits(query),
                admitted,
                "{:?}",
                query.trusted_authorities
            );
            assert_eq!(
                AdmittedIssuer::resolve(query, Some(&chain), &store, time).is_ok(),
                admitted,
                "{:?}",
                query.trusted_authorities
            );
        });
    }
}

/// A credential without an issuer chain holds no value: only a query naming no authority admits
/// it.
#[test]
fn an_issuer_without_a_chain_is_admitted_only_by_a_query_naming_no_authority() {
    let store = store(&[]);
    let resolve = |authorities| {
        over_query(authorities, |query| {
            AdmittedIssuer::resolve(query, None, &store, at(NOW))
                .map(|admitted| admitted.leaf().cloned())
        })
    };
    assert_eq!(resolve(serde_json::Value::Null), Ok(None));
    assert_eq!(
        resolve(json!([{"type": "aki", "values": [AKI]}]))
            .unwrap_err()
            .refusals(),
        [ChainRefusal::NoChain]
    );
}
