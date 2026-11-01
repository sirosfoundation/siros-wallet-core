//! The `aki` example of OpenID4VP 1.0, Section 6.1.1.1, against a certificate whose
//! AuthorityKeyIdentifier carries the bytes the value encodes.

use serde_json::json;
use siros_trust::{AdmittedIssuer, ChainRefusal, Ground, Refusal};

use crate::support::{at, authorities, chain, store, Cert, Key, NOW};

/// The specification's example value.
const AKI: &str = "s9tIpPmhxdiuNkHMEWNpYim8S8Y";

/// The bytes of [`AKI`], decoded by Python's `base64.urlsafe_b64decode`.
const KEY_IDENTIFIER: [u8; 20] = [
    0xb3, 0xdb, 0x48, 0xa4, 0xf9, 0xa1, 0xc5, 0xd8, 0xae, 0x36, 0x41, 0xcc, 0x11, 0x63, 0x69, 0x62,
    0x29, 0xbc, 0x4b, 0xc6,
];

/// [`AKI`] with the lowest bit of its last byte flipped, `0xc6` to `0xc7`.
const FLIPPED: &str = "s9tIpPmhxdiuNkHMEWNpYim8S8c";

#[test]
fn the_spec_aki_value_admits_its_key_and_a_flipped_bit_does_not() {
    let iaca = Cert::root("Test IACA", Key::p256(0x21));
    let document_signer =
        Cert::issued_by("Test Document Signer", Key::p256(0x22), &iaca).aki(&KEY_IDENTIFIER);
    let chain = chain(&[&document_signer]);
    let store = store(&[]);
    let resolve = |value: &str| {
        let query = authorities(json!([{"type": "aki", "values": [value]}]));
        AdmittedIssuer::resolve(&query, Some(&chain), &store, at(NOW))
    };

    let admitted = resolve(AKI).unwrap();
    let Ground::KeyIdentifier(key_identifier) = admitted.ground() else {
        panic!("admitted on another ground: {:?}", admitted.ground());
    };
    assert_eq!(key_identifier.as_bytes(), KEY_IDENTIFIER);
    assert_eq!(admitted.leaf(), Some(chain.leaf()));

    let refused = resolve(FLIPPED).unwrap_err();
    assert_eq!(
        refused.refusals(),
        [Refusal::Issuer(ChainRefusal::KeyIdentifierAbsent)]
    );
}
