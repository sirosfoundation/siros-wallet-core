//! COSE ECDH-ES + HKDF-256 direct key agreement derives the content keys of the cose-wg
//! examples.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use siros_oid4vp::{cose_kdf, ContentEncryption};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// SOURCE: github.com/cose-wg/Examples, `ecdh-direct-examples/p256-hkdf-256-01.json` and
/// `-02.json`: ECDH-ES (-25) direct with HKDF SHA-256 for A128GCM and A256GCM, recipient
/// protected header `{1: -25}`, no PartyU or PartyV information. The intermediates give the
/// secret Z and the CEK.
#[test]
fn cose_wg_ecdh_direct_hkdf_256() {
    let z = hex("4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6");
    let cases = [
        (
            ContentEncryption::A128Gcm,
            "56074D506729CA40C4B4FE50C6439893",
        ),
        (
            ContentEncryption::A256Gcm,
            "29CAA7326B683A73C98777707866D8838A3ADC3E3F46C180C54C5AAF01F1CC0C",
        ),
    ];
    for (enc, cek) in cases {
        assert_eq!(cose_kdf(&z, enc).unwrap().as_bytes(), hex(cek), "{enc:?}");
    }
}
