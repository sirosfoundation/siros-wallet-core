//! siros-paso's modules' values: RFC 9562's random UUIDs for `jti`, and the `COSE_Encrypt` the
//! module returns (RFC 9052 §5.1) under a content encryption it states, and its trust store's
//! roots.

use siros_paso::{CoseEnc, NotSealedCose, RandomId, RootCertificate, SealedCose};

#[test]
fn a_random_id_is_a_version_4_uuid() {
    // RFC 9562 Appendix A.3's example.
    assert_eq!(
        RandomId::from_bytes([
            0x91, 0x91, 0x08, 0xf7, 0x52, 0xd1, 0x33, 0x20, 0x5b, 0xac, 0xf8, 0x47, 0xdb, 0x41,
            0x48, 0xa8
        ])
        .to_string(),
        "919108f7-52d1-4320-9bac-f847db4148a8"
    );
    // RFC 9562 §5.4: version 4 in the version field, the variant bits 10.
    assert_eq!(
        RandomId::from_bytes([0; 16]).to_string(),
        "00000000-0000-4000-8000-000000000000"
    );
    assert_eq!(
        RandomId::from_bytes([0xff; 16]).to_string(),
        "ffffffff-ffff-4fff-bfff-ffffffffffff"
    );
    assert!(RandomId::parse("00000000-0000-4000-9abc-000000000001").is_ok());
    for invalid in [
        "00000000-0000-1000-8000-000000000000",
        "00000000-0000-4000-c000-000000000000",
        "00000000-0000-4000-8000-00000000000A",
        "00000000-0000-4000-8000-0000000000000",
        "000000000000-4000-8000-000000000000",
    ] {
        assert!(RandomId::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn a_cose_encrypt_of_another_form_or_encryption_is_refused() {
    // RFC 9052 §5.1: tag 96 (d8 60) around [protected, unprotected, ciphertext, recipients]; the
    // protected header {1: 3} (43 a1 01 03) names A256GCM (RFC 9053 §4.1), 80 an empty array.
    let a256gcm = vec![0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x03, 0xa0, 0x40, 0x80];
    assert!(SealedCose::parse(a256gcm.clone(), &[CoseEnc::A256GCM]).is_ok());
    assert!(matches!(
        SealedCose::parse(a256gcm, &[CoseEnc::A128GCM]),
        Err(NotSealedCose::Enc)
    ));
    assert!(matches!(
        SealedCose::parse(vec![0x84, 0x40, 0xa0, 0x40, 0x80], &[CoseEnc::A256GCM]),
        Err(NotSealedCose::Untagged)
    ));
    // 96([]): the tagged content lacks the structure's four items.
    assert!(matches!(
        SealedCose::parse(vec![0xd8, 0x60, 0x80], &[CoseEnc::A256GCM]),
        Err(NotSealedCose::Structure(_))
    ));
}

#[test]
fn a_root_certificate_is_a_der_certificate() {
    // RFC 5280 §4.1: a SEQUENCE holding an INTEGER is no Certificate.
    assert!(RootCertificate::parse(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
    assert!(RootCertificate::parse(&siros_x509::test_util::root()).is_ok());
}
