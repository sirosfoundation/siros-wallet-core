//! RFC 7518, Appendix C: the Concat KDF derives the RFC's content encryption key.

#![allow(clippy::unwrap_used)]

use siros_oid4vp::{concat_kdf, ContentEncryption};

/// SOURCE: RFC 7518, Appendix C. `ECDH-ES` with `A128GCM`, `apu` "Alice" and `apv` "Bob".
#[test]
fn rfc7518_appendix_c() {
    let z = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ];
    let key = concat_kdf(&z, ContentEncryption::A128Gcm, b"Alice", b"Bob").unwrap();
    assert_eq!(
        key.as_bytes(),
        [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
    );
    assert_eq!(
        siros_codec::base64url::encode(key.as_bytes()),
        "VqqN6vgjbSBcIijNcacQGg"
    );
}
