//! The COSE_Encrypt stand-in: a tagged COSE_Encrypt (RFC 9052 §5.1) whose ciphertext is the
//! plaintext, and the JOSE names of its algorithms.

use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::cose::coset::{
    CoseEncryptBuilder, CoseRecipientBuilder, HeaderBuilder, TaggedCborSerializable,
};
use siros_openid4vp::detail;
use siros_openid4vp::host::CoseEnc;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::KeyAgreement;

use crate::FAULT;

/// The COSE algorithms of a key agreement and a content encryption (RFC 9053 §6.3, §4.1).
#[must_use]
pub const fn cose_algorithms(
    alg: KeyAgreement,
    enc: CoseEnc,
) -> (iana::Algorithm, iana::Algorithm) {
    let recipient = match alg {
        KeyAgreement::EcdhEs => iana::Algorithm::ECDH_ES_HKDF_256,
        KeyAgreement::EcdhEsA128Kw => iana::Algorithm::ECDH_ES_A128KW,
        KeyAgreement::EcdhEsA192Kw => iana::Algorithm::ECDH_ES_A192KW,
        KeyAgreement::EcdhEsA256Kw => iana::Algorithm::ECDH_ES_A256KW,
    };
    let content = match enc {
        CoseEnc::A128Gcm => iana::Algorithm::A128GCM,
        CoseEnc::A192Gcm => iana::Algorithm::A192GCM,
        CoseEnc::A256Gcm => iana::Algorithm::A256GCM,
    };
    (recipient, content)
}

/// A tagged COSE_Encrypt whose ciphertext is the plaintext: the content encryption protected,
/// one recipient with the key agreement protected, the `kid` unprotected and an empty
/// ciphertext.
///
/// # Errors
///
/// coset cannot write the structure.
pub fn cose_encrypt(
    alg: KeyAgreement,
    enc: CoseEnc,
    kid: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Fault> {
    let (recipient, content) = cose_algorithms(alg, enc);
    CoseEncryptBuilder::new()
        .protected(HeaderBuilder::new().algorithm(content).build())
        .ciphertext(plaintext.to_vec())
        .add_recipient(
            CoseRecipientBuilder::new()
                .protected(HeaderBuilder::new().algorithm(recipient).build())
                .unprotected(HeaderBuilder::new().key_id(kid.as_bytes().to_vec()).build())
                .ciphertext(Vec::new())
                .build(),
        )
        .build()
        .to_tagged_vec()
        .map_err(|e| Fault::caused(FAULT, detail!("the COSE_Encrypt stand-in"), e))
}

/// The JOSE names of a COSE_Encrypt stand-in's recipient and content algorithms.
#[must_use]
pub fn jose_names(recipient: i64, content: i64) -> Option<(&'static str, &'static str)> {
    let alg = [
        KeyAgreement::EcdhEs,
        KeyAgreement::EcdhEsA128Kw,
        KeyAgreement::EcdhEsA192Kw,
        KeyAgreement::EcdhEsA256Kw,
    ]
    .into_iter()
    .find(|alg| cose_algorithms(*alg, CoseEnc::A128Gcm).0.to_i64() == recipient)?;
    let enc = [CoseEnc::A128Gcm, CoseEnc::A192Gcm, CoseEnc::A256Gcm]
        .into_iter()
        .find(|enc| enc.id() == content)?;
    Some((alg.as_str(), enc.as_str()))
}
