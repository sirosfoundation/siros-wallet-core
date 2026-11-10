//! The COSE_Encrypt stand-in: a tagged COSE_Encrypt (RFC 9052 §5.1) whose ciphertext is the
//! plaintext, and the JOSE names of its algorithms.

use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::cose::coset::{
    CoseEncryptBuilder, CoseRecipientBuilder, HeaderBuilder, TaggedCborSerializable,
};
use siros_openid4vp::detail;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::{ContentEncryption, KeyAgreement};
use siros_syntax::checked;

use crate::{caused, fault};

/// The key agreements the stand-in writes, with their COSE algorithms (RFC 9053 §6.3).
pub const AGREEMENTS: [(KeyAgreement<'static>, iana::Algorithm); 4] = [
    (KeyAgreement::ECDH_ES, iana::Algorithm::ECDH_ES_HKDF_256),
    (
        checked!(KeyAgreement, "ECDH-ES+A128KW"),
        iana::Algorithm::ECDH_ES_A128KW,
    ),
    (
        checked!(KeyAgreement, "ECDH-ES+A192KW"),
        iana::Algorithm::ECDH_ES_A192KW,
    ),
    (
        checked!(KeyAgreement, "ECDH-ES+A256KW"),
        iana::Algorithm::ECDH_ES_A256KW,
    ),
];

/// The content encryptions the stand-in writes, with their COSE algorithms (RFC 9053 §4.1).
pub const ENCRYPTIONS: [(ContentEncryption<'static>, iana::Algorithm); 3] = [
    (ContentEncryption::A128GCM, iana::Algorithm::A128GCM),
    (
        checked!(ContentEncryption, "A192GCM"),
        iana::Algorithm::A192GCM,
    ),
    (ContentEncryption::A256GCM, iana::Algorithm::A256GCM),
];

/// The COSE algorithms of a key agreement and a content encryption (RFC 9053 §6.3, §4.1);
/// `None` for one the stand-in does not write.
#[must_use]
pub fn cose_algorithms(
    alg: KeyAgreement<'_>,
    enc: ContentEncryption<'_>,
) -> Option<(iana::Algorithm, iana::Algorithm)> {
    let recipient = AGREEMENTS
        .iter()
        .find(|(known, _)| known.as_str() == alg.as_str())
        .map(|(_, cose)| *cose)?;
    let content = ENCRYPTIONS
        .iter()
        .find(|(known, _)| known.as_str() == enc.as_str())
        .map(|(_, cose)| *cose)?;
    Some((recipient, content))
}

/// A tagged COSE_Encrypt whose ciphertext is the plaintext: the content encryption protected,
/// one recipient with the key agreement protected, the `kid` unprotected and an empty
/// ciphertext.
///
/// # Errors
///
/// An agreement the stand-in does not write, or coset cannot write the structure.
pub fn cose_encrypt(
    alg: KeyAgreement<'_>,
    enc: ContentEncryption<'_>,
    kid: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Fault> {
    let (recipient, content) = cose_algorithms(alg, enc).ok_or_else(|| {
        fault(detail!(
            "a key agreement or a content encryption the stand-in does not write"
        ))
    })?;
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
        .map_err(|e| caused(detail!("the COSE_Encrypt stand-in"), e))
}

/// The JOSE names of a COSE_Encrypt stand-in's recipient and content algorithms.
#[must_use]
pub fn jose_names(recipient: i64, content: i64) -> Option<(&'static str, &'static str)> {
    let (alg, _) = AGREEMENTS
        .iter()
        .find(|(_, cose)| cose.to_i64() == recipient)?;
    let (enc, _) = ENCRYPTIONS
        .iter()
        .find(|(_, cose)| cose.to_i64() == content)?;
    Some((alg.as_str(), enc.as_str()))
}
