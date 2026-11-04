//! The `COSE_Encrypt` module siros-paso seals an mdoc's risk signals with (Risk Signals §7.6),
//! with the values it exchanges (feature `sealed-signals`).

use siros_explain::Explain;
use siros_openid4vp::cbor::Item;
use siros_openid4vp::cbor::cose::coset::RegisteredLabelWithPrivate;
use siros_openid4vp::cbor::cose::coset::iana::EnumI64;
use siros_openid4vp::cbor::cose::{CoseShape, read_encrypt};
use siros_openid4vp::cbor::{CborError, Value, decode};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::AgreeableKey;

/// A content encryption a `COSE_Encrypt` carries (IANA "COSE Algorithms", RFC 9053 §4.1): its
/// integer value. The registry is open; a module states the ones it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoseEnc(i64);

impl CoseEnc {
    /// A128GCM (RFC 9053 §4.1).
    pub const A128GCM: Self = Self(1);
    /// A192GCM.
    pub const A192GCM: Self = Self(2);
    /// A256GCM.
    pub const A256GCM: Self = Self(3);

    /// The value as a COSE header writes it.
    #[must_use]
    pub const fn new(id: i64) -> Self {
        Self(id)
    }

    /// The value.
    #[must_use]
    pub const fn id(self) -> i64 {
        self.0
    }
}

/// A `COSE_Encrypt` (RFC 9052 §5.1), as [`CoseEncrypt::encrypt_cose`] returns it: one CBOR item,
/// tag 96, with distinct keys at every depth (the core's `cbor::decode`), whose structure coset
/// reads. Only [`SealedCose::parse`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCose(Vec<u8>);

/// A ciphertext [`CoseEncrypt`] returned that breaks its form's rule: the module broke its
/// contract.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "paso.sealed")]
pub enum NotSealedCose {
    /// The bytes are no CBOR data item the wallet reads.
    #[error("the ciphertext is no CBOR data item the wallet reads")]
    Cbor(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The data item is no tag 96.
    #[error("the ciphertext is no item tagged 96 (COSE_Encrypt)")]
    Untagged,
    /// The tagged content is no `COSE_Encrypt` structure (RFC 9052 §5.1).
    #[error("the ciphertext's content is no COSE_Encrypt structure")]
    Structure(
        #[source]
        #[explain(name = "cause")]
        CoseShape,
    ),
    /// A content encryption the module does not state.
    #[error("the ciphertext's content encryption is none the module states")]
    Enc,
}

impl SealedCose {
    /// The `COSE_Encrypt` of one CBOR data item tagged 96 with distinct keys at every depth,
    /// whose content is a `COSE_Encrypt` structure under one of `stated`.
    ///
    /// # Errors
    ///
    /// The bytes are no such data item, its content no `COSE_Encrypt`, or its content encryption
    /// none of `stated`.
    pub fn parse(bytes: Vec<u8>, stated: &[CoseEnc]) -> Result<Self, NotSealedCose> {
        let Value::Tag(96, structure) = decode(&bytes).map_err(NotSealedCose::Cbor)? else {
            return Err(NotSealedCose::Untagged);
        };
        let structure = read_encrypt(*structure).map_err(NotSealedCose::Structure)?;
        let enc = structure
            .protected
            .header
            .alg
            .as_ref()
            .and_then(|alg| match alg {
                RegisteredLabelWithPrivate::Assigned(alg) => Some(alg.to_i64()),
                RegisteredLabelWithPrivate::PrivateUse(id) => Some(*id),
                RegisteredLabelWithPrivate::Text(_) => None,
            });
        if !enc.is_some_and(|enc| stated.iter().any(|stated| stated.id() == enc)) {
            return Err(NotSealedCose::Enc);
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The data item a CBOR proof embeds.
    pub(crate) fn into_item(self) -> Result<Item, CborError> {
        Item::parse(self.0)
    }
}

/// A `COSE_Encrypt` (RFC 9052 §5.1, tag 96) to a public key, with one recipient holding the
/// ephemeral key and, as label 4, the key's `kid` (RFC 9053 §6.3, ECDH-ES + HKDF-256). Used when
/// the build holds it.
///
/// # Implementing
///
/// `encryptions` lists the content encryptions `encrypt_cose` implements; siros-paso seals under
/// one the risk signal's key and the statement both admit (Risk Signals §7.6: A256GCM), and
/// refuses a ciphertext of another ([`NotSealedCose::Enc`]). [`TestCoseEncrypt`] is the double.
pub trait CoseEncrypt {
    /// The content encryptions it implements.
    fn encryptions(&self) -> &'static [CoseEnc];
    /// The plaintext encrypted to a public key under the key's own agreement (`key.alg`: -25, or
    /// a key wrap -29 to -31) and `enc`.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    fn encrypt_cose(
        &self,
        key: &AgreeableKey<'_>,
        enc: CoseEnc,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Fault>;
}

#[cfg(feature = "test-util")]
mod test_util {
    use siros_explain::checked;
    use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
    use siros_openid4vp::cbor::cose::coset::{
        CoseEncryptBuilder, CoseRecipientBuilder, HeaderBuilder, TaggedCborSerializable,
    };
    use siros_openid4vp::detail;
    use siros_openid4vp::plugins::Fault;
    use siros_openid4vp::request::{AgreeableKey, KeyAgreement};

    use super::{CoseEnc, CoseEncrypt};
    use crate::FAULT;

    /// The key agreements the stand-in writes, with their COSE algorithms (RFC 9053 §6.3).
    const AGREEMENTS: [(KeyAgreement<'static>, iana::Algorithm); 4] = [
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

    /// The `COSE_Encrypt` double: a tagged COSE_Encrypt whose ciphertext is the plaintext, the
    /// content encryption protected, one recipient with the key's agreement (ECDH-ES for a key
    /// without one) protected, the `kid` unprotected and an empty ciphertext. It states A128GCM,
    /// A192GCM and A256GCM.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct TestCoseEncrypt;

    impl CoseEncrypt for TestCoseEncrypt {
        fn encryptions(&self) -> &'static [CoseEnc] {
            &[CoseEnc::A128GCM, CoseEnc::A192GCM, CoseEnc::A256GCM]
        }

        fn encrypt_cose(
            &self,
            key: &AgreeableKey<'_>,
            enc: CoseEnc,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, Fault> {
            let alg = key.alg().unwrap_or(KeyAgreement::ECDH_ES);
            let recipient = AGREEMENTS
                .iter()
                .find(|(known, _)| known.as_str() == alg.as_str())
                .map(|(_, cose)| *cose)
                .ok_or_else(|| {
                    Fault::new(
                        FAULT,
                        detail!("a key agreement the stand-in does not write"),
                    )
                })?;
            let content = iana::Algorithm::from_i64(enc.id()).ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("a content encryption the stand-in does not write"),
                )
            })?;
            CoseEncryptBuilder::new()
                .protected(HeaderBuilder::new().algorithm(content).build())
                .ciphertext(plaintext.to_vec())
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(recipient).build())
                        .unprotected(
                            HeaderBuilder::new()
                                .key_id(key.kid().as_bytes().to_vec())
                                .build(),
                        )
                        .ciphertext(Vec::new())
                        .build(),
                )
                .build()
                .to_tagged_vec()
                .map_err(|e| Fault::caused(FAULT, detail!("the COSE_Encrypt stand-in"), e))
        }
    }
}

#[cfg(feature = "test-util")]
pub use test_util::TestCoseEncrypt;
