//! The host's modules (decision 13): one per family of capabilities a specification mandates
//! together. A plug-in states, as trait bounds on its implementation, the modules it requires
//! ([`Has`]) and those it uses when the build holds them ([`MayHave`]); a registry takes a
//! plug-in only when the build's host meets them. A run-time condition (a permission refused, a
//! sensor absent, a key missing) stays in the result of a module's call. Every module takes
//! `&self`: the state behind it is the platform's, and a module without state is a zero-sized
//! type the host gives as `&'static`.
//!
//! The core defines the access traits, its own modules ([`Platform`], [`Haip`],
//! [`RequestDecryption`], [`CoseEncrypt`]), the values they exchange, and each plug-in's phase 2 over the host
//! ([`ProfileHost`], [`FormatHost`]). A plug-in defines its own modules in its crate.

mod access;
mod authentication;
mod ciphertext;
mod ephemeral;
mod phase2;
mod values;

pub use crate::routing::AnsweredContext;
pub use access::{Empty, Has, Held, Host, MayHave, Slot};
pub use authentication::{
    Authentication, AuthenticationNeed, Categories, Factor, Inherence, Knowledge, Modality,
    Possession, Sensor, Strength,
};
pub use ciphertext::{CoseEnc, NotSealed, SealedCose, SealedJwe};
pub use ephemeral::{EphemeralKey, KeyHandle};
pub use phase2::{AnsweredOption, AnsweredQuery, FormatHost, PresentError, ProfileHost};
pub use values::{NotRandomId, Presentation, RandomId, Seconds, Signature, Timestamp, Usable};

use siros_explain::Explain;

use crate::ids::CredentialId;
use crate::jose::{CompactJwe, JweAlgorithms, JwsAlgorithms, Signed, VerificationKey};
use crate::plugins::Fault;
use crate::request::{AgreeableKey, Agreements, ContentEncryption};
use crate::wallet::Credential;

/// The wallet app: its clock, its credentials' status, the End-User's prompt, fresh ids.
pub trait Platform {
    /// The current time.
    fn now(&self) -> Timestamp;
    /// Whether the credential can still be presented (validity, status), checked now.
    fn usable<'c>(&self, credential: &'c Credential<'c>) -> Option<Usable<'c>>;
    /// The End-User's authentication, at least as strong as `need`; `None` when the End-User
    /// failed or cancelled.
    fn authenticate(&self, need: AuthenticationNeed) -> Option<Authentication>;
    /// A fresh random identifier.
    fn random_id(&self) -> RandomId;
}

/// HAIP's cryptography (HAIP §5, §7), one family (decision 13); the credentials' keys sit in the
/// platform's keystore. The module states what it implements, and the core accepts exactly that:
/// a module without a capability states none ([`JwsAlgorithms::NONE`], [`Agreements::NONE`]),
/// and the core never calls the method that would serve it.
pub trait Haip {
    /// The JWS algorithms `verify` verifies; HAIP's module states ES256 (§7).
    fn verifies(&self) -> JwsAlgorithms;
    /// The signature over the signing input under the key, by the signature's `alg`, called for
    /// a stated `alg` alone; a key that does not fit the `alg`, a point off its curve included,
    /// is `SignatureInvalid`.
    ///
    /// # Errors
    ///
    /// The signature does not verify under the key.
    fn verify(&self, key: &VerificationKey, signed: &Signed<'_>) -> Result<(), SignatureInvalid>;
    /// A signature with the credential's key.
    ///
    /// # Errors
    ///
    /// The End-User cancelled the key prompt, or the keystore broke its contract.
    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed>;
    /// The curves, key agreements and content encryptions `encrypt_jwe` implements, in the
    /// module's order of preference; HAIP's module states ECDH-ES on P-256 with A256GCM and
    /// A128GCM (§5).
    fn agreements(&self) -> Agreements;
    /// The plaintext encrypted to the key under its agreement and `enc`, as a compact JWE; the
    /// core calls it for a key and an `enc` its `agreements` state alone.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    fn encrypt_jwe(
        &self,
        key: &AgreeableKey<'_>,
        enc: ContentEncryption<'_>,
        plaintext: &[u8],
    ) -> Result<SealedJwe, Fault>;
}

/// A signature that does not verify under the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.host")]
#[error("the signature does not verify under the key")]
pub struct SignatureInvalid;

/// An encrypted Request Object (OpenID4VP §5.10, RFC 9101 §6.1); the key travels in the value.
pub trait RequestDecryption {
    /// The curves of the keys it draws and the JWE `alg` and `enc` values `decrypt` implements;
    /// HAIP's module states P-256, ECDH-ES, A256GCM and A128GCM.
    fn decrypts(&self) -> JweAlgorithms;

    /// A fresh key: its public JWK, on a stated curve, and the handle to the secret the module
    /// keeps.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    fn ephemeral_key(&self) -> Result<EphemeralKey, Fault>;

    /// The plaintext of a JWE encrypted to the key, as RFC 7516 §5.2 decrypts it: a `zip` of
    /// DEF uncompressed (step 17; §4.1.3: "MUST be understood and processed"). The key is
    /// consumed and its secret forgotten.
    ///
    /// # Errors
    ///
    /// The JWE does not decrypt under the key, whatever the cause.
    fn decrypt(&self, key: EphemeralKey, jwe: &CompactJwe<'_>) -> Result<Vec<u8>, DecryptFailed>;
}

/// A JWE that does not decrypt: one failure for every cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.host")]
#[error("the JWE does not decrypt under the key")]
pub struct DecryptFailed;

/// Why the credential's key made no signature.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.host")]
pub enum SignFailed {
    /// The End-User cancelled the key prompt.
    #[error("the End-User cancelled the signature")]
    Cancelled,
    /// The keystore broke its contract.
    #[error(transparent)]
    Fault(#[from] Fault),
}

/// A `COSE_Encrypt` (RFC 9052 §5.1, tag 96) to a public key, with one recipient holding the
/// ephemeral key and the key's `kid` (RFC 9053 §6.3, ECDH-ES + HKDF-256): siros-paso's sealed
/// signals. Used when the build holds it.
pub trait CoseEncrypt {
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
    ) -> Result<SealedCose, Fault>;
}

/// The modules the core itself needs, and the module it uses when the build holds it.
pub trait CoreHost:
    Has<dyn Platform> + Has<dyn Haip> + Has<dyn RequestDecryption> + MayHave<dyn CoseEncrypt>
{
}

impl<H: Has<dyn Platform> + Has<dyn Haip> + Has<dyn RequestDecryption> + MayHave<dyn CoseEncrypt>>
    CoreHost for H
{
}
