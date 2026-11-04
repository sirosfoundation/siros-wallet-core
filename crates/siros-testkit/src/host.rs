//! The core's modules as deterministic doubles: the platform's clock, identifiers, credential
//! checks and End-User authentication ([`TestPlatform`]); stand-ins for HAIP's keystore
//! ([`TestHaip`]) and the `COSE_Encrypt` module ([`TestCoseEncrypt`]), whose ciphertexts keep
//! their plaintext readable for the checks; and [`test_host!`](crate::test_host), which states
//! the modules of a test's host.

use std::borrow::Cow;
use std::cell::Cell;
use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_explain::AllOf;
use siros_openid4vp::detail;
use siros_openid4vp::host::{
    Authentication, AuthenticationNeed, CoseEnc, CoseEncrypt, Factor, Haip, Knowledge, Platform,
    Possession, RandomId, RequestDecryption, SealedCose, SealedJwe, SignFailed, Signature,
    SignatureInvalid, Timestamp, Usable,
};
use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::jose::{Signed, VerificationKey};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::{AgreeableKey, ContentEncryption};
use siros_openid4vp::wallet::Credential;

use crate::FAULT;
use crate::cose::cose_encrypt;
use crate::jose::TestRequestDecryption;

/// The platform double. `unusable` lists the credentials no longer valid; `authentication` is
/// what authenticating the End-User gives, whatever the need. It counts the identifiers it
/// issued and the End-User authentications it was asked for.
#[derive(Debug, Clone)]
pub struct TestPlatform {
    /// The clock.
    pub now: Timestamp,
    /// The credentials that can no longer be presented.
    pub unusable: Vec<String>,
    /// The End-User's authentication; `None` when the user fails it.
    pub authentication: Option<Authentication>,
    issued: Cell<u64>,
    authentications: Cell<u64>,
}

/// A six-digit PIN unlocking a key in the device's native WSCD, completed at `at`.
#[must_use]
pub fn pin_and_device(at: Timestamp) -> Authentication {
    Authentication::new(
        at,
        AllOf::one(Factor::Knowledge(Knowledge::Pin(NonZeroU32::new(6))))
            .and(AllOf::one(Factor::Possession(Possession::LocalNativeWscd))),
    )
}

impl Default for TestPlatform {
    /// At 1 785 000 000, every credential usable, and the user authenticated with
    /// [`pin_and_device`].
    fn default() -> Self {
        Self::at(Timestamp(1_785_000_000))
    }
}

impl TestPlatform {
    /// The default platform at another time.
    #[must_use]
    pub fn at(now: Timestamp) -> Self {
        Self {
            now,
            unusable: Vec::new(),
            authentication: Some(pin_and_device(now)),
            issued: Cell::new(0),
            authentications: Cell::new(0),
        }
    }

    /// The platform once it has issued `count` identifiers: its next is the count after.
    #[must_use]
    pub fn after_issuing(self, count: u64) -> Self {
        self.issued.set(count);
        self
    }

    /// How many identifiers it issued.
    #[must_use]
    pub fn issued(&self) -> u64 {
        self.issued.get()
    }

    /// How many times it was asked to authenticate the End-User.
    #[must_use]
    pub fn authentications(&self) -> u64 {
        self.authentications.get()
    }
}

/// The first 8 bytes of SHA-256, in lowercase hexadecimal: the stand-ins' digest.
#[must_use]
pub fn digest_prefix(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Platform for TestPlatform {
    fn now(&self) -> Timestamp {
        self.now
    }

    fn usable<'c>(&self, credential: &'c Credential<'c>) -> Option<Usable<'c>> {
        (!self.unusable.iter().any(|id| *id == credential.id.as_str()))
            .then(|| Usable::checked(credential))
    }

    fn authenticate(&self, _need: AuthenticationNeed) -> Option<Authentication> {
        self.authentications.set(self.authentications.get() + 1);
        self.authentication.clone()
    }

    /// `00000000-0000-4000-8000-` and the count of identifiers issued in twelve decimal digits.
    fn random_id(&self) -> RandomId {
        let issued = self.issued.get() + 1;
        self.issued.set(issued);
        let digits: Vec<u8> = format!("{:012}", issued % 1_000_000_000_000)
            .bytes()
            .map(|digit| digit - b'0')
            .collect();
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().skip(10).zip(digits.chunks(2)) {
            *byte = pair.iter().fold(0, |value, digit| (value << 4) | digit);
        }
        RandomId::from_bytes(bytes)
    }
}

/// HAIP's keystore stand-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestHaip;

impl Haip for TestHaip {
    /// ES256 under the key, by p256.
    fn verify(&self, key: &VerificationKey, signed: &Signed<'_>) -> Result<(), SignatureInvalid> {
        crate::jose::verifies(key, signed.signing_input(), signed.signature().as_bytes())
            .then_some(())
            .ok_or(SignatureInvalid)
    }

    /// `sig:{credential}:{digest of the data}`.
    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed> {
        Ok(Signature::new(
            format!("sig:{credential}:{}", digest_prefix(data)).into_bytes(),
        ))
    }

    /// A JWE in compact serialization with the key's agreement as `alg`, and the plaintext,
    /// base64url-encoded, where the ciphertext goes.
    fn encrypt_jwe(
        &self,
        key: &AgreeableKey<'_>,
        enc: ContentEncryption,
        plaintext: &[u8],
    ) -> Result<SealedJwe, Fault> {
        let header = Node::object([
            (
                Cow::Borrowed("alg"),
                Node::String(Cow::Borrowed(key.alg.as_str())),
            ),
            (
                Cow::Borrowed("enc"),
                Node::String(Cow::Borrowed(enc.as_str())),
            ),
            (Cow::Borrowed("kid"), Node::String(Cow::Borrowed(key.kid))),
        ])
        .map_err(|e| Fault::caused(FAULT, detail!("a JWE header"), e))?;
        SealedJwe::parse(format!(
            "{}...{}.",
            URL_SAFE_NO_PAD.encode(header.python_ascii().to_string()),
            URL_SAFE_NO_PAD.encode(plaintext)
        ))
        .map_err(|e| Fault::caused(FAULT, detail!("the JWE stand-in"), e))
    }
}

/// The `COSE_Encrypt` module's stand-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestCoseEncrypt;

impl CoseEncrypt for TestCoseEncrypt {
    /// A tagged COSE_Encrypt whose ciphertext is the plaintext ([`cose_encrypt`]), under the
    /// key's agreement.
    fn encrypt_cose(
        &self,
        key: &AgreeableKey<'_>,
        enc: CoseEnc,
        plaintext: &[u8],
    ) -> Result<SealedCose, Fault> {
        SealedCose::parse(cose_encrypt(key.alg, enc, key.kid, plaintext)?)
            .map_err(|e| Fault::caused(FAULT, detail!("the COSE_Encrypt stand-in"), e))
    }
}

/// A test's host: a struct whose fields hold its handle modules, with `Has` for each module it
/// holds and `MayHave` for each module a plug-in uses when the build holds it, after axum's
/// `#[derive(FromRef)]`. `zero_sized` modules take no field: the host gives them as `&'static`.
///
/// ```
/// use siros_openid4vp::host::{CoseEncrypt, Haip, Host, Platform, RequestDecryption};
/// use siros_testkit::{TestCoseEncrypt, TestHaip, TestPlatform, TestRequestDecryption};
///
/// siros_testkit::test_host! {
///     /// The host of a test.
///     #[derive(Default)]
///     pub struct Wallet {
///         handles { platform: TestPlatform => Platform }
///         zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
///         optional { TestCoseEncrypt => CoseEncrypt }
///         lacks {}
///     }
/// }
///
/// let host = Wallet::default();
/// assert_eq!(host.get::<dyn Platform>().now(), host.platform.now);
/// assert!(host.maybe::<dyn CoseEncrypt>().is_some());
/// ```
#[macro_export]
macro_rules! test_host {
    (
        $(#[$meta:meta])*
        $vis:vis struct $host:ident {
            handles { $($field:ident: $double:ty => $module:path),* $(,)? }
            zero_sized { $($zero:expr => $zmodule:path),* $(,)? }
            optional { $($held:expr => $omodule:path),* $(,)? }
            lacks { $($lmodule:path),* $(,)? }
        }
    ) => {
        $(#[$meta])*
        $vis struct $host {
            $(
                #[doc = concat!("The `", stringify!($module), "` module.")]
                pub $field: $double,
            )*
        }
        $(impl $crate::reexport::Has<dyn $module> for $host {
            fn module(&self) -> &(dyn $module + 'static) {
                &self.$field
            }
        })*
        $(impl $crate::reexport::Has<dyn $zmodule> for $host {
            fn module(&self) -> &(dyn $zmodule + 'static) {
                &$zero
            }
        })*
        $(impl $crate::reexport::MayHave<dyn $omodule> for $host {
            type Slot = $crate::reexport::Held<dyn $omodule>;

            fn slot(&self) -> &Self::Slot {
                const HELD: $crate::reexport::Held<dyn $omodule> =
                    $crate::reexport::Held::new(&$held);
                &HELD
            }
        })*
        $(impl $crate::reexport::MayHave<dyn $lmodule> for $host {
            type Slot = $crate::reexport::Empty;

            fn slot(&self) -> &Self::Slot {
                &$crate::reexport::Empty
            }
        })*
    };
}

crate::test_host! {
    /// The core's modules: the platform double, and HAIP's and the `COSE_Encrypt` module's
    /// stand-ins.
    #[derive(Debug, Clone, Default)]
    pub struct TestHost {
        handles { platform: TestPlatform => Platform }
        zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional { TestCoseEncrypt => CoseEncrypt }
        lacks {}
    }
}

impl TestHost {
    /// The host of the default platform at another time.
    #[must_use]
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
        }
    }
}
