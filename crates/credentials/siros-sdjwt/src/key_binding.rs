//! The presentation as sent and its Key Binding JWT (RFC 9901, Sections 4.3 and 4.3.1).

use rustc_hash::FxHashSet;
use serde_json::Value;
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_codec::signature::Es256Signature;

use crate::alg::HashAlg;
use crate::error::KeyBindingError;

/// The KB-JWT header. The host signs with ES256.
const HEADER: &str = r#"{"typ":"kb+jwt","alg":"ES256"}"#;

/// The payload claims Section 4.3 requires.
const REQUIRED: [&str; 4] = ["iat", "aud", "nonce", "sd_hash"];

/// `iat` of a KB-JWT: a NumericDate of whole seconds since 1970-01-01T00:00:00Z (RFC 7519,
/// Section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NumericDate(u64);

/// A time before 1970-01-01T00:00:00Z, which no NumericDate of whole seconds writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("time_before_epoch")]
pub struct BeforeEpoch;

impl NumericDate {
    /// The NumericDate of `time`.
    ///
    /// # Errors
    ///
    /// [`BeforeEpoch`] for a time before 1970-01-01T00:00:00Z.
    pub fn of(time: DateTime) -> Result<Self, BeforeEpoch> {
        u64::try_from(time.unix())
            .map(Self)
            .map_err(|_| BeforeEpoch)
    }

    /// The seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub fn seconds(self) -> u64 {
        self.0
    }
}

/// `aud` of a KB-JWT: the verifier the presentation is meant for (Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Audience(String);

impl Audience {
    /// The audience `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The audience.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `nonce` of a KB-JWT: the value the verifier's request gives for freshness (Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KbNonce(String);

impl KbNonce {
    /// The nonce `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The nonce.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An SD-JWT as sent to a verifier: the issuer JWT, then the selected disclosures, each
/// followed by `~` (Section 4).
pub struct Presentation {
    text: String,
    alg: HashAlg,
}

impl Presentation {
    pub(crate) fn new(text: String, alg: HashAlg) -> Self {
        Self { text, alg }
    }

    /// The compact form, sent alone when the verifier requires no key binding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The presentation with the signing input of its KB-JWT.
    ///
    /// The payload holds `iat`, `aud`, `nonce`, and `sd_hash` over [`as_str`](Self::as_str)
    /// with the credential's `_sd_alg` (Section 4.3.1), then the `extra` claims in their order.
    ///
    /// # Errors
    ///
    /// [`KeyBindingError`]: an extra claim repeats one of the four or another extra claim.
    pub fn key_binding(
        self,
        iat: NumericDate,
        aud: &Audience,
        nonce: &KbNonce,
        extra: &[(String, Value)],
    ) -> Result<KeyBinding, KeyBindingError> {
        let mut names = FxHashSet::default();
        for (name, _) in extra {
            if REQUIRED.contains(&name.as_str()) {
                return Err(KeyBindingError::RequiredClaim(name.clone()));
            }
            if !names.insert(name.as_str()) {
                return Err(KeyBindingError::RepeatedClaim(name.clone()));
            }
        }
        let sd_hash = self.alg.digest(self.text.as_bytes());
        let mut payload = format!(
            r#"{{"iat":{},"aud":{},"nonce":{},"sd_hash":"{}""#,
            iat.seconds(),
            json_string(aud.as_str()),
            json_string(nonce.as_str()),
            sd_hash.as_str(),
        );
        for (name, value) in extra {
            payload.push(',');
            payload.push_str(&json_string(name));
            payload.push(':');
            payload.push_str(&value.to_string());
        }
        payload.push('}');
        let signing_input = format!(
            "{}.{}",
            base64url::encode(HEADER.as_bytes()),
            base64url::encode(payload.as_bytes()),
        );
        Ok(KeyBinding {
            presentation: self.text,
            signing_input,
        })
    }
}

/// `text` as a JSON string.
fn json_string(text: &str) -> String {
    Value::from(text).to_string()
}

/// A presentation and the signing input of the KB-JWT bound to it.
pub struct KeyBinding {
    presentation: String,
    signing_input: String,
}

impl KeyBinding {
    /// The bytes the host signs: the KB-JWT's encoded header and payload, joined by `.` (RFC
    /// 7515, Section 5.1).
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    /// The SD-JWT+KB: the presentation, then the KB-JWT that `signature`, the ES256 signature
    /// over the signing input, completes (RFC 7518, Section 3.4).
    #[must_use]
    pub fn assemble(self, signature: &Es256Signature) -> String {
        let mut sd_jwt_kb = self.presentation;
        sd_jwt_kb.push_str(&self.signing_input);
        sd_jwt_kb.push('.');
        sd_jwt_kb.push_str(base64url::encode(signature.as_bytes()).as_str());
        sd_jwt_kb
    }
}
