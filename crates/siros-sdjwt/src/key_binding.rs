//! The presentation as sent and its Key Binding JWT (S4; RFC 9901 §4.3, §4.3.1).

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::json::Node;

use crate::alg::{HashAlg, SigningAlg};
use crate::error::KeyBindingError;

/// `iat` of a Key Binding JWT: whole seconds since 1970-01-01T00:00:00Z (RFC 7519 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NumericDate(pub u64);

/// `aud` of a Key Binding JWT: the Verifier the presentation is meant for (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Audience(String);

impl Audience {
    /// The audience `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }
}

/// `nonce` of a Key Binding JWT: the value the Verifier's request gives for freshness (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KbNonce(String);

impl KbNonce {
    /// The nonce `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }
}

/// An SD-JWT as sent to a Verifier: the Issuer-signed JWT, then the selected disclosures, each
/// followed by `~` (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    text: String,
    alg: HashAlg,
}

/// What a Key Binding JWT claims (§4.3).
#[derive(Debug, Clone, Copy)]
pub struct Binding<'b> {
    /// The holder key's JWS algorithm, the header's `alg`.
    pub alg: &'b SigningAlg,
    /// When the wallet signs.
    pub iat: NumericDate,
    /// The Verifier.
    pub aud: &'b Audience,
    /// The freshness value.
    pub nonce: &'b KbNonce,
}

impl Presentation {
    pub(crate) fn new(text: String, alg: HashAlg) -> Self {
        Self { text, alg }
    }

    /// The compact form, sent alone when no key binds the credential.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The presentation with the signing input of its Key Binding JWT: the header `{"typ", "alg"}`
    /// and the payload `iat`, `aud`, `nonce`, `sd_hash` over [`Self::as_str`] with the credential's
    /// `_sd_alg` (§4.3.1), then the `extra` claims in their order.
    ///
    /// # Errors
    ///
    /// [`KeyBindingError`]: an extra claim repeats one of the four or another extra claim.
    pub fn key_binding<'x>(
        self,
        binding: Binding<'_>,
        extra: impl IntoIterator<Item = (Cow<'x, str>, Node<'x>)>,
    ) -> Result<KeyBinding, KeyBindingError> {
        let text = |value: &str| Node::String(Cow::Owned(value.to_owned()));
        let header = Node::object([
            (Cow::Borrowed("typ"), text("kb+jwt")),
            (Cow::Borrowed("alg"), text(binding.alg.as_str())),
        ])?;
        let sd_hash = self.alg.digest(self.text.as_bytes());
        let seconds = i128::from(binding.iat.0);
        let mut claims: Vec<(Cow<'x, str>, Node<'x>)> = vec![
            (Cow::Borrowed("iat"), Node::integer(seconds)),
            (Cow::Borrowed("aud"), text(&binding.aud.0)),
            (Cow::Borrowed("nonce"), text(&binding.nonce.0)),
            (Cow::Borrowed("sd_hash"), text(sd_hash.as_str())),
        ];
        claims.extend(extra);
        let payload = Node::object(claims)?;
        let signing_input = format!("{}.{}", encoded(&header), encoded(&payload));
        Ok(KeyBinding {
            presentation: self.text,
            signing_input,
        })
    }
}

/// base64url without padding over the compact JSON.
fn encoded(node: &Node<'_>) -> String {
    URL_SAFE_NO_PAD.encode(node.python_compact().to_string())
}

/// A presentation and the signing input of the Key Binding JWT bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBinding {
    presentation: String,
    signing_input: String,
}

impl KeyBinding {
    /// The bytes the keystore signs: the encoded header and payload, joined by `.` (RFC 7515
    /// §5.1).
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    /// The SD-JWT+KB: the presentation, then the compact Key Binding JWT `signature` completes.
    #[must_use]
    pub fn assemble(self, signature: &[u8]) -> String {
        format!(
            "{}{}.{}",
            self.presentation,
            self.signing_input,
            URL_SAFE_NO_PAD.encode(signature)
        )
    }
}
