//! JOSE as requests carry it: a JWS in compact and JSON serialization (RFC 7515 §7) whose `alg`
//! is ES256, a compact JWE Request Object (RFC 7516 §7.1), and under `resolve` the JWT claims a
//! recipient checks (RFC 7519 §4.1) and the P-256 key a signature verifies under. JSON parses
//! through the core's [`json`](crate::json) module, which refuses a repeated member name at every
//! level; base64url decodes through the `base64` crate, without padding.

#[cfg(feature = "resolve")]
mod key;
mod parts;
#[cfg(feature = "resolve")]
mod time;

use std::borrow::Cow;

use siros_explain::Explain;

use crate::json::{JsonError, Node, Object};
use parts::{decode, object, utf8};

#[cfg(feature = "resolve")]
pub use key::{NotOnCurve, VerificationKey};
#[cfg(feature = "resolve")]
pub use time::{NumericDate, Skew, SkewTooLarge, TimeError, Validity};

/// Why a JWS does not parse (U10, U16).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.jws")]
pub enum JwsError {
    /// Not three parts, or a JWS JSON Serialization without its members (RFC 7515 §7).
    #[error("the JWS does not have the structure of its serialization")]
    Structure,
    /// A part is no base64url without padding.
    #[error("a JWS part is no base64url without padding")]
    Base64,
    /// A header, the payload or the JSON Serialization is no JSON object with unique member
    /// names at every level, or no UTF-8.
    #[error("{0}")]
    Json(#[explain(name = "cause")] JsonError),
    /// `alg` absent or other than ES256 (RFC 8725 §3.1, HAIP §7).
    #[error("alg {0:?}: the wallet verifies ES256 alone")]
    Algorithm(#[explain(name = "alg")] Option<String>),
    /// An ES256 signature of another length than 64 octets (RFC 7518 §3.4).
    #[error("the signature holds {0} octets; ES256 holds 64")]
    SignatureLength(#[explain(name = "octets")] usize),
    /// `crit` empty, outside the protected header, or naming a header the wallet does not
    /// process (RFC 7515 §4.1.11; U16).
    #[error("crit {0}: the wallet does not process it")]
    Critical(#[explain(name = "header")] String),
    /// A name in both a signature's protected and unprotected header (RFC 7515 §7.2.1).
    #[error("the protected and unprotected headers both name {0}")]
    HeaderTwice(#[explain(name = "header")] String),
}

impl From<JsonError> for JwsError {
    fn from(cause: JsonError) -> Self {
        Self::Json(cause)
    }
}

/// An ES256 signature: R and S, 32 octets each, big-endian (RFC 7518 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Es256Signature([u8; 64]);

impl Es256Signature {
    /// The signature of 64 octets; refused for another length.
    fn of(bytes: &[u8]) -> Result<Self, JwsError> {
        <[u8; 64]>::try_from(bytes)
            .map(Self)
            .map_err(|_| JwsError::SignatureLength(bytes.len()))
    }

    /// R then S.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// A protected header whose `alg` is ES256 (RFC 7515 §4): `typ` and `kid` read, `crit` refused,
/// every member kept for the prefix plug-in, which reads its own (the certificate chain).
#[derive(Debug, Clone)]
pub struct ProtectedHeader {
    typ: Option<String>,
    kid: Option<String>,
    members: Object<'static>,
}

impl ProtectedHeader {
    /// The header of a decoded protected header part.
    fn parse(part: &[u8]) -> Result<Self, JwsError> {
        let members = object(&utf8(part)?)?;
        match members.get("alg") {
            Some(Node::String(alg)) if alg == "ES256" => {}
            other => return Err(JwsError::Algorithm(other.map(shown))),
        }
        critical(&members)?;
        let member = |name: &str| members.get(name).and_then(Node::as_str).map(str::to_owned);
        Ok(Self {
            typ: member("typ"),
            kid: member("kid"),
            members,
        })
    }

    /// `typ` as received.
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// Whether `typ` names the media type: compared as RFC 7515 §4.1.9 says, `application/`
    /// prefixed when it holds no `/`, case-insensitively.
    #[must_use]
    pub fn typ_is(&self, subtype: &str) -> bool {
        self.typ.as_deref().is_some_and(|typ| {
            let bare = match typ.split_once('/') {
                None => Some(typ),
                Some((kind, rest)) => kind.eq_ignore_ascii_case("application").then_some(rest),
            };
            bare.is_some_and(|bare| bare.eq_ignore_ascii_case(subtype))
        })
    }

    /// `kid`, a case-sensitive string.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// A member as received.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Node<'static>> {
        self.members.get(name)
    }
}

/// A value as a message names it: a string's text, another value's JSON.
fn shown(value: &Node<'_>) -> String {
    value
        .as_str()
        .map_or_else(|| value.python_compact().to_string(), str::to_owned)
}

/// RFC 7515 §4.1.11: `crit` lists the extensions a recipient must process. The wallet processes
/// none, so a `crit` it finds is refused, an empty one too.
fn critical(members: &Object<'_>) -> Result<(), JwsError> {
    members.get("crit").map_or(Ok(()), |crit| {
        let first = crit
            .as_array()
            .and_then(|names| names.first())
            .map_or_else(|| shown(crit), shown);
        Err(JwsError::Critical(first))
    })
}

/// A JWS in compact serialization (RFC 7515 §7.1): its text, its protected header, its payload
/// decoded to UTF-8, its signing input and its signature.
#[derive(Debug, Clone)]
pub struct CompactJws<'t> {
    text: Cow<'t, str>,
    header: ProtectedHeader,
    payload: String,
    signing_input: String,
    signature: Es256Signature,
}

impl<'t> CompactJws<'t> {
    /// Splits the three parts, decodes them and parses the header; refused per [`JwsError`].
    /// The payload's JSON is read by the envelope.
    ///
    /// # Errors
    ///
    /// The text breaks a rule of [`JwsError`].
    pub fn parse(text: impl Into<Cow<'t, str>>) -> Result<Self, JwsError> {
        let text = text.into();
        let (header, payload, signature) = match text.split('.').collect::<Vec<_>>()[..] {
            [header, payload, signature] => (header, payload, signature),
            _ => return Err(JwsError::Structure),
        };
        let signing_input = format!("{header}.{payload}");
        let header = ProtectedHeader::parse(&decode(header).map_err(|_| JwsError::Base64)?)?;
        let payload = utf8(&decode(payload).map_err(|_| JwsError::Base64)?)?.into_owned();
        let signature = Es256Signature::of(&decode(signature).map_err(|_| JwsError::Base64)?)?;
        Ok(Self {
            header,
            payload,
            signing_input,
            signature,
            text,
        })
    }

    /// The text as received.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The protected header.
    #[must_use]
    pub const fn header(&self) -> &ProtectedHeader {
        &self.header
    }

    /// The payload, UTF-8.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// The one signature.
    #[must_use]
    pub fn signed(&self) -> Signed<'_> {
        Signed {
            header: &self.header,
            unprotected: None,
            signing_input: self.signing_input.as_bytes(),
            signature: &self.signature,
        }
    }
}

/// A JWS in JSON serialization, general or flattened (RFC 7515 §7.2): the text as received, the
/// payload decoded, each signature with its headers: one or more, the first apart.
#[derive(Debug, Clone)]
pub struct JsonJws<'t> {
    text: Cow<'t, str>,
    payload: String,
    first: JsonSignature,
    rest: Vec<JsonSignature>,
}

/// One signature of a JWS JSON Serialization: its protected header, its unprotected header
/// (names disjoint from the protected one's), its signing input, its signature.
#[derive(Debug, Clone)]
pub struct JsonSignature {
    header: ProtectedHeader,
    unprotected: Option<Object<'static>>,
    signing_input: String,
    signature: Es256Signature,
}

impl JsonSignature {
    /// One signature object (or the flattened serialization's members) over the payload part.
    fn parse(members: &Object<'_>, payload: &str) -> Result<Self, JwsError> {
        let protected = members
            .get("protected")
            .and_then(Node::as_str)
            .ok_or(JwsError::Structure)?;
        let header = ProtectedHeader::parse(&decode(protected).map_err(|_| JwsError::Base64)?)?;
        let unprotected = match members.get("header") {
            None => None,
            Some(Node::Object(unprotected)) => Some(unprotected.clone().into_owned()),
            Some(_) => return Err(JwsError::Structure),
        };
        if let Some(unprotected) = &unprotected {
            if unprotected.get("crit").is_some() {
                return Err(JwsError::Critical("crit".to_owned()));
            }
            if let Some(name) = unprotected
                .names()
                .find(|name| header.members.get(name).is_some())
            {
                return Err(JwsError::HeaderTwice(name.to_owned()));
            }
        }
        let signature = members
            .get("signature")
            .and_then(Node::as_str)
            .ok_or(JwsError::Structure)?;
        Ok(Self {
            header,
            unprotected,
            signing_input: format!("{protected}.{payload}"),
            signature: Es256Signature::of(&decode(signature).map_err(|_| JwsError::Base64)?)?,
        })
    }

    fn signed(&self) -> Signed<'_> {
        Signed {
            header: &self.header,
            unprotected: self.unprotected.as_ref(),
            signing_input: self.signing_input.as_bytes(),
            signature: &self.signature,
        }
    }
}

impl<'t> JsonJws<'t> {
    /// Parses the serialization; refused per [`JwsError`], an empty `signatures` array included
    /// (RFC 7515 §7.2.1).
    ///
    /// # Errors
    ///
    /// The text breaks a rule of [`JwsError`].
    pub fn parse(text: impl Into<Cow<'t, str>>) -> Result<Self, JwsError> {
        let text = text.into();
        let Node::Object(members) = Node::parse(&text)? else {
            return Err(JwsError::Structure);
        };
        let payload_part = members
            .get("payload")
            .and_then(Node::as_str)
            .ok_or(JwsError::Structure)?;
        let payload = utf8(&decode(payload_part).map_err(|_| JwsError::Base64)?)?.into_owned();
        let mut signatures = match members.get("signatures") {
            Some(Node::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Node::Object(signature) => JsonSignature::parse(signature, payload_part),
                    _ => Err(JwsError::Structure),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(JwsError::Structure),
            None => vec![JsonSignature::parse(&members, payload_part)?],
        }
        .into_iter();
        let first = signatures.next().ok_or(JwsError::Structure)?;
        let rest = signatures.collect();
        Ok(Self {
            text,
            payload,
            first,
            rest,
        })
    }

    /// The text as received.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The payload, UTF-8.
    #[must_use]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// Each signature with its unprotected header, in the order received: one or more.
    pub fn signatures(&self) -> impl Iterator<Item = Signed<'_>> {
        std::iter::once(self.first()).chain(self.rest())
    }

    /// The first signature.
    #[must_use]
    pub fn first(&self) -> Signed<'_> {
        self.first.signed()
    }

    /// The signatures after the first, in the order received.
    pub fn rest(&self) -> impl Iterator<Item = Signed<'_>> {
        self.rest.iter().map(JsonSignature::signed)
    }
}

/// A signature to verify, as the JWS holds it: its protected header, its unprotected header (a
/// JWS JSON Serialization's), its signing input (RFC 7515 §5.1 step 8) and its bytes. Only the
/// JWS it belongs to makes one, so the signing input is that header's and that payload's.
#[derive(Debug, Clone, Copy)]
pub struct Signed<'s> {
    header: &'s ProtectedHeader,
    unprotected: Option<&'s Object<'static>>,
    signing_input: &'s [u8],
    signature: &'s Es256Signature,
}

impl<'s> Signed<'s> {
    /// The protected header.
    #[must_use]
    pub const fn header(&self) -> &'s ProtectedHeader {
        self.header
    }

    /// The unprotected header; `None` for a compact JWS, and for a JSON one without it.
    #[must_use]
    pub const fn unprotected(&self) -> Option<&'s Object<'static>> {
        self.unprotected
    }

    /// ASCII(BASE64URL(protected header) || '.' || BASE64URL(payload)).
    #[must_use]
    pub const fn signing_input(&self) -> &'s [u8] {
        self.signing_input
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &'s Es256Signature {
        self.signature
    }
}

/// Why a JWE Request Object does not parse (U11).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.jwe")]
pub enum JweError {
    /// Not five parts (RFC 7516 §7.1).
    #[error("the JWE does not have five parts")]
    Structure,
    /// A part is no base64url without padding.
    #[error("a JWE part is no base64url without padding")]
    Base64,
    /// The protected header is no JSON object with unique member names at every level.
    #[error("{0}")]
    Json(#[explain(name = "cause")] JsonError),
    /// `alg` absent or other than `ECDH-ES` (RFC 7518 §4.6; HAIP §5).
    #[error("alg {0:?}: the wallet decrypts ECDH-ES alone")]
    Algorithm(#[explain(name = "alg")] Option<String>),
    /// `enc` absent or other than A128GCM and A256GCM (HAIP §5).
    #[error("enc {0:?}: the wallet decrypts A128GCM and A256GCM alone")]
    Encryption(#[explain(name = "enc")] Option<String>),
    /// `crit` naming a header the wallet does not process (RFC 7516 §4.1.13).
    #[error("crit {0}: the wallet does not process it")]
    Critical(#[explain(name = "header")] String),
}

/// A compact JWE Request Object (RFC 7516 §7.1): five base64url parts, its protected header read,
/// with `alg` `ECDH-ES` and `enc` A128GCM or A256GCM, the algorithms the wallet accepts (RFC 8725
/// §3.1; HAIP §5). `RequestDecryption::decrypt` decrypts it.
#[derive(Debug, Clone)]
pub struct CompactJwe<'t> {
    text: &'t str,
    header: Object<'static>,
}

/// The `alg` values a [`CompactJwe`] Request Object may name (HAIP §5).
const JWE_ALGORITHMS: &[&str] = &["ECDH-ES"];

/// The `enc` values a [`CompactJwe`] Request Object may name (HAIP §5).
const JWE_ENCRYPTIONS: &[&str] = &["A128GCM", "A256GCM"];

impl<'t> CompactJwe<'t> {
    /// The JWE, refused per [`JweError`].
    ///
    /// # Errors
    ///
    /// The text breaks a rule of [`JweError`].
    pub fn parse(text: &'t str) -> Result<Self, JweError> {
        let parts: Vec<&str> = text.split('.').collect();
        let [header, _, _, _, _] = parts.as_slice() else {
            return Err(JweError::Structure);
        };
        let header = decode(header).map_err(|_| JweError::Base64)?;
        if parts.iter().any(|part| decode(part).is_err()) {
            return Err(JweError::Base64);
        }
        let header = utf8(&header)
            .and_then(|text| object(&text))
            .map_err(JweError::Json)?;
        match header.get("alg") {
            Some(Node::String(alg)) if JWE_ALGORITHMS.contains(&alg.as_ref()) => {}
            other => return Err(JweError::Algorithm(other.map(shown))),
        }
        match header.get("enc") {
            Some(Node::String(enc)) if JWE_ENCRYPTIONS.contains(&enc.as_ref()) => {}
            other => return Err(JweError::Encryption(other.map(shown))),
        }
        match header.get("crit") {
            Some(crit) => Err(JweError::Critical(shown(crit))),
            None => Ok(Self { text, header }),
        }
    }

    /// The text as received.
    #[must_use]
    pub const fn as_str(&self) -> &'t str {
        self.text
    }

    /// The protected header.
    #[must_use]
    pub const fn header(&self) -> &Object<'static> {
        &self.header
    }
}

/// The payload of a compact serialization's three parts, decoded to UTF-8 whatever the rest
/// holds: what a refused JWS still names (reading 3).
#[must_use]
pub fn payload_text(text: &str) -> Option<String> {
    let [_, payload, _] = text.split('.').collect::<Vec<_>>()[..] else {
        return None;
    };
    String::from_utf8(decode(payload).ok()?).ok()
}
