//! The Verifier's `client_metadata` (OpenID4VP 1.0 §5.1): its `vp_formats_supported` and the
//! public keys of its `jwks`, with the vocabulary of the algorithms a key agrees with.

use serde_json::value::RawValue;
use siros_explain::Explain;

use crate::ids::{FormatId, KeyId};
use crate::json::{JsonError, Node, Object};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `client_metadata` that is no JSON object, or whose `vp_formats_supported` or `jwks` breaks its
/// rule (rule C6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum MetadataError {
    /// No JSON with unique member names.
    #[error("{0}")]
    #[explain(id = "metadata.json")]
    Json(#[from] JsonError),
    /// No object.
    #[error("client_metadata is not a JSON object")]
    #[explain(id = "metadata.not_object")]
    NotObject,
    /// `vp_formats_supported` is no object.
    #[error("vp_formats_supported is not a JSON object")]
    #[explain(id = "metadata.vp_formats")]
    VpFormats,
    /// `jwks` is no JWK Set: an object whose `keys` is an array (RFC 7517 §5).
    #[error("jwks is not a JWK Set")]
    #[explain(id = "metadata.jwks")]
    Jwks,
}

/// The client metadata: an object whose `vp_formats_supported`, when present, is an object, and
/// whose `jwks`, when present, is a JWK Set, its keys held apart.
#[derive(Debug, Clone)]
pub struct ClientMetadata<'a> {
    object: Object<'a>,
    keys: Vec<Node<'a>>,
}

impl<'a> ClientMetadata<'a> {
    /// Parses the client metadata; an absent parameter is an empty object.
    pub fn parse(raw: Option<&'a RawValue>) -> Result<Self, MetadataError> {
        let object = match raw {
            None => {
                return Ok(Self {
                    object: Object::default(),
                    keys: Vec::new(),
                });
            }
            Some(raw) => match Node::from_raw(raw)? {
                Node::Object(object) => object,
                _ => return Err(MetadataError::NotObject),
            },
        };
        if object
            .get("vp_formats_supported")
            .is_some_and(|formats| formats.as_object().is_none())
        {
            return Err(MetadataError::VpFormats);
        }
        let keys = match object.get("jwks") {
            None => Vec::new(),
            Some(jwks) => jwks
                .get("keys")
                .and_then(Node::as_array)
                .ok_or(MetadataError::Jwks)?
                .to_vec(),
        };
        Ok(Self { object, keys })
    }

    /// The Verifier's `vp_formats_supported` value for a format; `None` when it states nothing.
    #[must_use]
    pub fn vp_formats(&self, format: &FormatId<'_>) -> Option<&Node<'a>> {
        self.object
            .get("vp_formats_supported")
            .and_then(|formats| formats.get(format.as_str()))
    }

    /// A member of `client_metadata`.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Node<'a>> {
        self.object.get(name)
    }

    /// The `jwks` keys the wallet can agree a key with, in the Verifier's order.
    #[must_use]
    pub fn agreeable_keys(&self) -> Vec<AgreeableKey<'_>> {
        self.keys.iter().filter_map(AgreeableKey::of).collect()
    }
}

/// Whether a text is a JOSE name: one or more of the printable ASCII characters other than space
/// and `"` (RFC 7518 §7.1's registry names).
pub(crate) const fn jose_name(text: &str) -> bool {
    let mut rest = text.as_bytes();
    if rest.is_empty() {
        return false;
    }
    while let [byte, tail @ ..] = rest {
        if *byte <= 0x20 || *byte > 0x7e || *byte == b'"' {
            return false;
        }
        rest = tail;
    }
    true
}

macro_rules! jose_names {
    ($($(#[$doc:meta])* $type:ident;)*) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $type<'n>(&'n str);

        impl<'n> $type<'n> {
            /// The name; `None` for an empty text or a character outside printable ASCII, space
            /// and `"`.
            #[must_use]
            pub const fn new(name: &'n str) -> Option<Self> {
                if jose_name(name) { Some(Self(name)) } else { None }
            }

            /// The name as JOSE writes it.
            #[must_use]
            pub const fn as_str(self) -> &'n str {
                self.0
            }
        }

        impl std::fmt::Display for $type<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
    )*};
}

jose_names! {
    /// A JWK's `crv` (IANA "JSON Web Key Elliptic Curve" registry; RFC 7518 §6.2.1.1, RFC 8037
    /// §2): the vocabulary modules and key rules state keys in. A module names its own with
    /// `checked!(Curve, "...")`.
    Curve;
    /// A JWE key agreement `alg` (RFC 7518 §4.6; IANA "JSON Web Signature and Encryption
    /// Algorithms").
    KeyAgreement;
    /// A JWE content encryption `enc` (RFC 7518 §5.1; the same registry).
    ContentEncryption;
}

impl Curve<'static> {
    /// `P-256` (RFC 7518 §6.2.1.1).
    pub const P_256: Self = siros_syntax::checked!(Curve<'static>, "P-256");
}

impl KeyAgreement<'static> {
    /// `ECDH-ES` (RFC 7518 §4.6).
    pub const ECDH_ES: Self = siros_syntax::checked!(KeyAgreement<'static>, "ECDH-ES");
}

impl ContentEncryption<'static> {
    /// `A128GCM` (RFC 7518 §5.3).
    pub const A128GCM: Self = siros_syntax::checked!(ContentEncryption<'static>, "A128GCM");
    /// `A256GCM` (RFC 7518 §5.3).
    pub const A256GCM: Self = siros_syntax::checked!(ContentEncryption<'static>, "A256GCM");
}

/// What a module agrees keys and encrypts with: curves, key agreements and content encryptions,
/// each in the module's order of preference. [`Agreements::NONE`] is the statement of a module
/// that encrypts nothing, whose `encrypt_jwe` the core never calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agreements {
    curves: &'static [Curve<'static>],
    agreements: &'static [KeyAgreement<'static>],
    encryptions: &'static [ContentEncryption<'static>],
}

impl Agreements {
    /// No curve, no key agreement, no content encryption.
    pub const NONE: Self = Self::new(&[], &[], &[]);

    /// The statement.
    #[must_use]
    pub const fn new(
        curves: &'static [Curve<'static>],
        agreements: &'static [KeyAgreement<'static>],
        encryptions: &'static [ContentEncryption<'static>],
    ) -> Self {
        Self {
            curves,
            agreements,
            encryptions,
        }
    }

    /// Whether it states a key of this curve and this agreement.
    #[must_use]
    pub fn agrees(&self, curve: Curve<'_>, agreement: KeyAgreement<'_>) -> bool {
        self.curves.iter().any(|c| c.as_str() == curve.as_str())
            && self
                .agreements
                .iter()
                .any(|a| a.as_str() == agreement.as_str())
    }

    /// Whether it states the content encryption.
    #[must_use]
    pub fn encrypts(&self, enc: ContentEncryption<'_>) -> bool {
        self.encryptions.iter().any(|e| e.as_str() == enc.as_str())
    }

    /// Whether it states a key of this curve, this agreement and this content encryption.
    #[must_use]
    pub fn admits(
        &self,
        curve: Curve<'_>,
        agreement: KeyAgreement<'_>,
        enc: ContentEncryption<'_>,
    ) -> bool {
        self.curves.iter().any(|c| c.as_str() == curve.as_str())
            && self
                .agreements
                .iter()
                .any(|a| a.as_str() == agreement.as_str())
            && self.encryptions.iter().any(|e| e.as_str() == enc.as_str())
    }

    /// The curves.
    #[must_use]
    pub const fn curves(&self) -> &'static [Curve<'static>] {
        self.curves
    }

    /// The key agreements.
    #[must_use]
    pub const fn agreements(&self) -> &'static [KeyAgreement<'static>] {
        self.agreements
    }

    /// The content encryptions, in the module's order of preference.
    #[must_use]
    pub const fn encryptions(&self) -> &'static [ContentEncryption<'static>] {
        self.encryptions
    }
}

/// A key's public coordinates, base64url-decoded (RFC 7518 §6.2.1.2, §6.2.1.3; RFC 8037 §2): `y`
/// for an `EC` key. Their lengths and the point's place on its curve are the agreeing party's
/// rule: the key rule checks the lengths it accepts, the module checks the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    x: Vec<u8>,
    y: Option<Vec<u8>>,
}

impl Point {
    /// `x`.
    #[must_use]
    pub fn x(&self) -> &[u8] {
        &self.x
    }

    /// `y`, for an `EC` key.
    #[must_use]
    pub fn y(&self) -> Option<&[u8]> {
        self.y.as_deref()
    }
}

/// A JWK's `kty` (RFC 7517 §4.1), as the key wrote it. Only [`AgreeableKey::of`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyType<'k>(&'k str);

impl<'k> KeyType<'k> {
    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'k str {
        self.0
    }
}

/// A public key the wallet can agree a key with: the JWK, its `kid`, its curve, its point, and
/// its `alg` when present. Only [`AgreeableKey::of`] makes one, from a JWK whose `use`, when
/// present, is `enc`.
#[derive(Debug, Clone)]
pub struct AgreeableKey<'k> {
    jwk: &'k Node<'k>,
    kty: KeyType<'k>,
    kid: KeyId<'k>,
    curve: Curve<'k>,
    point: Point,
    alg: Option<KeyAgreement<'k>>,
}

impl<'k> AgreeableKey<'k> {
    /// The key; `None` without `kty`, `crv`, `x` or `kid`, without `y` for an `EC` key, with a
    /// `crv` or `alg` that is no JOSE name, with coordinates that are no base64url, or with a
    /// `use` other than `enc`.
    #[must_use]
    pub fn of(jwk: &'k Node<'k>) -> Option<Self> {
        let member = |name: &str| jwk.get(name).and_then(Node::as_str);
        let coordinate =
            |name: &str| member(name).and_then(|text| URL_SAFE_NO_PAD.decode(text).ok());
        let kty = member("kty")?;
        let curve = Curve::new(member("crv")?)?;
        let x = coordinate("x")?;
        let y = match (kty, jwk.get("y")) {
            ("EC", _) => Some(coordinate("y")?),
            (_, None) => None,
            (_, Some(_)) => Some(coordinate("y")?),
        };
        let usable = jwk
            .get("use")
            .is_none_or(|value| value.as_str() == Some("enc"));
        let alg = match jwk.get("alg") {
            None => None,
            Some(alg) => Some(KeyAgreement::new(alg.as_str()?)?),
        };
        usable.then_some(Self {
            jwk,
            kty: KeyType(kty),
            kid: KeyId::new(member("kid")?),
            curve,
            point: Point { x, y },
            alg,
        })
    }

    /// The whole JWK.
    #[must_use]
    pub const fn jwk(&self) -> &'k Node<'k> {
        self.jwk
    }

    /// The key type, `kty`.
    #[must_use]
    pub const fn kty(&self) -> KeyType<'k> {
        self.kty
    }

    /// The `kid`.
    #[must_use]
    pub const fn kid(&self) -> &KeyId<'k> {
        &self.kid
    }

    /// The curve.
    #[must_use]
    pub const fn curve(&self) -> Curve<'k> {
        self.curve
    }

    /// The point.
    #[must_use]
    pub const fn point(&self) -> &Point {
        &self.point
    }

    /// The key's `alg`, when present.
    #[must_use]
    pub const fn alg(&self) -> Option<KeyAgreement<'k>> {
        self.alg
    }
}
