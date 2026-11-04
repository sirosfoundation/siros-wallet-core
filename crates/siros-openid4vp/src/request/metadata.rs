//! The Verifier's `client_metadata` (OpenID4VP 1.0 §5.1): its `vp_formats_supported`, the public
//! keys of its `jwks`, and the response encryption the key rule chooses from them (§8.3, HAIP
//! §5).

use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use siros_explain::Explain;

use crate::ids::FormatId;
use crate::json::{JsonError, Node, Object, quote};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `client_metadata` that is no JSON object, or whose `vp_formats_supported` is none (rule C6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.metadata")]
pub enum MetadataError {
    /// No JSON with unique member names.
    #[error("{0}")]
    Json(
        #[from]
        #[explain(name = "cause")]
        JsonError,
    ),
    /// No object.
    #[error("client_metadata is not a JSON object")]
    NotObject,
    /// `vp_formats_supported` is no object.
    #[error("vp_formats_supported is not a JSON object")]
    VpFormats,
}

/// The client metadata: an object whose `vp_formats_supported`, when present, is an object.
#[derive(Debug, Clone)]
pub struct ClientMetadata<'a> {
    object: Object<'a>,
}

impl<'a> ClientMetadata<'a> {
    /// Parses the client metadata; an absent parameter is an empty object.
    pub fn parse(raw: Option<&'a RawValue>) -> Result<Self, MetadataError> {
        let object = match raw {
            None => {
                return Ok(Self {
                    object: Object::default(),
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
        Ok(Self { object })
    }

    /// The Verifier's `vp_formats_supported` value for a format; `None` when it states nothing.
    #[must_use]
    pub fn vp_formats(&self, format: &FormatId<'_>) -> Option<&Node<'a>> {
        self.object
            .get("vp_formats_supported")
            .and_then(|formats| formats.get(format.as_str()))
    }

    /// The `jwks` keys the wallet can agree a key with, in the Verifier's order.
    #[must_use]
    pub fn agreeable_keys(&self) -> Vec<AgreeableKey<'_>> {
        self.object
            .get("jwks")
            .and_then(|jwks| jwks.get("keys"))
            .and_then(Node::as_array)
            .map(|keys| keys.iter().filter_map(AgreeableKey::of).collect())
            .unwrap_or_default()
    }
}

/// An elliptic curve the wallet agrees keys on (RFC 7518 §6.2, RFC 8037).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// P-256.
    P256,
    /// P-384.
    P384,
    /// P-521.
    P521,
    /// X25519.
    X25519,
    /// X448.
    X448,
}

impl Curve {
    fn of(kty: &str, crv: &str) -> Option<Self> {
        match (kty, crv) {
            ("EC", "P-256") => Some(Self::P256),
            ("EC", "P-384") => Some(Self::P384),
            ("EC", "P-521") => Some(Self::P521),
            ("OKP", "X25519") => Some(Self::X25519),
            ("OKP", "X448") => Some(Self::X448),
            _ => None,
        }
    }

    /// The curve's `crv` name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
        }
    }

    /// Whether the key type is `EC`, with a `y` coordinate.
    #[must_use]
    pub const fn is_ec(self) -> bool {
        matches!(self, Self::P256 | Self::P384 | Self::P521)
    }
}

/// A key agreement the wallet implements (RFC 7518 §4.6): ECDH-ES, direct or with AES key wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAgreement {
    /// `ECDH-ES`.
    EcdhEs,
    /// `ECDH-ES+A128KW`.
    EcdhEsA128Kw,
    /// `ECDH-ES+A192KW`.
    EcdhEsA192Kw,
    /// `ECDH-ES+A256KW`.
    EcdhEsA256Kw,
}

impl KeyAgreement {
    fn parse(name: &str) -> Option<Self> {
        [
            Self::EcdhEs,
            Self::EcdhEsA128Kw,
            Self::EcdhEsA192Kw,
            Self::EcdhEsA256Kw,
        ]
        .into_iter()
        .find(|alg| alg.as_str() == name)
    }

    /// The `alg` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
        }
    }
}

/// A content encryption the wallet implements (RFC 7518 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncryption {
    /// `A128GCM`.
    A128Gcm,
    /// `A192GCM`.
    A192Gcm,
    /// `A256GCM`.
    A256Gcm,
    /// `A128CBC-HS256`.
    A128CbcHs256,
    /// `A192CBC-HS384`.
    A192CbcHs384,
    /// `A256CBC-HS512`.
    A256CbcHs512,
}

impl ContentEncryption {
    const ALL: [Self; 6] = [
        Self::A128Gcm,
        Self::A192Gcm,
        Self::A256Gcm,
        Self::A128CbcHs256,
        Self::A192CbcHs384,
        Self::A256CbcHs512,
    ];

    /// The content encryption of an `enc` name the wallet implements.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|enc| enc.as_str() == name)
    }

    /// The `enc` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
        }
    }
}

/// A public key the wallet can agree a key with: a curve it implements, the key's coordinates,
/// a `kid`, and `use` and `alg`, when present, an encryption key and a key agreement it
/// implements.
#[derive(Debug, Clone, Copy)]
pub struct AgreeableKey<'k> {
    /// The whole JWK.
    pub jwk: &'k Node<'k>,
    /// The `kid`.
    pub kid: &'k str,
    /// The curve.
    pub curve: Curve,
    /// The `x` coordinate.
    pub x: &'k str,
    /// The `y` coordinate of an EC key.
    pub y: Option<&'k str>,
    /// The key agreement: the key's `alg`, else ECDH-ES.
    pub alg: KeyAgreement,
}

impl<'k> AgreeableKey<'k> {
    /// The key, when the wallet can agree a key with it.
    #[must_use]
    pub fn of(jwk: &'k Node<'k>) -> Option<Self> {
        let member = |name: &str| jwk.get(name).and_then(Node::as_str);
        let curve = Curve::of(member("kty")?, member("crv")?)?;
        let y = if curve.is_ec() {
            Some(member("y")?)
        } else {
            None
        };
        let usable = jwk
            .get("use")
            .is_none_or(|value| value.as_str() == Some("enc"));
        let alg = match jwk.get("alg") {
            None => KeyAgreement::EcdhEs,
            Some(alg) => KeyAgreement::parse(alg.as_str()?)?,
        };
        usable.then_some(Self {
            jwk,
            kid: member("kid")?,
            curve,
            x: member("x")?,
            y,
            alg,
        })
    }

    /// The JWK SHA-256 Thumbprint (RFC 7638).
    #[must_use]
    pub fn thumbprint(&self) -> [u8; 32] {
        thumbprint(
            if self.curve.is_ec() { "EC" } else { "OKP" },
            self.curve.name(),
            self.x,
            self.y,
        )
    }
}

/// RFC 7638 §3.2: SHA-256 over the key's required members, sorted, without whitespace: `crv`,
/// `kty`, `x` and, for an EC key, `y` (RFC 7518 §6.2, RFC 8037 §2).
#[must_use]
pub fn thumbprint(kty: &str, crv: &str, x: &str, y: Option<&str>) -> [u8; 32] {
    let members = [
        ("crv", Some(crv)),
        ("kty", Some(kty)),
        ("x", Some(x)),
        ("y", y),
    ];
    let canonical = members
        .iter()
        .filter_map(|(name, value)| value.map(|value| format!("{}:{}", quote(name), quote(value))))
        .collect::<Vec<_>>()
        .join(",");
    let canonical = format!("{{{canonical}}}");
    Sha256::digest(canonical.as_bytes()).into()
}

/// A Verifier key the wallet encrypts responses to (§8.3, HAIP §5): an [`AgreeableKey`] of
/// `client_metadata.jwks` with `kty` EC, `crv` P-256, `alg` present and `ECDH-ES`, `use` `enc`
/// when present, each coordinate 32 octets (RFC 7518 §6.2.1.2, §6.2.1.3).
#[derive(Debug, Clone, Copy)]
pub struct ResponseKey<'k>(AgreeableKey<'k>);

impl<'k> ResponseKey<'k> {
    /// The key, when the key rule accepts it.
    fn of(key: AgreeableKey<'k>) -> Option<Self> {
        let octets = |coordinate: &str| {
            URL_SAFE_NO_PAD
                .decode(coordinate)
                .is_ok_and(|decoded| decoded.len() == 32)
        };
        (key.curve == Curve::P256
            && key.alg == KeyAgreement::EcdhEs
            && key.jwk.get("alg").is_some()
            && octets(key.x)
            && key.y.is_some_and(octets))
        .then_some(Self(key))
    }

    /// The key as the wallet agrees with it.
    #[must_use]
    pub const fn key(&self) -> &AgreeableKey<'k> {
        &self.0
    }
}

/// A content encryption the wallet encrypts responses with (HAIP §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEnc {
    /// `A128GCM`.
    A128Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl ResponseEnc {
    /// The content encryption as the JWE's `enc` names it.
    #[must_use]
    pub const fn content(self) -> ContentEncryption {
        match self {
            Self::A128Gcm => ContentEncryption::A128Gcm,
            Self::A256Gcm => ContentEncryption::A256Gcm,
        }
    }
}

/// The encryption chosen for a response: the Verifier's first [`ResponseKey`] in its order, and
/// `A256GCM` when `encrypted_response_enc_values_supported` lists it, else `A128GCM` when it lists
/// it or the member is absent (§5.1's default). Only [`Encryption::choose`] makes one.
#[derive(Debug, Clone, Copy)]
pub struct Encryption<'k> {
    key: ResponseKey<'k>,
    enc: ResponseEnc,
}

impl<'k> Encryption<'k> {
    /// The key rule (§8.3, HAIP §5; reading 25); `None` makes C7.
    #[must_use]
    pub fn choose(metadata: &'k ClientMetadata<'k>) -> Option<Self> {
        let key = metadata
            .agreeable_keys()
            .into_iter()
            .find_map(ResponseKey::of)?;
        let listed = |name: &str| {
            metadata
                .object
                .get("encrypted_response_enc_values_supported")
                .map(|values| {
                    values.as_array().is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some(name))
                    })
                })
        };
        let enc = match (listed("A256GCM"), listed("A128GCM")) {
            (Some(true), _) => ResponseEnc::A256Gcm,
            (None, _) | (_, Some(true)) => ResponseEnc::A128Gcm,
            (Some(false), _) => return None,
        };
        Some(Self { key, enc })
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &ResponseKey<'k> {
        &self.key
    }

    /// The content encryption.
    #[must_use]
    pub const fn enc(&self) -> ResponseEnc {
        self.enc
    }
}
