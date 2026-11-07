//! The registration: an issued SD-JWT read (S1, S2) and held as the `dc+sd-jwt` document, its view
//! built from the processed claims, with the credential's validity. The wallet checks the
//! Issuer-signed JWT's signature with x5c key resolution before it registers (HAIP §6.1.1).

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::ids::CredentialType;
use siros_openid4vp::json::{self, Node};
use siros_openid4vp::known_object;
use siros_openid4vp::request::Curve;
use siros_openid4vp::wallet::{DocumentBytes, Holder, ViewBytes};

use crate::alg::SigningAlg;
use crate::error::{
    HolderKeyFault, JwkCoordinate, PermanentClaim, RegistrationError, ValidityClaim,
};
use crate::sd_jwt::{JwtType, SdJwt};
use crate::tree::{ClaimValue, Element, IssuedClaim, Object};
use crate::type_metadata;

/// The key of the document a registration holds, and the Issuer-signed JWT's `typ` (SD-JWT VC
/// §3.2.1).
pub const DOCUMENT: &str = "dc+sd-jwt";

/// The effective Type Metadata the wallet resolved ([`crate::type_metadata`]).
#[derive(Debug, Clone)]
pub struct ResolvedMetadata<'a> {
    /// The document.
    pub document: json::Object<'a>,
    /// Whether the view names the document's `display` as a defined module.
    pub display: DisplayModule,
}

/// Whether the wallet loaded a document's `display` as a defined module
/// ([`type_metadata::convert`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayModule {
    /// It did, so the view names the module.
    Loaded,
    /// It did not.
    NotLoaded,
}

/// What the wallet resolved beside the issued SD-JWT.
#[derive(Debug, Clone, Default)]
pub struct Resolved<'a> {
    /// `None` when the credential's issuer publishes no Type Metadata.
    pub metadata: Option<ResolvedMetadata<'a>>,
    /// Each type the credential's type extends, nearest first (§6.4).
    pub extends: Vec<CredentialType<'a>>,
    /// The curve of the issuer's key: RFC 7518 §3.4 and RFC 9864 fix it for each JWS algorithm but
    /// `EdDSA`, whose key the wallet's x5c resolution read.
    pub issuer_curve: Option<Curve<'a>>,
}

/// An issued SD-JWT as the registration holds it: the view, and the document phase 2 presents
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    view: Vec<u8>,
    document: Vec<u8>,
    holder: Holder,
}

impl Registered {
    /// The registration of the compact SD-JWT `issued`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the text is no issued SD-JWT (S1), it breaks SD-JWT VC's rules, or its
    /// claims make no view.
    pub fn of(issued: &str, resolved: &Resolved<'_>) -> Result<Self, RegistrationError> {
        let sd_jwt = SdJwt::parse(issued)?;
        if sd_jwt.typ().map(JwtType::as_str) != Some(DOCUMENT) {
            return Err(RegistrationError::Typ);
        }
        if let Some(claim) = PermanentClaim::ALL
            .into_iter()
            .find(|claim| sd_jwt.claims().get(claim.name()).is_some_and(disclosed))
        {
            return Err(RegistrationError::SelectivelyDisclosed(claim));
        }
        let view = view(&sd_jwt, resolved)?;
        let holder = match sd_jwt.claims().get("cnf") {
            Some(_) => Holder::Bound,
            None => Holder::Unbound,
        };
        Ok(Self {
            view: view.written_compact().into_bytes(),
            document: issued.as_bytes().to_vec(),
            holder,
        })
    }

    /// The view: `{"type", "metadata", "values", "issuer"?, "alg", "curve"?, "key_alg"?,
    /// "key_curve"?, "extends"?, "validity"?, "display_module"?}`.
    #[must_use]
    pub fn view(&self) -> ViewBytes<'_> {
        ViewBytes::new(&self.view)
    }

    /// The document, under [`DOCUMENT`].
    #[must_use]
    pub fn document(&self) -> DocumentBytes<'_> {
        DocumentBytes::new(&self.document)
    }

    /// The credential's `Facts::holder`: `cnf` binds it to a key. Phase 2 refuses a credential
    /// whose facts say otherwise.
    #[must_use]
    pub fn holder(&self) -> Holder {
        self.holder
    }
}

/// Whether a disclosure reveals `claim` or one of its sub-claims.
fn disclosed(claim: &IssuedClaim) -> bool {
    claim.disclosure().is_some()
        || match claim.value() {
            ClaimValue::Object(object) => object.members().any(|(_, member)| disclosed(member)),
            ClaimValue::Array(elements) => elements.iter().any(|element| match element {
                Element::Present(member) => disclosed(member),
                Element::Withheld(_) => false,
            }),
            _ => false,
        }
}

fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

/// The view of the processed claims.
fn view(sd_jwt: &SdJwt, resolved: &Resolved<'_>) -> Result<Node<'static>, RegistrationError> {
    let claims = sd_jwt.claims();
    let kind = string(claims.get("vct")).ok_or(RegistrationError::Vct)?;
    let issuer = match claims.get("iss") {
        None => None,
        Some(iss) => Some(string(Some(iss)).ok_or(RegistrationError::Iss)?),
    };
    let curve = issuer_curve(sd_jwt.signing_alg(), resolved.issuer_curve)?;
    let (key_alg, key_curve) = holder_key(claims)?.unzip();
    let extends = (!resolved.extends.is_empty()).then(|| {
        Node::Array(
            resolved
                .extends
                .iter()
                .map(|kind| text(kind.as_str()))
                .collect(),
        )
    });
    let display_module = resolved
        .metadata
        .as_ref()
        .filter(|metadata| metadata.display == DisplayModule::Loaded)
        .map(|metadata| {
            let digest = type_metadata::module_of(&metadata.document);
            let hex: String = digest
                .digest()
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            text(&hex)
        });
    let metadata = resolved
        .metadata
        .as_ref()
        .map_or_else(json::Object::default, |metadata| {
            metadata.document.clone().into_owned()
        });
    Ok(Node::Object(known_object! {
        "type" => Some(text(kind)),
        "metadata" => Some(Node::Object(metadata)),
        "values" => Some(sd_jwt.values()),
        "issuer" => issuer.map(text),
        "alg" => Some(text(sd_jwt.signing_alg().as_str())),
        "curve" => curve.map(|curve| text(curve.as_str())),
        "key_alg" => key_alg.map(text),
        "key_curve" => key_curve.map(text),
        "extends" => extends,
        "validity" => validity(claims)?,
        "display_module" => display_module,
    }))
}

fn string(claim: Option<&IssuedClaim>) -> Option<&str> {
    match claim?.value() {
        ClaimValue::String(text) => Some(text),
        _ => None,
    }
}

/// The curve the JWS algorithm fixes (RFC 7518 §3.4; RFC 8812 §3.1; RFC 9864 §2.2).
fn fixed_curve(alg: &str) -> Option<&'static str> {
    match alg {
        "ES256" => Some("P-256"),
        "ES384" => Some("P-384"),
        "ES512" => Some("P-521"),
        "ES256K" => Some("secp256k1"),
        "Ed25519" => Some("Ed25519"),
        "Ed448" => Some("Ed448"),
        _ => None,
    }
}

/// The curve of the issuer's key: the one its algorithm fixes, else the one the wallet resolved.
fn issuer_curve<'a>(
    alg: &SigningAlg,
    resolved: Option<Curve<'a>>,
) -> Result<Option<Curve<'a>>, RegistrationError> {
    match (fixed_curve(alg.as_str()).and_then(Curve::new), resolved) {
        (Some(fixed), Some(curve)) if fixed != curve => Err(RegistrationError::IssuerCurve {
            alg: alg.clone(),
            curve: curve.into(),
        }),
        (Some(fixed), _) => Ok(Some(fixed)),
        (None, curve) => Ok(curve),
    }
}

/// What a holder key's curve fixes of its JWK: its `kty`, its coordinates and their size, and its
/// JWS algorithm (RFC 7518 §3.4, §6.2.1.2; RFC 8037 §2, §3.1; RFC 8812 §3.1).
struct KeyShape {
    kty: &'static str,
    coordinates: &'static [JwkCoordinate],
    size: usize,
    alg: &'static str,
}

impl KeyShape {
    /// The shape of a key on `curve`; `None` for a curve that signs under no JWS algorithm.
    fn of(curve: &str) -> Option<Self> {
        let elliptic = |size, alg| Self {
            kty: "EC",
            coordinates: &[JwkCoordinate::X, JwkCoordinate::Y],
            size,
            alg,
        };
        let edwards = |size| Self {
            kty: "OKP",
            coordinates: &[JwkCoordinate::X],
            size,
            alg: "EdDSA",
        };
        match curve {
            "P-256" => Some(elliptic(32, "ES256")),
            "P-384" => Some(elliptic(48, "ES384")),
            "P-521" => Some(elliptic(66, "ES512")),
            "secp256k1" => Some(elliptic(32, "ES256K")),
            "Ed25519" => Some(edwards(32)),
            "Ed448" => Some(edwards(57)),
            _ => None,
        }
    }

    /// Whether `value` is the base64url of a coordinate.
    fn holds(&self, value: Option<&str>) -> bool {
        value
            .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
            .is_some_and(|bytes| bytes.len() == self.size)
    }
}

/// `cnf.jwk`'s algorithm and curve (RFC 7800 §3.1, §3.2): its `alg`, else its curve's; `None`
/// without a `cnf`. No other confirmation method names a key the Key Binding JWT's signature
/// answers to (SD-JWT VC §3.2.2.2).
fn holder_key(claims: &Object) -> Result<Option<(&str, &str)>, HolderKeyFault> {
    let Some(cnf) = claims.get("cnf") else {
        return Ok(None);
    };
    let ClaimValue::Object(cnf) = cnf.value() else {
        return Err(HolderKeyFault::Cnf);
    };
    let jwk = cnf.get("jwk").ok_or(HolderKeyFault::Cnf)?;
    let ClaimValue::Object(jwk) = jwk.value() else {
        return Err(HolderKeyFault::Jwk);
    };
    let curve = string(jwk.get("crv")).ok_or(HolderKeyFault::Curve)?;
    let shape = KeyShape::of(curve).ok_or(HolderKeyFault::Curve)?;
    if string(jwk.get("kty")) != Some(shape.kty) {
        return Err(HolderKeyFault::KeyType);
    }
    if let Some(name) = shape
        .coordinates
        .iter()
        .find(|coordinate| !shape.holds(string(jwk.get(coordinate.name()))))
    {
        return Err(HolderKeyFault::Coordinate(*name));
    }
    let alg = match jwk.get("alg") {
        None => shape.alg,
        Some(alg) => string(Some(alg))
            .filter(|alg| *alg == shape.alg || fixed_curve(alg) == Some(curve))
            .ok_or(HolderKeyFault::Alg)?,
    };
    Ok(Some((alg, curve)))
}

/// `{"not_before": nbf, "not_after": exp}`, each a NumericDate as the issuer wrote it (SD-JWT VC
/// §3.2.2.2, RFC 7519 §2), which a finite double holds. `None` when the processed payload states
/// neither: SD-JWT VC makes both optional, and RFC 9901 §9.7 leaves which validity claims a
/// credential needs to the operating environment's rules, which the wallet applies with
/// `Platform::usable` (§7.1, step 6). A digest with no disclosure hides no claim this view could
/// report: a decoy (§4.2.5) reads the same, and [`PermanentClaim`] refuses `exp` and `nbf` once
/// they are disclosed.
fn validity(claims: &Object) -> Result<Option<Node<'static>>, RegistrationError> {
    let date = |claim: ValidityClaim| -> Result<Option<Node<'static>>, RegistrationError> {
        match claims.get(claim.name()).map(IssuedClaim::value) {
            None => Ok(None),
            Some(ClaimValue::Number(number)) if number.to_double().is_some_and(f64::is_finite) => {
                Ok(Some(Node::Number(number.clone())))
            }
            Some(_) => Err(RegistrationError::Validity(claim)),
        }
    };
    let (not_before, not_after) = (date(ValidityClaim::Nbf)?, date(ValidityClaim::Exp)?);
    if not_before.is_none() && not_after.is_none() {
        return Ok(None);
    }
    Ok(Some(Node::Object(known_object! {
        "not_before" => not_before,
        "not_after" => not_after,
    })))
}
