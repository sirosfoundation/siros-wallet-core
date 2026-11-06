//! The registration: an issued SD-JWT read (S1, S2) and held as the `dc+sd-jwt` document, its view
//! built from the processed claims, with the credential's validity. The wallet checks the
//! Issuer-signed JWT's signature with x5c key resolution before it registers (HAIP §6.1.1).

use std::borrow::Cow;

use siros_openid4vp::json::Node;

use crate::error::RegistrationError;
use crate::sd_jwt::SdJwt;
use crate::tree::{ClaimValue, Element, IssuedClaim, Object};
use crate::type_metadata;

/// The key of the document a registration holds, and the Issuer-signed JWT's `typ` (SD-JWT VC
/// §3.2.1).
pub const DOCUMENT: &str = "dc+sd-jwt";

/// The registered claims no disclosure holds, sub-claims included (SD-JWT VC §3.2.2).
const PERMANENT: [&str; 8] = [
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "aka_vcts",
    "status",
];

/// What the wallet resolved beside the issued SD-JWT.
#[derive(Debug, Clone, Default)]
pub struct Resolved<'a> {
    /// The effective Type Metadata of the credential's type ([`crate::type_metadata`]); `None`
    /// when its issuer publishes none.
    pub metadata: Option<Node<'a>>,
    /// Whether the wallet loaded the metadata's `display` as a defined module
    /// ([`type_metadata::convert`]), so the view names it.
    pub display_loaded: bool,
    /// Each type the credential's type extends, nearest first (§6.4).
    pub extends: Vec<&'a str>,
    /// The curve of the issuer's key: RFC 7518 §3.4 and RFC 9864 fix it for each JWS algorithm but
    /// `EdDSA`, whose key the wallet's x5c resolution read.
    pub issuer_curve: Option<&'a str>,
}

/// An issued SD-JWT as the registration holds it: the view, and the document phase 2 presents
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    view: Vec<u8>,
    document: Vec<u8>,
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
        if sd_jwt.typ() != Some(DOCUMENT) {
            return Err(RegistrationError::Typ);
        }
        if let Some(claim) = PERMANENT
            .into_iter()
            .find(|claim| sd_jwt.claims().get(claim).is_some_and(disclosed))
        {
            return Err(RegistrationError::SelectivelyDisclosed(claim));
        }
        let view = view(&sd_jwt, resolved)?;
        Ok(Self {
            view: view.written_compact().into_bytes(),
            document: issued.as_bytes().to_vec(),
        })
    }

    /// The view: `{"type", "metadata", "values", "issuer"?, "alg", "curve"?, "key_alg"?,
    /// "key_curve"?, "extends"?, "validity"?, "display_module"?}`.
    #[must_use]
    pub fn view(&self) -> &[u8] {
        &self.view
    }

    /// The document, under [`DOCUMENT`].
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
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
    let metadata = metadata(resolved.metadata.as_ref())?;
    let mut members: Vec<(Cow<'static, str>, Node<'static>)> = vec![
        ("type".into(), text(kind)),
        ("metadata".into(), metadata),
        ("values".into(), sd_jwt.values()?),
    ];
    if let Some(iss) = claims.get("iss") {
        let iss = string(Some(iss)).ok_or(RegistrationError::Iss)?;
        members.push(("issuer".into(), text(iss)));
    }
    members.push(("alg".into(), text(sd_jwt.signing_alg())));
    if let Some(curve) = issuer_curve(sd_jwt.signing_alg(), resolved.issuer_curve)? {
        members.push(("curve".into(), text(curve)));
    }
    if let Some((alg, curve)) = holder_key(claims)? {
        members.push(("key_alg".into(), text(&alg)));
        members.push(("key_curve".into(), text(&curve)));
    }
    if !resolved.extends.is_empty() {
        let extends = resolved.extends.iter().map(|kind| text(kind)).collect();
        members.push(("extends".into(), Node::Array(extends)));
    }
    if let Some(validity) = validity(claims)? {
        members.push(("validity".into(), validity));
    }
    if let (true, Some(document)) = (resolved.display_loaded, resolved.metadata.as_ref()) {
        let digest = type_metadata::module_of(document);
        let hex: String = digest.digest().iter().map(|b| format!("{b:02x}")).collect();
        members.push(("display_module".into(), text(&hex)));
    }
    Ok(Node::object(members)?)
}

fn string(claim: Option<&IssuedClaim>) -> Option<&str> {
    match claim?.value() {
        ClaimValue::String(text) => Some(text),
        _ => None,
    }
}

/// The metadata as a claims view reads it (`{}` when none).
fn metadata(metadata: Option<&Node<'_>>) -> Result<Node<'static>, RegistrationError> {
    let Some(metadata) = metadata else {
        return Node::object([]).map_err(RegistrationError::Json);
    };
    if metadata.as_object().is_none() {
        return Err(RegistrationError::Metadata);
    }
    Ok(metadata.clone().into_owned())
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
    alg: &str,
    resolved: Option<&'a str>,
) -> Result<Option<&'a str>, RegistrationError> {
    match (fixed_curve(alg), resolved) {
        (Some(fixed), Some(curve)) if fixed != curve => Err(RegistrationError::IssuerCurve {
            alg: alg.to_owned(),
            curve: curve.to_owned(),
        }),
        (Some(fixed), _) => Ok(Some(fixed)),
        (None, curve) => Ok(curve),
    }
}

/// The JWS algorithm of a key on a curve (RFC 7518 §3.4; RFC 8037 §3.1); `None` for a curve that
/// signs under none of them.
fn signing_alg(curve: &str) -> Option<&'static str> {
    match curve {
        "P-256" => Some("ES256"),
        "P-384" => Some("ES384"),
        "P-521" => Some("ES512"),
        "secp256k1" => Some("ES256K"),
        "Ed25519" | "Ed448" => Some("EdDSA"),
        _ => None,
    }
}

/// `cnf.jwk`'s algorithm and curve (RFC 7800 §3.2): its `alg`, else its curve's; `None` without a
/// `jwk`, as a credential bound in another way or to no key has.
fn holder_key(claims: &Object) -> Result<Option<(String, String)>, RegistrationError> {
    let Some(ClaimValue::Object(cnf)) = claims.get("cnf").map(IssuedClaim::value) else {
        return Ok(None);
    };
    let Some(jwk) = cnf.get("jwk") else {
        return Ok(None);
    };
    let ClaimValue::Object(jwk) = jwk.value() else {
        return Err(RegistrationError::Key);
    };
    let curve = string(jwk.get("crv")).ok_or(RegistrationError::Key)?;
    let alg = match jwk.get("alg") {
        Some(alg) => string(Some(alg)).ok_or(RegistrationError::Key)?,
        None => signing_alg(curve).ok_or(RegistrationError::Key)?,
    };
    Ok(Some((alg.to_owned(), curve.to_owned())))
}

/// `{"not_before": nbf, "not_after": exp}`, each a NumericDate as the issuer wrote it (SD-JWT VC
/// §3.2.2.2, RFC 7519 §2), which a finite double holds; `None` when the issuer states neither.
fn validity(claims: &Object) -> Result<Option<Node<'static>>, RegistrationError> {
    let date = |name: &'static str| -> Result<Option<Node<'static>>, RegistrationError> {
        match claims.get(name).map(IssuedClaim::value) {
            None => Ok(None),
            Some(ClaimValue::Number(number)) if number.to_double().is_some_and(f64::is_finite) => {
                Ok(Some(Node::Number(number.clone())))
            }
            Some(_) => Err(RegistrationError::Validity(name)),
        }
    };
    let members: Vec<(Cow<'static, str>, Node<'static>)> =
        [("not_before", date("nbf")?), ("not_after", date("exp")?)]
            .into_iter()
            .filter_map(|(name, value)| Some((Cow::Borrowed(name), value?)))
            .collect();
    if members.is_empty() {
        return Ok(None);
    }
    Ok(Some(Node::object(members)?))
}
