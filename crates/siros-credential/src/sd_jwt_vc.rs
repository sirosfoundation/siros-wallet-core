//! The rules of SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19) over a stored SD-JWT.

use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_dcql::{CryptographicBinding, Vct};
use siros_mdoc::P256Key;
use siros_sdjwt::{Claim, ClaimValue, Element, Object, SdJwt};

use crate::error::{
    ClaimFault, Coordinate, CoordinateFault, CredentialError, HolderKeyError, RegisteredClaim,
};
use crate::usable::Validity;

/// An SD-JWT VC: an SD-JWT with a string `vct`, its registered claims permanently disclosed.
pub(crate) struct SdJwtVc {
    sd_jwt: SdJwt,
    vct: Vct,
    holder_key: Option<P256Key>,
    validity: Validity,
}

impl SdJwtVc {
    /// The SD-JWT VC of the compact form `data`.
    pub(crate) fn read(data: &str) -> Result<Self, CredentialError> {
        let sd_jwt = SdJwt::parse(data)?;
        let claims = sd_jwt.claims();
        if let Some(claim) = RegisteredClaim::ALL
            .into_iter()
            .find(|claim| claims.get(claim.name()).is_some_and(disclosed))
        {
            return Err(CredentialError::SelectivelyDisclosed(claim));
        }
        let vct = match claims.get("vct").map(Claim::value) {
            Some(ClaimValue::String(vct)) => Vct::new(vct),
            Some(_) => return Err(CredentialError::Vct(ClaimFault::WrongType)),
            None => return Err(CredentialError::Vct(ClaimFault::Absent)),
        };
        let holder_key = match claims.get("cnf").map(Claim::value) {
            None => None,
            Some(ClaimValue::Object(cnf)) => {
                Some(p256_jwk(cnf).map_err(CredentialError::HolderKey)?)
            }
            Some(_) => return Err(CredentialError::Cnf),
        };
        let validity = Validity::new(
            numeric_date(claims.get("nbf"), RegisteredClaim::Nbf)?,
            numeric_date(claims.get("exp"), RegisteredClaim::Exp)?,
        );
        Ok(Self {
            sd_jwt,
            vct,
            holder_key,
            validity,
        })
    }

    pub(crate) fn sd_jwt(&self) -> &SdJwt {
        &self.sd_jwt
    }

    pub(crate) fn vct(&self) -> &Vct {
        &self.vct
    }

    /// Whether `cnf` names a holder key: the KB-JWT must be secured by that key (Section
    /// 2.2.2.3).
    pub(crate) fn binding(&self) -> CryptographicBinding {
        match self.holder_key {
            Some(_) => CryptographicBinding::Bound,
            None => CryptographicBinding::Unbound,
        }
    }

    pub(crate) fn validity(&self) -> Validity {
        self.validity
    }

    /// The P-256 key of `cnf.jwk` (RFC 7800, Section 3.2); `None` without `cnf`.
    pub(crate) fn holder_key(&self) -> Option<P256Key> {
        self.holder_key
    }
}

/// The P-256 key of `cnf`'s `jwk`: `kty` `EC`, `crv` `P-256`, and `x` and `y` of 32 bytes of
/// base64url (RFC 7518, Section 6.2.1).
fn p256_jwk(cnf: &Object) -> Result<P256Key, HolderKeyError> {
    let jwk = match cnf.get("jwk").map(Claim::value) {
        Some(ClaimValue::Object(jwk)) => jwk,
        _ => return Err(HolderKeyError::Jwk),
    };
    let text = |name: &str| match jwk.get(name).map(Claim::value) {
        Some(ClaimValue::String(text)) => Some(text.as_str()),
        _ => None,
    };
    if text("kty") != Some("EC") {
        return Err(HolderKeyError::KeyType);
    }
    if text("crv") != Some("P-256") {
        return Err(HolderKeyError::Curve);
    }
    let coordinate = |which: Coordinate, name: &str| -> Result<[u8; 32], HolderKeyError> {
        let fault = |fault| HolderKeyError::Coordinate(which, fault);
        let bytes = base64url::decode(text(name).ok_or(fault(CoordinateFault::NotString))?)
            .map_err(|e| fault(CoordinateFault::Base64(e)))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| fault(CoordinateFault::Length(bytes.len())))
    };
    Ok(P256Key::new(
        coordinate(Coordinate::X, "x")?,
        coordinate(Coordinate::Y, "y")?,
    ))
}

/// Whether a disclosure reveals `claim` or one of its sub-claims.
fn disclosed(claim: &Claim) -> bool {
    claim.disclosure().is_some()
        || match claim.value() {
            ClaimValue::Object(object) => object.members().any(|(_, member)| disclosed(member)),
            ClaimValue::Array(elements) => elements.iter().any(|element| match element {
                Element::Present(member) => disclosed(member),
                Element::Withheld => false,
            }),
            _ => false,
        }
}

/// The NumericDate claim `claim`, named `name` (RFC 7519, Section 2).
///
/// A fractional NumericDate rounds up to the next second. For whole seconds `now`, `now ≥ t`
/// and `now ≥ ⌈t⌉` agree, and so do `now < t` and `now < ⌈t⌉`.
fn numeric_date(
    claim: Option<&Claim>,
    name: RegisteredClaim,
) -> Result<Option<DateTime>, CredentialError> {
    let Some(claim) = claim else {
        return Ok(None);
    };
    let ClaimValue::Number(number) = claim.value() else {
        return Err(CredentialError::NumericDate(name));
    };
    let seconds = match number.as_i64() {
        Some(seconds) => Some(seconds),
        None => number
            .as_f64()
            .map(f64::ceil)
            .filter(|s| (DateTime::MIN_UNIX as f64..=DateTime::MAX_UNIX as f64).contains(s))
            // Within the range above, the conversion is exact.
            .map(|s| s as i64),
    };
    seconds
        .and_then(DateTime::from_unix)
        .map(Some)
        .ok_or(CredentialError::NumericDate(name))
}
