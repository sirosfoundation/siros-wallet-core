//! Claims path pointer resolution (C3): Q4 for SD-JWT VC, `[namespace, element]` for mdoc
//! (OpenID4VP 1.0, Sections 7.1 and 7.2).

use serde_json::{Map, Value as Json};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_dcql::{
    mdoc_components, resolve, ClaimPath, CredentialFormat, CredentialRef, CryptographicBinding,
    PathError,
};
use siros_mdoc::{IssuerSignedItem, Mdoc};
use siros_sdjwt::{Node, NodeValue};

use crate::credential::{Body, Credential};
use crate::tree::ClaimTree;
use crate::usable::UsableCredential;
use crate::value::{self, TypedValue};

/// A claim a pointer selects, in its format's tree.
enum Found<'a> {
    SdJwt(Node<'a>),
    Mdoc(&'a Cbor),
}

impl<'a> Found<'a> {
    fn typed(self) -> TypedValue<'a> {
        match self {
            Found::SdJwt(node) => match node.value() {
                NodeValue::Payload(object) => value::payload(object),
                NodeValue::Claim(claim) => value::json(claim.value()),
            },
            Found::Mdoc(value) => value::cbor(value),
        }
    }
}

impl Credential {
    /// The values of the claims `path` selects, in the order of their selection.
    ///
    /// For an SD-JWT VC, [`siros_dcql::resolve`] walks the claim tree: an index counts issued
    /// positions and selects nothing at a withheld one, and `null` selects the present
    /// elements. For an mdoc, the path is `[namespace, element]` and selects that element's
    /// value.
    ///
    /// # Errors
    ///
    /// [`PathError`] when the path does not fit the credential or selects nothing.
    pub fn claims(&self, path: &ClaimPath) -> Result<Vec<TypedValue<'_>>, PathError> {
        Ok(self.select(path)?.into_iter().map(Found::typed).collect())
    }

    fn select(&self, path: &ClaimPath) -> Result<Vec<Found<'_>>, PathError> {
        match &self.body {
            Body::SdJwtVc(vc) => Ok(resolve(vc.sd_jwt().root(), path)?
                .into_iter()
                .map(Found::SdJwt)
                .collect()),
            Body::Mdoc(mdoc) => Ok(vec![Found::Mdoc(element(mdoc, path)?)]),
        }
    }
}

/// The value of the element `path` names (Section 7.2.1). A namespace or an element the mdoc
/// lacks selects nothing.
fn element<'a>(mdoc: &'a Mdoc, path: &ClaimPath) -> Result<&'a Cbor, PathError> {
    let (name_space, identifier) = mdoc_components(path)?;
    mdoc.name_spaces()
        .iter()
        .find(|n| *n.name() == name_space)
        .and_then(|n| n.items().iter().find(|i| *i.identifier() == identifier))
        .map(IssuerSignedItem::value)
        .ok_or(PathError::Empty)
}

/// What claims path pointers select claims in: a stored credential, or its claim tree.
pub trait ClaimSource {
    /// The values of the claims `path` selects, in the order of their selection.
    ///
    /// # Errors
    ///
    /// [`PathError`] when the path does not fit the claims or selects nothing.
    fn claims(&self, path: &ClaimPath) -> Result<Vec<TypedValue<'_>>, PathError>;
}

impl ClaimSource for Credential {
    fn claims(&self, path: &ClaimPath) -> Result<Vec<TypedValue<'_>>, PathError> {
        Credential::claims(self, path)
    }
}

impl ClaimSource for ClaimTree {
    fn claims(&self, path: &ClaimPath) -> Result<Vec<TypedValue<'_>>, PathError> {
        ClaimTree::claims(self, path)
    }
}

/// DCQL evaluation (OpenID4VP 1.0, Section 6.4) over the credential.
///
/// [`claim`](siros_dcql::Credential::claim) gives each selected value as JSON for the
/// comparison with `values` (Section 6.3). A `full-date` compares as `"YYYY-MM-DD"`, a `tdate`
/// as `"YYYY-MM-DDThh:mm:ssZ"`, and a byte string as its base64url text, as RFC 8949, Section
/// 6.1 converts CBOR to JSON.
impl siros_dcql::Credential for Credential {
    /// The decimal `credentialId`.
    fn id(&self) -> &CredentialRef {
        Credential::id(self)
    }

    /// `dc+sd-jwt` or `mso_mdoc`.
    fn format(&self) -> &CredentialFormat {
        self.format_identifier()
    }

    fn claim(&self, path: &ClaimPath) -> Result<Vec<Json>, PathError> {
        Ok(self
            .select(path)?
            .into_iter()
            .map(|found| found.typed().to_json())
            .collect())
    }

    /// An SD-JWT VC is bound when it has `cnf`; an mdoc always has its MSO's device key.
    fn binding(&self) -> CryptographicBinding {
        match &self.body {
            Body::SdJwtVc(vc) => vc.binding(),
            Body::Mdoc(_) => CryptographicBinding::Bound,
        }
    }
}

/// DCQL evaluation over usable credentials only (A1).
impl siros_dcql::Credential for UsableCredential<'_> {
    fn id(&self) -> &CredentialRef {
        siros_dcql::Credential::id(self.credential())
    }

    fn format(&self) -> &CredentialFormat {
        siros_dcql::Credential::format(self.credential())
    }

    fn claim(&self, path: &ClaimPath) -> Result<Vec<Json>, PathError> {
        self.credential().claim(path)
    }

    fn binding(&self) -> CryptographicBinding {
        self.credential().binding()
    }
}

impl TypedValue<'_> {
    /// The value as JSON, for the comparison with a claims query's `values` (OpenID4VP 1.0,
    /// Section 6.3): a `full-date` as `"YYYY-MM-DD"`, a `tdate` as `"YYYY-MM-DDThh:mm:ssZ"`, a
    /// byte string as its base64url text, as RFC 8949, Section 6.1 converts CBOR to JSON.
    #[must_use]
    pub fn to_json(self) -> Json {
        match self {
            TypedValue::Null => Json::Null,
            TypedValue::Bool(b) => Json::Bool(b),
            TypedValue::Integer(i) => integer(i),
            TypedValue::Number(n) => Json::Number(n.clone()),
            TypedValue::Text(t) => Json::String(t.to_owned()),
            TypedValue::Bytes(b) => Json::String(base64url::encode(b).into()),
            TypedValue::FullDate(d) => Json::String(d.to_string()),
            TypedValue::DateTime(t) => Json::String(t.to_string()),
            TypedValue::Array(a) => Json::Array(a.elements().map(TypedValue::to_json).collect()),
            TypedValue::Object(o) => {
                // Extended member by member: a map collected at once sorts first, which links a
                // slice sort into the picker.
                let mut members = Map::new();
                members.extend(
                    o.members()
                        .map(|(name, value)| (name.to_owned(), value.to_json())),
                );
                Json::Object(members)
            }
        }
    }
}

fn integer(i: i128) -> Json {
    if let Ok(i) = i64::try_from(i) {
        return Json::from(i);
    }
    if let Ok(u) = u64::try_from(i) {
        return Json::from(u);
    }
    // Below -2^63 JSON holds the integer as a float only.
    Json::from(i as f64)
}
