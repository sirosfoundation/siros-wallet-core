//! A stored mdoc: its `IssuerSigned` and the MSO (ISO/IEC 18013-5, 8.3.2.1.2.2 and 9.1.2).

use std::fmt;

use rustc_hash::FxHashSet;
use siros_codec::base64url;
use siros_codec::cbor::{self, Item, Kind, Value};
use siros_dcql::DocType;

use crate::error::{
    DocTypeFault, EnvelopeFault, IssuerAuthFault, ItemFault, ItemMember, MdocError, NameSpacesFault,
};
use crate::issuer_auth::IssuerAuth;
use crate::mso::{non_empty_array, non_empty_map, Mso};
use crate::names::{DigestId, ElementIdentifier, NameSpace};

/// An mdoc whose `Document` and items agree with its MSO.
#[derive(Clone, PartialEq, Eq)]
pub struct Mdoc {
    issuer_signed: Vec<u8>,
    name_spaces: Vec<IssuerNameSpace>,
    issuer_auth: IssuerAuth,
    mso: Mso,
}

/// A namespace of `IssuerSigned` and its items, in the issuer's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerNameSpace {
    name: NameSpace,
    items: Vec<IssuerSignedItem>,
}

/// An `IssuerSignedItem` whose digest the MSO lists.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerSignedItem {
    bytes: Vec<u8>,
    digest_id: DigestId,
    identifier: ElementIdentifier,
    value: Value,
}

impl Mdoc {
    /// Reads base64url, without padding, of an `IssuerSigned`, of a `Document`, or of a
    /// `DeviceResponse` with one document.
    ///
    /// # Errors
    ///
    /// [`MdocError`]: the first part of the credential that breaks its structure or disagrees
    /// with the MSO.
    pub fn parse(data: &str) -> Result<Self, MdocError> {
        let bytes = base64url::decode(data).map_err(MdocError::Encoding)?;
        let root = cbor::decode(&bytes).map_err(MdocError::Cbor)?;
        let (issuer_signed, doc_type) = envelope(&root)?;
        let auth = issuer_signed
            .get("issuerAuth")
            .ok_or(MdocError::IssuerAuth(IssuerAuthFault::Absent))?;
        let (issuer_auth, payload) = IssuerAuth::read(auth)?;
        let mso = Mso::read(payload)?;
        if doc_type.is_some_and(|d| *mso.doc_type() != d) {
            return Err(MdocError::DocType(DocTypeFault::Mismatch));
        }
        let name_spaces = match issuer_signed.get("nameSpaces") {
            Some(spaces) => read_name_spaces(spaces, &mso)?,
            None => Vec::new(),
        };
        Ok(Self {
            issuer_signed: issuer_signed.raw().to_vec(),
            name_spaces,
            issuer_auth,
            mso,
        })
    }

    /// `docType`.
    #[must_use]
    pub fn doc_type(&self) -> &DocType {
        self.mso.doc_type()
    }

    /// The namespaces of `IssuerSigned`, in the issuer's order.
    pub fn name_spaces(&self) -> &[IssuerNameSpace] {
        &self.name_spaces
    }

    /// `issuerAuth`.
    pub fn issuer_auth(&self) -> &IssuerAuth {
        &self.issuer_auth
    }

    /// The MSO.
    pub fn mso(&self) -> &Mso {
        &self.mso
    }

    /// The encoded `IssuerSigned`.
    pub fn issuer_signed(&self) -> &[u8] {
        &self.issuer_signed
    }
}

impl IssuerNameSpace {
    /// The namespace.
    #[must_use]
    pub fn name(&self) -> &NameSpace {
        &self.name
    }

    /// Its items, in the issuer's order, each element identifier once.
    pub fn items(&self) -> &[IssuerSignedItem] {
        &self.items
    }
}

impl IssuerSignedItem {
    /// `IssuerSignedItemBytes`, `#6.24(bstr .cbor IssuerSignedItem)`, as the issuer wrote it.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `digestID`.
    #[must_use]
    pub fn digest_id(&self) -> DigestId {
        self.digest_id
    }

    /// `elementIdentifier`.
    #[must_use]
    pub fn identifier(&self) -> &ElementIdentifier {
        &self.identifier
    }

    /// `elementValue`.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// `IssuerSignedItem = {"digestID": uint, "random": bstr, "elementIdentifier": tstr,
    /// "elementValue": any}`.
    fn read(name_space: &NameSpace, tagged: &Item<'_>) -> Result<Self, MdocError> {
        let inner = tagged
            .untag(24)
            .and_then(Item::as_bytes)
            .ok_or_else(|| MdocError::NameSpaces(NameSpacesFault::NotTagged(name_space.clone())))?;
        let item = cbor::decode(inner).map_err(|e| MdocError::Item(ItemFault::Cbor(e)))?;
        let missing = |member| MdocError::Item(ItemFault::Member(member));
        let Some(Kind::Unsigned(digest_id)) = item.get("digestID").map(Item::kind) else {
            return Err(missing(ItemMember::DigestId));
        };
        item.get("random")
            .and_then(Item::as_bytes)
            .ok_or(missing(ItemMember::Random))?;
        let identifier = item
            .get("elementIdentifier")
            .and_then(Item::as_text)
            .ok_or(missing(ItemMember::ElementIdentifier))?;
        let value = item
            .get("elementValue")
            .ok_or(missing(ItemMember::ElementValue))?;
        Ok(Self {
            bytes: tagged.raw().to_vec(),
            digest_id: DigestId::new(*digest_id),
            identifier: ElementIdentifier::new(identifier),
            value: Value::from_item(value),
        })
    }
}

/// Shows the namespaces, `issuerAuth` and the MSO: an element value may be a secret.
impl fmt::Debug for Mdoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mdoc")
            .field("name_spaces", &self.name_spaces)
            .field("issuer_auth", &self.issuer_auth)
            .field("mso", &self.mso)
            .finish_non_exhaustive()
    }
}

/// Shows `digestID` and the element identifier: the value may be a secret.
impl fmt::Debug for IssuerSignedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerSignedItem")
            .field("digest_id", &self.digest_id)
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

/// The `IssuerSigned` map, and the `Document`'s `docType` when there is one.
fn envelope<'i, 'a>(root: &'i Item<'a>) -> Result<(&'i Item<'a>, Option<&'a str>), MdocError> {
    if root.get("issuerAuth").is_some() {
        return Ok((root, None));
    }
    let document = match root.get("documents").and_then(Item::as_array) {
        Some([document]) => document,
        Some(documents) => {
            return Err(MdocError::Envelope(EnvelopeFault::Documents(
                documents.len(),
            )))
        }
        None => root,
    };
    let issuer_signed = document
        .get("issuerSigned")
        .ok_or(MdocError::Envelope(EnvelopeFault::IssuerSigned))?;
    let doc_type = document
        .get("docType")
        .and_then(Item::as_text)
        .ok_or(MdocError::DocType(DocTypeFault::Document))?;
    Ok((issuer_signed, Some(doc_type)))
}

/// `IssuerNameSpaces = {+ NameSpace => [+ IssuerSignedItemBytes]}`, each item with the digest
/// the MSO lists.
fn read_name_spaces(spaces: &Item<'_>, mso: &Mso) -> Result<Vec<IssuerNameSpace>, MdocError> {
    let fault = MdocError::NameSpaces;
    let entries = non_empty_map(Some(spaces)).map_err(|e| fault(NameSpacesFault::Member(e)))?;
    let mut names = FxHashSet::default();
    let mut name_spaces = Vec::with_capacity(entries.len());
    for (name, items) in entries {
        let name = name.as_text().ok_or(fault(NameSpacesFault::NameNotText))?;
        if !names.insert(name) {
            return Err(fault(NameSpacesFault::Repeated(NameSpace::new(name))));
        }
        let name = NameSpace::new(name);
        let items = non_empty_array(Some(items))
            .map_err(|e| fault(NameSpacesFault::Items(name.clone(), e)))?;
        let items = read_items(&name, items, mso)?;
        name_spaces.push(IssuerNameSpace { name, items });
    }
    Ok(name_spaces)
}

fn read_items(
    name_space: &NameSpace,
    items: &[Item<'_>],
    mso: &Mso,
) -> Result<Vec<IssuerSignedItem>, MdocError> {
    let mut identifiers = FxHashSet::default();
    let mut read = Vec::with_capacity(items.len());
    for tagged in items {
        let item = IssuerSignedItem::read(name_space, tagged)?;
        if !identifiers.insert(item.identifier.clone()) {
            return Err(MdocError::RepeatedElement);
        }
        let digest = mso.digest_algorithm().digest(&item.bytes);
        if mso.value_digest(name_space, item.digest_id) != Some(&digest) {
            return Err(MdocError::ItemDigest);
        }
        read.push(item);
    }
    Ok(read)
}
