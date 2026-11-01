//! The `MobileSecurityObject` (ISO/IEC 18013-5, 9.1.2.4).

use rustc_hash::FxHashMap;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use siros_codec::cbor::{self, Item, Kind};
use siros_codec::date::DateTime;
use siros_codec::member::MemberFault;
use siros_dcql::DocType;

use crate::device_key::P256Key;
use crate::error::{
    DeviceKeyFault, DocTypeFault, MdocError, NameFault, PayloadFault, ValidityFault, ValidityTime,
    ValueDigestsFault,
};
use crate::key_authorizations::KeyAuthorizations;
use crate::names::{DigestId, NameSpace};

/// The MSO the issuer signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mso {
    doc_type: DocType,
    digest_algorithm: DigestAlgorithm,
    value_digests: FxHashMap<NameSpace, FxHashMap<DigestId, ItemDigest>>,
    device_key: P256Key,
    key_authorizations: KeyAuthorizations,
    validity: Validity,
}

impl Mso {
    /// `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)`.
    pub(crate) fn read(payload: &[u8]) -> Result<Self, MdocError> {
        let tagged =
            cbor::decode(payload).map_err(|e| MdocError::Payload(PayloadFault::Cbor(e)))?;
        let inner = tagged
            .untag(24)
            .and_then(Item::as_bytes)
            .ok_or(MdocError::Payload(PayloadFault::NotTagged))?;
        let mso = cbor::decode(inner).map_err(|e| MdocError::Payload(PayloadFault::Mso(e)))?;
        let doc_type = mso
            .get("docType")
            .and_then(Item::as_text)
            .ok_or(MdocError::DocType(DocTypeFault::Mso))?;
        let digest_algorithm = DigestAlgorithm::read(mso.get("digestAlgorithm"))
            .map_err(MdocError::DigestAlgorithm)?;
        let device_key_info = mso
            .get("deviceKeyInfo")
            .ok_or(MdocError::DeviceKey(DeviceKeyFault::Info))?;
        Ok(Self {
            doc_type: DocType::new(doc_type),
            digest_algorithm,
            value_digests: read_value_digests(mso.get("valueDigests"), digest_algorithm)
                .map_err(MdocError::ValueDigests)?,
            device_key: P256Key::read(device_key_info.get("deviceKey"))
                .map_err(MdocError::DeviceKey)?,
            key_authorizations: KeyAuthorizations::read(device_key_info.get("keyAuthorizations"))
                .map_err(MdocError::KeyAuthorizations)?,
            validity: Validity::read(mso.get("validityInfo")).map_err(MdocError::Validity)?,
        })
    }

    /// `docType`.
    #[must_use]
    pub fn doc_type(&self) -> &DocType {
        &self.doc_type
    }

    /// `digestAlgorithm`.
    #[must_use]
    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// The digest `valueDigests` lists for `digest_id` of `name_space`.
    #[must_use]
    pub fn value_digest(&self, name_space: &NameSpace, digest_id: DigestId) -> Option<&ItemDigest> {
        self.value_digests
            .get(name_space)
            .and_then(|digests| digests.get(&digest_id))
    }

    /// `deviceKeyInfo.deviceKey`.
    #[must_use]
    pub fn device_key(&self) -> &P256Key {
        &self.device_key
    }

    /// `deviceKeyInfo.keyAuthorizations`; none when it is absent.
    #[must_use]
    pub fn key_authorizations(&self) -> &KeyAuthorizations {
        &self.key_authorizations
    }

    /// `validityInfo`.
    #[must_use]
    pub fn validity(&self) -> &Validity {
        &self.validity
    }
}

/// A digest algorithm of `digestAlgorithm` (ISO/IEC 18013-5, 9.1.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// `SHA-256`.
    Sha256,
    /// `SHA-384`.
    Sha384,
    /// `SHA-512`.
    Sha512,
}

/// The digest of an `IssuerSignedItemBytes`, of its algorithm's length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemDigest(Vec<u8>);

impl ItemDigest {
    /// The digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl DigestAlgorithm {
    fn read(item: Option<&Item<'_>>) -> Result<Self, NameFault> {
        let name = item
            .ok_or(NameFault::Member(MemberFault::Absent))?
            .as_text()
            .ok_or(NameFault::Member(MemberFault::WrongType))?;
        match name {
            "SHA-256" => Ok(Self::Sha256),
            "SHA-384" => Ok(Self::Sha384),
            "SHA-512" => Ok(Self::Sha512),
            _ => Err(NameFault::Unknown),
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The digest of `bytes`.
    pub(crate) fn digest(self, bytes: &[u8]) -> ItemDigest {
        ItemDigest(match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        })
    }
}

/// A non-empty map.
pub(crate) fn non_empty_map<'i, 'a>(
    item: Option<&'i Item<'a>>,
) -> Result<&'i [(Item<'a>, Item<'a>)], MemberFault> {
    match item.ok_or(MemberFault::Absent)?.as_map() {
        None => Err(MemberFault::WrongType),
        Some([]) => Err(MemberFault::Empty),
        Some(entries) => Ok(entries),
    }
}

/// A non-empty array.
pub(crate) fn non_empty_array<'i, 'a>(
    item: Option<&'i Item<'a>>,
) -> Result<&'i [Item<'a>], MemberFault> {
    match item.ok_or(MemberFault::Absent)?.as_array() {
        None => Err(MemberFault::WrongType),
        Some([]) => Err(MemberFault::Empty),
        Some(items) => Ok(items),
    }
}

/// `ValueDigests = {+ NameSpace => {+ DigestID => Digest}}`.
fn read_value_digests(
    item: Option<&Item<'_>>,
    algorithm: DigestAlgorithm,
) -> Result<FxHashMap<NameSpace, FxHashMap<DigestId, ItemDigest>>, ValueDigestsFault> {
    let name_spaces = non_empty_map(item).map_err(ValueDigestsFault::Member)?;
    let mut value_digests = FxHashMap::default();
    for (name_space, digests) in name_spaces {
        let name_space = NameSpace::new(name_space.as_text().ok_or(ValueDigestsFault::NameSpace)?);
        let digests = read_digests(&name_space, digests, algorithm)?;
        if value_digests.contains_key(&name_space) {
            return Err(ValueDigestsFault::RepeatedNameSpace(name_space));
        }
        value_digests.insert(name_space, digests);
    }
    Ok(value_digests)
}

/// `{+ DigestID => Digest}` of `name_space`.
fn read_digests(
    name_space: &NameSpace,
    digests: &Item<'_>,
    algorithm: DigestAlgorithm,
) -> Result<FxHashMap<DigestId, ItemDigest>, ValueDigestsFault> {
    let digests = non_empty_map(Some(digests))
        .map_err(|fault| ValueDigestsFault::Digests(name_space.clone(), fault))?;
    let mut by_id = FxHashMap::default();
    for (id, digest) in digests {
        let Kind::Unsigned(id) = id.kind() else {
            return Err(ValueDigestsFault::DigestId(name_space.clone()));
        };
        let id = DigestId::new(*id);
        let digest = digest
            .as_bytes()
            .ok_or_else(|| ValueDigestsFault::Digest(name_space.clone(), id))?;
        if digest.len() != algorithm.output_len() {
            return Err(ValueDigestsFault::DigestLength(
                name_space.clone(),
                id,
                digest.len(),
            ));
        }
        if by_id.insert(id, ItemDigest(digest.to_vec())).is_some() {
            return Err(ValueDigestsFault::RepeatedDigestId(name_space.clone(), id));
        }
    }
    Ok(by_id)
}

/// `validityInfo`: `signed ≤ validFrom < validUntil` (ISO/IEC 18013-5, 9.1.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Validity {
    signed: DateTime,
    valid_from: DateTime,
    valid_until: DateTime,
}

impl Validity {
    fn read(item: Option<&Item<'_>>) -> Result<Self, ValidityFault> {
        let validity = item.ok_or(ValidityFault::Absent)?;
        let time = |member: ValidityTime| -> Result<DateTime, ValidityFault> {
            validity
                .get(member.name())
                .and_then(|t| t.untag(0))
                .and_then(Item::as_text)
                .and_then(DateTime::parse)
                .ok_or(ValidityFault::Time(member))
        };
        let signed = time(ValidityTime::Signed)?;
        let valid_from = time(ValidityTime::ValidFrom)?;
        let valid_until = time(ValidityTime::ValidUntil)?;
        if valid_from < signed || valid_until <= valid_from {
            return Err(ValidityFault::Order);
        }
        Ok(Self {
            signed,
            valid_from,
            valid_until,
        })
    }

    /// `signed`: when the issuer signed the MSO.
    #[must_use]
    pub fn signed(&self) -> DateTime {
        self.signed
    }

    /// `validFrom`: the MSO is valid from this second.
    #[must_use]
    pub fn valid_from(&self) -> DateTime {
        self.valid_from
    }

    /// `validUntil`: the MSO is valid before this second.
    #[must_use]
    pub fn valid_until(&self) -> DateTime {
        self.valid_until
    }
}
