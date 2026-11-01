//! The refusals of reading and of disclosing, each with a stable code and its cause.

use siros_codec::cbor::CborError;
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;

use crate::names::{DigestId, NameSpace};

/// Why a stored credential is no mdoc [`Mdoc::parse`](crate::Mdoc::parse) reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("mso_mdoc: {}: {:?}", self.code(), self)]
pub enum MdocError {
    /// The text is not base64url without padding.
    Encoding(#[source] Base64Error),
    /// The bytes are not one CBOR item the strict reader accepts.
    #[error("mso_mdoc: cbor: {0}")]
    Cbor(#[source] CborError),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    Envelope(#[source] EnvelopeFault),
    /// `issuerAuth` is not an untagged `COSE_Sign1` with a protected header, a payload and a
    /// signature as byte strings.
    IssuerAuth(#[source] IssuerAuthFault),
    /// The protected header names no algorithm (label 1) as an integer.
    Algorithm(#[source] AlgorithmFault),
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    X5chain(#[source] MemberFault),
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    Payload(#[source] PayloadFault),
    /// The MSO has no `docType`, or the `Document` names another.
    DocType(#[source] DocTypeFault),
    /// `digestAlgorithm` is not `SHA-256`, `SHA-384` or `SHA-512`.
    DigestAlgorithm(#[source] NameFault),
    /// `valueDigests` is no non-empty map from namespaces to non-empty maps from `digestID` to
    /// digests of the algorithm's length, each namespace and `digestID` once.
    ValueDigests(#[source] ValueDigestsFault),
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    DeviceKey(#[source] DeviceKeyFault),
    /// `keyAuthorizations` breaks its CDDL, repeats a name, or names a namespace both whole and
    /// by its elements.
    KeyAuthorizations(#[source] KeyAuthorizationsFault),
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`, or
    /// `validFrom` precedes `signed` or does not precede `validUntil`.
    Validity(#[source] ValidityFault),
    /// `nameSpaces` is no non-empty map from namespaces to non-empty arrays of
    /// `IssuerSignedItemBytes`, each namespace once.
    NameSpaces(#[source] NameSpacesFault),
    /// An `IssuerSignedItem` lacks `digestID`, `random`, `elementIdentifier` or `elementValue`.
    Item(#[source] ItemFault),
    /// A namespace holds an element identifier twice.
    RepeatedElement,
    /// The digest of an `IssuerSignedItemBytes` is not the one `valueDigests` lists under its
    /// namespace and `digestID`.
    ItemDigest,
}

/// Why the top level is no envelope [`Mdoc::parse`](crate::Mdoc::parse) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum EnvelopeFault {
    /// `documents` holds this many documents, where one is read.
    #[error("`documents` holds {0} documents, where one is read")]
    Documents(usize),
    /// The `Document` has no `issuerSigned`.
    #[error("the `Document` has no `issuerSigned`")]
    IssuerSigned,
}

/// Why `issuerAuth` is no `COSE_Sign1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum IssuerAuthFault {
    /// `IssuerSigned` has no `issuerAuth`.
    #[error("`IssuerSigned` has no `issuerAuth`")]
    Absent,
    /// It is not an array of four items.
    #[error("it is not an array of four items")]
    NotSign1,
    /// The protected header is not a byte string.
    #[error("the protected header is not a byte string")]
    Protected,
    /// The payload is not a byte string.
    #[error("the payload is not a byte string")]
    Payload,
    /// The signature is not a byte string.
    #[error("the signature is not a byte string")]
    Signature,
}

/// Why the protected header names no algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AlgorithmFault {
    /// The header is not one CBOR item.
    #[error("the header is not one CBOR item")]
    Header(#[source] CborError),
    /// The header has no integer under label 1.
    #[error("the header has no integer under label 1")]
    Absent,
}

/// Why the payload is no MSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadFault {
    /// The payload is not one CBOR item.
    #[error("the payload is not one CBOR item")]
    Cbor(#[source] CborError),
    /// It is not a byte string under tag 24.
    #[error("it is not a byte string under tag 24")]
    NotTagged,
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    Mso(#[source] CborError),
}

/// Why the `docType` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum DocTypeFault {
    /// The MSO has no `docType` text.
    #[error("the MSO has no `docType` text")]
    Mso,
    /// The `Document` has no `docType` text.
    #[error("the `Document` has no `docType` text")]
    Document,
    /// The `Document` names another `docType` than its MSO.
    #[error("the `Document` names another `docType` than its MSO")]
    Mismatch,
}

/// Why a member names nothing this crate knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NameFault {
    /// It is absent or not text.
    #[error("it is absent or not text")]
    Member(#[source] MemberFault),
    /// It names none of the values this crate reads.
    #[error("it names none of the values this crate reads")]
    Unknown,
}

/// Why `valueDigests` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ValueDigestsFault {
    /// `valueDigests` is no non-empty map.
    #[error("`valueDigests` is no non-empty map")]
    Member(#[source] MemberFault),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    NameSpace,
    /// The namespace's digests are no non-empty map.
    #[error("the digests of namespace `{0}` are no non-empty map")]
    Digests(NameSpace, #[source] MemberFault),
    /// A `digestID` of the namespace is not an unsigned integer.
    #[error("a `digestID` of namespace `{0}` is not an unsigned integer")]
    DigestId(NameSpace),
    /// The digest under this `digestID` is not a byte string.
    #[error("the digest under `digestID` {1} of namespace `{0}` is not a byte string")]
    Digest(NameSpace, DigestId),
    /// The digest under this `digestID` has this many bytes, another length than the
    /// algorithm's.
    #[error(
        "the digest under `digestID` {1} of namespace `{0}` has {2} bytes, another length than the algorithm's"
    )]
    DigestLength(NameSpace, DigestId, usize),
    /// The namespace lists this `digestID` twice.
    #[error("namespace `{0}` lists `digestID` {1} twice")]
    RepeatedDigestId(NameSpace, DigestId),
    /// The map holds this namespace twice.
    #[error("the map holds namespace `{0}` twice")]
    RepeatedNameSpace(NameSpace),
}

/// Why `deviceKeyInfo.deviceKey` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum DeviceKeyFault {
    /// The MSO has no `deviceKeyInfo`.
    #[error("the MSO has no `deviceKeyInfo`")]
    Info,
    /// `deviceKeyInfo` has no `deviceKey`.
    #[error("`deviceKeyInfo` has no `deviceKey`")]
    Absent,
    /// `kty` (label 1) is not 2, EC2.
    #[error("`kty` (label 1) is not 2, EC2")]
    KeyType,
    /// `crv` (label -1) is not 1, P-256.
    #[error("`crv` (label -1) is not 1, P-256")]
    Curve,
    /// `x` (label -2) or `y` (label -3) is not a 32-byte string.
    #[error("`x` (label -2) or `y` (label -3) is not a 32-byte string")]
    Coordinate,
}

/// Why a list of names in `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NamesFault {
    /// It is no non-empty array.
    #[error("it is no non-empty array")]
    Member(#[source] MemberFault),
    /// A name is not text.
    #[error("a name is not text")]
    NotText,
    /// It holds this name twice.
    #[error("it holds the name {0:?} twice")]
    Repeated(String),
}

/// Why `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum KeyAuthorizationsFault {
    /// It is not a map.
    #[error("it is not a map")]
    NotMap,
    /// `nameSpaces`.
    #[error("`nameSpaces`")]
    NameSpaces(#[source] NamesFault),
    /// `dataElements` is no non-empty map.
    #[error("`dataElements` is no non-empty map")]
    DataElements(#[source] MemberFault),
    /// A namespace of `dataElements` is not text.
    #[error("a namespace of `dataElements` is not text")]
    NameSpace,
    /// The element identifiers of this namespace.
    #[error("the element identifiers of namespace `{0}`")]
    Elements(NameSpace, #[source] NamesFault),
    /// This namespace is in `nameSpaces` and in `dataElements`.
    #[error("namespace `{0}` is in `nameSpaces` and in `dataElements`")]
    Overlap(NameSpace),
    /// `dataElements` holds this namespace twice.
    #[error("`dataElements` holds namespace `{0}` twice")]
    RepeatedNameSpace(NameSpace),
}

/// A time of `validityInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityTime {
    /// `signed`.
    Signed,
    /// `validFrom`.
    ValidFrom,
    /// `validUntil`.
    ValidUntil,
}

impl ValidityTime {
    /// The member's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::ValidFrom => "validFrom",
            Self::ValidUntil => "validUntil",
        }
    }
}

/// Why `validityInfo` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ValidityFault {
    /// The MSO has no `validityInfo`.
    #[error("the MSO has no `validityInfo`")]
    Absent,
    /// This time is absent or no 20-character `tdate`.
    #[error("`{}` is absent or no 20-character `tdate`", .0.name())]
    Time(ValidityTime),
    /// `validFrom` precedes `signed`, or does not precede `validUntil`.
    #[error("`validFrom` precedes `signed`, or does not precede `validUntil`")]
    Order,
}

/// Why `nameSpaces` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NameSpacesFault {
    /// `nameSpaces` is no non-empty map.
    #[error("`nameSpaces` is no non-empty map")]
    Member(#[source] MemberFault),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    NameNotText,
    /// The map holds this namespace twice.
    #[error("the map holds namespace `{0}` twice")]
    Repeated(NameSpace),
    /// The namespace's items are no non-empty array.
    #[error("the items of namespace `{0}` are no non-empty array")]
    Items(NameSpace, #[source] MemberFault),
    /// An item of the namespace is no byte string under tag 24.
    #[error("an item of namespace `{0}` is no byte string under tag 24")]
    NotTagged(NameSpace),
}

/// A member of `IssuerSignedItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemMember {
    /// `digestID`, an unsigned integer.
    DigestId,
    /// `random`, a byte string.
    Random,
    /// `elementIdentifier`, text.
    ElementIdentifier,
    /// `elementValue`.
    ElementValue,
}

/// Why an `IssuerSignedItem` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ItemFault {
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    Cbor(#[source] CborError),
    /// This member is absent or of another CBOR type.
    #[error("`{}` is absent or of another CBOR type", .0.name())]
    Member(ItemMember),
}

impl ItemMember {
    /// The member's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::DigestId => "digestID",
            Self::Random => "random",
            Self::ElementIdentifier => "elementIdentifier",
            Self::ElementValue => "elementValue",
        }
    }
}

impl MdocError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Encoding(_) => "encoding",
            Self::Cbor(_) => "cbor",
            Self::Envelope(_) => "envelope",
            Self::IssuerAuth(_) => "issuer_auth",
            Self::Algorithm(_) => "algorithm",
            Self::X5chain(_) => "x5chain",
            Self::Payload(_) => "payload",
            Self::DocType(_) => "doc_type",
            Self::DigestAlgorithm(_) => "digest_algorithm",
            Self::ValueDigests(_) => "value_digests",
            Self::DeviceKey(_) => "device_key",
            Self::KeyAuthorizations(_) => "key_authorizations",
            Self::Validity(_) => "validity",
            Self::NameSpaces(_) => "name_spaces",
            Self::Item(_) => "item",
            Self::RepeatedElement => "repeated_element",
            Self::ItemDigest => "item_digest",
        }
    }
}

/// Why [`Mdoc::disclose`](crate::Mdoc::disclose) refuses a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("mso_mdoc disclosure: {}", self.code())]
pub enum DisclosureError {
    /// A selected element is no item of the mdoc.
    UnknownElement,
    /// An element is selected twice.
    RepeatedSelection,
    /// The MSO's `KeyAuthorizations` do not authorize a `DeviceSigned` element (OpenID4VP 1.0,
    /// B.2.1).
    Unauthorized,
    /// A `DeviceSigned` element is given twice.
    RepeatedDeviceElement,
}

impl DisclosureError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownElement => "unknown_element",
            Self::RepeatedSelection => "repeated_selection",
            Self::Unauthorized => "unauthorized_device_element",
            Self::RepeatedDeviceElement => "repeated_device_element",
        }
    }
}
