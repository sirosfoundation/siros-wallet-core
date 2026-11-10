//! The refusals of reading and of disclosing, each with a stable code and its cause.

use std::fmt;

use base64::DecodeError;
use siros_explain::Explain;
use siros_openid4vp::cbor::CborError as Core;

use super::names::{DigestId, NameSpace};

/// Why a stored credential is no mdoc [`StoredMdoc::parse`](super::StoredMdoc::parse) reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[error("mso_mdoc: {}: {:?}", self.code(), self)]
pub enum MdocError {
    /// The text is not base64url without padding.
    #[explain(id = "stored.mdoc_error.encoding")]
    Encoding(#[source] DecodeError),
    /// The bytes are not one CBOR item the strict reader accepts.
    #[error("mso_mdoc: cbor: {0}")]
    #[explain(id = "stored.mdoc_error.cbor")]
    Cbor(#[source] CborError),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    #[explain(id = "stored.mdoc_error.envelope")]
    Envelope(#[source] EnvelopeFault),
    /// `issuerAuth` is not an untagged `COSE_Sign1` with a protected header, a payload and a
    /// signature as byte strings.
    #[explain(id = "stored.mdoc_error.issuer_auth")]
    IssuerAuth(#[source] IssuerAuthFault),
    /// The protected header names no algorithm (label 1) as an integer.
    #[explain(id = "stored.mdoc_error.algorithm")]
    Algorithm(#[source] AlgorithmFault),
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    #[explain(id = "stored.mdoc_error.x5chain")]
    X5chain(#[source] MemberFault),
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    #[explain(id = "stored.mdoc_error.payload")]
    Payload(#[source] PayloadFault),
    /// The MSO has no `docType`, or the `Document` names another.
    #[explain(id = "stored.mdoc_error.doc_type")]
    DocType(#[source] DocTypeFault),
    /// `digestAlgorithm` is not `SHA-256`, `SHA-384` or `SHA-512`.
    #[explain(id = "stored.mdoc_error.digest_algorithm")]
    DigestAlgorithm(#[source] NameFault),
    /// `valueDigests` is no non-empty map from namespaces to non-empty maps from `digestID` to
    /// digests of the algorithm's length, each namespace and `digestID` once.
    #[explain(id = "stored.mdoc_error.value_digests")]
    ValueDigests(#[source] ValueDigestsFault),
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    #[explain(id = "stored.mdoc_error.device_key")]
    DeviceKey(#[source] DeviceKeyFault),
    /// `keyAuthorizations` breaks its CDDL, repeats a name, or names a namespace both whole and
    /// by its elements.
    #[explain(id = "stored.mdoc_error.key_authorizations")]
    KeyAuthorizations(#[source] KeyAuthorizationsFault),
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`, or
    /// `validFrom` precedes `signed` or does not precede `validUntil`.
    #[explain(id = "stored.mdoc_error.validity")]
    Validity(#[source] ValidityFault),
    /// `nameSpaces` is no non-empty map from namespaces to non-empty arrays of
    /// `IssuerSignedItemBytes`, each namespace once.
    #[explain(id = "stored.mdoc_error.name_spaces")]
    NameSpaces(#[source] NameSpacesFault),
    /// An `IssuerSignedItem` lacks `digestID`, `random`, `elementIdentifier` or `elementValue`.
    #[explain(id = "stored.mdoc_error.item")]
    Item(#[source] ItemFault),
    /// A namespace holds an element identifier twice.
    #[explain(id = "stored.mdoc_error.repeated_element")]
    RepeatedElement,
    /// The digest of an `IssuerSignedItemBytes` is not the one `valueDigests` lists under its
    /// namespace and `digestID`.
    #[explain(id = "stored.mdoc_error.item_digest")]
    ItemDigest,
}

/// Why the top level is no envelope [`StoredMdoc::parse`](super::StoredMdoc::parse) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum EnvelopeFault {
    /// `documents` holds this many documents, where one is read.
    #[error("`documents` holds {count} documents, where one is read")]
    #[explain(id = "stored.envelope_fault.documents")]
    Documents {
        /// The documents.
        count: usize,
    },
    /// The `Document` has no `issuerSigned`.
    #[error("the `Document` has no `issuerSigned`")]
    #[explain(id = "stored.envelope_fault.issuer_signed")]
    IssuerSigned,
}

/// Why `issuerAuth` is no `COSE_Sign1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum IssuerAuthFault {
    /// `IssuerSigned` has no `issuerAuth`.
    #[error("`IssuerSigned` has no `issuerAuth`")]
    #[explain(id = "stored.issuer_auth_fault.absent")]
    Absent,
    /// It is not an array of four items.
    #[error("it is not an array of four items")]
    #[explain(id = "stored.issuer_auth_fault.not_sign1")]
    NotSign1,
    /// The protected header is not a byte string.
    #[error("the protected header is not a byte string")]
    #[explain(id = "stored.issuer_auth_fault.protected")]
    Protected,
    /// The payload is not a byte string.
    #[error("the payload is not a byte string")]
    #[explain(id = "stored.issuer_auth_fault.payload")]
    Payload,
    /// The signature is not a byte string.
    #[error("the signature is not a byte string")]
    #[explain(id = "stored.issuer_auth_fault.signature")]
    Signature,
}

/// Why the protected header names no algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum AlgorithmFault {
    /// The header is not one CBOR item.
    #[error("the header is not one CBOR item")]
    #[explain(id = "stored.algorithm_fault.header")]
    Header(#[source] CborError),
    /// The header has no integer under label 1.
    #[error("the header has no integer under label 1")]
    #[explain(id = "stored.algorithm_fault.absent")]
    Absent,
}

/// Why the payload is no MSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum PayloadFault {
    /// The payload is not one CBOR item.
    #[error("the payload is not one CBOR item")]
    #[explain(id = "stored.payload_fault.cbor")]
    Cbor(#[source] CborError),
    /// It is not a byte string under tag 24.
    #[error("it is not a byte string under tag 24")]
    #[explain(id = "stored.payload_fault.not_tagged")]
    NotTagged,
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    #[explain(id = "stored.payload_fault.mso")]
    Mso(#[source] CborError),
}

/// Why the `docType` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum DocTypeFault {
    /// The MSO has no `docType` text.
    #[error("the MSO has no `docType` text")]
    #[explain(id = "stored.doc_type_fault.mso")]
    Mso,
    /// The `Document` has no `docType` text.
    #[error("the `Document` has no `docType` text")]
    #[explain(id = "stored.doc_type_fault.document")]
    Document,
    /// The `Document` names another `docType` than its MSO.
    #[error("the `Document` names another `docType` than its MSO")]
    #[explain(id = "stored.doc_type_fault.mismatch")]
    Mismatch,
}

/// Why a member names nothing this crate knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum NameFault {
    /// It is absent or not text.
    #[error("it is absent or not text")]
    #[explain(id = "stored.name_fault.member")]
    Member(#[source] MemberFault),
    /// It names none of the values this crate reads.
    #[error("it names none of the values this crate reads")]
    #[explain(id = "stored.name_fault.unknown")]
    Unknown,
}

/// Why `valueDigests` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum ValueDigestsFault {
    /// `valueDigests` is no non-empty map.
    #[error("`valueDigests` is no non-empty map")]
    #[explain(id = "stored.value_digests_fault.member")]
    Member(#[source] MemberFault),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    #[explain(id = "stored.value_digests_fault.name_space")]
    NameSpace,
    /// The namespace's digests are no non-empty map.
    #[error("the digests of namespace `{namespace}` are no non-empty map")]
    #[explain(id = "stored.value_digests_fault.digests")]
    Digests {
        /// The namespace.
        namespace: NameSpace,
        /// The rule its digests break.
        #[source]
        cause: MemberFault,
    },
    /// A `digestID` of the namespace is not an unsigned integer.
    #[error("a `digestID` of namespace `{namespace}` is not an unsigned integer")]
    #[explain(id = "stored.value_digests_fault.digest_id")]
    DigestId {
        /// The namespace.
        namespace: NameSpace,
    },
    /// The digest under this `digestID` is not a byte string.
    #[error(
        "the digest under `digestID` {digest_id} of namespace `{namespace}` is not a byte string"
    )]
    #[explain(id = "stored.value_digests_fault.digest")]
    Digest {
        /// The namespace.
        namespace: NameSpace,
        /// The `digestID`.
        digest_id: DigestId,
    },
    /// The digest under this `digestID` has this many bytes, another length than the
    /// algorithm's.
    #[error(
        "the digest under `digestID` {digest_id} of namespace `{namespace}` has {length} bytes, another length than the algorithm's"
    )]
    #[explain(id = "stored.value_digests_fault.digest_length")]
    DigestLength {
        /// The namespace.
        namespace: NameSpace,
        /// The `digestID`.
        digest_id: DigestId,
        /// The digest's bytes.
        length: usize,
    },
}

/// Why `deviceKeyInfo.deviceKey` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum DeviceKeyFault {
    /// The MSO has no `deviceKeyInfo`.
    #[error("the MSO has no `deviceKeyInfo`")]
    #[explain(id = "stored.device_key_fault.info")]
    Info,
    /// `deviceKeyInfo` has no `deviceKey`.
    #[error("`deviceKeyInfo` has no `deviceKey`")]
    #[explain(id = "stored.device_key_fault.absent")]
    Absent,
    /// `kty` (label 1) is not the curve's: 2, EC2, or 1, OKP.
    #[error("`kty` (label 1) is not the curve's")]
    #[explain(id = "stored.device_key_fault.key_type")]
    KeyType,
    /// `crv` (label -1) names no curve of ISO/IEC 18013-5 Table 22.
    #[error("`crv` (label -1) names no curve of Table 22")]
    #[explain(id = "stored.device_key_fault.curve")]
    Curve,
    /// A P-256 key's `x` (label -2) or `y` (label -3) is not a 32-byte string.
    #[error("a P-256 key's `x` (label -2) or `y` (label -3) is not a 32-byte string")]
    #[explain(id = "stored.device_key_fault.coordinate")]
    Coordinate,
    /// `alg` (label 3) is a signature algorithm the curve does not make (RFC 9052 §7.1; RFC 9053
    /// §2.1, §2.2, §7.1; RFC 9864 §2).
    #[error("`alg` (label 3) is a signature algorithm the curve does not make")]
    #[explain(id = "stored.device_key_fault.algorithm")]
    Algorithm,
}

/// Why a list of names in `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum NamesFault {
    /// It is no non-empty array.
    #[error("it is no non-empty array")]
    #[explain(id = "stored.names_fault.member")]
    Member(#[source] MemberFault),
    /// A name is not text.
    #[error("a name is not text")]
    #[explain(id = "stored.names_fault.not_text")]
    NotText,
    /// It holds this name twice.
    #[error("it holds the name {name:?} twice")]
    #[explain(id = "stored.names_fault.repeated")]
    Repeated {
        /// The name.
        name: String,
    },
}

/// Why `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum KeyAuthorizationsFault {
    /// It is not a map.
    #[error("it is not a map")]
    #[explain(id = "stored.key_authorizations_fault.not_map")]
    NotMap,
    /// `nameSpaces`.
    #[error("`nameSpaces`")]
    #[explain(id = "stored.key_authorizations_fault.name_spaces")]
    NameSpaces(#[source] NamesFault),
    /// `dataElements` is no non-empty map.
    #[error("`dataElements` is no non-empty map")]
    #[explain(id = "stored.key_authorizations_fault.data_elements")]
    DataElements(#[source] MemberFault),
    /// A namespace of `dataElements` is not text.
    #[error("a namespace of `dataElements` is not text")]
    #[explain(id = "stored.key_authorizations_fault.name_space")]
    NameSpace,
    /// The element identifiers of this namespace.
    #[error("the element identifiers of namespace `{namespace}`")]
    #[explain(id = "stored.key_authorizations_fault.elements")]
    Elements {
        /// The namespace.
        namespace: NameSpace,
        /// The rule its element identifiers break.
        #[source]
        cause: NamesFault,
    },
    /// This namespace is in `nameSpaces` and in `dataElements`.
    #[error("namespace `{namespace}` is in `nameSpaces` and in `dataElements`")]
    #[explain(id = "stored.key_authorizations_fault.overlap")]
    Overlap {
        /// The namespace.
        namespace: NameSpace,
    },
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

/// The member's name.
impl fmt::Display for ValidityTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why `validityInfo` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum ValidityFault {
    /// The MSO has no `validityInfo`.
    #[error("the MSO has no `validityInfo`")]
    #[explain(id = "stored.validity_fault.absent")]
    Absent,
    /// This time is absent or no 20-character `tdate`.
    #[error("`{time}` is absent or no 20-character `tdate`")]
    #[explain(id = "stored.validity_fault.time")]
    Time {
        /// The time.
        time: ValidityTime,
    },
    /// `validFrom` precedes `signed`, or does not precede `validUntil`.
    #[error("`validFrom` precedes `signed`, or does not precede `validUntil`")]
    #[explain(id = "stored.validity_fault.order")]
    Order,
}

/// Why `nameSpaces` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum NameSpacesFault {
    /// `nameSpaces` is no non-empty map.
    #[error("`nameSpaces` is no non-empty map")]
    #[explain(id = "stored.name_spaces_fault.member")]
    Member(#[source] MemberFault),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    #[explain(id = "stored.name_spaces_fault.name_space")]
    NameSpace,
    /// The namespace's items are no non-empty array.
    #[error("the items of namespace `{namespace}` are no non-empty array")]
    #[explain(id = "stored.name_spaces_fault.items")]
    Items {
        /// The namespace.
        namespace: NameSpace,
        /// The rule its items break.
        #[source]
        cause: MemberFault,
    },
    /// An item of the namespace is no byte string under tag 24.
    #[error("an item of namespace `{namespace}` is no byte string under tag 24")]
    #[explain(id = "stored.name_spaces_fault.not_tagged")]
    NotTagged {
        /// The namespace.
        namespace: NameSpace,
    },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ItemFault {
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    #[explain(id = "stored.item_fault.cbor")]
    Cbor(#[source] CborError),
    /// This member is absent or of another CBOR type.
    #[error("`{member}` is absent or of another CBOR type")]
    #[explain(id = "stored.item_fault.member")]
    Member {
        /// The member.
        member: ItemMember,
    },
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

/// The member's name.
impl fmt::Display for ItemMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
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

super::position!(
    /// The position of an entry in an array member.
    pub ArrayIndex
);

/// What breaks the rule of a member of a decoded CBOR map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum MemberFault {
    /// The member is absent.
    #[error("the member is absent")]
    #[explain(id = "stored.member_fault.absent")]
    Absent,
    /// The member has another type than its rule gives it.
    #[error("the member has another type than its rule gives it")]
    #[explain(id = "stored.member_fault.wrong_type")]
    WrongType,
    /// The member is an empty string, array or map.
    #[error("the member is an empty string, array or map")]
    #[explain(id = "stored.member_fault.empty")]
    Empty,
    /// The array entry at this position breaks the rule of the entries.
    #[error("the array entry at position {position} breaks the rule of the entries")]
    #[explain(id = "stored.member_fault.entry")]
    Entry {
        /// The entry's position.
        position: ArrayIndex,
    },
}

/// Why bytes are no CBOR data item the core reads (RFC 8949): the kind of the core's
/// [`CborError`](siros_openid4vp::cbor::CborError).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
pub enum CborError {
    /// The bytes end inside the data item.
    #[error("the bytes end inside the data item")]
    #[explain(id = "stored.cbor_error.truncated")]
    Truncated,
    /// A head that is not well-formed, or a value the reading refuses.
    #[error("a head that is not well-formed")]
    #[explain(id = "stored.cbor_error.malformed")]
    Malformed,
    /// A text string that is no UTF-8.
    #[error("a text string that is no UTF-8")]
    #[explain(id = "stored.cbor_error.utf8")]
    Utf8,
    /// Nesting deeper than the reading admits.
    #[error("nesting deeper than the reading admits")]
    #[explain(id = "stored.cbor_error.depth")]
    Depth,
    /// Bytes after the data item.
    #[error("bytes after the data item")]
    #[explain(id = "stored.cbor_error.trailing")]
    Trailing,
    /// A map holds one key twice.
    #[error("a map holds one key twice")]
    #[explain(id = "stored.cbor_error.repeated_key")]
    RepeatedKey,
}

impl From<Core> for CborError {
    fn from(error: Core) -> Self {
        match error {
            Core::Truncated => Self::Truncated,
            Core::Utf8 { .. } => Self::Utf8,
            Core::Depth { .. } => Self::Depth,
            Core::Trailing { .. } => Self::Trailing,
            Core::RepeatedKey { .. } => Self::RepeatedKey,
            Core::Malformed { .. }
            | Core::Indefinite { .. }
            | Core::Simple { .. }
            | Core::Encode { .. }
            | Core::IntegerRange { .. }
            | Core::DoubleRange { .. }
            | Core::Key { .. }
            | Core::Object { .. }
            | Core::Unknown { .. } => Self::Malformed,
        }
    }
}
