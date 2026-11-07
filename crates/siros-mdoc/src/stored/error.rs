//! The refusals of reading and of disclosing, each with a stable code and its cause.

use base64::DecodeError;
use siros_explain::{Count, Explain, IntoArg, kind};
use siros_openid4vp::cbor::CborError as Core;

use super::names::{DigestId, ElementIdentifier, NameSpace};

/// Why a stored credential is no mdoc [`StoredMdoc::parse`](super::StoredMdoc::parse) reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.mdoc_error")]
#[error("mso_mdoc: {}: {:?}", self.code(), self)]
pub enum MdocError {
    /// The text is not base64url without padding.
    Encoding(
        #[source]
        #[explain(skip)]
        DecodeError,
    ),
    /// The bytes are not one CBOR item the strict reader accepts.
    #[error("mso_mdoc: cbor: {0}")]
    Cbor(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    Envelope(
        #[source]
        #[explain(name = "cause")]
        EnvelopeFault,
    ),
    /// `issuerAuth` is not an untagged `COSE_Sign1` with a protected header, a payload and a
    /// signature as byte strings.
    IssuerAuth(
        #[source]
        #[explain(name = "cause")]
        IssuerAuthFault,
    ),
    /// The protected header names no algorithm (label 1) as an integer.
    Algorithm(
        #[source]
        #[explain(name = "cause")]
        AlgorithmFault,
    ),
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    X5chain(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    Payload(
        #[source]
        #[explain(name = "cause")]
        PayloadFault,
    ),
    /// The MSO has no `docType`, or the `Document` names another.
    DocType(
        #[source]
        #[explain(name = "cause")]
        DocTypeFault,
    ),
    /// `digestAlgorithm` is not `SHA-256`, `SHA-384` or `SHA-512`.
    DigestAlgorithm(
        #[source]
        #[explain(name = "cause")]
        NameFault,
    ),
    /// `valueDigests` is no non-empty map from namespaces to non-empty maps from `digestID` to
    /// digests of the algorithm's length, each namespace and `digestID` once.
    ValueDigests(
        #[source]
        #[explain(name = "cause")]
        ValueDigestsFault,
    ),
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    DeviceKey(
        #[source]
        #[explain(name = "cause")]
        DeviceKeyFault,
    ),
    /// `keyAuthorizations` breaks its CDDL, repeats a name, or names a namespace both whole and
    /// by its elements.
    KeyAuthorizations(
        #[source]
        #[explain(name = "cause")]
        KeyAuthorizationsFault,
    ),
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`, or
    /// `validFrom` precedes `signed` or does not precede `validUntil`.
    Validity(
        #[source]
        #[explain(name = "cause")]
        ValidityFault,
    ),
    /// `nameSpaces` is no non-empty map from namespaces to non-empty arrays of
    /// `IssuerSignedItemBytes`, each namespace once.
    NameSpaces(
        #[source]
        #[explain(name = "cause")]
        NameSpacesFault,
    ),
    /// An `IssuerSignedItem` lacks `digestID`, `random`, `elementIdentifier` or `elementValue`.
    Item(
        #[source]
        #[explain(name = "cause")]
        ItemFault,
    ),
    /// A namespace holds an element identifier twice.
    RepeatedElement,
    /// The digest of an `IssuerSignedItemBytes` is not the one `valueDigests` lists under its
    /// namespace and `digestID`.
    ItemDigest,
}

/// Why the top level is no envelope [`StoredMdoc::parse`](super::StoredMdoc::parse) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.envelope_fault")]
pub enum EnvelopeFault {
    /// `documents` holds this many documents, where one is read.
    #[error("`documents` holds {0} documents, where one is read")]
    Documents(#[explain(name = "count")] usize),
    /// The `Document` has no `issuerSigned`.
    #[error("the `Document` has no `issuerSigned`")]
    IssuerSigned,
}

/// Why `issuerAuth` is no `COSE_Sign1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.issuer_auth_fault")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.algorithm_fault")]
pub enum AlgorithmFault {
    /// The header is not one CBOR item.
    #[error("the header is not one CBOR item")]
    Header(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// The header has no integer under label 1.
    #[error("the header has no integer under label 1")]
    Absent,
}

/// Why the payload is no MSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.payload_fault")]
pub enum PayloadFault {
    /// The payload is not one CBOR item.
    #[error("the payload is not one CBOR item")]
    Cbor(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// It is not a byte string under tag 24.
    #[error("it is not a byte string under tag 24")]
    NotTagged,
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    Mso(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
}

/// Why the `docType` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.doc_type_fault")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.name_fault")]
pub enum NameFault {
    /// It is absent or not text.
    #[error("it is absent or not text")]
    Member(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// It names none of the values this crate reads.
    #[error("it names none of the values this crate reads")]
    Unknown,
}

/// Why `valueDigests` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.value_digests_fault")]
pub enum ValueDigestsFault {
    /// `valueDigests` is no non-empty map.
    #[error("`valueDigests` is no non-empty map")]
    Member(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    NameSpace,
    /// The namespace's digests are no non-empty map.
    #[error("the digests of namespace `{0}` are no non-empty map")]
    Digests(
        #[explain(name = "namespace")] NameSpace,
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// A `digestID` of the namespace is not an unsigned integer.
    #[error("a `digestID` of namespace `{0}` is not an unsigned integer")]
    DigestId(#[explain(name = "namespace")] NameSpace),
    /// The digest under this `digestID` is not a byte string.
    #[error("the digest under `digestID` {1} of namespace `{0}` is not a byte string")]
    Digest(
        #[explain(name = "namespace")] NameSpace,
        #[explain(name = "digest_id")] DigestId,
    ),
    /// The digest under this `digestID` has this many bytes, another length than the
    /// algorithm's.
    #[error(
        "the digest under `digestID` {1} of namespace `{0}` has {2} bytes, another length than the algorithm's"
    )]
    DigestLength(
        #[explain(name = "namespace")] NameSpace,
        #[explain(name = "digest_id")] DigestId,
        #[explain(name = "length")] usize,
    ),
}

/// Why `deviceKeyInfo.deviceKey` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.device_key_fault")]
pub enum DeviceKeyFault {
    /// The MSO has no `deviceKeyInfo`.
    #[error("the MSO has no `deviceKeyInfo`")]
    Info,
    /// `deviceKeyInfo` has no `deviceKey`.
    #[error("`deviceKeyInfo` has no `deviceKey`")]
    Absent,
    /// `kty` (label 1) is not the curve's: 2, EC2, or 1, OKP.
    #[error("`kty` (label 1) is not the curve's")]
    KeyType,
    /// `crv` (label -1) names no curve of ISO/IEC 18013-5 Table 22.
    #[error("`crv` (label -1) names no curve of Table 22")]
    Curve,
    /// A P-256 key's `x` (label -2) or `y` (label -3) is not a 32-byte string.
    #[error("a P-256 key's `x` (label -2) or `y` (label -3) is not a 32-byte string")]
    Coordinate,
    /// `alg` (label 3) is a signature algorithm the curve does not make (RFC 9052 §7.1; RFC 9053
    /// §2.1, §2.2, §7.1; RFC 9864 §2).
    #[error("`alg` (label 3) is a signature algorithm the curve does not make")]
    Algorithm,
}

/// Why a list of names in `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.names_fault")]
pub enum NamesFault {
    /// It is no non-empty array.
    #[error("it is no non-empty array")]
    Member(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// A name is not text.
    #[error("a name is not text")]
    NotText,
    /// It holds this name twice.
    #[error("it holds the name {0:?} twice")]
    Repeated(#[explain(name = "name")] String),
}

/// Why `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.key_authorizations_fault")]
pub enum KeyAuthorizationsFault {
    /// It is not a map.
    #[error("it is not a map")]
    NotMap,
    /// `nameSpaces`.
    #[error("`nameSpaces`")]
    NameSpaces(
        #[source]
        #[explain(name = "cause")]
        NamesFault,
    ),
    /// `dataElements` is no non-empty map.
    #[error("`dataElements` is no non-empty map")]
    DataElements(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// A namespace of `dataElements` is not text.
    #[error("a namespace of `dataElements` is not text")]
    NameSpace,
    /// The element identifiers of this namespace.
    #[error("the element identifiers of namespace `{0}`")]
    Elements(
        #[explain(name = "namespace")] NameSpace,
        #[source]
        #[explain(name = "cause")]
        NamesFault,
    ),
    /// This namespace is in `nameSpaces` and in `dataElements`.
    #[error("namespace `{0}` is in `nameSpaces` and in `dataElements`")]
    Overlap(#[explain(name = "namespace")] NameSpace),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.validity_fault")]
pub enum ValidityFault {
    /// The MSO has no `validityInfo`.
    #[error("the MSO has no `validityInfo`")]
    Absent,
    /// This time is absent or no 20-character `tdate`.
    #[error("`{}` is absent or no 20-character `tdate`", .0.name())]
    Time(#[explain(name = "time")] ValidityTime),
    /// `validFrom` precedes `signed`, or does not precede `validUntil`.
    #[error("`validFrom` precedes `signed`, or does not precede `validUntil`")]
    Order,
}

/// Why `nameSpaces` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.name_spaces_fault")]
pub enum NameSpacesFault {
    /// `nameSpaces` is no non-empty map.
    #[error("`nameSpaces` is no non-empty map")]
    Member(
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// A namespace is not text.
    #[error("a namespace is not text")]
    NameSpace,
    /// The namespace's items are no non-empty array.
    #[error("the items of namespace `{0}` are no non-empty array")]
    Items(
        #[explain(name = "namespace")] NameSpace,
        #[source]
        #[explain(name = "cause")]
        MemberFault,
    ),
    /// An item of the namespace is no byte string under tag 24.
    #[error("an item of namespace `{0}` is no byte string under tag 24")]
    NotTagged(#[explain(name = "namespace")] NameSpace),
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
#[explain(domain = "mdoc.stored.item_fault")]
pub enum ItemFault {
    /// The tagged bytes are not one CBOR item.
    #[error("the tagged bytes are not one CBOR item")]
    Cbor(
        #[source]
        #[explain(name = "cause")]
        CborError,
    ),
    /// This member is absent or of another CBOR type.
    #[error("`{}` is absent or of another CBOR type", .0.name())]
    Member(#[explain(name = "member")] ItemMember),
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

super::position!(
    /// The position of an entry in an array member.
    pub ArrayIndex
);

/// What breaks the rule of a member of a decoded CBOR map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.member_fault")]
pub enum MemberFault {
    /// The member is absent.
    #[error("the member is absent")]
    Absent,
    /// The member has another type than its rule gives it.
    #[error("the member has another type than its rule gives it")]
    WrongType,
    /// The member is an empty string, array or map.
    #[error("the member is an empty string, array or map")]
    Empty,
    /// The array entry at this position breaks the rule of the entries.
    #[error("the array entry at position {0} breaks the rule of the entries")]
    Entry(#[explain(name = "position")] ArrayIndex),
}

impl IntoArg for ArrayIndex {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(self.value() as u64)
    }
}

impl IntoArg for DigestId {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(self.value())
    }
}

impl IntoArg for NameSpace {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        self.as_str()
    }
}

impl IntoArg for ElementIdentifier {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        self.as_str()
    }
}

impl IntoArg for ValidityTime {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

impl IntoArg for ItemMember {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// Why bytes are no CBOR data item the core reads (RFC 8949): the kind of the core's
/// [`CborError`](siros_openid4vp::cbor::CborError).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "mdoc.stored.cbor_error")]
pub enum CborError {
    /// The bytes end inside the data item.
    #[error("the bytes end inside the data item")]
    Truncated,
    /// A head that is not well-formed, or a value the reading refuses.
    #[error("a head that is not well-formed")]
    Malformed,
    /// A text string that is no UTF-8.
    #[error("a text string that is no UTF-8")]
    Utf8,
    /// Nesting deeper than the reading admits.
    #[error("nesting deeper than the reading admits")]
    Depth,
    /// Bytes after the data item.
    #[error("bytes after the data item")]
    Trailing,
    /// A map holds one key twice.
    #[error("a map holds one key twice")]
    RepeatedKey,
}

impl From<Core> for CborError {
    fn from(error: Core) -> Self {
        match error {
            Core::Truncated => Self::Truncated,
            Core::Utf8(_) => Self::Utf8,
            Core::Depth(_) => Self::Depth,
            Core::Trailing(_) => Self::Trailing,
            Core::RepeatedKey(_) => Self::RepeatedKey,
            Core::Malformed(_)
            | Core::Indefinite(_)
            | Core::Simple(_)
            | Core::Encode(_)
            | Core::IntegerRange(_)
            | Core::DoubleRange(_)
            | Core::Key(_)
            | Core::Object(_)
            | Core::Unknown(_) => Self::Malformed,
        }
    }
}
