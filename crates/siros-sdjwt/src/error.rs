//! Why a stored SD-JWT or a key binding is refused. Each error has a stable code and carries
//! its cause.

use siros_codec::json::JsonFault;
use siros_codec::Base64Error;

use crate::alg::Digest;
use crate::tree::DisclosureId;

/// Why a base64url segment encodes no JSON value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum EncodedJsonFault {
    /// The segment is not base64url without padding.
    #[error("the segment is not base64url without padding")]
    Base64(#[source] Base64Error),
    /// The bytes are no JSON value, or an object repeats a member name (RFC 7519, Section 4).
    #[error(
        "the bytes are no JSON value, or an object repeats a member name (RFC 7519, Section 4)"
    )]
    Json(#[source] JsonFault),
}

/// Why the issuer JWT is no compact JWS of a JSON header and payload (RFC 7515, Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum IssuerJwtFault {
    /// It has this many `.`-separated segments, where a JWS has three.
    #[error("it has {0} `.`-separated segments, where a JWS has three")]
    Segments(usize),
    /// The signature segment is empty.
    #[error("the signature segment is empty")]
    SignatureEmpty,
    /// The signature segment is not base64url without padding.
    #[error("the signature segment is not base64url without padding")]
    Signature(#[source] Base64Error),
    /// The header segment encodes no JSON value.
    #[error("the header segment encodes no JSON value")]
    Header(#[source] EncodedJsonFault),
    /// The header is not a JSON object.
    #[error("the header is not a JSON object")]
    HeaderNotObject,
    /// The payload segment encodes no JSON value.
    #[error("the payload segment encodes no JSON value")]
    Payload(#[source] EncodedJsonFault),
    /// The payload is not a JSON object.
    #[error("the payload is not a JSON object")]
    PayloadNotObject,
}

/// Why a disclosure is none of the two forms of Sections 4.2.1 and 4.2.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum DisclosureFault {
    /// The text encodes no JSON value.
    #[error("the text encodes no JSON value")]
    Encoding(#[source] EncodedJsonFault),
    /// The value is not a JSON array.
    #[error("the value is not a JSON array")]
    NotArray,
    /// The array has this many elements, where a disclosure has two or three.
    #[error("the array has {0} elements, where a disclosure has two or three")]
    Length(usize),
    /// The salt is not a string.
    #[error("the salt is not a string")]
    Salt,
    /// The claim name is not a string.
    #[error("the claim name is not a string")]
    Name,
}

/// Why `_sd_alg` names no supported algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SdAlgFault {
    /// It is not a string.
    #[error("it is not a string")]
    NotString,
    /// It names this algorithm, outside `sha-256`, `sha-384` and `sha-512`.
    #[error("it names the algorithm {0:?}, outside `sha-256`, `sha-384` and `sha-512`")]
    Unknown(String),
}

/// A reserved claim name outside its role (Sections 4.1, 4.1.1 and 7.1, step 3.c.ii.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ReservedFault {
    /// An `_sd` member is not an array.
    #[error("an `_sd` member is not an array")]
    SdNotArray,
    /// An `_sd` member holds an entry other than a digest string.
    #[error("an `_sd` member holds an entry other than a digest string")]
    SdDigest,
    /// An object outside an array element has a `...` member.
    #[error("an object outside an array element has a `...` member")]
    Ellipsis,
    /// An object below the payload's top level has an `_sd_alg` member.
    #[error("an object below the payload's top level has an `_sd_alg` member")]
    NestedSdAlg,
    /// A disclosure names this reserved claim: `_sd`, `...` or `_sd_alg`.
    #[error("a disclosure names the reserved claim {0:?}: `_sd`, `...` or `_sd_alg`")]
    Disclosed(String),
    /// An array element holds `...` beside another member.
    #[error("an array element holds `...` beside another member")]
    ElementMembers,
    /// An array element's `...` is not a digest string.
    #[error("an array element's `...` is not a digest string")]
    ElementDigest,
}

/// Where a disclosure is referenced against its form (Section 7.1, steps 3.c.ii.1 and
/// 3.c.iii.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Placement {
    /// An `_sd` digest names an array element disclosure.
    ElementInObject,
    /// An array digest names an object property disclosure.
    PropertyInArray,
}

/// Why text is not a stored SD-JWT (RFC 9901, Sections 4 and 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}: {:?}", self.code(), self)]
pub enum ParseError {
    /// The issuer JWT is not three base64url segments whose header and payload are JSON objects
    /// with unique member names.
    IssuerJwt(#[source] IssuerJwtFault),
    /// A disclosure does not decode to a JSON array of a string salt and a value, or of a string
    /// salt, a string claim name and a value (Section 4.2).
    Disclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// What breaks its form.
        #[source]
        fault: DisclosureFault,
    },
    /// `_sd_alg` is not `sha-256`, `sha-384` or `sha-512` (Sections 4.1.1 and 9.4).
    UnsupportedSdAlg(#[source] SdAlgFault),
    /// `_sd`, `...` or `_sd_alg` appears outside its role.
    ReservedClaimName(#[source] ReservedFault),
    /// This digest appears twice in the payload and the disclosures, or two disclosures share it
    /// (Section 7.1, step 4).
    RepeatedDigest(Digest),
    /// A digest names a disclosure of the other form.
    MisplacedDisclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// Where its digest stands.
        placement: Placement,
    },
    /// A disclosure names this claim, which its object already has (Section 7.1, step
    /// 3.c.ii.3).
    ClaimNameExists(String),
    /// No digest of the payload or of another disclosure references this disclosure (Section
    /// 7.1, step 5).
    UnreferencedDisclosure(DisclosureId),
    /// The claims nest deeper than [`MAX_DEPTH`](crate::MAX_DEPTH), disclosures included.
    TooDeep,
    /// The issuer JWT's `x5c` header parameter breaks RFC 7515, Section 4.1.6.
    X5c(#[source] X5cError),
}

siros_codec::position!(
    /// The position of a certificate in `x5c`, the signer's at 0.
    pub(crate) X5cIndex
);

/// Why an `x5c` header parameter is no chain of certificates (RFC 7515, Section 4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum X5cError {
    /// It is not an array.
    #[error("it is not an array")]
    NotArray,
    /// The array is empty.
    #[error("the array is empty")]
    Empty,
    /// The certificate at this position is not a string.
    #[error("the certificate at position {0} is not a string")]
    NotString(X5cIndex),
    /// The certificate at this position is not base64 with padding.
    #[error("the certificate at position {0} is not base64 with padding")]
    Base64(X5cIndex, #[source] Base64Error),
}

impl ParseError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::IssuerJwt(_) => "issuer_jwt_malformed",
            Self::Disclosure { .. } => "disclosure_malformed",
            Self::UnsupportedSdAlg(_) => "sd_alg_unsupported",
            Self::ReservedClaimName(_) => "reserved_claim_name",
            Self::RepeatedDigest(_) => "digest_repeated",
            Self::MisplacedDisclosure { .. } => "disclosure_misplaced",
            Self::ClaimNameExists(_) => "claim_name_exists",
            Self::UnreferencedDisclosure(_) => "disclosure_unreferenced",
            Self::TooDeep => "claims_too_deep",
            Self::X5c(_) => "issuer_jwt_x5c_malformed",
        }
    }
}

/// Why claims do not form a KB-JWT payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}: {:?}", self.code(), self)]
pub enum KeyBindingError {
    /// An extra claim has this name, which Section 4.3 gives a required claim: `iat`, `aud`,
    /// `nonce` or `sd_hash`.
    RequiredClaim(String),
    /// Two extra claims have this name.
    RepeatedClaim(String),
}

impl KeyBindingError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RequiredClaim(_) | Self::RepeatedClaim(_) => "kb_jwt_claim_collision",
        }
    }
}
