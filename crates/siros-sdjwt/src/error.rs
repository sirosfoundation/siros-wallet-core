//! Why an issued SD-JWT, or a view of one, is refused.

use siros_explain::Explain;
use siros_openid4vp::json::JsonError;

use crate::alg::Digest;
use crate::tree::DisclosureId;

/// Why a base64url segment encodes no JSON value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.encoded")]
pub enum EncodedJsonFault {
    /// The segment is not base64url without padding.
    #[error("the segment is not base64url without padding")]
    Base64(
        #[source]
        #[explain(skip)]
        base64::DecodeError,
    ),
    /// The bytes are no UTF-8 text (RFC 8259 §8.1).
    #[error("the bytes are no UTF-8 text")]
    Utf8,
    /// The bytes are no JSON value, or an object repeats a member name (RFC 7519 §4).
    #[error("the bytes are no JSON value, or an object repeats a member name (RFC 7519 §4)")]
    Json(
        #[source]
        #[explain(name = "cause")]
        JsonError,
    ),
}

/// Why the Issuer-signed JWT is no compact JWS of a JSON header and payload (RFC 7515 §7.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.issuer_jwt")]
pub enum IssuerJwtFault {
    /// It has this many `.`-separated segments, where a JWS has three.
    #[error("it has {0} `.`-separated segments, where a JWS has three")]
    Segments(#[explain(name = "count")] usize),
    /// The signature segment is empty.
    #[error("the signature segment is empty")]
    SignatureEmpty,
    /// The signature segment is not base64url without padding.
    #[error("the signature segment is not base64url without padding")]
    Signature(
        #[source]
        #[explain(skip)]
        base64::DecodeError,
    ),
    /// The header segment encodes no JSON value.
    #[error("the header segment encodes no JSON value")]
    Header(
        #[source]
        #[explain(name = "cause")]
        EncodedJsonFault,
    ),
    /// The header is not a JSON object.
    #[error("the header is not a JSON object")]
    HeaderNotObject,
    /// The payload segment encodes no JSON value.
    #[error("the payload segment encodes no JSON value")]
    Payload(
        #[source]
        #[explain(name = "cause")]
        EncodedJsonFault,
    ),
    /// The payload is not a JSON object.
    #[error("the payload is not a JSON object")]
    PayloadNotObject,
    /// The header's `alg` is no string, `none` or a MAC algorithm (RFC 9901 §4.1).
    #[error("the header's alg is no string, none or a MAC algorithm (RFC 9901 §4.1)")]
    Alg,
}

/// Why a disclosure is none of the two forms of RFC 9901 §4.2.1 and §4.2.2.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.disclosure")]
pub enum DisclosureFault {
    /// The text encodes no JSON value.
    #[error("the text encodes no JSON value")]
    Encoding(
        #[source]
        #[explain(name = "cause")]
        EncodedJsonFault,
    ),
    /// The value is not a JSON array.
    #[error("the value is not a JSON array")]
    NotArray,
    /// The array has this many elements, where a disclosure has two or three.
    #[error("the array has {0} elements, where a disclosure has two or three")]
    Length(#[explain(name = "count")] usize),
    /// The salt is not a string.
    #[error("the salt is not a string")]
    Salt,
    /// The claim name is not a string.
    #[error("the claim name is not a string")]
    Name,
}

/// Why `_sd_alg` names no supported algorithm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.sd_alg")]
pub enum SdAlgFault {
    /// It is not a string.
    #[error("it is not a string")]
    NotString,
    /// It names this algorithm, outside `sha-256`, `sha-384` and `sha-512`.
    #[error("it names the algorithm {0}, outside sha-256, sha-384 and sha-512")]
    Unknown(#[explain(name = "algorithm")] String),
}

/// A reserved claim name outside its role (RFC 9901 §4.1, §4.1.1, §7.1 step 3.c.ii.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.reserved")]
pub enum ReservedFault {
    /// An `_sd` member is not an array.
    #[error("an _sd member is not an array")]
    SdNotArray,
    /// An `_sd` member holds an entry other than a digest string.
    #[error("an _sd member holds an entry other than a digest string")]
    SdDigest,
    /// An object outside an array element has a `...` member.
    #[error("an object outside an array element has a ... member")]
    Ellipsis,
    /// An object below the payload's top level has an `_sd_alg` member.
    #[error("an object below the payload's top level has an _sd_alg member")]
    NestedSdAlg,
    /// A disclosure names this reserved claim: `_sd`, `...` or `_sd_alg`.
    #[error("a disclosure names the reserved claim {0}")]
    Disclosed(#[explain(name = "claim")] String),
    /// An array element holds `...` beside another member.
    #[error("an array element holds ... beside another member")]
    ElementMembers,
    /// An array element's `...` is not a digest string.
    #[error("an array element's ... is not a digest string")]
    ElementDigest,
}

/// Where a disclosure is referenced against its form (RFC 9901 §7.1, steps 3.c.ii.1, 3.c.iii.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Misplaced {
    /// An `_sd` digest names an array element disclosure.
    ElementInObject,
    /// An array digest names an object property disclosure.
    PropertyInArray,
}

impl std::fmt::Display for Misplaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ElementInObject => "an element in an _sd digest",
            Self::PropertyInArray => "a property in an array digest",
        })
    }
}

/// Why text is not an issued SD-JWT (RFC 9901 §4, §7.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.parse")]
pub enum ParseError {
    /// The text does not end in the `~` that follows the last part (§4).
    #[error("the text does not end in a ~")]
    NoFinalTilde,
    /// The Issuer-signed JWT is not three base64url segments whose header and payload are JSON
    /// objects with unique member names.
    #[error("the Issuer-signed JWT: {0}")]
    IssuerJwt(
        #[source]
        #[explain(name = "cause")]
        IssuerJwtFault,
    ),
    /// A disclosure does not decode to a JSON array of a string salt and a value, or of a string
    /// salt, a string claim name and a value (§4.2).
    #[error("disclosure {disclosure:?}: {fault}")]
    Disclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// What breaks its form.
        #[source]
        #[explain(name = "cause")]
        fault: DisclosureFault,
    },
    /// `_sd_alg` is not `sha-256`, `sha-384` or `sha-512` (§4.1.1, §9.4).
    #[error("_sd_alg: {0}")]
    UnsupportedSdAlg(
        #[source]
        #[explain(name = "cause")]
        SdAlgFault,
    ),
    /// `_sd`, `...` or `_sd_alg` appears outside its role.
    #[error("{0}")]
    ReservedClaimName(
        #[source]
        #[explain(name = "cause")]
        ReservedFault,
    ),
    /// This digest appears twice in the payload and the disclosures, or two disclosures share it
    /// (§7.1, step 4).
    #[error("the digest {0:?} appears twice")]
    RepeatedDigest(#[explain(name = "digest")] Digest),
    /// A digest names a disclosure of the other form.
    #[error("disclosure {disclosure:?} is {placement}")]
    MisplacedDisclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// Where its digest stands.
        #[explain(skip)]
        placement: Misplaced,
    },
    /// A disclosure names this claim, which its object already has (§7.1, step 3.c.ii.3).
    #[error("a disclosure names the claim {0}, which its object already has")]
    ClaimNameExists(#[explain(name = "claim")] String),
    /// No digest of the payload or of another disclosure references this disclosure (§7.1, step
    /// 5).
    #[error("no digest references disclosure {0:?}")]
    UnreferencedDisclosure(#[explain(name = "disclosure")] DisclosureId),
    /// The claims nest deeper than [`MAX_DEPTH`](crate::MAX_DEPTH), disclosures included.
    #[error("the claims nest too deep")]
    TooDeep,
    /// The Issuer-signed JWT's `x5c` header parameter breaks RFC 7515 §4.1.6.
    #[error("x5c: {0}")]
    X5c(
        #[source]
        #[explain(name = "cause")]
        X5cError,
    ),
}

/// Why an `x5c` header parameter is no chain of certificates (RFC 7515 §4.1.6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.x5c")]
pub enum X5cError {
    /// It is not a non-empty array.
    #[error("it is not a non-empty array")]
    NotArray,
    /// The certificate at this position is not base64 with padding, as a string.
    #[error("the certificate at position {0} is not a base64 string with padding")]
    Certificate(#[explain(name = "position")] usize),
}

/// Why an issued SD-JWT makes no view (SD-JWT VC §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.registration")]
pub enum RegistrationError {
    /// The text is no issued SD-JWT.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// `vct` is absent or no string (SD-JWT VC §3.2.2.1).
    #[error("vct is absent or no string (SD-JWT VC §3.2.2.1)")]
    Vct,
    /// `iss` is no string (SD-JWT VC §3.2.2.2, RFC 7519 §4.1.1).
    #[error("iss is no string (RFC 7519 §4.1.1)")]
    Iss,
    /// `cnf.jwk` is no object with a string `crv` and, when stated, a string `alg` (RFC 7800 §3.2).
    #[error("cnf.jwk is no object with a string crv (RFC 7800 §3.2)")]
    Key,
    /// `nbf` or `exp` is no number a finite double holds (RFC 7519 §2).
    #[error("{0} is no NumericDate (RFC 7519 §2)")]
    Validity(#[explain(name = "claim")] &'static str),
    /// The curve the wallet resolved contradicts the curve the JWS algorithm fixes (RFC 7518
    /// §3.1).
    #[error("the issuer's key on {curve} cannot sign {alg}")]
    IssuerCurve {
        /// The JWS algorithm.
        alg: String,
        /// The curve the wallet resolved.
        curve: String,
    },
    /// The metadata is no object.
    #[error("the type metadata is no object")]
    Metadata,
    /// The view repeats a member name.
    #[error(transparent)]
    Json(#[from] JsonError),
}

/// Why a path selects no disclosure of the credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.select")]
pub enum SelectError {
    /// The component at this position names no value the credential holds.
    #[error("the path's component {0} names no value the credential holds")]
    Absent(#[explain(name = "position")] usize),
}

/// Why claims make no Key Binding JWT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.key_binding")]
pub enum KeyBindingError {
    /// An extra claim repeats a claim of the payload (RFC 9901 §4.3).
    #[error(transparent)]
    Repeated(#[from] JsonError),
}
