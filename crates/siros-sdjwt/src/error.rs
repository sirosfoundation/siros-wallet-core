//! Why an issued SD-JWT, or a view of one, is refused.

use siros_explain::{Explain, IntoArg, kind};
use siros_openid4vp::json::JsonError;

use crate::alg::{Digest, SigningAlg};
use crate::tree::DisclosureId;

/// A closed set of names, each its own member of an error.
macro_rules! claim_names {
    ($($(#[$doc:meta])* $type:ident { $($(#[$variant_doc:meta])* $variant:ident => $name:literal,)+ })+) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $type {
            $($(#[$variant_doc])* $variant,)+
        }

        impl $type {
            /// The name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }

        impl IntoArg for $type {
            type Kind = kind::Name;

            fn arg(&self) -> &'static str {
                self.name()
            }
        }
    )+};
}

claim_names! {
    /// A registered claim no disclosure holds, sub-claims included (SD-JWT VC §3.2.2).
    PermanentClaim {
        /// `iss`.
        Iss => "iss",
        /// `nbf`.
        Nbf => "nbf",
        /// `exp`.
        Exp => "exp",
        /// `cnf`.
        Cnf => "cnf",
        /// `vct`.
        Vct => "vct",
        /// `vct#integrity`.
        VctIntegrity => "vct#integrity",
        /// `aka_vcts`.
        AkaVcts => "aka_vcts",
        /// `status`.
        Status => "status",
    }
    /// A claim stating when the credential is valid (RFC 7519 §4.1.4, §4.1.5).
    ValidityClaim {
        /// `nbf`.
        Nbf => "nbf",
        /// `exp`.
        Exp => "exp",
    }
    /// A coordinate of a holder key's JWK (RFC 7518 §6.2.1.2, RFC 8037 §2).
    JwkCoordinate {
        /// `x`.
        X => "x",
        /// `y`.
        Y => "y",
    }
}

impl PermanentClaim {
    /// Each of them.
    pub(crate) const ALL: [Self; 8] = [
        Self::Iss,
        Self::Nbf,
        Self::Exp,
        Self::Cnf,
        Self::Vct,
        Self::VctIntegrity,
        Self::AkaVcts,
        Self::Status,
    ];
}

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

/// Why `cnf` names no key a Key Binding JWT can answer to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.holder_key")]
pub enum HolderKeyFault {
    /// `cnf` is no object with a `jwk` member (RFC 7800 §3.1).
    #[error("it is no object with a jwk member (RFC 7800 §3.1)")]
    Cnf,
    /// `jwk` is no object (RFC 7800 §3.2).
    #[error("its jwk is no object (RFC 7800 §3.2)")]
    Jwk,
    /// `crv` is no string naming a curve that signs under a JWS algorithm.
    #[error("its crv names no curve that signs under a JWS algorithm")]
    Curve,
    /// `kty` is not the key type of the curve (RFC 7518 §6.2; RFC 8037 §2).
    #[error("its kty is not the key type of its curve")]
    KeyType,
    /// This coordinate is no base64url of the curve's coordinate size (RFC 7518 §6.2.1.2).
    #[error("its {} is no base64url of the curve's coordinate size", .0.name())]
    Coordinate(#[explain(name = "coordinate")] JwkCoordinate),
    /// `alg` is no algorithm the curve signs under: `none` and the MAC algorithms among them
    /// (RFC 9901 §4.3).
    #[error("its alg is no algorithm its curve signs under")]
    Alg,
}

/// Why an issued SD-JWT makes no view (SD-JWT VC §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.registration")]
pub enum RegistrationError {
    /// The text is no issued SD-JWT.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The Issuer-signed JWT's `typ` is not `dc+sd-jwt` (SD-JWT VC §3.2.1).
    #[error("the Issuer-signed JWT's typ is not dc+sd-jwt (SD-JWT VC §3.2.1)")]
    Typ,
    /// A disclosure reveals this registered claim or one of its sub-claims (SD-JWT VC §3.2.2).
    #[error("a disclosure reveals the registered claim {} (SD-JWT VC §3.2.2)", .0.name())]
    SelectivelyDisclosed(#[explain(name = "claim")] PermanentClaim),
    /// `vct` is absent or no string (SD-JWT VC §3.2.2.1).
    #[error("vct is absent or no string (SD-JWT VC §3.2.2.1)")]
    Vct,
    /// `iss` is no string (SD-JWT VC §3.2.2.2, RFC 7519 §4.1.1).
    #[error("iss is no string (RFC 7519 §4.1.1)")]
    Iss,
    /// `cnf` names no key a Key Binding JWT can answer to.
    #[error("cnf: {0}")]
    Key(
        #[from]
        #[explain(name = "cause")]
        HolderKeyFault,
    ),
    /// `nbf` or `exp` is no number a finite double holds (RFC 7519 §2).
    #[error("{} is no NumericDate (RFC 7519 §2)", .0.name())]
    Validity(#[explain(name = "claim")] ValidityClaim),
    /// The curve the wallet resolved contradicts the curve the JWS algorithm fixes (RFC 7518
    /// §3.1).
    #[error("the issuer's key on {curve} cannot sign {alg}", alg = .alg.as_str())]
    IssuerCurve {
        /// The JWS algorithm.
        alg: SigningAlg,
        /// The curve the wallet resolved.
        curve: String,
    },
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

/// Why a registered credential cannot be presented: a fault's source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.present")]
pub enum PresentFault {
    /// The credential holds no `dc+sd-jwt` document.
    #[error("no dc+sd-jwt document")]
    NoDocument,
    /// The document is no UTF-8 text.
    #[error("the document is no UTF-8 text")]
    DocumentText,
    /// The document is no issued SD-JWT.
    #[error("the document: {0}")]
    Document(
        #[source]
        #[explain(name = "cause")]
        ParseError,
    ),
    /// The document's `cnf` and the credential's `Facts::holder` disagree.
    #[error("the document's cnf and the credential's holder fact disagree")]
    Holder,
    /// The view states a value the document does not hold.
    #[error("the view states a value the document does not hold")]
    View,
    /// A selected path reaches no value of the document.
    #[error("a selected path: {0}")]
    Selected(
        #[source]
        #[explain(name = "cause")]
        SelectError,
    ),
    /// The view's `key_alg` signs with no private key (RFC 9901 §4.3).
    #[error("the view's key_alg signs with no private key")]
    KeyAlg,
    /// A transaction's member needs a Key Binding JWT, and the credential has no key (B.3.3).
    #[error("the member {0} needs a Key Binding JWT, and the credential has no key (B.3.3)")]
    NoKeyForMember(#[explain(name = "member")] String),
    /// A Key Binding JWT holds claims, and this member is a data element.
    #[error("a Key Binding JWT holds claims, and {0} is a data element")]
    NoClaim(#[explain(name = "member")] String),
    /// A Key Binding JWT claim holds no byte string or CBOR data item.
    #[error("a Key Binding JWT claim holds no byte string or CBOR data item ({0})")]
    Binary(#[explain(name = "member")] String),
    /// The member's JSON text reads as no value.
    #[error("the member's JSON text: {0}")]
    MemberJson(
        #[source]
        #[explain(name = "cause")]
        JsonError,
    ),
    /// A member is one of the Key Binding JWT's own claims.
    #[error("a member is a Key Binding JWT claim: {0}")]
    KeyBinding(
        #[source]
        #[explain(name = "cause")]
        KeyBindingError,
    ),
}
