//! Why an issued SD-JWT, or a view of one, is refused.

use std::fmt;

use siros_openid4vp::claims::kit::MergeError;

use siros_explain::Explain;
use siros_openid4vp::json::JsonError;
use siros_openid4vp::request::Curve;

use crate::alg::{Digest, SigningAlg};
use crate::tree::DisclosureId;

/// A curve the wallet resolved, as a refusal names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCurve(String);

impl From<Curve<'_>> for ResolvedCurve {
    fn from(curve: Curve<'_>) -> Self {
        Self(curve.as_str().to_owned())
    }
}

impl fmt::Display for ResolvedCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A closed set of names, each its own member of an error, written by its name.
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

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
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
pub enum EncodedJsonFault {
    /// The segment is not base64url without padding.
    #[error("the segment is not base64url without padding")]
    #[explain(id = "encoded.base64")]
    Base64(#[source] base64::DecodeError),
    /// The bytes are no UTF-8 text (RFC 8259 §8.1).
    #[error("the bytes are no UTF-8 text")]
    #[explain(id = "encoded.utf8")]
    Utf8,
    /// The bytes are no JSON value, or an object repeats a member name (RFC 7519 §4).
    #[error("the bytes are no JSON value, or an object repeats a member name (RFC 7519 §4)")]
    #[explain(id = "encoded.json")]
    Json(#[source] JsonError),
}

/// Why the Issuer-signed JWT is no compact JWS of a JSON header and payload (RFC 7515 §7.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum IssuerJwtFault {
    /// It has this many `.`-separated segments, where a JWS has three.
    #[error("it has {count} `.`-separated segments, where a JWS has three")]
    #[explain(id = "issuer_jwt.segments")]
    Segments {
        /// The segments.
        count: usize,
    },
    /// The signature segment is empty.
    #[error("the signature segment is empty")]
    #[explain(id = "issuer_jwt.signature_empty")]
    SignatureEmpty,
    /// The signature segment is not base64url without padding.
    #[error("the signature segment is not base64url without padding")]
    #[explain(id = "issuer_jwt.signature")]
    Signature(#[source] base64::DecodeError),
    /// The header segment encodes no JSON value.
    #[error("the header segment encodes no JSON value")]
    #[explain(id = "issuer_jwt.header")]
    Header(#[source] EncodedJsonFault),
    /// The header is not a JSON object.
    #[error("the header is not a JSON object")]
    #[explain(id = "issuer_jwt.header_not_object")]
    HeaderNotObject,
    /// The payload segment encodes no JSON value.
    #[error("the payload segment encodes no JSON value")]
    #[explain(id = "issuer_jwt.payload")]
    Payload(#[source] EncodedJsonFault),
    /// The payload is not a JSON object.
    #[error("the payload is not a JSON object")]
    #[explain(id = "issuer_jwt.payload_not_object")]
    PayloadNotObject,
    /// The header's `alg` is no string, `none` or a MAC algorithm (RFC 9901 §4.1).
    #[error("the header's alg is no string, none or a MAC algorithm (RFC 9901 §4.1)")]
    #[explain(id = "issuer_jwt.alg")]
    Alg,
}

/// Why a disclosure is none of the two forms of RFC 9901 §4.2.1 and §4.2.2.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum DisclosureFault {
    /// The text encodes no JSON value.
    #[error("the text encodes no JSON value")]
    #[explain(id = "disclosure.encoding")]
    Encoding(#[source] EncodedJsonFault),
    /// The value is not a JSON array.
    #[error("the value is not a JSON array")]
    #[explain(id = "disclosure.not_array")]
    NotArray,
    /// The array has this many elements, where a disclosure has two or three.
    #[error("the array has {count} elements, where a disclosure has two or three")]
    #[explain(id = "disclosure.length")]
    Length {
        /// The elements.
        count: usize,
    },
    /// The salt is not a string.
    #[error("the salt is not a string")]
    #[explain(id = "disclosure.salt")]
    Salt,
    /// The claim name is not a string.
    #[error("the claim name is not a string")]
    #[explain(id = "disclosure.name")]
    Name,
}

/// Why `_sd_alg` names no supported algorithm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum SdAlgFault {
    /// It is not a string.
    #[error("it is not a string")]
    #[explain(id = "sd_alg.not_string")]
    NotString,
    /// It names this algorithm, outside `sha-256`, `sha-384` and `sha-512`.
    #[error("it names the algorithm {algorithm}, outside sha-256, sha-384 and sha-512")]
    #[explain(id = "sd_alg.unknown")]
    Unknown {
        /// The algorithm's name.
        algorithm: String,
    },
}

/// A reserved claim name outside its role (RFC 9901 §4.1, §4.1.1, §7.1 step 3.c.ii.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ReservedFault {
    /// An `_sd` member is not an array.
    #[error("an _sd member is not an array")]
    #[explain(id = "reserved.sd_not_array")]
    SdNotArray,
    /// An `_sd` member holds an entry other than a digest string.
    #[error("an _sd member holds an entry other than a digest string")]
    #[explain(id = "reserved.sd_digest")]
    SdDigest,
    /// An object outside an array element has a `...` member.
    #[error("an object outside an array element has a ... member")]
    #[explain(id = "reserved.ellipsis")]
    Ellipsis,
    /// An object below the payload's top level has an `_sd_alg` member.
    #[error("an object below the payload's top level has an _sd_alg member")]
    #[explain(id = "reserved.nested_sd_alg")]
    NestedSdAlg,
    /// A disclosure names this reserved claim: `_sd`, `...` or `_sd_alg`.
    #[error("a disclosure names the reserved claim {claim}")]
    #[explain(id = "reserved.disclosed")]
    Disclosed {
        /// The claim name.
        claim: String,
    },
    /// An array element holds `...` beside another member.
    #[error("an array element holds ... beside another member")]
    #[explain(id = "reserved.element_members")]
    ElementMembers,
    /// An array element's `...` is not a digest string.
    #[error("an array element's ... is not a digest string")]
    #[explain(id = "reserved.element_digest")]
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
pub enum ParseError {
    /// The text does not end in the `~` that follows the last part (§4).
    #[error("the text does not end in a ~")]
    #[explain(id = "parse.no_final_tilde")]
    NoFinalTilde,
    /// The Issuer-signed JWT is not three base64url segments whose header and payload are JSON
    /// objects with unique member names.
    #[error("the Issuer-signed JWT: {0}")]
    #[explain(id = "parse.issuer_jwt")]
    IssuerJwt(#[source] IssuerJwtFault),
    /// A disclosure does not decode to a JSON array of a string salt and a value, or of a string
    /// salt, a string claim name and a value (§4.2).
    #[error("disclosure {disclosure:?}: {fault}")]
    #[explain(id = "parse.disclosure")]
    Disclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// What breaks its form.
        #[source]
        fault: DisclosureFault,
    },
    /// `_sd_alg` is not `sha-256`, `sha-384` or `sha-512` (§4.1.1, §9.4).
    #[error("_sd_alg: {0}")]
    #[explain(id = "parse.unsupported_sd_alg")]
    UnsupportedSdAlg(#[source] SdAlgFault),
    /// `_sd`, `...` or `_sd_alg` appears outside its role.
    #[error("{0}")]
    #[explain(id = "parse.reserved_claim_name")]
    ReservedClaimName(#[source] ReservedFault),
    /// This digest appears twice in the payload and the disclosures, or two disclosures share it
    /// (§7.1, step 4).
    #[error("the digest {digest:?} appears twice")]
    #[explain(id = "parse.repeated_digest")]
    RepeatedDigest {
        /// The digest.
        digest: Digest,
    },
    /// A digest names a disclosure of the other form.
    #[error("disclosure {disclosure:?} is {placement}")]
    #[explain(id = "parse.misplaced_disclosure")]
    MisplacedDisclosure {
        /// The disclosure.
        disclosure: DisclosureId,
        /// Where its digest stands.
        #[explain(skip)]
        placement: Misplaced,
    },
    /// A disclosure names this claim, which its object already has (§7.1, step 3.c.ii.3).
    #[error("a disclosure names the claim {claim}, which its object already has")]
    #[explain(id = "parse.claim_name_exists")]
    ClaimNameExists {
        /// The claim name.
        claim: String,
    },
    /// No digest of the payload or of another disclosure references this disclosure (§7.1, step
    /// 5).
    #[error("no digest references disclosure {disclosure:?}")]
    #[explain(id = "parse.unreferenced_disclosure")]
    UnreferencedDisclosure {
        /// The disclosure.
        disclosure: DisclosureId,
    },
    /// The claims nest deeper than [`MAX_DEPTH`](crate::MAX_DEPTH), disclosures included.
    #[error("the claims nest too deep")]
    #[explain(id = "parse.too_deep")]
    TooDeep,
    /// The Issuer-signed JWT's `x5c` header parameter breaks RFC 7515 §4.1.6.
    #[error("x5c: {0}")]
    #[explain(id = "parse.x5c")]
    X5c(#[source] X5cError),
}

/// Why an `x5c` header parameter is no chain of certificates (RFC 7515 §4.1.6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum X5cError {
    /// It is not a non-empty array.
    #[error("it is not a non-empty array")]
    #[explain(id = "x5c.not_array")]
    NotArray,
    /// The certificate at this position is not base64 with padding, as a string.
    #[error("the certificate at position {position} is not a base64 string with padding")]
    #[explain(id = "x5c.certificate")]
    Certificate {
        /// The certificate's position, the leaf at 0.
        position: usize,
    },
}

/// Why `cnf` names no key a Key Binding JWT can answer to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum HolderKeyFault {
    /// `cnf` is no object with a `jwk` member (RFC 7800 §3.1).
    #[error("it is no object with a jwk member (RFC 7800 §3.1)")]
    #[explain(id = "holder_key.cnf")]
    Cnf,
    /// `jwk` is no object (RFC 7800 §3.2).
    #[error("its jwk is no object (RFC 7800 §3.2)")]
    #[explain(id = "holder_key.jwk")]
    Jwk,
    /// `crv` is no string naming a curve that signs under a JWS algorithm.
    #[error("its crv names no curve that signs under a JWS algorithm")]
    #[explain(id = "holder_key.curve")]
    Curve,
    /// `kty` is not the key type of the curve (RFC 7518 §6.2; RFC 8037 §2).
    #[error("its kty is not the key type of its curve")]
    #[explain(id = "holder_key.key_type")]
    KeyType,
    /// This coordinate is no base64url of the curve's coordinate size (RFC 7518 §6.2.1.2).
    #[error("its {coordinate} is no base64url of the curve's coordinate size")]
    #[explain(id = "holder_key.coordinate")]
    Coordinate {
        /// The coordinate.
        coordinate: JwkCoordinate,
    },
    /// `alg` is no algorithm the curve signs under: `none` and the MAC algorithms among them
    /// (RFC 9901 §4.3).
    #[error("its alg is no algorithm its curve signs under")]
    #[explain(id = "holder_key.alg")]
    Alg,
}

/// Why an issued SD-JWT makes no view (SD-JWT VC §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum RegistrationError {
    /// The text is no issued SD-JWT.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The Issuer-signed JWT's `typ` is not `dc+sd-jwt` (SD-JWT VC §3.2.1).
    #[error("the Issuer-signed JWT's typ is not dc+sd-jwt (SD-JWT VC §3.2.1)")]
    #[explain(id = "registration.typ")]
    Typ,
    /// A disclosure reveals this registered claim or one of its sub-claims (SD-JWT VC §3.2.2).
    #[error("a disclosure reveals the registered claim {claim} (SD-JWT VC §3.2.2)")]
    #[explain(id = "registration.selectively_disclosed")]
    SelectivelyDisclosed {
        /// The claim.
        claim: PermanentClaim,
    },
    /// `vct` is absent or no string (SD-JWT VC §3.2.2.1).
    #[error("vct is absent or no string (SD-JWT VC §3.2.2.1)")]
    #[explain(id = "registration.vct")]
    Vct,
    /// `iss` is no string (SD-JWT VC §3.2.2.2, RFC 7519 §4.1.1).
    #[error("iss is no string (RFC 7519 §4.1.1)")]
    #[explain(id = "registration.iss")]
    Iss,
    /// `cnf` names no key a Key Binding JWT can answer to.
    #[error("cnf: {0}")]
    #[explain(id = "registration.key")]
    Key(#[from] HolderKeyFault),
    /// `nbf` or `exp` is no number a finite double holds (RFC 7519 §2).
    #[error("{claim} is no NumericDate (RFC 7519 §2)")]
    #[explain(id = "registration.validity")]
    Validity {
        /// The claim.
        claim: ValidityClaim,
    },
    /// The curve the wallet resolved contradicts the curve the JWS algorithm fixes (RFC 7518
    /// §3.1).
    #[error("the issuer's key on {curve} cannot sign {alg}")]
    #[explain(id = "registration.issuer_curve")]
    IssuerCurve {
        /// The JWS algorithm.
        alg: SigningAlg,
        /// The curve the wallet resolved.
        curve: ResolvedCurve,
    },
    /// The display metadata breaks a rule of the merge.
    #[error("the display metadata: {cause}")]
    #[explain(id = "registration.metadata")]
    Metadata {
        /// The rule.
        #[from]
        cause: MergeError,
    },
}

/// Why a path selects no disclosure of the credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum SelectError {
    /// The component at this position names no value the credential holds.
    #[error("the path's component {position} names no value the credential holds")]
    #[explain(id = "select.absent")]
    Absent {
        /// The component's position, the first at 0.
        position: usize,
    },
}

/// Why claims make no Key Binding JWT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum KeyBindingError {
    /// An extra claim repeats a claim of the payload (RFC 9901 §4.3).
    #[error(transparent)]
    Repeated(#[from] JsonError),
}

/// Why a registered credential cannot be presented: a fault's source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum PresentFault {
    /// The credential holds no `dc+sd-jwt` document.
    #[error("no dc+sd-jwt document")]
    #[explain(id = "present.no_document")]
    NoDocument,
    /// The document is no UTF-8 text.
    #[error("the document is no UTF-8 text")]
    #[explain(id = "present.document_text")]
    DocumentText,
    /// The document is no issued SD-JWT.
    #[error("the document: {0}")]
    #[explain(id = "present.document")]
    Document(#[source] ParseError),
    /// The document's `cnf` and the credential's `Facts::holder` disagree.
    #[error("the document's cnf and the credential's holder fact disagree")]
    #[explain(id = "present.holder")]
    Holder,
    /// The view states a value the document does not hold.
    #[error("the view states a value the document does not hold")]
    #[explain(id = "present.view")]
    View,
    /// A selected path reaches no value of the document.
    #[error("a selected path: {0}")]
    #[explain(id = "present.selected")]
    Selected(#[source] SelectError),
    /// The view's `key_alg` signs with no private key (RFC 9901 §4.3).
    #[error("the view's key_alg signs with no private key")]
    #[explain(id = "present.key_alg")]
    KeyAlg,
    /// A transaction's member needs a Key Binding JWT, and the credential has no key (B.3.3).
    #[error("the member {member} needs a Key Binding JWT, and the credential has no key (B.3.3)")]
    #[explain(id = "present.no_key_for_member")]
    NoKeyForMember {
        /// The member.
        member: String,
    },
    /// A Key Binding JWT holds claims, and this member is a data element.
    #[error("a Key Binding JWT holds claims, and {member} is a data element")]
    #[explain(id = "present.no_claim")]
    NoClaim {
        /// The member.
        member: String,
    },
    /// A Key Binding JWT claim holds no byte string or CBOR data item.
    #[error("a Key Binding JWT claim holds no byte string or CBOR data item ({member})")]
    #[explain(id = "present.binary")]
    Binary {
        /// The member.
        member: String,
    },
    /// The member's JSON text reads as no value.
    #[error("the member's JSON text: {0}")]
    #[explain(id = "present.member_json")]
    MemberJson(#[source] JsonError),
    /// A member is one of the Key Binding JWT's own claims.
    #[error("a member is a Key Binding JWT claim: {0}")]
    #[explain(id = "present.key_binding")]
    KeyBinding(#[source] KeyBindingError),
}
