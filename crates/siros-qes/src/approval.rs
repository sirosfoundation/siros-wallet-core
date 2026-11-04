//! The `qesApprovalRequest` an entry carries (CSC §7.1.1 and its example), parsed by the type's
//! rules (OpenID4VP §5.1: unknown members, wrong types, invalid values, missing required
//! members).

use siros_explain::Explain;
use siros_openid4vp::json::{Node, Object};

use crate::binding::ApprovalHash;
use crate::repr::Repr;

/// The members an entry may hold: OpenID4VP §5.1's, §7.1.1's and its example's.
const KNOWN: [&str; 7] = [
    "type",
    "credential_ids",
    "locations",
    "numSignatures",
    "signatureQualifier",
    "documentInfos",
    "hashAlgorithmOID",
];

/// A rule of the type an entry breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "qes.problem")]
pub(crate) enum Problem {
    /// The entry is no JSON object, which OpenID4VP §5.1 refuses first.
    #[error("the entry is not a JSON object")]
    NotAnObject,
    /// A member the type does not define.
    #[error("unknown member {0}")]
    UnknownMember(#[explain(name = "member")] String),
    /// `numSignatures` is no positive integer.
    #[error("numSignatures is not a positive integer")]
    SignatureCount,
    /// `signatureQualifier` is none the wallet renders; the value as Python's `repr` writes it.
    #[error("signatureQualifier {0} is not one this wallet renders")]
    SignatureQualifier(#[explain(name = "qualifier")] String),
    /// `hashAlgorithmOID` is no string.
    #[error("hashAlgorithmOID is absent: §7.2 identifies the approval's hash with it")]
    NoHashAlgorithm,
    /// `hashAlgorithmOID` names no hash the wallet computes.
    #[error("hashAlgorithmOID {0} names no hash this wallet computes")]
    UnknownHashAlgorithm(#[explain(name = "oid")] String),
    /// `documentInfos` is no non-empty array.
    #[error("documentInfos is not a non-empty array")]
    NoDocuments,
    /// A document is no object of the document members with their types, holding `hash` and
    /// `hashType`.
    #[error("documentInfos[{0}] is not a document with hash and hashType")]
    NotADocument(#[explain(name = "document")] usize),
    /// A document's access is of type `OTP` without its `oneTimePassword`.
    #[error("documentInfos[{0}]: an OTP access without its oneTimePassword")]
    OtpWithoutPassword(#[explain(name = "document")] usize),
    /// `locations` is no array of strings.
    #[error("locations is not an array of strings")]
    Locations,
}

/// `numSignatures`: a positive integer, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignatureCount<'e>(&'e str);

impl<'e> SignatureCount<'e> {
    /// A JSON integer above zero; JSON writes it without sign or leading zero.
    fn parse(value: &'e Node<'_>) -> Option<Self> {
        match value {
            Node::Number(number)
                if number.text().bytes().all(|b| b.is_ascii_digit()) && number.text() != "0" =>
            {
                Some(Self(number.text()))
            }
            _ => None,
        }
    }

    /// The count's decimal digits.
    pub(crate) fn as_str(self) -> &'e str {
        self.0
    }
}

/// What a QES creates (CSC §6.4 `signatureQualifier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Creation {
    /// An electronic signature.
    Signature,
    /// An electronic seal.
    Seal,
}

/// The trust framework under which a QES is qualified (CSC §6.4 `signatureQualifier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framework {
    /// The EU eIDAS regulation.
    Eidas,
}

/// A CSC API `signatureQualifier` the wallet renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureQualifier {
    /// `eu_eidas_qes`.
    EuEidasQes,
    /// `eu_eidas_qeseal`.
    EuEidasQeseal,
}

impl SignatureQualifier {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "eu_eidas_qes" => Some(Self::EuEidasQes),
            "eu_eidas_qeseal" => Some(Self::EuEidasQeseal),
            _ => None,
        }
    }

    /// The value as the CSC API writes it.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EuEidasQes => "eu_eidas_qes",
            Self::EuEidasQeseal => "eu_eidas_qeseal",
        }
    }

    /// What it creates.
    pub(crate) const fn creation(self) -> Creation {
        match self {
            Self::EuEidasQes => Creation::Signature,
            Self::EuEidasQeseal => Creation::Seal,
        }
    }

    /// Its framework.
    pub(crate) const fn framework(self) -> Framework {
        match self {
            Self::EuEidasQes | Self::EuEidasQeseal => Framework::Eidas,
        }
    }
}

/// A document's link: its `href`, and its `checksum` (W3C SRI metadata) when given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link<'e> {
    /// The URI.
    pub(crate) href: &'e str,
    /// The integrity metadata.
    pub(crate) checksum: Option<&'e str>,
}

/// One of `documentInfos`, as the rendering and the checksums read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DocumentInfo<'e> {
    /// The `label`.
    pub(crate) label: Option<&'e str>,
    /// The `oneTimePassword` of an access of type `OTP`.
    pub(crate) one_time_password: Option<&'e str>,
    /// The link, when the document has an `href`.
    pub(crate) link: Option<Link<'e>>,
}

/// The JSON kind of a document member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A string.
    String,
    /// An object.
    Object,
}

impl Kind {
    fn holds(self, value: &Node<'_>) -> bool {
        match self {
            Self::String => value.as_str().is_some(),
            Self::Object => value.as_object().is_some(),
        }
    }
}

/// The document members and their kinds.
const DOCUMENT: [(&str, Kind); 6] = [
    ("label", Kind::String),
    ("hash", Kind::String),
    ("hashType", Kind::String),
    ("access", Kind::Object),
    ("href", Kind::String),
    ("checksum", Kind::String),
];

impl<'e> DocumentInfo<'e> {
    /// The document at `at`: an object of the document members, each of its type, holding `hash`
    /// and `hashType`; an access of type `OTP` holds its `oneTimePassword` as a string.
    fn parse(value: &'e Node<'_>, at: usize) -> Result<Self, Problem> {
        let not_a_document = || Problem::NotADocument(at);
        let object = value.as_object().ok_or_else(not_a_document)?;
        let well_typed = object.members().iter().all(|member| {
            DOCUMENT
                .iter()
                .any(|(name, kind)| member.name == *name && kind.holds(&member.value))
        });
        if !well_typed || object.get("hash").is_none() || object.get("hashType").is_none() {
            return Err(not_a_document());
        }
        let access = object.get("access");
        let one_time_password = match access.and_then(|access| access.get("type")) {
            Some(Node::String(kind)) if kind == "OTP" => Some(
                access
                    .and_then(|access| access.get("oneTimePassword"))
                    .and_then(Node::as_str)
                    .ok_or(Problem::OtpWithoutPassword(at))?,
            ),
            _ => None,
        };
        let text = |name: &str| object.get(name).and_then(Node::as_str);
        Ok(Self {
            label: text("label"),
            one_time_password,
            link: text("href").map(|href| Link {
                href,
                checksum: text("checksum"),
            }),
        })
    }
}

/// A `qesApprovalRequest` keeping the type's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalRequest<'e> {
    /// `numSignatures`.
    pub(crate) count: SignatureCount<'e>,
    /// `signatureQualifier`.
    pub(crate) qualifier: SignatureQualifier,
    /// `hashAlgorithmOID`.
    pub(crate) hash: ApprovalHash,
    /// `documentInfos`, in array order.
    pub(crate) documents: Vec<DocumentInfo<'e>>,
}

impl<'e> ApprovalRequest<'e> {
    /// The entry's request, or every rule it breaks in the rules' order: unknown members in
    /// member order, `numSignatures`, `signatureQualifier`, `hashAlgorithmOID`, `documentInfos`
    /// document by document, `locations`.
    pub(crate) fn parse(entry: &'e Node<'_>) -> Result<Self, Vec<Problem>> {
        let object = entry
            .as_object()
            .ok_or_else(|| vec![Problem::NotAnObject])?;
        let mut problems = Problems(
            object
                .names()
                .filter(|name| !KNOWN.contains(name))
                .map(|name| Problem::UnknownMember(name.to_owned()))
                .collect(),
        );
        let count = problems.take(
            object
                .get("numSignatures")
                .and_then(SignatureCount::parse)
                .ok_or(Problem::SignatureCount),
        );
        let qualifier = problems.take(qualifier(object));
        let hash = problems.take(hash(object));
        let documents = problems.take_all(documents(object));
        let locations = problems.take(locations(object));
        match (count, qualifier, hash, documents, locations) {
            (Some(count), Some(qualifier), Some(hash), Some(documents), Some(()))
                if problems.0.is_empty() =>
            {
                Ok(Self {
                    count,
                    qualifier,
                    hash,
                    documents,
                })
            }
            _ => Err(problems.0),
        }
    }
}

/// The problems found so far, in the rules' order.
struct Problems(Vec<Problem>);

impl Problems {
    /// The value a rule parsed, or `None` with its problem kept.
    fn take<T>(&mut self, result: Result<T, Problem>) -> Option<T> {
        result.map_err(|problem| self.0.push(problem)).ok()
    }

    /// The value a rule parsed, or `None` with its problems kept.
    fn take_all<T>(&mut self, result: Result<T, Vec<Problem>>) -> Option<T> {
        result.map_err(|problems| self.0.extend(problems)).ok()
    }
}

fn qualifier(object: &Object<'_>) -> Result<SignatureQualifier, Problem> {
    let value = object.get("signatureQualifier");
    value
        .and_then(Node::as_str)
        .and_then(SignatureQualifier::parse)
        .ok_or_else(|| Problem::SignatureQualifier(Repr(value).to_string()))
}

fn hash(object: &Object<'_>) -> Result<ApprovalHash, Problem> {
    let oid = object
        .get("hashAlgorithmOID")
        .and_then(Node::as_str)
        .ok_or(Problem::NoHashAlgorithm)?;
    ApprovalHash::of(oid).ok_or_else(|| Problem::UnknownHashAlgorithm(oid.to_owned()))
}

/// `documentInfos`, or each document's problem in array order.
fn documents<'e>(object: &'e Object<'_>) -> Result<Vec<DocumentInfo<'e>>, Vec<Problem>> {
    let items = object
        .get("documentInfos")
        .and_then(Node::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| vec![Problem::NoDocuments])?;
    let mut documents = Vec::new();
    let mut problems = Vec::new();
    for (at, item) in items.iter().enumerate() {
        match DocumentInfo::parse(item, at) {
            Ok(document) => documents.push(document),
            Err(problem) => problems.push(problem),
        }
    }
    if problems.is_empty() {
        Ok(documents)
    } else {
        Err(problems)
    }
}

/// `locations`, when given: an array of strings.
fn locations(object: &Object<'_>) -> Result<(), Problem> {
    match object.get("locations") {
        Some(value)
            if !value
                .as_array()
                .is_some_and(|items| items.iter().all(|item| Kind::String.holds(item))) =>
        {
            Err(Problem::Locations)
        }
        _ => Ok(()),
    }
}
