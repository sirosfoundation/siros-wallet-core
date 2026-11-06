//! A PaSO `transaction_data` entry (Core §7.1, Proof Metadata §5.1, OpenID4VP §5.1) and the
//! rules PaSO sets on a request carrying its entries (Core §3, §7.1, §7.4.1).

use siros_explain::Explain;
use siros_openid4vp::ids::TransactionType;
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::refusal::Refusal;

use siros_openid4vp::jose::JwsError;

use crate::adhoc::AdhocFailure;
use crate::outcome::NotCompatible;
use crate::rules::PasoRule;
use siros_openid4vp::request::{Entry, EntryIndex, QuerySet, Request, factor, project};

/// The members a PaSO entry may hold: OpenID4VP's `type` and `credential_ids`, Core §7.1's
/// `payload`, Proof Metadata §5.1's `metadata`.
const MEMBERS: [&str; 4] = ["type", "credential_ids", "payload", "metadata"];

/// A PaSO entry's `payload`: a JSON object.
#[derive(Debug, Clone, Copy)]
pub struct Payload<'e> {
    node: &'e Node<'static>,
    object: &'e Object<'static>,
}

impl<'e> Payload<'e> {
    /// The payload of a value that is an object.
    #[must_use]
    pub fn of(node: &'e Node<'static>) -> Option<Self> {
        match node {
            Node::Object(object) => Some(Self { node, object }),
            _ => None,
        }
    }

    /// The payload as a JSON value.
    #[must_use]
    pub const fn node(self) -> &'e Node<'static> {
        self.node
    }

    /// The payload's members.
    #[must_use]
    pub const fn object(self) -> &'e Object<'static> {
        self.object
    }
}

/// A member of a PaSO entry that breaks Core §7.1, Proof Metadata §5.1 or OpenID4VP §5.1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.entry")]
pub enum EntryRule {
    /// A member none of the three specifications defines.
    #[error("unknown member {0} (OpenID4VP §5.1)")]
    UnknownMember(#[explain(name = "member")] String),
    /// `payload` is absent or no object.
    #[error("payload is not a JSON object (Core §7.1)")]
    PayloadNotObject,
    /// `metadata` is no string.
    #[error("metadata is not a string (Proof Metadata §5.1)")]
    MetadataNotString,
}

/// A PaSO entry: its type, its payload, and the ad-hoc metadata JWT it may carry.
#[derive(Debug, Clone, Copy)]
pub struct PasoEntry<'e> {
    /// The entry as received.
    pub entry: &'e Entry<'e>,
    /// The type identifier.
    pub kind: &'e TransactionType<'static>,
    /// The payload.
    pub payload: Payload<'e>,
    /// The ad-hoc metadata JWT (Proof Metadata §5.1), as received.
    pub metadata: Option<&'e str>,
}

impl<'e> PasoEntry<'e> {
    /// The entry as its rendering reads it: the payload an object (Core §7.1), the ad-hoc
    /// metadata, when present, a string (Proof Metadata §5.1); a member it does not read takes
    /// no part. A payload that is no object makes the entry not compatible; ad-hoc metadata that
    /// is no string is no compact JWS (§5.3).
    pub fn read(entry: &'e Entry<'e>) -> Result<Self, NotCompatible> {
        let members = entry.members();
        let payload = members
            .get("payload")
            .and_then(Payload::of)
            .ok_or(NotCompatible::PayloadNotObject)?;
        let metadata = match members.get("metadata") {
            None => None,
            Some(Node::String(jwt)) => Some(jwt.as_ref()),
            Some(_) => return Err(AdhocFailure::Jws(JwsError::Structure).into()),
        };
        Ok(Self {
            entry,
            kind: entry.kind(),
            payload,
            metadata,
        })
    }
}

/// The member rules an entry breaks, in order: each unknown member in member order, then the
/// payload's rule, then the metadata's.
fn broken(entry: &Entry<'_>) -> Vec<EntryRule> {
    let members = entry.members();
    let unknown = members.as_object().into_iter().flat_map(|object| {
        object
            .names()
            .filter(|name| !MEMBERS.contains(name))
            .map(|name| EntryRule::UnknownMember(name.to_owned()))
    });
    let payload = members
        .get("payload")
        .and_then(Payload::of)
        .is_none()
        .then_some(EntryRule::PayloadNotObject);
    let metadata = members
        .get("metadata")
        .filter(|metadata| metadata.as_str().is_none())
        .map(|_| EntryRule::MetadataNotString);
    unknown.chain(payload).chain(metadata).collect()
}

/// The rules PaSO sets on a request over its own entries, in order: the request is signed
/// (Core §3); each entry's members (Core §7.1, Proof Metadata §5.1, OpenID4VP §5.1); the
/// alternatives involving its entries' queries are transposable, and those queries sit in one
/// credential set (Core §7.4.1).
#[must_use]
pub fn refusals(request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
    let mut out = Vec::new();
    if request.request_object().is_none() {
        out.push(Refusal::new(PasoRule::Unsigned));
    }
    let own: Vec<(EntryIndex, &Entry<'_>)> = request
        .indexed_entries()
        .filter(|(index, _)| entries.contains(index))
        .collect();
    for (index, entry) in &own {
        out.extend(broken(entry).into_iter().map(|rule| {
            Refusal::new(PasoRule::Entry {
                entry: index.get(),
                rule,
            })
        }));
    }
    let named: QuerySet = request
        .indexed_queries()
        .filter(|(_, query)| {
            own.iter()
                .any(|(_, entry)| entry.credential_ids().iter().any(|id| query.id == **id))
        })
        .map(|(index, _)| index)
        .collect();
    let involving: Vec<QuerySet> = request
        .alternative_sets()
        .into_iter()
        .filter(|alternative| !alternative.intersection(named).is_empty())
        .collect();
    let coupled = factor(&involving, request.query_order())
        .into_iter()
        .any(|block| {
            project(&involving, block)
                .iter()
                .any(|option| option.len() > 1)
        });
    if coupled {
        out.push(Refusal::new(PasoRule::Coupled));
    }
    let holding = request.sets().map_or(0, |sets| {
        sets.iter()
            .filter(|set| {
                set.options
                    .iter()
                    .flatten()
                    .any(|query| named.contains(*query))
            })
            .count()
    });
    if holding > 1 {
        out.push(Refusal::new(PasoRule::Sets));
    }
    out
}
