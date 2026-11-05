//! The request as OpenID4VP 1.0 defines it, read from its envelope: DCQL Credential Queries
//! and Credential Sets (§6), `transaction_data` entries (§5.1), the parameters a response binds,
//! the alternatives the sets allow (§6.4.2) and their factoring into independent choices.

mod dcql;
mod digest;
mod entry;
mod factor;
mod metadata;
mod rules;
mod sets;

use std::borrow::Cow;

use serde_json::value::RawValue;

use crate::envelope::{Channel, Envelope, NonceError, Signatures};
use crate::ids::{ClientId, Nonce};
use crate::json;
use crate::refusal::{Refusal, Refused};

pub use dcql::{CredentialSet, HolderBinding, Multiplicity, Query, TrustedAuthority};
pub use digest::RequestDigest;
pub use entry::{Entry, Malformed};
pub use factor::{factor, project, splits};
pub(crate) use metadata::jose_name;
pub use metadata::{
    AgreeableKey, Agreements, ClientMetadata, ContentEncryption, Curve, KeyAgreement,
    MetadataError, Point,
};
pub use rules::{DcqlRule, ParameterRule, StructureRule, UndecodedEntry};
pub use sets::{Item, ItemSet, MAX_POSITIONS, Position, QueryIndex, QuerySet, Set};

/// A `transaction_data` entry by its position in the array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryIndex(usize);

impl EntryIndex {
    /// The position in `transaction_data`.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// One combination of Credential Queries the Credential Sets allow (§6.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    /// The queries in set order then option order, each once.
    pub queries: Vec<QueryIndex>,
    /// The same queries as a set.
    pub set: QuerySet,
}

/// A request: its protocol parameters parsed from its envelope, its entries decoded (rule C0),
/// its alternatives computed. The rules that need the plug-ins run when the matcher accepts it.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    envelope: Envelope<'a>,
    nonce: Nonce<'a>,
    client_metadata: Option<&'a RawValue>,
    expected_origins: Vec<Cow<'a, str>>,
    queries: Vec<Query<'a>>,
    sets: Option<Vec<CredentialSet>>,
    entries: Vec<Entry<'a>>,
    alternatives: Vec<Alternative>,
    query_order: Vec<QueryIndex>,
}

fn structure(rule: StructureRule) -> Refused {
    Refused::one(Refusal::new(rule))
}

impl<'a> Request<'a> {
    /// The request an envelope holds, which it keeps. Refused in this order: S3 a `scope` value by
    /// URI naming no registered scope query; S4 `dcql_query` beside a `scope` naming one (§5.1);
    /// DCQL's structure, `dcql_query` or a `scope` naming a query required (§5.1), a `scope`'s
    /// queries read as their union; `nonce` absent, or N1 not URL-safe ASCII;
    /// `expected_origins` and `transaction_data` breaking their structure; C0, every entry that
    /// does not decode; P7, a URI request with a query waiving holder binding and no `state`.
    ///
    /// # Errors
    ///
    /// The rules the request breaks.
    pub fn parse(envelope: &Envelope<'a>) -> Result<Self, Refused> {
        let channel = envelope.channel();
        let parameters = envelope.parameters();
        let scoped = match (channel, parameters.text("scope")) {
            (Channel::Uri, Some(scope)) => {
                let scope = scope.unwrap_or_default();
                let entries = scope
                    .split(' ')
                    .map(|value| {
                        envelope.scopes().named(value).ok_or_else(|| {
                            Refused::one(Refusal::new(ParameterRule::Scope(value.to_owned())))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if parameters.holds("dcql_query") {
                    return Err(Refused::one(Refusal::new(ParameterRule::ScopeAndQuery)));
                }
                Some(entries)
            }
            _ => None,
        };
        let dcql = match scoped {
            Some(entries) => {
                let credentials = entries
                    .iter()
                    .flat_map(|entry| entry.credentials.iter().copied())
                    .collect();
                let sets: Vec<_> = entries
                    .iter()
                    .flat_map(|entry| entry.sets.iter().copied())
                    .collect();
                dcql::Dcql::of(credentials, (!sets.is_empty()).then_some(sets))
            }
            None => dcql::Dcql::parse(
                parameters
                    .raw("dcql_query")
                    .ok_or_else(|| structure(StructureRule::DcqlAbsent))?,
            ),
        }
        .map_err(Refused::one)?;
        let nonce = match envelope.nonce() {
            Ok(nonce) => nonce.clone(),
            Err(NonceError::Unsafe) => {
                return Err(Refused::one(Refusal::new(ParameterRule::Nonce)));
            }
            Err(NonceError::Absent) => return Err(structure(StructureRule::Nonce)),
        };
        // Annex A: an unsigned request's expected_origins are ignored, and A.2 lists them over the
        // DC API alone.
        let signed_dc_api = matches!(channel, Channel::DcApi(_))
            && !matches!(envelope.signatures(), Signatures::Unsigned);
        let expected_origins = match parameters.raw("expected_origins").filter(|_| signed_dc_api) {
            None => Vec::new(),
            Some(raw) => strings(raw).ok_or_else(|| structure(StructureRule::ExpectedOrigins))?,
        };
        let entries = match parameters.raw("transaction_data") {
            None => Vec::new(),
            Some(raw) => strings(raw)
                .filter(|entries| !entries.is_empty())
                .ok_or_else(|| structure(StructureRule::TransactionData))
                .and_then(decode_entries)?,
        };
        if matches!(channel, Channel::Uri)
            && !parameters.holds("state")
            && dcql
                .queries
                .iter()
                .any(|query| query.holder_binding == HolderBinding::Waived)
        {
            return Err(Refused::one(Refusal::new(ParameterRule::StateRequired)));
        }
        let alternatives = alternatives(&dcql.queries, dcql.sets.as_deref());
        let mut query_order = Vec::new();
        for query in alternatives
            .iter()
            .flat_map(|alternative| &alternative.queries)
        {
            if !query_order.contains(query) {
                query_order.push(*query);
            }
        }
        Ok(Self {
            envelope: envelope.clone(),
            nonce,
            client_metadata: parameters.raw("client_metadata"),
            expected_origins,
            queries: dcql.queries,
            sets: dcql.sets,
            entries,
            alternatives,
            query_order,
        })
    }

    /// The envelope the request was read from: its channel, its signatures, its routing.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope<'a> {
        &self.envelope
    }

    /// The JWS text of a signed request, compact or JSON.
    #[must_use]
    pub fn request_object(&self) -> Option<&'a str> {
        match self.envelope.signatures() {
            Signatures::Unsigned => None,
            Signatures::One { jws, .. } => Some(jws.text()),
            Signatures::Many(signers) => Some(signers.jws().text()),
        }
    }

    /// The `client_id` of a Request Object; `None` for an unsigned and a multisigned DC API
    /// request.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId<'a>> {
        self.envelope.client_id()
    }

    /// The `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &Nonce<'a> {
        &self.nonce
    }

    /// The `client_metadata` as received.
    #[must_use]
    pub fn client_metadata(&self) -> Option<&'a RawValue> {
        self.client_metadata
    }

    /// A signed DC API request's `expected_origins` as received; empty for another request.
    #[must_use]
    pub fn expected_origins(&self) -> &[Cow<'a, str>] {
        &self.expected_origins
    }

    /// The Credential Queries.
    #[must_use]
    pub fn queries(&self) -> &[Query<'a>] {
        &self.queries
    }

    /// The query at a position.
    #[must_use]
    pub fn query(&self, index: QueryIndex) -> Option<&Query<'a>> {
        self.queries.get(index.get())
    }

    /// The queries with their positions.
    pub fn indexed_queries(&self) -> impl Iterator<Item = (QueryIndex, &Query<'a>)> {
        self.queries
            .iter()
            .enumerate()
            .filter_map(|(k, query)| QueryIndex::new(k).map(|index| (index, query)))
    }

    /// The Credential Sets, when present.
    #[must_use]
    pub fn sets(&self) -> Option<&[CredentialSet]> {
        self.sets.as_deref()
    }

    /// The `transaction_data` entries.
    #[must_use]
    pub fn entries(&self) -> &[Entry<'a>] {
        &self.entries
    }

    /// The entries with their positions.
    pub fn indexed_entries(&self) -> impl Iterator<Item = (EntryIndex, &Entry<'a>)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(k, entry)| (EntryIndex(k), entry))
    }

    /// The entry at a position.
    #[must_use]
    pub fn entry(&self, index: EntryIndex) -> Option<&Entry<'a>> {
        self.entries.get(index.0)
    }

    /// The entries whose `credential_ids` name the query, in array order.
    #[must_use]
    pub fn entries_naming(&self, query: QueryIndex) -> Vec<EntryIndex> {
        let id = self.query(query).map(|query| query.id.as_str());
        self.indexed_entries()
            .filter(|(_, entry)| {
                id.is_some_and(|id| entry.credential_ids().iter().any(|named| named == id))
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// The queries some entry names.
    #[must_use]
    pub fn entry_named(&self) -> QuerySet {
        self.indexed_queries()
            .filter(|(index, _)| !self.entries_naming(*index).is_empty())
            .map(|(index, _)| index)
            .collect()
    }

    /// The alternatives (§6.4.2): every required set satisfied by one option, every optional set
    /// by one option or none; ordered by sets in array order, options in array order, an
    /// optional set's "none" last. Without Credential Sets, the one alternative of every query.
    #[must_use]
    pub fn alternatives(&self) -> &[Alternative] {
        &self.alternatives
    }

    /// The alternatives as sets.
    #[must_use]
    pub fn alternative_sets(&self) -> Vec<QuerySet> {
        self.alternatives
            .iter()
            .map(|alternative| alternative.set)
            .collect()
    }

    /// The queries in the order they first appear across the alternatives.
    #[must_use]
    pub fn query_order(&self) -> &[QueryIndex] {
        &self.query_order
    }

    /// The digest of the request as received.
    #[must_use]
    pub const fn digest(&self) -> &'a RequestDigest {
        self.envelope.received().digest()
    }
}

fn strings(raw: &RawValue) -> Option<Vec<Cow<'_, str>>> {
    let items: Vec<&RawValue> = serde_json::from_str(raw.get()).ok()?;
    items
        .into_iter()
        .map(|item| json::string(item).ok())
        .collect()
}

/// Rule C0: every entry decodes, else the refusal of each that does not.
fn decode_entries(raw: Vec<Cow<'_, str>>) -> Result<Vec<Entry<'_>>, Refused> {
    let mut entries = Vec::new();
    let mut refusals = Vec::new();
    for (k, text) in raw.into_iter().enumerate() {
        match Entry::decode(text) {
            Ok(entry) => entries.push(entry),
            Err(malformed) => refusals.push(Refusal::new(UndecodedEntry {
                entry: k,
                malformed,
            })),
        }
    }
    Refused::of(refusals).map_or(Ok(entries), Err)
}

fn alternatives(queries: &[Query<'_>], sets: Option<&[CredentialSet]>) -> Vec<Alternative> {
    let all = || {
        (0..queries.len())
            .filter_map(QueryIndex::new)
            .collect::<Vec<_>>()
    };
    let Some(sets) = sets else {
        let queries = all();
        return vec![Alternative {
            set: QuerySet::of(queries.iter().copied()),
            queries,
        }];
    };
    let choices: Vec<Vec<Option<&Vec<QueryIndex>>>> = sets
        .iter()
        .map(|set| {
            set.options
                .iter()
                .map(Some)
                .chain((!set.required).then_some(None))
                .collect()
        })
        .collect();
    let mut out: Vec<Alternative> = Vec::new();
    for combination in crate::product::product(&choices) {
        let mut ordered: Vec<QueryIndex> = Vec::new();
        for query in combination.into_iter().flatten().flatten() {
            if !ordered.contains(query) {
                ordered.push(*query);
            }
        }
        let set = QuerySet::of(ordered.iter().copied());
        if !out.iter().any(|alternative| alternative.set == set) {
            out.push(Alternative {
                queries: ordered,
                set,
            });
        }
    }
    out
}
