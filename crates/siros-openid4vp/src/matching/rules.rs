//! The request rules that need the plug-ins, in the order they run: the core's C1-C4 and C8, the
//! routing's rules at C5's place, C6 (client metadata that is a JSON object), the named mode's
//! own rules (a JWE mode's C7), each format's rules per query, each profile's over its entries;
//! and the request they accept. C0 runs when the request is parsed.

use siros_explain::{AllOf, Explain};

use crate::envelope::Channel;
use crate::plugins::registry::{Catalog, Placed};
use crate::plugins::{FormatQuery, ProfileHandle, Registry};
use crate::refusal::{ErrorCode, Refusal, Refused, ReprList, RequestRule};
use crate::request::{ClientMetadata, EntryIndex, MetadataError, QueryIndex, Request};
use crate::routing::{QueryContext, RoutedMode, VerifierMetadata};
use crate::wallet_metadata::Placement;

/// The core's rules C1 to C8, each with its code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.rules")]
pub enum CoreRule {
    /// C1: an entry's type has no profile.
    #[error("C1 entry {entry}: no profile for type {kind}")]
    #[explain(id = "c1")]
    NoProfile {
        /// The entry's position.
        entry: usize,
        /// Its type.
        kind: String,
    },
    /// C2: an entry's `credential_ids` name a query the request lacks.
    #[error("C2 entry {entry}: credential_ids {ids} names no Credential Query of the request")]
    #[explain(id = "c2")]
    CredentialIds {
        /// The entry's position.
        entry: usize,
        /// Its `credential_ids`.
        ids: ReprList,
    },
    /// C3: an alternative presents two queries transaction data names.
    #[error("C3 two queries transaction data names can be presented together")]
    #[explain(id = "c3")]
    TwoTransactions,
    /// C4: entries of two profiles name one query.
    #[error("C4 {query}: entries of two profiles name it")]
    #[explain(id = "c4")]
    TwoProfiles {
        /// The query's id.
        query: String,
    },
    /// C6: `client_metadata` breaks its rule.
    #[error("C6 client_metadata: {0}")]
    #[explain(id = "c6")]
    ClientMetadata(#[explain(name = "cause")] MetadataError),
    /// C8: a signed request whose `expected_origins` lack the Origin.
    #[error("C8 a signed request whose expected_origins {expected} lack the Origin {origin}")]
    #[explain(id = "c8")]
    ExpectedOrigins {
        /// The `expected_origins`.
        expected: ReprList,
        /// The Origin.
        origin: String,
    },
}

impl RequestRule for CoreRule {
    fn code(&self) -> ErrorCode {
        match self {
            Self::NoProfile { .. }
            | Self::CredentialIds { .. }
            | Self::TwoTransactions
            | Self::TwoProfiles { .. } => ErrorCode::INVALID_TRANSACTION_DATA,
            Self::ClientMetadata(_) | Self::ExpectedOrigins { .. } => ErrorCode::INVALID_REQUEST,
        }
    }
}

/// The transaction data of one query: its profile and the entries naming it, in array order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The profile every entry naming the query belongs to (C4).
    pub profile: ProfileHandle,
    /// The entries naming the query.
    pub entries: Vec<EntryIndex>,
}

/// A query's format, as its plug-in parsed it.
pub(crate) struct Formatted<'q> {
    /// The placement the format stated at registration.
    pub(crate) placement: Option<Placement>,
    pub(crate) query: Box<dyn FormatQuery + 'q>,
}

/// What the matcher knows of each query.
pub(crate) struct Plan<'q> {
    pub(crate) formatted: Option<Formatted<'q>>,
    pub(crate) transaction: Option<Transaction>,
}

/// A request every rule accepts, with its registry.
pub struct Accepted<'q> {
    request: &'q Request<'q>,
    registry: &'q dyn Catalog,
    metadata: ClientMetadata<'q>,
    mode: RoutedMode,
    plans: Vec<Plan<'q>>,
}

impl<'q> Accepted<'q> {
    /// Runs the rules; refused with every rule the request breaks, in order: C1 to C4, C8, the
    /// routing's rules at C5's place, C6, the named mode's own rules (a JWE mode's C7), each
    /// format's, each profile's. The mode is the one the request's envelope routed it to.
    pub fn new<H>(request: &'q Request<'q>, registry: &'q Registry<H>) -> Result<Self, Refused> {
        let registry: &'q dyn Catalog = registry;
        let mut refusals = entry_rules(request, registry);
        refusals.extend(one_transaction(request));
        let (transactions, c4) = transactions(request, registry);
        refusals.extend(c4);
        refusals.extend(expected_origin(request));
        let routing = request.envelope().routing();
        refusals.extend(routing.refusals());
        let mode = routing.answer();
        let metadata = match ClientMetadata::parse(request.client_metadata()) {
            Ok(metadata) => metadata,
            Err(e) => {
                let c6 = Refusal::new(CoreRule::ClientMetadata(e));
                return Err(Refused::adding(refusals, c6));
            }
        };
        if let Ok((_, registered)) = &mode {
            refusals.extend(registered.rules(request, &VerifierMetadata::of(&metadata)));
        }
        let mode = mode.map(|(mode, _)| mode);
        let mut plans = Vec::new();
        for ((index, query), transaction) in request.indexed_queries().zip(transactions) {
            let formatted = match Formatted::of(
                request,
                registry,
                &metadata,
                mode.as_ref().ok().map(RoutedMode::name),
                index,
                query,
            ) {
                Some(Err(rules)) => {
                    refusals.extend(rules.into_items());
                    None
                }
                parsed => parsed.and_then(Result::ok),
            };
            plans.push(Plan {
                formatted,
                transaction,
            });
        }
        refusals.extend(profile_rules(request, registry));
        match (Refused::of(refusals), mode) {
            (Some(refused), _) => Err(refused),
            (None, Ok(mode)) => Ok(Self {
                request,
                registry,
                metadata,
                mode,
                plans,
            }),
            (None, Err(c5)) => Err(Refused::one(c5)),
        }
    }

    /// The request.
    #[must_use]
    pub fn request(&self) -> &'q Request<'q> {
        self.request
    }

    /// The plug-ins.
    pub(crate) fn registry(&self) -> &'q dyn Catalog {
        self.registry
    }

    /// The parsed client metadata.
    #[must_use]
    pub fn metadata(&self) -> &ClientMetadata<'q> {
        &self.metadata
    }

    /// The response mode the routing's rules accepted.
    #[must_use]
    pub const fn mode(&self) -> &RoutedMode {
        &self.mode
    }

    pub(crate) fn plan(&self, query: QueryIndex) -> Option<&Plan<'q>> {
        self.plans.get(query.get())
    }

    /// The transaction data naming a query.
    #[must_use]
    pub fn transaction(&self, query: QueryIndex) -> Option<&Transaction> {
        self.plan(query).and_then(|plan| plan.transaction.as_ref())
    }

    /// The query's options as its format parsed them; empty for a format without a plug-in.
    #[must_use]
    pub fn options(&self, query: QueryIndex) -> &[crate::plugins::OptionItems] {
        self.plan(query)
            .and_then(|plan| plan.formatted.as_ref())
            .map_or(&[], |formatted| formatted.query.options())
    }
}

impl<'q> Formatted<'q> {
    /// The query as its format parses it, or the format's rules it breaks; `None` for a format
    /// without a plug-in.
    fn of(
        request: &'q Request<'q>,
        registry: &'q dyn Catalog,
        metadata: &ClientMetadata<'q>,
        mode: Option<crate::routing::ModeName>,
        index: QueryIndex,
        query: &'q crate::request::Query<'q>,
    ) -> Option<Result<Self, AllOf<Refusal>>> {
        let Placed { format, placement } = registry.placed(&query.format)?;
        let context = QueryContext::of(
            request,
            mode,
            request.entry_named().contains(index),
            metadata.vp_formats(&query.format).cloned(),
        );
        Some(format.query(query, context).map(|parsed| Self {
            placement,
            query: parsed,
        }))
    }
}

/// C3: one confirmation carries one transaction, so no alternative presents two queries
/// transaction data names. It covers §5.1's "MUST use only one of the referenced Credentials".
fn one_transaction(request: &Request<'_>) -> Option<Refusal> {
    let named = request.entry_named();
    request
        .alternatives()
        .iter()
        .any(|alternative| alternative.set.intersection(named).len() > 1)
        .then(|| Refusal::new(CoreRule::TwoTransactions))
}

/// Each query's transaction, and C4: the entries naming one query belong to one profile, so one
/// credential carries one transaction.
fn transactions(
    request: &Request<'_>,
    registry: &dyn Catalog,
) -> (Vec<Option<Transaction>>, Vec<Refusal>) {
    let mut refusals = Vec::new();
    let mut transactions = Vec::new();
    for (index, query) in request.indexed_queries() {
        let entries = request.entries_naming(index);
        let mut profiles: Vec<Option<ProfileHandle>> = Vec::new();
        for profile in entries
            .iter()
            .filter_map(|e| request.entry(*e))
            .map(|entry| registry.profile(entry.kind()))
        {
            if !profiles.contains(&profile) {
                profiles.push(profile);
            }
        }
        if profiles.len() > 1 {
            refusals.push(Refusal::new(CoreRule::TwoProfiles {
                query: query.id.to_string(),
            }));
        }
        transactions.push(match profiles.first() {
            Some(Some(profile)) => Some(Transaction {
                profile: *profile,
                entries,
            }),
            _ => None,
        });
    }
    (transactions, refusals)
}

/// C8 (Annex A): a signed DC API request names the Origin in its `expected_origins`, which
/// detects a request another Verifier replays.
fn expected_origin(request: &Request<'_>) -> Option<Refusal> {
    let Channel::DcApi(origin) = request.envelope().channel() else {
        return None;
    };
    let named = request
        .expected_origins()
        .iter()
        .any(|expected| expected.as_ref() == origin.as_str());
    (request.request_object().is_some() && !named).then(|| {
        Refusal::new(CoreRule::ExpectedOrigins {
            expected: ReprList::strings(request.expected_origins()),
            origin: origin.to_string(),
        })
    })
}

/// For each entry in array order (OpenID4VP §5.1): C1, its type has a profile; C2, its
/// `credential_ids` name queries of the request.
fn entry_rules(request: &Request<'_>, registry: &dyn Catalog) -> Vec<Refusal> {
    let mut refusals = Vec::new();
    for (k, entry) in request.indexed_entries() {
        let k = k.get();
        if registry.profile(entry.kind()).is_none() {
            refusals.push(Refusal::new(CoreRule::NoProfile {
                entry: k,
                kind: entry.kind().to_string(),
            }));
        }
        let ids = entry.credential_ids();
        if !ids
            .iter()
            .all(|id| request.queries().iter().any(|query| query.id == **id))
        {
            refusals.push(Refusal::new(CoreRule::CredentialIds {
                entry: k,
                ids: ReprList::strings(ids),
            }));
        }
    }
    refusals
}

/// Each profile's rules over its entries, the profiles in the order of their first entry.
fn profile_rules(request: &Request<'_>, registry: &dyn Catalog) -> Vec<Refusal> {
    let mut groups: Vec<(ProfileHandle, Vec<EntryIndex>)> = Vec::new();
    for (index, entry) in request.indexed_entries() {
        let Some(profile) = registry.profile(entry.kind()) else {
            continue;
        };
        match groups.iter_mut().find(|(handle, _)| *handle == profile) {
            Some((_, own)) => own.push(index),
            None => groups.push((profile, vec![index])),
        }
    }
    groups
        .iter()
        .filter_map(|(handle, own)| {
            registry
                .profile_ref(*handle)
                .map(|profile| profile.refusals(request, own))
        })
        .flatten()
        .collect()
}
