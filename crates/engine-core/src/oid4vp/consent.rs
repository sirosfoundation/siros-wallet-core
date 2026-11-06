//! The consent component (#525): what an OID4VP flow decides about the
//! host's answer to its credential selection — the DCQL vetting, the
//! one place that decides whether the answer is acceptable for the
//! request the engine sent, independent of the host or transport that
//! carried it.
//!
//! The host is not trusted to have honoured the query it was sent: the
//! policy compares the answer with it before anything is signed (the
//! Go engine's `consentPolicy.Decide`, whose call site reads "The
//! client is not trusted to have honoured the query it was sent: the
//! policy compares the answer with it before anything is signed").
//!
//! The modes (`presentation.dcql_consent_check`): `off` compares
//! nothing, `warn` records the violation (telemetry: the reason class
//! and the query id alone, never a claim name or value) and proceeds —
//! the default — and `enforce` refuses the presentation: the verifier
//! is answered `access_denied`, as a decline is.
//!
//! **A query that cannot be interpreted is a violation**: "cannot
//! compare" never means "allowed". The vetting parses the query once,
//! each claims path by OpenID4VP 1.0 §7 for its Credential Query's
//! `format`, and compares the answer with the parsed query; a disclosed
//! claim spelled as the JSON text of its path is parsed the same way
//! and compared as a path. The bounds are part of the contract: a
//! claim path beyond [`MAX_CLAIM_PATH_ELEMS`] elements or an entry
//! beyond [`MAX_CLAIM_ENTRY_LEN`] bytes cannot be compared, so it is
//! refused — in enforce mode — never read as authorised.

use std::borrow::Cow;

use engine_ports::{ConsentCheckMode, TelemetryEvent, VpSelection};
use rustc_hash::FxHashMap;
use serde_json::Value;

use crate::claims_path::{
    ClaimsPathError, JsonComponent, PresentationClaimsPath, PresentationComponent,
};
use crate::oid4vci::types::CredentialFormat;
use crate::runtime::FlowContext;

/// A selected query id is not in the request's DCQL query.
pub const REASON_OUTSIDE_QUERY: &str = "consent_outside_query";
/// A query id was selected twice without the query setting `multiple`.
pub const REASON_DUPLICATE: &str = "consent_duplicate_query";
/// A disclosed claim is not authorised by the query.
pub const REASON_CLAIM_OUTSIDE: &str = "consent_claim_outside_query";
/// The query itself could not be interpreted.
pub const REASON_UNPARSEABLE: &str = "consent_query_unparseable";

/// Top-level claims a wallet may legitimately report as disclosed
/// without the verifier having asked: they are never selectively
/// disclosable.
const ALWAYS_DISCLOSED: [&str; 7] = ["iss", "iat", "exp", "nbf", "vct", "cnf", "status"];

/// The bound on a DCQL `claims[].path` element count.
pub const MAX_CLAIM_PATH_ELEMS: usize = 32;
/// The bound on one `disclosed_claims` entry, in bytes.
pub const MAX_CLAIM_ENTRY_LEN: usize = 512;
/// The bound on a query id before it is reported (telemetry).
pub const MAX_LOGGED_QUERY_ID: usize = 64;

/// Why a match answer does not fit the query it was vetted against.
/// Carries the reason and, for an id the request's own query defines,
/// that id — never a claim name or value (the Go `consentViolation`:
/// "These are the only things logged about a violation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The reason.
    pub reason: Reason,
    /// The query id, when the request's query defines it. A
    /// client-supplied id is kept out (and so out of the telemetry).
    pub query_id: String,
}

/// Why a match answer does not fit the query: one reason per class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A selected query id is not in the query, or in no option of its
    /// `credential_sets`: [`REASON_OUTSIDE_QUERY`].
    OutsideQuery,
    /// A query id was selected twice without the query setting
    /// `multiple`: [`REASON_DUPLICATE`].
    Duplicate,
    /// A disclosed claim is not authorised by the query:
    /// [`REASON_CLAIM_OUTSIDE`].
    ClaimOutside,
    /// The query cannot be interpreted, for this reason:
    /// [`REASON_UNPARSEABLE`].
    Unparseable(QueryError),
}

impl Reason {
    /// The reason class, which the telemetry record and the flow's
    /// completion carry.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::OutsideQuery => REASON_OUTSIDE_QUERY,
            Self::Duplicate => REASON_DUPLICATE,
            Self::ClaimOutside => REASON_CLAIM_OUTSIDE,
            Self::Unparseable(_) => REASON_UNPARSEABLE,
        }
    }
}

/// Why the vetting cannot interpret a DCQL query (OpenID4VP 1.0 §6):
/// positions and rules, never a claim name or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// `credentials` is absent, no array, or empty: §6 asks for "A
    /// non-empty array of Credential Queries".
    #[error("the query has no credentials")]
    NoCredentials,
    /// A Claims Query cannot be interpreted.
    #[error("claims query {claim} of credential query {credential}: {why}")]
    ClaimsQuery {
        /// The Credential Query's position in `credentials`, from 0.
        credential: usize,
        /// The Claims Query's position in its `claims`, from 0.
        claim: usize,
        /// Why it cannot be interpreted.
        why: ClaimsQueryError,
    },
}

/// Why the vetting cannot interpret a Claims Query (OpenID4VP 1.0
/// §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsQueryError {
    /// It has no `path`, which §6.3 requires.
    #[error("it has no path")]
    NoPath,
    /// Its path has more than [`MAX_CLAIM_PATH_ELEMS`] components, too
    /// many to compare.
    #[error("its path has too many components to compare")]
    PathTooLong,
    /// Its path is no claims path pointer into a Credential of the
    /// Credential Query's format (§7).
    #[error("{0}")]
    Path(ClaimsPathError),
}

/// Vets the host's match answer against the DCQL query it was sent,
/// under the deployment's mode, and records a violation through the
/// telemetry — the warn-mode record, and the enforce-mode refusal's
/// audit line.
///
/// Returns the violation an `enforce` deployment refuses on;
/// `warn` and `off` return `None` (`off` without comparing anything).
/// A query the engine cannot interpret is a violation, never a pass.
pub async fn vet(
    ctx: &FlowContext,
    dcql: Option<&Value>,
    selections: &[VpSelection],
) -> Option<Violation> {
    let mode = ctx.ports.consent_check;
    if mode == ConsentCheckMode::Off {
        return None;
    }
    // No query (a scope-only, legacy request) has nothing to compare
    // with (the Go Decide's rule).
    let query = dcql?;
    let violation = match Query::parse(query) {
        Ok(query) => query.vet(selections)?,
        // The query cannot be interpreted: a violation, never a pass.
        Err(error) => Violation {
            reason: Reason::Unparseable(error),
            query_id: String::new(),
        },
    };
    // The record: the reason class and the query id alone, the id
    // bounded — never a claim name or value.
    ctx.ports.telemetry.event(TelemetryEvent {
        name: "oid4vp_consent_violation".to_owned(),
        flow_id: Some(ctx.flow_id.clone()),
        fields: vec![
            ("mode".to_owned(), mode.as_str().to_owned()),
            ("reason".to_owned(), violation.reason.class().to_owned()),
            (
                "credential_query_id".to_owned(),
                loggable(&violation.query_id),
            ),
        ],
    });
    if mode == ConsentCheckMode::Enforce {
        return Some(violation);
    }
    None
}

/// The request's DCQL query as the vetting reads it (OpenID4VP 1.0 §6).
struct Query<'a> {
    /// The Credential Queries by `id` (§6.1); one without an `id` is
    /// held under the empty id.
    credentials: FxHashMap<&'a str, CredentialQuery<'a>>,
    /// The ids the options of `credential_sets` name (§6.2), when the
    /// query carries a non-empty `credential_sets`.
    in_sets: Option<Vec<&'a str>>,
}

/// One Credential Query (OpenID4VP 1.0 §6.1), as the vetting reads it.
struct CredentialQuery<'a> {
    /// `format`, when OpenID4VCI 1.0 Appendix A defines it: how its
    /// claims paths, and the disclosed claims spelled as paths, read.
    format: Option<CredentialFormat>,
    /// `multiple`: more than one Credential may answer the query.
    multiple: bool,
    /// `claims` (§6.3): none when absent.
    claims: Vec<ClaimsQuery<'a>>,
    /// `claim_sets`: the claim ids of each combination.
    claim_sets: Vec<Vec<&'a str>>,
}

/// One Claims Query (OpenID4VP 1.0 §6.3), as the vetting reads it.
struct ClaimsQuery<'a> {
    /// Its `id`.
    id: Option<&'a str>,
    /// Its `path`, parsed for the Credential Query's `format` (§7).
    path: PresentationClaimsPath,
}

impl<'a> Query<'a> {
    /// The query the JSON value `dcql` writes.
    fn parse(dcql: &'a Value) -> Result<Self, QueryError> {
        let credentials = dcql
            .get("credentials")
            .and_then(Value::as_array)
            .filter(|credentials| !credentials.is_empty())
            .ok_or(QueryError::NoCredentials)?;
        let mut by_id = FxHashMap::default();
        for (at, credential) in credentials.iter().enumerate() {
            let id = credential
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            by_id.insert(id, CredentialQuery::parse(credential, at)?);
        }
        // The credential_sets constraint: when the query carries them,
        // an id that appears in no option is outside the request.
        let in_sets = dcql
            .get("credential_sets")
            .and_then(Value::as_array)
            .filter(|sets| !sets.is_empty())
            .map(|sets| {
                sets.iter()
                    .filter_map(|set| set.get("options").and_then(Value::as_array))
                    .flatten()
                    .filter_map(Value::as_array)
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect()
            });
        Ok(Self {
            credentials: by_id,
            in_sets,
        })
    }

    /// The violation of a match answer, or `None` when it fits.
    ///
    /// Enforced (the Go `checkConsentAgainstDCQL`): every selected query
    /// id exists in the query; no id is selected twice unless it sets
    /// `multiple`; when `credential_sets` exists, only ids that appear in
    /// some option are selected; every `disclosed_claims` entry is
    /// authorised by the query's claims (or by one claim set, as a
    /// subset). A query with no claims authorises no disclosed claims.
    /// Not enforced: that credential sets are satisfied, `values`
    /// constraints, and what the resulting vp_token contains.
    fn vet(&self, selections: &[VpSelection]) -> Option<Violation> {
        let mut seen: Vec<&str> = Vec::new();
        for selection in selections {
            let query_id = selection.credential_query_id.as_str();
            let Some(credential) = self.credentials.get(query_id) else {
                // The id came from the client, not the query: keep it out
                // of the violation (and so out of the telemetry).
                return Some(Violation {
                    reason: Reason::OutsideQuery,
                    query_id: String::new(),
                });
            };
            // The request's own query defines the id, so the violation
            // carries it.
            let violation = |reason: Reason| Violation {
                reason,
                query_id: query_id.to_owned(),
            };

            // The credential_sets constraint: an id the query's
            // credentials define but no option offers is outside the
            // request (the Go `inSets` rule).
            if self
                .in_sets
                .as_ref()
                .is_some_and(|ids| !ids.contains(&query_id))
            {
                return Some(violation(Reason::OutsideQuery));
            }

            // A duplicate selection needs the query's `multiple`.
            if seen.contains(&query_id) && !credential.multiple {
                return Some(violation(Reason::Duplicate));
            }
            seen.push(query_id);

            if !credential.authorises(&selection.disclosed_claims) {
                return Some(violation(Reason::ClaimOutside));
            }
        }
        None
    }
}

impl<'a> CredentialQuery<'a> {
    /// The Credential Query the JSON value `credential` writes, at the
    /// position `at` in `credentials`.
    fn parse(credential: &'a Value, at: usize) -> Result<Self, QueryError> {
        // The format decides how a claims path reads (§§7.1, 7.2). A
        // format OpenID4VCI 1.0 Appendix A does not define, or none,
        // keeps §7's grammar alone.
        let format = credential
            .get("format")
            .and_then(Value::as_str)
            .and_then(CredentialFormat::from_identifier);
        let claims = credential
            .get("claims")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(claim, value)| {
                ClaimsQuery::parse(value, format).map_err(|why| QueryError::ClaimsQuery {
                    credential: at,
                    claim,
                    why,
                })
            })
            .collect::<Result<_, _>>()?;
        let claim_sets = credential
            .get("claim_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|set| {
                set.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect()
            })
            .collect();
        Ok(Self {
            format,
            multiple: credential
                .get("multiple")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            claims,
            claim_sets,
        })
    }

    /// Whether every `disclosed_claims` entry is authorised by the
    /// query's claims, or by one claim set as a subset. An empty
    /// disclosed list is always fine: the host sends it when the query
    /// names no claims, and clients treat it as "what the query
    /// requests".
    fn authorises(&self, disclosed: &[String]) -> bool {
        if disclosed.is_empty() {
            return true;
        }
        if self.claim_sets.is_empty() {
            // No claim sets: the claims authorise jointly.
            let paths: Vec<&PresentationClaimsPath> =
                self.claims.iter().map(|claim| &claim.path).collect();
            return all_allowed(&paths, self.format, disclosed);
        }
        // The claim sets: the disclosed entries must fit inside one set's
        // claim paths (a subset of one combination).
        self.claim_sets.iter().any(|set| {
            let paths: Vec<&PresentationClaimsPath> = set
                .iter()
                .flat_map(|id| {
                    self.claims
                        .iter()
                        .filter(move |claim| claim.id == Some(*id))
                })
                .map(|claim| &claim.path)
                .collect();
            all_allowed(&paths, self.format, disclosed)
        })
    }
}

impl<'a> ClaimsQuery<'a> {
    /// The Claims Query the JSON value `claim` writes into a Credential
    /// of the format `format`.
    fn parse(claim: &'a Value, format: Option<CredentialFormat>) -> Result<Self, ClaimsQueryError> {
        let path = claim.get("path").ok_or(ClaimsQueryError::NoPath)?;
        // The bound applies before the parse: a longer path is never
        // compared.
        if path
            .as_array()
            .is_some_and(|components| components.len() > MAX_CLAIM_PATH_ELEMS)
        {
            return Err(ClaimsQueryError::PathTooLong);
        }
        Ok(Self {
            id: claim.get("id").and_then(Value::as_str),
            path: PresentationClaimsPath::parse(path, format).map_err(ClaimsQueryError::Path)?,
        })
    }
}

/// Whether every disclosed entry is authorised by one of the
/// requested claim paths, each parsed for the Credential Query's
/// format `format`.
///
/// Clients spell an entry three ways, and each is accepted. The
/// engine's mini host sends the JSON text of the claims path pointer
/// (`["eu.pid","given_name"]`): it is parsed for `format` as the
/// requested paths are, and compared with them as a path ([`covers`]).
/// A text that OpenID4VP 1.0 §7 refuses names no requested claim. The
/// wallet-frontend joins the whole path with `.`
/// (`"eu.pid.given_name"`, a null wildcard joins as the empty string),
/// while the Kotlin and Swift SDKs send only the last path element
/// (`"given_name"`). In those two spellings, a null path element
/// matches any element, and an entry that is a descendant of a
/// requested path (the requested claim is an object) is a subset and
/// is accepted.
fn all_allowed(
    paths: &[&PresentationClaimsPath],
    format: Option<CredentialFormat>,
    disclosed: &[String],
) -> bool {
    let requested: Vec<Vec<Step<'_>>> = paths.iter().map(|path| steps(path)).collect();
    let spelled: Vec<Vec<PathElem<'_>>> = requested
        .iter()
        .map(|steps| steps.iter().map(|step| step.spelled()).collect())
        .collect();
    disclosed.iter().all(|entry| {
        // Never selectively disclosable: legitimate without a request.
        if ALWAYS_DISCLOSED.contains(&entry.as_str()) {
            return true;
        }
        if entry.len() > MAX_CLAIM_ENTRY_LEN {
            return false;
        }
        match serde_json::from_str::<Value>(entry) {
            // The JSON text of a claims path pointer.
            Ok(value @ Value::Array(_)) => {
                PresentationClaimsPath::parse(&value, format).is_ok_and(|path| {
                    let disclosed = steps(&path);
                    always_disclosed(&disclosed)
                        || requested
                            .iter()
                            .any(|requested| covers(requested, &disclosed))
                })
            }
            // A claim name: the path's last element, or its elements
            // joined with `.`.
            _ => spelled.iter().any(|elems| path_allows(elems, entry)),
        }
    })
}

/// One component of a parsed claims path, as the vetting compares
/// paths. A pointer into an ISO mdoc has two keys, the namespace and
/// the data element identifier, and a pointer into a Credential of
/// another format compares as a pointer into a JSON-based Credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step<'a> {
    /// A string component.
    Key(&'a str),
    /// A non-negative integer component.
    Index(u64),
    /// A null component: every element of an array.
    All,
}

impl<'a> Step<'a> {
    /// The step as a claim name spells it: a key as itself, an index
    /// in decimal, whatever its spelling in the query, and a null as a
    /// wildcard.
    fn spelled(self) -> PathElem<'a> {
        match self {
            Self::Key(key) => PathElem::Text(Cow::Borrowed(key)),
            Self::Index(index) => PathElem::Text(Cow::Owned(index.to_string())),
            Self::All => PathElem::Wildcard,
        }
    }
}

/// The steps of a parsed claims path.
fn steps(path: &PresentationClaimsPath) -> Vec<Step<'_>> {
    match path {
        PresentationClaimsPath::Json(components) => components
            .iter()
            .map(|component| match component {
                JsonComponent::Key(key) => Step::Key(key),
                JsonComponent::Index(index) => Step::Index(*index),
                JsonComponent::AllElements => Step::All,
            })
            .collect(),
        PresentationClaimsPath::Mdoc {
            namespace,
            data_element,
        } => vec![Step::Key(namespace), Step::Key(data_element)],
        PresentationClaimsPath::OtherFormat(components) => components
            .iter()
            .map(|component| match component {
                PresentationComponent::Key(key) => Step::Key(key),
                PresentationComponent::Integer(integer) => Step::Index(*integer),
                PresentationComponent::Null => Step::All,
            })
            .collect(),
    }
}

/// Whether the requested path authorises the disclosed path, both as
/// their steps: each requested step selects the disclosed step at its
/// position, a null any index, and the disclosed path may continue
/// into the requested claim's value. OpenID4VP 1.0 §7.3:
/// `["degrees", null, "type"]` selects "All type claims in the degrees
/// array", and `["address"]` selects "The claim address with its
/// sub-claims as the value".
fn covers(requested: &[Step<'_>], disclosed: &[Step<'_>]) -> bool {
    // A claims path has one component at least (§7).
    !requested.is_empty()
        && requested.len() <= disclosed.len()
        && requested
            .iter()
            .zip(disclosed)
            .all(|(requested, disclosed)| match requested {
                Step::All => matches!(disclosed, Step::Index(_) | Step::All),
                Step::Key(_) | Step::Index(_) => requested == disclosed,
            })
}

/// Whether a disclosed path is a top-level claim that is never
/// selectively disclosable.
fn always_disclosed(disclosed: &[Step<'_>]) -> bool {
    matches!(disclosed, [Step::Key(name)] if ALWAYS_DISCLOSED.contains(name))
}

/// Whether one requested claim path, spelled as its matcher elements,
/// authorises one disclosed entry.
fn path_allows(elems: &[PathElem<'_>], entry: &str) -> bool {
    // A claims path has one component at least (§7).
    let Some(last) = elems.last() else {
        return false;
    };
    // The bare last-element form: a text matches itself, and a trailing
    // wildcard (null) any bare entry at all (the Go `pathElemString`
    // failure the bare check reads as a match: a request for
    // [..., any] names any last element).
    let bare = match last {
        PathElem::Text(text) => text == entry,
        PathElem::Wildcard => true,
    };
    // The "."-joined form, or a descendant of it.
    bare || match_joined_path(entry, elems)
}

/// One `claims[].path` component, as a claim name spells it: text (a
/// string, or a non-negative integer's decimal form) or a wildcard
/// (null).
#[derive(Debug, Clone)]
enum PathElem<'a> {
    /// A string component, or an integer component's decimal form.
    Text(Cow<'a, str>),
    /// A null component: it matches any run up to a dot boundary,
    /// including none.
    Wildcard,
}

/// Whether `entry` is the `.`-joined form of the path `elems` spell, or
/// of a descendant of it. Elements may themselves contain dots (an mdoc
/// namespace such as `org.iso.18013.5.1`), so `entry` is not split:
/// each element is matched as a prefix ending at a dot boundary, and a
/// null element matches any run of characters up to a dot boundary
/// (including none).
///
/// The result is memoised on (path index, entry offset), so the work
/// is polynomial in `len(path)` and `len(entry)` however many wildcards
/// a verifier-controlled query contains (the Go `matchJoinedPath`,
/// whose memo comment this mirrors).
fn match_joined_path(entry: &str, elems: &[PathElem<'_>]) -> bool {
    let entry = entry.as_bytes();
    let mut memo: FxHashMap<(usize, usize), bool> = FxHashMap::default();
    match_joined_rec(entry, elems, 0, 0, &mut memo)
}

/// One memoised step of [`match_joined_path`]: does the remainder of
/// `entry` from `off` match the path's elements from `pi` on?
fn match_joined_rec(
    entry: &[u8],
    elems: &[PathElem<'_>],
    pi: usize,
    off: usize,
    memo: &mut FxHashMap<(usize, usize), bool>,
) -> bool {
    let key = (pi, off);
    if let Some(cached) = memo.get(&key) {
        return *cached;
    }
    // Marked before computing, as the Go matcher marks: a re-entry
    // reads as no match rather than recursing.
    memo.insert(key, false);
    let result = match_joined_compute(entry, elems, pi, off, memo);
    memo.insert(key, result);
    result
}

/// Computes one step of [`match_joined_rec`], unmemoised: the last
/// element consumes to the end (so a descendant of the path matches),
/// every other element must be followed by a `.` separator, and a
/// wildcard consumes up to some dot boundary of the remainder — or
/// all of it.
fn match_joined_compute(
    entry: &[u8],
    elems: &[PathElem<'_>],
    pi: usize,
    off: usize,
    memo: &mut FxHashMap<(usize, usize), bool>,
) -> bool {
    let last = pi + 1 == elems.len();
    // Continues past element pi, whose match ended at entry[end].
    let mut after = |end: usize| -> bool {
        if last {
            match_joined_rec(entry, elems, pi + 1, end, memo)
        } else {
            end < entry.len()
                && entry.get(end) == Some(&b'.')
                && match_joined_rec(entry, elems, pi + 1, end + 1, memo)
        }
    };
    if pi == elems.len() {
        // The path is consumed: what remains of the entry is nothing,
        // or a descendant of it (the requested claim is an object).
        return off >= entry.len() || entry.get(off) == Some(&b'.');
    }
    match elems.get(pi) {
        // An element past the path's end never matches: the path is
        // shorter than the entry's joined form.
        None => false,
        Some(PathElem::Text(text)) => {
            entry
                .get(off..)
                .is_some_and(|rest| rest.starts_with(text.as_bytes()))
                && after(off + text.len())
        }
        Some(PathElem::Wildcard) => {
            // It consumes up to some dot boundary of the remainder,
            // or all of it.
            let mut result = false;
            let mut offset = off;
            while offset < entry.len() && !result {
                if entry.get(offset) == Some(&b'.') {
                    result = after(offset);
                }
                offset += 1;
            }
            if !result {
                result = after(entry.len());
            }
            result
        }
    }
}

/// Bounds a query id before it is reported (telemetry): at
/// [`MAX_LOGGED_QUERY_ID`] characters, ellipsis after.
fn loggable(id: &str) -> String {
    if id.chars().count() > MAX_LOGGED_QUERY_ID {
        let cut: String = id.chars().take(MAX_LOGGED_QUERY_ID).collect();
        format!("{cut}...")
    } else {
        id.to_owned()
    }
}
