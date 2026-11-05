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
//! compare" never means "allowed". The bounds are part of the contract:
//! a claim path beyond [`MAX_CLAIM_PATH_ELEMS`] elements or an entry
//! beyond [`MAX_CLAIM_ENTRY_LEN`] bytes cannot be compared, so it is
//! refused — in enforce mode — never read as authorised.

use engine_ports::{ConsentCheckMode, TelemetryEvent, VpSelection};

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
/// Carries the reason class and, for an id the request's own query
/// defines, that id — never a claim name or value (the Go
/// `consentViolation`: "These are the only things logged about a
/// violation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The reason class.
    pub reason: &'static str,
    /// The query id, when the request's query defines it. A
    /// client-supplied id is kept out (and so out of the telemetry).
    pub query_id: String,
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
    dcql: Option<&serde_json::Value>,
    selections: &[VpSelection],
) -> Option<Violation> {
    let mode = ctx.ports.consent_check;
    if mode == ConsentCheckMode::Off {
        return None;
    }
    // No query (a scope-only, legacy request) has nothing to compare
    // with (the Go Decide's rule).
    let query = dcql?;
    let violation = match check(query, selections) {
        Ok(None) => return None,
        Ok(Some(violation)) => violation,
        // The query cannot be interpreted: a violation, never a pass.
        Err(()) => Violation {
            reason: REASON_UNPARSEABLE,
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
            ("reason".to_owned(), violation.reason.to_owned()),
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

/// Checks a match answer against the request's DCQL query.
///
/// `Ok(None)`: the answer fits. `Ok(Some)`: the violation. `Err(())`:
/// the query cannot be interpreted (the caller treats that as a
/// violation — "cannot compare" never means "allowed").
///
/// Enforced (the Go `checkConsentAgainstDCQL`): every selected query
/// id exists in the query; no id is selected twice unless it sets
/// `multiple`; when `credential_sets` exists, only ids that appear in
/// some option are selected; every `disclosed_claims` entry is
/// authorised by the query's claims (or by one claim set, as a
/// subset). A query with no claims authorises no disclosed claims.
/// Not enforced: that credential sets are satisfied, `values`
/// constraints, and what the resulting vp_token contains.
fn check(dcql: &serde_json::Value, selections: &[VpSelection]) -> Result<Option<Violation>, ()> {
    let credentials = dcql
        .get("credentials")
        .and_then(|v| v.as_array())
        .ok_or(())?;
    if credentials.is_empty() {
        // A query with no credentials is no query.
        return Err(());
    }

    // The query's credentials by id, their claim paths validated as
    // they are read.
    let mut by_id: rustc_hash::FxHashMap<String, &serde_json::Value> =
        rustc_hash::FxHashMap::default();
    for credential in credentials {
        let id = credential
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        if let Some(claims) = credential.get("claims").and_then(|v| v.as_array()) {
            for claim in claims {
                let path = claim.get("path").and_then(|v| v.as_array()).ok_or(())?;
                validate_claim_path(path)?;
            }
        }
        by_id.insert(id, credential);
    }

    // The credential_sets constraint: when the query carries them, an
    // id that appears in no option is outside the request.
    let mut in_sets: Option<Vec<String>> = None;
    if let Some(sets) = dcql.get("credential_sets").and_then(|v| v.as_array()) {
        if !sets.is_empty() {
            let mut ids = Vec::new();
            for set in sets {
                if let Some(options) = set.get("options").and_then(|v| v.as_array()) {
                    for option in options {
                        if let Some(option_ids) = option.as_array() {
                            for id in option_ids.iter().filter_map(|v| v.as_str()) {
                                ids.push(id.to_owned());
                            }
                        }
                    }
                }
            }
            in_sets = Some(ids);
        }
    }

    let mut seen: Vec<String> = Vec::new();
    for selection in selections {
        let query_id = &selection.credential_query_id;
        let Some(credential) = by_id.get(query_id).copied() else {
            // The id came from the client, not the query: keep it out
            // of the violation (and so out of the telemetry).
            return Ok(Some(Violation {
                reason: REASON_OUTSIDE_QUERY,
                query_id: String::new(),
            }));
        };
        // The violation carries the id only when the request's own
        // query defines it.
        let known = !query_id.is_empty();

        // The credential_sets constraint: an id the query's
        // credentials define but no option offers is outside the
        // request (the Go `inSets` rule).
        if let Some(ids) = &in_sets {
            if !ids.iter().any(|id| id == query_id) {
                return Ok(Some(Violation {
                    reason: REASON_OUTSIDE_QUERY,
                    query_id: if known {
                        query_id.clone()
                    } else {
                        String::new()
                    },
                }));
            }
        }

        // A duplicate selection needs the query's `multiple`.
        if seen.contains(query_id) {
            let multiple = credential
                .get("multiple")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !multiple {
                return Ok(Some(Violation {
                    reason: REASON_DUPLICATE,
                    query_id: if known {
                        query_id.clone()
                    } else {
                        String::new()
                    },
                }));
            }
        }
        seen.push(query_id.clone());

        let claims = credential.get("claims").and_then(|v| v.as_array());
        let claim_sets = credential.get("claim_sets").and_then(|v| v.as_array());
        if !claims_authorised(claims, claim_sets, &selection.disclosed_claims) {
            return Ok(Some(Violation {
                reason: REASON_CLAIM_OUTSIDE,
                query_id: if known {
                    query_id.clone()
                } else {
                    String::new()
                },
            }));
        }
    }
    Ok(None)
}

/// Checks one DCQL `claims[].path`: non-empty, bounded, and made only
/// of strings, non-negative integers and null (the wildcard) — as
/// DCQL defines (OpenID4VP §8.1). A path with anything else cannot be
/// interpreted, and must not be read as a wildcard.
fn validate_claim_path(path: &[serde_json::Value]) -> Result<(), ()> {
    if path.is_empty() || path.len() > MAX_CLAIM_PATH_ELEMS {
        return Err(());
    }
    for element in path {
        match element {
            serde_json::Value::Null | serde_json::Value::String(_) => {}
            serde_json::Value::Number(number) => {
                // A non-negative integer (a JSON fraction is not one).
                let _ = number.as_u64().ok_or(())?;
            }
            _ => return Err(()),
        }
    }
    Ok(())
}

/// Whether every `disclosed_claims` entry is authorised by the
/// credential's claims, or by one claim set as a subset. An empty
/// disclosed list is always fine: the host sends it when the query
/// names no claims, and clients treat it as "what the query requests".
fn claims_authorised(
    claims: Option<&Vec<serde_json::Value>>,
    claim_sets: Option<&Vec<serde_json::Value>>,
    disclosed: &[String],
) -> bool {
    if disclosed.is_empty() {
        return true;
    }
    let empty: Vec<serde_json::Value> = Vec::new();
    let claims = claims.unwrap_or(&empty);
    let paths: Vec<Vec<serde_json::Value>> = claims
        .iter()
        .map(|claim| {
            claim
                .get("path")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let sets = claim_sets.unwrap_or(&empty);
    if sets.is_empty() {
        // No claim sets: the claims authorise jointly.
        return all_allowed(&paths, disclosed);
    }
    // The claim sets: the disclosed entries must fit inside one set's
    // claim paths (a subset of one combination).
    for set in sets {
        let mut set_paths: Vec<Vec<serde_json::Value>> = Vec::new();
        for id in set
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            for claim in claims {
                if claim.get("id").and_then(|v| v.as_str()) == Some(id) {
                    if let Some(path) = claim.get("path").and_then(|v| v.as_array()) {
                        set_paths.push(path.clone());
                    }
                }
            }
        }
        if all_allowed(&set_paths, disclosed) {
            return true;
        }
    }
    false
}

/// Whether every disclosed entry is authorised by one of the
/// requested claim paths.
///
/// Clients spell an entry two ways: the wallet-frontend joins the
/// whole path with `.` (`["eu.pid","given_name"]` →
/// `"eu.pid.given_name"`, a null wildcard joins as the empty string),
/// while the Kotlin and Swift SDKs send only the last path element
/// (`"given_name"`). Both are accepted. A null path element matches
/// any element; an entry that is a descendant of a requested path (the
/// requested claim is an object) is a subset and is accepted.
fn all_allowed(paths: &[Vec<serde_json::Value>], disclosed: &[String]) -> bool {
    disclosed.iter().all(|entry| {
        // Never selectively disclosable: legitimate without a request.
        if ALWAYS_DISCLOSED.contains(&entry.as_str()) {
            return true;
        }
        if entry.len() > MAX_CLAIM_ENTRY_LEN {
            return false;
        }
        paths
            .iter()
            .any(|path| !path.is_empty() && path_allows(path, entry))
    })
}

/// Whether one requested claim path authorises one disclosed entry.
fn path_allows(path: &[serde_json::Value], entry: &str) -> bool {
    // The bare last-element form: a string matches itself, a number
    // its decimal form, and a trailing wildcard (null) any bare entry
    // at all (the Go `pathElemString` failure the bare check reads as
    // a match: a request for [..., any] names any last element).
    let bare = match path.last() {
        Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(text)) => text == entry,
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .is_some_and(|value| value.to_string() == entry),
        _ => false,
    };
    if bare {
        return true;
    }
    // The "."-joined form, or a descendant of it.
    match_joined_path(entry, path)
}

/// One `claims[].path` element, in the form the matcher reads: text
/// (a string, or a non-negative integer's decimal form) or a wildcard
/// (null).
#[derive(Debug, Clone)]
enum PathElem {
    /// A string element, or an integer element's decimal form.
    Text(String),
    /// A null element: it matches any run up to a dot boundary,
    /// including none.
    Wildcard,
}

/// Reads a validated path into its matcher elements. `None` for an
/// element the matcher cannot interpret — `validate_claim_path` has
/// refused those before a path reaches here, so a matcher that sees
/// one refuses.
fn path_elems(path: &[serde_json::Value]) -> Option<Vec<PathElem>> {
    path.iter()
        .map(|element| match element {
            serde_json::Value::String(text) => Some(PathElem::Text(text.clone())),
            serde_json::Value::Number(number) => number
                .as_u64()
                .map(|value| PathElem::Text(value.to_string())),
            serde_json::Value::Null => Some(PathElem::Wildcard),
            _ => None,
        })
        .collect()
}

/// Whether `entry` is the `.`-joined form of `path` or of a descendant
/// of it. Elements may themselves contain dots (an mdoc namespace such
/// as `org.iso.18013.5.1`), so `entry` is not split: each element is
/// matched as a prefix ending at a dot boundary, and a null element
/// matches any run of characters up to a dot boundary (including
/// none).
///
/// The result is memoised on (path index, entry offset), so the work
/// is polynomial in `len(path)` and `len(entry)` however many wildcards
/// a verifier-controlled query contains (the Go `matchJoinedPath`,
/// whose memo comment this mirrors).
fn match_joined_path(entry: &str, path: &[serde_json::Value]) -> bool {
    let Some(elems) = path_elems(path) else {
        return false;
    };
    let entry = entry.as_bytes();
    let mut memo: rustc_hash::FxHashMap<(usize, usize), bool> = rustc_hash::FxHashMap::default();
    match_joined_rec(entry, &elems, 0, 0, &mut memo)
}

/// One memoised step of [`match_joined_path`]: does the remainder of
/// `entry` from `off` match the path's elements from `pi` on?
fn match_joined_rec(
    entry: &[u8],
    elems: &[PathElem],
    pi: usize,
    off: usize,
    memo: &mut rustc_hash::FxHashMap<(usize, usize), bool>,
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
    elems: &[PathElem],
    pi: usize,
    off: usize,
    memo: &mut rustc_hash::FxHashMap<(usize, usize), bool>,
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
