//! The Verifier's checks of a presentation against its own query, steps 1 to 5 of
//! `zkp_req`, Section 4.1. Steps 6 to 8 build the statement and verify the proof; the system
//! defines them.

use siros_codec::cbor::Value;

use crate::formats::ZkpFormats;
use crate::ids::{ItemIndex, ReqSetIndex, ResultKey, SystemId};
use crate::presentation::ZkpPresentation;
use crate::query::{QueryOption, ReqItem, ReqSets, ZkpReqQuery};
use crate::select::System;

/// Why a presentation breaks steps 1 to 5 of Section 4.1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StructureRejection {
    /// Step 1: the Verifier did not list `system_id`.
    #[error("system_id is not listed")]
    SystemNotListed,
    /// Step 1: the Verifier did not list `proof_backend`.
    #[error("proof_backend is not listed")]
    BackendNotListed,
    /// Step 2: the system does not run on the proof backend.
    #[error("the system does not run on the proof backend")]
    SystemNotOnBackend,
    /// Step 3: the query has `_req_sets` and the presentation has no `req_set`.
    #[error("req_set is missing")]
    ReqSetMissing,
    /// Step 3: the query has no `_req_sets` and the presentation has a `req_set`.
    #[error("req_set is present for a query without _req_sets")]
    ReqSetExtra,
    /// Step 3: `req_set` names no option.
    #[error("req_set names no option")]
    ReqSetUnknown,
    /// Step 4: the keys of `results` differ from the option's `return` handles.
    #[error("results keys differ from the option's return handles")]
    ResultKeys,
    /// Step 5: an item whose function has no result has a value other than `true`.
    #[error("`_req` item {item} has a function without a result and a value other than true")]
    ResultNotTrue {
        /// The item's `_req` index.
        item: ItemIndex,
    },
}

/// The answered option of `presentation` and its system, after steps 1 to 5 of Section 4.1.
///
/// `system_of` gives the Verifier's system of an identifier. `has_result` says whether an
/// item's function has a result (the function catalogue's rule).
///
/// # Errors
///
/// [`StructureRejection`]: the first step that fails. Step 2 fails for a system the
/// Verifier runs none of.
pub fn answered_option<'q, S: System>(
    query: &'q ZkpReqQuery,
    formats: &ZkpFormats,
    presentation: &ZkpPresentation,
    system_of: impl Fn(&SystemId) -> Option<S>,
    has_result: impl Fn(&ReqItem) -> bool,
) -> Result<(&'q QueryOption, S), StructureRejection> {
    if !formats.lists_system(&presentation.system_id) {
        return Err(StructureRejection::SystemNotListed);
    }
    if !formats.lists_backend(&presentation.proof_backend) {
        return Err(StructureRejection::BackendNotListed);
    }
    let system = system_of(&presentation.system_id)
        .filter(|system| system.runs_on(&presentation.proof_backend))
        .ok_or(StructureRejection::SystemNotOnBackend)?;
    let option = option_of(query, presentation.req_set)?;
    check_results(query, option, &presentation.results, has_result)?;
    Ok((option, system))
}

fn option_of(
    query: &ZkpReqQuery,
    req_set: Option<ReqSetIndex>,
) -> Result<&QueryOption, StructureRejection> {
    match (query.req_sets(), req_set) {
        (ReqSets::Present, None) => Err(StructureRejection::ReqSetMissing),
        (ReqSets::Absent, Some(_)) => Err(StructureRejection::ReqSetExtra),
        (_, req_set) => query
            .option(req_set)
            .ok_or(StructureRejection::ReqSetUnknown),
    }
}

fn check_results(
    query: &ZkpReqQuery,
    option: &QueryOption,
    results: &[(ResultKey, Value)],
    has_result: impl Fn(&ReqItem) -> bool,
) -> Result<(), StructureRejection> {
    let mut handles = 0_usize;
    for &index in option.items() {
        let item = query.item(index).ok_or(StructureRejection::ReqSetUnknown)?;
        let Some(handle) = item.ret() else { continue };
        let value = results
            .iter()
            .find(|(key, _)| key.as_str() == handle.as_str())
            .map(|(_, value)| value)
            .ok_or(StructureRejection::ResultKeys)?;
        if !has_result(item) && *value != Value::Bool(true) {
            return Err(StructureRejection::ResultNotTrue { item: index });
        }
        handles += 1;
    }
    if results.len() != handles {
        return Err(StructureRejection::ResultKeys);
    }
    Ok(())
}
