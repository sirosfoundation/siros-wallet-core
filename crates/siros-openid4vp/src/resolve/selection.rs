//! The records the returned ids name, and whether they are a selection the request allows.

use siros_explain::AllOf;

use super::{Finding, Outcome, Rejection};
use crate::ids::QueryId;
use crate::matching::{Accepted, EntryView, ReturnedRecord, Views};
use crate::request::{Multiplicity, QuerySet};

/// The records the wallet derives for the returned ids; Fallback naming each id that is none of
/// them, and the input each id that names a derived record with other rendering inputs names
/// otherwise. Nothing renders to compare.
pub(super) fn derived<'v>(
    views: &'v Views<'v>,
    returned: &[ReturnedRecord<'_>],
) -> Result<Vec<&'v EntryView<'v>>, Outcome> {
    let records: Vec<Option<&EntryView<'_>>> =
        returned.iter().map(|id| views.by_id(id.as_str())).collect();
    let diverged: Vec<Finding> = records
        .iter()
        .zip(returned)
        .enumerate()
        .filter(|(_, (view, _))| view.is_none())
        .map(
            |(record, (_, id))| match views.iter().find_map(|view| view.record.other_input(id)) {
                Some(input) => Finding::Rendered { record, input },
                None => Finding::Diverged { record },
            },
        )
        .collect();
    AllOf::new(diverged).map_or_else(
        || Ok(records.into_iter().flatten().collect()),
        |diverged| Err(Outcome::Fallback(diverged)),
    )
}

/// Rejected unless the records are a selection the request allows: a query without `multiple`
/// takes one record, one with it distinct credentials; at most one record carries transactions
/// (one confirmation); the queries presented are one of the request's alternatives.
pub(super) fn check(accepted: &Accepted<'_>, records: &[&EntryView<'_>]) -> Result<(), Rejection> {
    let request = accepted.request();
    let mut queries: Vec<(&QueryId<'_>, Vec<&str>)> = Vec::new();
    for view in records {
        let credential = view.record.credential.as_str();
        match queries
            .iter_mut()
            .find(|(query, _)| *query == view.record.query)
        {
            Some((_, credentials)) => credentials.push(credential),
            None => queries.push((view.record.query, vec![credential])),
        }
    }
    for (query, credentials) in &queries {
        let mut distinct = credentials.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let multiple = request
            .queries()
            .iter()
            .any(|q| q.id == **query && q.multiple == Multiplicity::Many);
        if distinct.len() != credentials.len() || (credentials.len() > 1 && !multiple) {
            return Err(Rejection::QueryRecords {
                query: query.to_string(),
                records: credentials.len(),
                credentials: distinct.len(),
            });
        }
    }
    if records
        .iter()
        .filter(|view| !view.record.entries.is_empty())
        .count()
        > 1
    {
        return Err(Rejection::TwoTransactions);
    }
    let presented: QuerySet = records.iter().map(|view| view.pick.query).collect();
    if !request
        .alternatives()
        .iter()
        .any(|alternative| alternative.set() == presented)
    {
        let mut names: Vec<String> = queries.iter().map(|(query, _)| query.to_string()).collect();
        names.sort();
        return Err(Rejection::NoAlternative(names));
    }
    Ok(())
}
