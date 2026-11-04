//! `check_tampered`: the records phase 2 rejects or falls back on.

use crate::common::HaipHost;
use serde_json::{Value, json};
use siros_openid4vp::matching::{EntryView, Views};
use siros_openid4vp::request::{Multiplicity, QuerySet};
use siros_openid4vp::resolve::{Finding, Outcome, Prepared};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::Published;

use crate::dressed::Case;
use crate::generate::{host, published};
use crate::tally::Tally;

use super::Fields;

/// Phase 2 trusts the user's choice alone. Rejected: an id that is no record, and records the
/// wallet derives that no selection allows (two for a query without `multiple`, two carrying
/// transactions, queries no alternative holds). Fallback, every finding "diverged": a record the
/// wallet does not derive, whatever part of it changed (an entry, the option, the credential,
/// the query, an attested fact, the request it commits to).
pub(super) fn tampered(
    case: &Case<'_>,
    views: &Views<'_>,
    records: &[&EntryView<'_>],
    tally: &mut Tally,
) {
    let ids: Vec<String> = records
        .iter()
        .map(|view| view.record.id().as_str().to_owned())
        .collect();
    let fields: Vec<Fields> = records.iter().map(|view| Fields::of(view)).collect();
    let with = |extra: String| {
        let mut out = ids.clone();
        out.push(extra);
        out
    };
    let mut rejected: Vec<Vec<String>> = vec![with("none".to_owned())];
    let mut diverging: Vec<(Vec<String>, Vec<usize>)> = Vec::new();
    if let Some(first) = fields.first() {
        let mut nope = first.clone();
        "nope".clone_into(&mut nope.query);
        diverging.push((with(nope.id()), vec![ids.len()]));
    }
    let alternatives: Vec<QuerySet> = case.request.alternative_sets();
    let index_of = |query: &str| {
        case.request
            .indexed_queries()
            .find(|(_, q)| q.id.as_str() == query)
            .map(|(index, _)| index)
            .expect("a query of the request")
    };
    for (k, (view, record)) in records.iter().zip(&fields).enumerate() {
        let changed = |change: &dyn Fn(&mut Fields)| {
            let mut tampered = record.clone();
            change(&mut tampered);
            let mut out = ids.clone();
            out[k] = tampered.id();
            (out, vec![k])
        };
        let stray = case
            .request
            .indexed_entries()
            .find(|(_, entry)| !entry.credential_ids().contains(&record.query))
            .map(|(index, _)| index.get());
        if let Some(stray) = stray {
            diverging.push(changed(&|r: &mut Fields| {
                r.entries.push(stray);
                r.entries.sort_unstable();
                r.entries.dedup();
            }));
        }
        diverging.push(changed(&|r: &mut Fields| r.option = 99));
        diverging.push(changed(&|r: &mut Fields| {
            "nobody".clone_into(&mut r.credential)
        }));
        diverging.push(changed(&|r: &mut Fields| r.request = "d".repeat(43)));
        diverging.push(changed(&|r: &mut Fields| match r.attested.first_mut() {
            None => r
                .attested
                .push(("display_locale".to_owned(), "zz".to_owned())),
            Some((_, text)) => text.push('x'),
        }));
        let others: Vec<&EntryView<'_>> = views
            .iter()
            .filter(|o| {
                o.record.query == view.record.query && o.record.credential != view.record.credential
            })
            .collect();
        let multiple = case.query(view.pick.query).multiple == Multiplicity::Many;
        if !multiple {
            rejected.push(with(ids[k].clone()));
            rejected.extend(
                others
                    .iter()
                    .take(1)
                    .map(|o| with(o.record.id().as_str().to_owned())),
            );
        } else if !record.entries.is_empty() {
            rejected.extend(
                others
                    .iter()
                    .filter(|o| !o.record.entries.is_empty())
                    .take(1)
                    .map(|o| with(o.record.id().as_str().to_owned())),
            );
        }
        let all: QuerySet = fields.iter().map(|r| index_of(&r.query)).collect();
        let rest: QuerySet = fields
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != k)
            .map(|(_, r)| index_of(&r.query))
            .collect();
        if rest != all && !alternatives.contains(&rest) {
            let mut without = ids.clone();
            drop(without.remove(k));
            rejected.push(without);
        }
    }
    let nothing = Published::default();
    for bad in rejected {
        let bad: Vec<&str> = bad.iter().map(String::as_str).collect();
        match Prepared::prepare(case.request, &bad, case.wallet, case.registry, case.env)
            .and_then(|prepared| prepared.respond(|resource| nothing.answer(resource), &host(&[])))
        {
            Err(Outcome::Rejected(_)) => tally.add("tampered selections rejected"),
            other => panic!("R-tampered selection accepted: {bad:?} {other:?}"),
        }
    }
    for (bad, at) in diverging {
        let bad: Vec<&str> = bad.iter().map(String::as_str).collect();
        match Prepared::prepare(case.request, &bad, case.wallet, case.registry, case.env)
            .and_then(|prepared| prepared.respond(|resource| nothing.answer(resource), &host(&[])))
        {
            Err(Outcome::Fallback(findings)) => {
                let got: Vec<usize> = findings
                    .items()
                    .iter()
                    .map(|finding| match finding {
                        Finding::Diverged { record } => *record,
                        other => panic!("R-diverged: {other:?}"),
                    })
                    .collect();
                assert_eq!(got, at, "R-diverged");
                tally.add("tampered records falling back");
            }
            other => panic!("R-tampered record answered or rejected: {bad:?} {other:?}"),
        }
    }
}

/// The issuer's metadata renewed after the display: the record's integrity is no longer the
/// wallet's, so phase 2 derives another record and the shown one diverges.
pub(super) fn renewed(
    case: &Case<'_>,
    ids: &[&str],
    records: &[&EntryView<'_>],
    host: &HaipHost,
    tally: &mut Tally,
) {
    let Some((k, refreshed)) = records.iter().enumerate().find(|(_, view)| {
        view.record
            .attested
            .is_some_and(|attested| attested.get("metadata_integrity").is_some())
    }) else {
        return;
    };
    let mut held = case.held.to_vec();
    let target = held
        .iter_mut()
        .find(|h| h.id == refreshed.record.credential.as_str())
        .expect("the record's credential");
    for (key, content) in &mut target.documents {
        if key == "paso" {
            let mut document: Value = serde_json::from_slice(content).expect("a PaSO document");
            document["integrity"] = json!("sha256-renewed");
            *content = document.to_string().into_bytes();
        }
    }
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("a credential"))
            .collect(),
    )
    .expect("a wallet");
    let published = published();
    match Prepared::prepare(case.request, ids, &wallet, case.registry, case.env)
        .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
    {
        Err(Outcome::Fallback(findings)) => {
            let kinds: Vec<&str> = findings
                .items()
                .iter()
                .filter_map(|finding| match finding {
                    Finding::Diverged { record } if *record == k => Some("diverged"),
                    Finding::Unusable { record } if *record == k => Some("unusable"),
                    Finding::Revalidation { record, .. } if *record == k => Some("revalidation"),
                    _ => None,
                })
                .collect();
            assert_eq!(kinds, ["diverged"], "R-renewed metadata");
            tally.add("fallbacks: metadata renewed after the display");
        }
        other => panic!("R-renewed metadata answered: {other:?}"),
    }
}
