//! check_props.py `check_display`: the display both renderers draw, for either choice of the
//! wallet: static slots first, then the offer's; every selection parses back from Credential
//! Manager's ids, holds one transaction at most and shows its header, else the wallet's; foreign
//! ids are refused. Each selection of the preselecting shape gets its response.

use siros_openid4vp::matching::{
    Choice as Shown, Consent, EntryView, Match, Offered, Pick, SelectionError, Views, display,
    offer, wallet_header,
};
use siros_openid4vp::rows::Choice;

use crate::dressed::Case;
use crate::generate;
use crate::response;
use crate::tally::Tally;

/// Every way to choose one entry per slot, the first slot varying slowest.
fn product<T>(slots: &[Vec<T>]) -> Vec<Vec<&T>> {
    slots.iter().fold(vec![Vec::new()], |done, slot| {
        done.iter()
            .flat_map(|prefix| {
                slot.iter().map(move |choice| {
                    let mut next = prefix.clone();
                    next.push(choice);
                    next
                })
            })
            .collect()
    })
}

/// Checks the display of a case whose consent the wallet can meet.
pub fn check(case: &Case<'_>, matched: &Match<'_>, views: &Views<'_>, tally: &mut Tally) {
    let Some(consent) = Consent::of(matched) else {
        return;
    };
    // Phase 2's host for the case, every response drawing on its identifiers in turn.
    let host = generate::host(case.unusable);
    let statics = case.statics;
    for choice in [Choice::First, Choice::LetChoose] {
        let sets = offer(matched, &consent, choice);
        let shown = display(&sets, views, statics).expect("no fault");
        assert_eq!(sets.len(), shown.sets().len(), "P-display sets");
        for (set, slots) in sets.iter().zip(shown.sets()) {
            // The wallet's static entries first, one slot each, then the offer's slots.
            let (head, rest) = slots.split_at(statics.len());
            assert!(
                head.iter().zip(statics).all(|(slot, content)| {
                    matches!(slot.as_slice(), [Shown::Static(known)] if *known == content)
                }),
                "P-static slots first"
            );
            let got: Vec<Vec<Option<Pick>>> = rest
                .iter()
                .map(|slot| {
                    slot.iter()
                        .map(|choice| match choice {
                            Shown::Entry(view) => Some(view.pick),
                            Shown::Nothing => None,
                            Shown::Static(content) => panic!("P-display slots: {}", content.id),
                        })
                        .collect()
                })
                .collect();
            let want: Vec<Vec<Option<Pick>>> = set
                .iter()
                .map(|slot| {
                    slot.iter()
                        .map(|offered| match offered {
                            Offered::Pick(pick) => Some(*pick),
                            Offered::Nothing => None,
                        })
                        .collect()
                })
                .collect();
            assert_eq!(got, want, "P-display slots");
        }
        tally.add_many("static boxes", statics.len() * shown.sets().len());
        for (k, slots) in shown.sets().iter().enumerate() {
            for combo in product(slots) {
                let ids: Vec<&str> = combo.iter().map(|choice| choice.id()).collect();
                // The ids Credential Manager returns parse back to the selection's records; one
                // transaction at most (C3, and one transaction-bearing member per `multiple`
                // fill).
                let selection = match shown.select(k, &ids) {
                    Ok(selection) => selection,
                    Err(SelectionError::TwoTransactions) => {
                        panic!("P-one transaction per selection: {ids:?}")
                    }
                    Err(e) => panic!("P-selection parses back: {e}"),
                };
                let entries: Vec<&EntryView<'_>> = combo
                    .iter()
                    .filter_map(|choice| match choice {
                        Shown::Entry(view) => Some(*view),
                        Shown::Static(_) | Shown::Nothing => None,
                    })
                    .collect();
                let records: Vec<&str> = entries
                    .iter()
                    .map(|view| view.record.id().as_str())
                    .collect();
                assert_eq!(selection.ids(), records, "P-selection parses back");
                let applying: Vec<_> = entries.iter().filter_map(|view| view.header).collect();
                assert!(applying.len() <= 1, "P-one transaction per selection");
                // The selection's header is its transaction's, else the wallet's own.
                let header = selection.header();
                match applying.first() {
                    Some(transaction) => {
                        assert_eq!(&header, *transaction, "P-header of the selection");
                        tally.add("selections with a transaction");
                    }
                    None => {
                        assert_eq!(header, wallet_header(), "P-wallet header");
                        tally.add("selections with the wallet's header");
                    }
                }
                tally.add("display selections");
                // Both choices offer the same selections: the preselecting one answers each.
                if choice == Choice::First {
                    let defaults = combo
                        .iter()
                        .zip(slots)
                        .all(|(chosen, slot)| std::ptr::eq(*chosen, &slot[0]));
                    response::check(case, matched, views, &records, &host, defaults, tally);
                }
            }
            // Refused: an id that is not one of its slot's entries, a selection of the wrong
            // length, a set the display lacks.
            let ids: Vec<&str> = slots.iter().map(|slot| slot[0].id()).collect();
            let firsts: Vec<&str> = slots[0].iter().map(Shown::id).collect();
            let foreign = slots
                .last()
                .and_then(|last| last.iter().map(Shown::id).find(|id| !firsts.contains(id)));
            let mut tampered: Vec<(usize, Vec<&str>)> = Vec::new();
            if let Some(foreign) = foreign.filter(|_| slots.len() > 1) {
                let mut changed = ids.clone();
                changed[0] = foreign;
                tampered.push((k, changed));
            }
            tampered.push((k, ids[..ids.len() - 1].to_vec()));
            tampered.push((shown.sets().len(), ids.clone()));
            for (at, bad) in tampered {
                assert!(
                    shown.select(at, &bad).is_err(),
                    "P-foreign selection accepted: set {at} {bad:?}"
                );
                tally.add("foreign selections refused");
            }
        }
    }
}
