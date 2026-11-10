//! The consent display every platform lays out: each entry's record, consent entry and header,
//! the sets of slots of choices, and the selection read back from the ids the platform returns.

use std::fmt;

use rustc_hash::FxHashMap;
use siros_explain::Explain;
use siros_i18n::{Context, ResolveError};

use super::{Match, OfferSet, Offered, Pick, Record, ShownDigest};
use crate::claims::Foreign;
use crate::consent::{Card, ConsentEntry, Header};
use crate::detail;
use crate::ids::StaticEntryId;
use crate::plugins::{Fault, OptionIndex, Options, Shown};
use crate::plugins::{caused, fault};
use crate::request::Item;
use crate::rows::{Env, WalletText};

/// The header of a request without a transaction: the wallet's own, resolved by `context`.
///
/// # Errors
///
/// `context` resolves no text for one of [`WalletText::RequestTitle`], [`WalletText::Share`] and
/// [`WalletText::Deny`].
pub fn wallet_header(context: &Context) -> Result<Header, ResolveError> {
    Ok(Header {
        title: context.resolve(&WalletText::RequestTitle)?,
        confirm: context.resolve(&WalletText::Share)?,
        cancel: context.resolve(&WalletText::Deny)?,
    })
}

/// The option's items in every option the candidate answers, then those this option adds.
///
/// # Errors
///
/// [`Foreign::Option`]: `option` or an answerable option is no option of `options`.
pub fn option_items(
    options: &Options,
    answerable: &[OptionIndex],
    option: OptionIndex,
) -> Result<(Vec<Item>, Vec<Item>), Foreign> {
    let items = options.option(option)?.items();
    let answerable = answerable
        .iter()
        .map(|other| options.option(*other))
        .collect::<Result<Vec<_>, _>>()?;
    let in_all = |item: &Item| answerable.iter().all(|other| other.items().contains(item));
    let everyone: Vec<Item> = items.iter().copied().filter(in_all).collect();
    let chosen = items
        .iter()
        .copied()
        .filter(|item| !everyone.contains(item))
        .collect();
    Ok((everyone, chosen))
}

/// One consent entry: its pick, its record, what it shows, and its transaction's header.
#[derive(Debug, Clone)]
pub struct EntryView<'m> {
    /// The pick.
    pub pick: Pick,
    /// The record.
    pub record: Record<'m>,
    /// What it shows: the format's card, with the profile's overlay for a transaction.
    pub entry: ConsentEntry,
    /// The transaction's header.
    pub header: Option<&'m Header>,
}

/// Every consent entry: one per query, candidate and answerable option.
#[derive(Debug, Clone)]
pub struct Views<'m> {
    views: Vec<EntryView<'m>>,
    by_pick: FxHashMap<Pick, usize>,
}

impl<'m> Views<'m> {
    /// Every (query, candidate, answerable option): its record, its consent entry, and the
    /// header of the transaction it authorizes. `context` resolves the cards' texts, which the
    /// records commit to.
    ///
    /// # Errors
    ///
    /// A format's fault drawing a card, such as one caused by the `ResolveError` of a text
    /// `context` cannot resolve.
    pub fn of(matched: &'m Match<'m>, env: &Env, context: &Context) -> Result<Self, Fault> {
        let accepted = matched.accepted();
        let request = accepted.request();
        let digest = request.digest();
        let mut views = Vec::new();
        for plan in accepted.plans() {
            let (index, query) = (plan.index, plan.query);
            // A query whose format has no plug-in has no candidate.
            let Some(formatted) = plan.formatted.as_ref() else {
                continue;
            };
            let options = formatted.query.options();
            for (at, candidate) in matched.indexed_candidates(index) {
                let bound = candidate.bound.as_ref().map(|binding| &binding.bound);
                for option in &candidate.options {
                    let (everyone, chosen) = option_items(options, &candidate.options, *option)
                        .map_err(|foreign| caused(detail!("a candidate's option"), foreign))?;
                    let entries = bound.map_or(&[][..], |bound| bound.entries.entries());
                    let card = formatted.query.draw(
                        candidate.credential,
                        Shown {
                            everyone: &everyone,
                            chosen: &chosen,
                        },
                        env,
                        context,
                    )?;
                    let header = bound.map(|bound| &bound.header);
                    let overlay = bound.map(|bound| &bound.overlay);
                    let record = Record::new(
                        query.id(),
                        &candidate.credential.id,
                        *option,
                        entries,
                        bound.map(|b| &b.attested),
                        digest,
                        ShownDigest::of(&card, header, overlay),
                    );
                    views.push(EntryView {
                        pick: Pick {
                            query: index,
                            candidate: at,
                            option: *option,
                        },
                        record,
                        entry: ConsentEntry::new(card, overlay.cloned()),
                        header,
                    });
                }
            }
        }
        let by_pick = views
            .iter()
            .enumerate()
            .map(|(k, view)| (view.pick, k))
            .collect();
        Ok(Self { views, by_pick })
    }

    /// The entry of a pick.
    #[must_use]
    pub fn get(&self, pick: Pick) -> Option<&EntryView<'m>> {
        self.by_pick.get(&pick).and_then(|k| self.views.get(*k))
    }

    /// The entry whose record has this id.
    #[must_use]
    pub fn by_id(&self, id: &str) -> Option<&EntryView<'m>> {
        self.views
            .iter()
            .find(|view| view.record.id().as_str() == id)
    }

    /// Every entry, by query, candidate and option.
    pub fn iter(&self) -> impl Iterator<Item = &EntryView<'m>> {
        self.views.iter()
    }
}

/// An entry the wallet adds to every set, one per slot, first in every set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticEntry {
    /// Its id, which the platform returns when the End-User picks it.
    pub id: StaticEntryId<'static>,
    /// What it shows.
    pub card: Card,
}

/// One choice of a slot.
#[derive(Debug, Clone, Copy)]
pub enum Choice<'v> {
    /// A static entry.
    Static(&'v StaticEntry),
    /// The empty choice, "none".
    Nothing,
    /// A consent entry.
    Entry(&'v EntryView<'v>),
}

/// A choice's id: a static entry's, `none`, or a record's. The platform returns it when the
/// End-User picks the choice. Only [`Choice::id`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChoiceId<'v>(&'v str);

impl<'v> ChoiceId<'v> {
    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'v str {
        self.0
    }
}

impl<'v> Choice<'v> {
    /// The choice's id.
    #[must_use]
    pub fn id(&self) -> ChoiceId<'v> {
        ChoiceId(match self {
            Self::Static(content) => content.id.as_str(),
            Self::Nothing => "none",
            Self::Entry(view) => view.record.id().as_str(),
        })
    }
}

/// The consent display: sets of slots of choices. Each set opens with one slot per static entry,
/// then holds the slots of the offer.
#[derive(Debug, Clone)]
pub struct Display<'v> {
    sets: Vec<Vec<Vec<Choice<'v>>>>,
}

/// The display of an offer, with the wallet's static entries.
pub fn display<'v>(
    sets: &[OfferSet],
    views: &'v Views<'v>,
    statics: &'v [StaticEntry],
) -> Result<Display<'v>, Fault> {
    let head = || statics.iter().map(|content| vec![Choice::Static(content)]);
    let sets = sets
        .iter()
        .map(|set| {
            let slots = set
                .iter()
                .map(|slot| {
                    slot.iter()
                        .map(|offered| match offered {
                            Offered::Nothing => Ok(Choice::Nothing),
                            Offered::Pick(pick) => {
                                views.get(*pick).map(Choice::Entry).ok_or_else(|| {
                                    fault(detail!("{pick:?} has no view", pick = *pick))
                                })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(head().chain(slots).collect())
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    Ok(Display { sets })
}

/// A set of a [`Display`] by its position in [`Display::sets`]. Only [`Display::set`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SetIndex(usize);

impl SetIndex {
    /// The position in [`Display::sets`].
    #[must_use]
    pub const fn position(self) -> usize {
        self.0
    }
}

impl fmt::Display for SetIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A selection that is not one of the display's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum SelectionError {
    /// No set at that index.
    #[error("set {set} of {sets}")]
    #[explain(id = "selection.no_set")]
    NoSet {
        /// The position the platform returned.
        set: usize,
        /// The number of sets.
        sets: usize,
    },
    /// Not one id per slot.
    #[error("set {set}: {ids} ids for {slots} slots")]
    #[explain(id = "selection.length")]
    Length {
        /// The set.
        set: SetIndex,
        /// The ids returned.
        ids: usize,
        /// The slots.
        slots: usize,
    },
    /// An id that is not exactly one of its slot's choices.
    #[error("set {set} slot {slot}: {id} is not one of its entries")]
    #[explain(id = "selection.not_a_choice")]
    NotAChoice {
        /// The set.
        set: SetIndex,
        /// The slot.
        slot: usize,
        /// The id.
        id: String,
    },
    /// Two chosen entries carry transactions.
    #[error("two chosen entries carry transactions; one confirmation carries one")]
    #[explain(id = "selection.two_transactions")]
    TwoTransactions,
}

impl<'v> Display<'v> {
    /// The sets.
    #[must_use]
    pub fn sets(&self) -> &[Vec<Vec<Choice<'v>>>] {
        &self.sets
    }

    /// The set at the position the platform returned.
    ///
    /// # Errors
    ///
    /// [`SelectionError::NoSet`]: the display holds no set there.
    pub fn set(&self, position: usize) -> Result<DisplaySet<'_, 'v>, SelectionError> {
        self.sets
            .get(position)
            .map(|slots| DisplaySet {
                index: SetIndex(position),
                slots,
            })
            .ok_or(SelectionError::NoSet {
                set: position,
                sets: self.sets.len(),
            })
    }
}

/// One set of a [`Display`], which the platform returned.
#[derive(Debug, Clone, Copy)]
pub struct DisplaySet<'d, 'v> {
    index: SetIndex,
    slots: &'d [Vec<Choice<'v>>],
}

impl<'v> DisplaySet<'_, 'v> {
    /// Its position in the display.
    #[must_use]
    pub const fn index(&self) -> SetIndex {
        self.index
    }

    /// Its slots of choices.
    #[must_use]
    pub const fn slots(&self) -> &[Vec<Choice<'v>>] {
        self.slots
    }

    /// The selection of the chosen entry's id per slot. An id that is not one of its slot's
    /// choices is refused.
    ///
    /// # Errors
    ///
    /// [`SelectionError`]: not one id per slot, an id of no choice of its slot, or two
    /// transactions.
    pub fn select(&self, ids: &[&str]) -> Result<Selection<'v>, SelectionError> {
        let set = self.index;
        if ids.len() != self.slots.len() {
            return Err(SelectionError::Length {
                set,
                ids: ids.len(),
                slots: self.slots.len(),
            });
        }
        let mut chosen = Vec::new();
        for (slot, (choices, id)) in self.slots.iter().zip(ids).enumerate() {
            let hits: Vec<&Choice<'v>> = choices
                .iter()
                .filter(|choice| choice.id().as_str() == *id)
                .collect();
            match hits.as_slice() {
                [Choice::Entry(view)] => chosen.push(*view),
                [_] => {}
                _ => {
                    return Err(SelectionError::NotAChoice {
                        set,
                        slot,
                        id: (*id).to_owned(),
                    });
                }
            }
        }
        if chosen.iter().filter(|view| view.header.is_some()).count() > 1 {
            return Err(SelectionError::TwoTransactions);
        }
        Ok(Selection { chosen })
    }
}

/// The entries a selection presents, at most one carrying a transaction.
#[derive(Debug, Clone)]
pub struct Selection<'v> {
    chosen: Vec<&'v EntryView<'v>>,
}

impl<'v> Selection<'v> {
    /// The ids of the records the selection presents, in slot order.
    #[must_use]
    pub fn ids(&self) -> Vec<&'v str> {
        self.chosen
            .iter()
            .map(|view| view.record.id().as_str())
            .collect()
    }

    /// The header for the selection: the transaction's, else the wallet's own, resolved by
    /// `context`.
    ///
    /// # Errors
    ///
    /// `context` resolves no text for one of the wallet's header's statements.
    pub fn header(&self, context: &Context) -> Result<Header, ResolveError> {
        match self.chosen.iter().find_map(|view| view.header) {
            Some(header) => Ok(header.clone()),
            None => wallet_header(context),
        }
    }
}
