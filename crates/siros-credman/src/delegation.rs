//! A9 and K4: whether a set of the consent display needs the wallet's display, and the delegation
//! the matcher sends for its entries. A set of a request without `transaction_data`, whose entries
//! Credential Manager's own display shows whole, of credentials the wallet presents from its
//! background service, with nothing left to choose, needs no wallet display; the matcher then
//! sends `Full` delegation, and the wallet fulfils from its background service.

use siros_explain::{Explain, Text};
use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::matching::{Choice, Display, SelectionError};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::request::Request;

use crate::field::{Extent, Field};

/// The credentials the app declares presentable without the wallet's UI: each key signs without
/// user interaction, and the wallet's background service answers.
#[derive(Debug, Clone, Copy)]
pub struct Presentable<'p>(pub &'p [CredentialId<'p>]);

/// Whether the request carries `transaction_data`, which the End-User confirms on the wallet's
/// display (T5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionData {
    /// No `transaction_data`.
    Absent,
    /// `transaction_data` entries.
    Carried,
}

impl TransactionData {
    /// Whether the request carries `transaction_data`.
    #[must_use]
    pub fn of(request: &Request<'_>) -> Self {
        if request.entries().is_empty() {
            Self::Absent
        } else {
            Self::Carried
        }
    }
}

/// Whether Credential Manager showed everything a set's entries carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostDisplay {
    /// It showed every text of the entries.
    Full,
    /// Its display level left text of an entry out (`display_skipped`).
    Skipped,
}

/// What A9 judges a set by, apart from Credential Manager's display level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetFacts {
    /// Every entry's credential is presentable without the wallet's UI.
    pub presentable: bool,
    /// The request carries no `transaction_data`.
    pub no_transaction_data: bool,
    /// Every slot holds one choice: the End-User chooses nothing, neither an addition nor a
    /// subset of a `multiple` query's candidates.
    pub settled: bool,
    /// Every row of every entry shows as a field, whole.
    pub whole: bool,
}

/// Whether a set needs the wallet's display (A9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletDisplay {
    /// The End-User consents on Credential Manager's display alone, and the wallet presents
    /// from its background service.
    NotNeeded,
    /// The End-User consents on the wallet's display.
    Needed,
}

/// The delegation the matcher sends for every entry of a set (K4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delegation {
    /// `Full`: Credential Manager keeps its display, and the wallet fulfils from its background
    /// service.
    Full,
    /// No delegation: the wallet's display opens.
    None,
}

/// How the wallet fulfils a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fulfilment {
    /// On its own display, where the End-User consented.
    WalletUi,
    /// From its background service, after the End-User consented on Credential Manager's
    /// display, which showed the set's entries as this says.
    Background(HostDisplay),
}

/// Why a background fulfilment is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "credman.fulfilment")]
pub enum WalletDisplayNeeded {
    /// The set needs the wallet's display (A9).
    #[error("set {set} needs the wallet's display")]
    Needed {
        /// The set.
        set: usize,
    },
    /// The display holds no such set.
    #[error(transparent)]
    Selection(#[from] SelectionError),
}

impl WalletDisplayNeeded {
    /// The error the wallet answers with: `access_denied` (RFC 6749 §4.1.2.1), as for a declined
    /// consent.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::ACCESS_DENIED
    }
}

impl SetFacts {
    /// The facts of a set of the display of a request carrying `transactions`, its static entries
    /// left out: they disclose nothing. `text_of` renders each row's texts as Credential Manager
    /// draws them.
    ///
    /// # Errors
    ///
    /// `text_of`'s first error.
    pub fn of<E>(
        set: &[Vec<Choice<'_>>],
        presentable: Presentable<'_>,
        transactions: TransactionData,
        text_of: &mut impl FnMut(&Text) -> Result<String, E>,
    ) -> Result<Self, E> {
        let entries = || {
            set.iter().flatten().filter_map(|choice| match choice {
                Choice::Entry(view) => Some(*view),
                Choice::Static(_) | Choice::Nothing => None,
            })
        };
        let mut whole = true;
        for row in entries().flat_map(|view| view.entry.rows()) {
            whole &= Field::of(row, text_of)?.is_ok_and(|field| field.extent() == Extent::Whole);
        }
        Ok(Self {
            presentable: entries().all(|view| presentable.0.contains(view.record.credential)),
            no_transaction_data: transactions == TransactionData::Absent,
            settled: set.iter().all(|slot| slot.len() == 1),
            whole,
        })
    }
}

impl WalletDisplay {
    /// A9: none of the wallet's when every entry's credential is presentable without its UI, the
    /// request carries no `transaction_data`, nothing is left to choose, every row shows whole,
    /// and Credential Manager showed everything.
    #[must_use]
    pub const fn of(facts: SetFacts, host: HostDisplay) -> Self {
        let SetFacts {
            presentable,
            no_transaction_data,
            settled,
            whole,
        } = facts;
        if presentable
            && no_transaction_data
            && settled
            && whole
            && matches!(host, HostDisplay::Full)
        {
            Self::NotNeeded
        } else {
            Self::Needed
        }
    }
}

impl Delegation {
    /// K4: `Full` for a set that needs no wallet display, none otherwise.
    #[must_use]
    pub const fn of(display: WalletDisplay) -> Self {
        match display {
            WalletDisplay::NotNeeded => Self::Full,
            WalletDisplay::Needed => Self::None,
        }
    }
}

impl Fulfilment {
    /// A9 in the wallet: a background fulfilment of a set of the display of a request carrying
    /// `transactions` that needs the wallet's display is refused; on the wallet's display every
    /// set stands. `text_of` renders each row's texts as Credential Manager drew them.
    ///
    /// # Errors
    ///
    /// `text_of`'s first error, outside; [`WalletDisplayNeeded`] inside: the set needs the wallet's
    /// display, or the display holds no such set.
    pub fn check<E>(
        self,
        display: &Display<'_>,
        set: usize,
        presentable: Presentable<'_>,
        transactions: TransactionData,
        text_of: &mut impl FnMut(&Text) -> Result<String, E>,
    ) -> Result<Result<(), WalletDisplayNeeded>, E> {
        let Self::Background(host) = self else {
            return Ok(Ok(()));
        };
        let sets = display.sets();
        let Some(slots) = sets.get(set) else {
            return Ok(Err(SelectionError::NoSet {
                set,
                sets: sets.len(),
            }
            .into()));
        };
        let facts = SetFacts::of(slots, presentable, transactions, text_of)?;
        Ok(match WalletDisplay::of(facts, host) {
            WalletDisplay::NotNeeded => Ok(()),
            WalletDisplay::Needed => Err(WalletDisplayNeeded::Needed { set }),
        })
    }
}
