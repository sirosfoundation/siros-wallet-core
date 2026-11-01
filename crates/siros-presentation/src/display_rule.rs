//! The wallet's display (A9): whether the user must consent to an offer on the wallet's UI.

use siros_display::{Extent, Field};

use crate::offers::Offer;
use crate::transactions::Transactions;

/// Whether an offer needs the wallet's display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletDisplay {
    /// The user can consent on the picker's display alone, and the wallet presents without its
    /// UI.
    NotNeeded,
    /// The user consents on the wallet's display.
    Needed,
}

/// Whether the wallet presents a credential from its background service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presentability {
    /// Every member credential is registered as presentable without the wallet's UI: its key
    /// signs without user interaction and the wallet's background service answers.
    WithoutUi,
    /// A member credential is presentable on the wallet's UI only.
    OnWalletUi,
}

/// Whether the request carries `transaction_data`, which its type renders in the wallet (T5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionData {
    /// No `transaction_data`.
    Absent,
    /// `transaction_data` entries.
    Carried,
}

/// Whether the user still chooses something in an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Choice {
    /// Nothing is left to choose.
    Settled,
    /// The user chooses: optional additions, or a subset of the candidates of a `multiple`
    /// query.
    Open,
}

/// Whether every disclosed claim and every proof statement of an offer shows as a row, whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rows {
    /// Each shows as a row that holds its text whole.
    Whole,
    /// A row is clipped, or a claim or a statement shows in no row.
    Clipped,
}

/// Whether the host shows everything the entries of an offer carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostDisplay {
    /// The host shows every text of the offer's entries; the wallet's own display shows all.
    Full,
    /// The host's level leaves text of an entry out (`display_skipped`).
    Skipped,
}

/// What A9 judges an offer by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplayFacts {
    /// Whether the wallet presents the member credentials from its background service.
    pub presentability: Presentability,
    /// Whether the request carries `transaction_data`.
    pub transaction_data: TransactionData,
    /// Whether the offer has optional additions to choose.
    pub additions: Choice,
    /// Whether a member answers a `multiple` query with more than one candidate, a subset of
    /// which the user chooses.
    pub subsets: Choice,
    /// Whether every disclosed claim and every proof statement shows as a row, whole.
    pub rows: Rows,
    /// Whether the host shows everything the offer's entries carry.
    pub host: HostDisplay,
}

impl WalletDisplay {
    /// The display an offer of `facts` needs: none of the wallet's when every member is
    /// presentable without the UI, the request carries no `transaction_data`, nothing is left
    /// to choose, every row shows whole and the host shows everything.
    pub fn of(facts: &DisplayFacts) -> Self {
        let settled = DisplayFacts {
            presentability: Presentability::WithoutUi,
            transaction_data: TransactionData::Absent,
            additions: Choice::Settled,
            subsets: Choice::Settled,
            rows: Rows::Whole,
            host: HostDisplay::Full,
        };
        if *facts == settled {
            Self::NotNeeded
        } else {
            Self::Needed
        }
    }
}

impl Rows {
    /// Whether `fields`, the picker's fields of every disclosed claim and proof statement of an
    /// offer, each show whole.
    pub fn of<'f>(fields: impl IntoIterator<Item = &'f Field>) -> Self {
        if fields
            .into_iter()
            .all(|field| field.extent() == Extent::Whole)
        {
            Self::Whole
        } else {
            Self::Clipped
        }
    }
}

impl HostDisplay {
    /// What the host shows of an offer whose entries it showed as `entries`: skipped when it
    /// skipped text of one of them.
    pub fn of(entries: impl IntoIterator<Item = HostDisplay>) -> Self {
        if entries.into_iter().all(|entry| entry == Self::Full) {
            Self::Full
        } else {
            Self::Skipped
        }
    }
}

impl TransactionData {
    /// Whether the request of `transactions` carries `transaction_data`.
    pub fn of<D>(transactions: &Transactions<D>) -> Self {
        if transactions.carried() {
            Self::Carried
        } else {
            Self::Absent
        }
    }
}

impl Choice {
    /// Whether `offer` has optional additions to choose.
    pub fn of_additions(offer: &Offer) -> Self {
        if offer.additions().is_empty() {
            Self::Settled
        } else {
            Self::Open
        }
    }

    /// Whether a member of `offer` answers a `multiple` query with more than one candidate.
    pub fn of_subsets(offer: &Offer) -> Self {
        if offer.members().iter().any(|m| m.candidates().len() > 1) {
            Self::Open
        } else {
            Self::Settled
        }
    }
}
