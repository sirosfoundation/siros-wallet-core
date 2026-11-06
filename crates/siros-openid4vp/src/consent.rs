//! The consent entry as platform-neutral data, which the matcher's platform mapping and the
//! wallet UI lay out. A format plug-in draws a credential's [`Card`]; a transaction's profile
//! gives an [`Overlay`], whose [`TransactionHeader`] holds what the End-User confirms; the core's
//! display step pairs them in a [`ConsentEntry`]. An overlay's texts depend on the request, so
//! each is a [`RequestText`], which a registration's package holds the messages of.

use siros_explain::{RequestText, Text};

use crate::rows::{Icon, Row};

/// What a format plug-in draws for a credential and the items an option shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The card's icon.
    pub icon: Icon,
    /// The card's title.
    pub title: Text,
    /// The card's subtitle, such as its issuer.
    pub subtitle: Option<Text>,
    /// The rows of the items, those of every answerable option first.
    pub rows: Vec<Row>,
}

/// What a transaction's profile draws over the format's card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    /// The rows the entry shows before the card's rows.
    pub rows: Vec<Row<RequestText>>,
    /// The transaction's header, for a transaction whose counterparty and amount the End-User
    /// confirms (PSD2 RTS Art. 5(1)(a): the payee and the amount).
    pub header: Option<TransactionHeader>,
    /// The security hint: plain text, shown exactly.
    pub hint: Option<RequestText>,
}

/// A transaction's header: the counterparty, the amount, and the rows that show them, which the
/// entry leaves out of its rows. A profile fills it; a platform's mapping lays it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionHeader {
    /// The counterparty: a payee, a merchant.
    pub counterparty: RequestText,
    /// The amount.
    pub amount: RequestText,
    /// The rows the header shows.
    pub rows: Vec<Row<RequestText>>,
}

/// A consent entry: the card, and the overlay of the transaction when there is one. Only the
/// core's display step makes one, so a platform mapping reads entries it cannot write:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::consent::{Card, ConsentEntry};
///
/// fn forged(card: Card) -> ConsentEntry {
///     ConsentEntry { card, overlay: None }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEntry {
    card: Card,
    overlay: Option<Overlay>,
}

impl ConsentEntry {
    /// The entry of a card and its transaction's overlay.
    #[cfg(feature = "match")]
    pub(crate) const fn new(card: Card, overlay: Option<Overlay>) -> Self {
        Self { card, overlay }
    }

    /// The card, the entry's identity.
    #[must_use]
    pub const fn card(&self) -> &Card {
        &self.card
    }

    /// The transaction's overlay.
    #[must_use]
    pub const fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }

    /// The rows the entry shows: the overlay's, then the card's. A transaction header's rows
    /// stay out.
    pub fn rows(&self) -> impl Iterator<Item = Row> + '_ {
        self.overlay
            .iter()
            .flat_map(|overlay| overlay.rows.iter().cloned().map(Row::from))
            .chain(self.card.rows.iter().cloned())
    }
}

/// One title, one confirm action, one cancel action for the whole request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The title.
    pub title: Text,
    /// The confirm action.
    pub confirm: Text,
    /// The cancel action.
    pub cancel: Text,
}
