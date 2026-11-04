//! Boxes in Credential Manager's vocabulary (Standard and Payment entries), which the DC API
//! and the wallet UI both draw. A format plug-in draws a credential's [`Card`]; a transaction's
//! profile gives an [`Overlay`]; the core composes the entry's [`EntryBox`] from both.

use crate::rows::{Icon, Label, Row};

/// What a format plug-in draws for a credential and the items an option shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The card's icon.
    pub icon: Icon,
    /// The card's title.
    pub title: String,
    /// The card's subtitle, such as its issuer.
    pub subtitle: Option<String>,
    /// The rows of the items, those of every answerable option first.
    pub rows: Vec<Row>,
}

/// What a transaction's profile draws over the format's card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    /// The rows the box shows before the card's rows.
    pub rows: Vec<Row>,
    /// For a payment presentation, its header.
    pub payment: Option<PaymentHeader>,
    /// The security hint: plain text, shown exactly.
    pub hint: Option<String>,
}

/// The header of a payment presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentHeader {
    /// The merchant.
    pub merchant: String,
    /// The amount, formatted.
    pub amount: String,
    /// The rows the header shows; the box leaves them out of its rows.
    pub rows: Vec<Row>,
}

/// A Standard entry (`AddEntryToSet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardBox {
    /// The icon.
    pub icon: Icon,
    /// The title.
    pub title: String,
    /// The subtitle.
    pub subtitle: Option<String>,
    /// The warning.
    pub warning: Option<String>,
    /// The fields.
    pub rows: Vec<Row>,
}

/// A Payment entry (`AddPaymentEntryToSetV2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentBox {
    /// The merchant.
    pub merchant: String,
    /// The amount.
    pub amount: String,
    /// The payment method's name: the card's title.
    pub method_name: String,
    /// The payment method's subtitle: the card's subtitle.
    pub method_subtitle: Option<String>,
    /// The payment method's icon: the card's icon.
    pub method_icon: Icon,
    /// The free text: the security hint.
    pub additional_info: Option<String>,
    /// The fields.
    pub rows: Vec<Row>,
}

/// The box of a consent entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryBox {
    /// A Standard entry.
    Standard(StandardBox),
    /// A Payment entry.
    Payment(PaymentBox),
}

impl EntryBox {
    /// The entry's box: the card alone, or with the overlay's rows before the card's, its hint,
    /// and for a payment its header. The card stays the box's identity.
    #[must_use]
    pub fn compose(card: Card, overlay: Option<&Overlay>) -> Self {
        let Card {
            icon,
            title,
            subtitle,
            rows,
        } = card;
        let Some(overlay) = overlay else {
            return Self::Standard(StandardBox {
                icon,
                title,
                subtitle,
                warning: None,
                rows,
            });
        };
        let rows = overlay.rows.iter().cloned().chain(rows).collect();
        match &overlay.payment {
            None => Self::Standard(StandardBox {
                icon,
                title,
                subtitle,
                warning: overlay.hint.clone(),
                rows,
            }),
            Some(header) => Self::Payment(PaymentBox {
                merchant: header.merchant.clone(),
                amount: header.amount.clone(),
                method_name: title,
                method_subtitle: subtitle,
                method_icon: icon,
                additional_info: overlay.hint.clone(),
                rows,
            }),
        }
    }

    /// The box's rows.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        match self {
            Self::Standard(entry) => &entry.rows,
            Self::Payment(entry) => &entry.rows,
        }
    }

    /// The card's icon on the entry.
    #[must_use]
    pub fn icon(&self) -> &Icon {
        match self {
            Self::Standard(entry) => &entry.icon,
            Self::Payment(entry) => &entry.method_icon,
        }
    }
}

/// One title, one confirm action, one cancel action for the whole request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The title.
    pub title: Label,
    /// The confirm action.
    pub confirm: Label,
    /// The cancel action.
    pub cancel: Label,
}
