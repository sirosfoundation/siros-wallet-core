//! Credential Manager's Standard and Payment entries, laid out from the core's consent entry.

use siros_openid4vp::consent::{Card, ConsentEntry};
use siros_openid4vp::matching::StaticEntry;
use siros_openid4vp::rows::{Icon, Row};

/// A Standard entry (`AddEntryToSet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardEntry {
    /// The icon.
    pub icon: Icon,
    /// The title.
    pub title: String,
    /// The subtitle.
    pub subtitle: Option<String>,
    /// The warning: the overlay's hint.
    pub warning: Option<String>,
    /// The fields.
    pub rows: Vec<Row>,
}

/// A Payment entry (`AddPaymentEntryToSetV2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentEntry {
    /// The merchant: the header's counterparty.
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

/// The entry Credential Manager draws for a consent entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredmanEntry {
    /// A Standard entry.
    Standard(StandardEntry),
    /// A Payment entry: an entry whose overlay holds a transaction header.
    Payment(PaymentEntry),
}

impl CredmanEntry {
    /// The card alone, or with the overlay's rows before the card's, its hint, and with a
    /// transaction header a Payment entry, whose rows leave out the header's. The card stays the
    /// entry's identity.
    #[must_use]
    pub fn of(entry: &ConsentEntry) -> Self {
        let Card {
            icon,
            title,
            subtitle,
            ..
        } = entry.card().clone();
        let rows = entry.rows().cloned().collect();
        let Some(overlay) = entry.overlay() else {
            return Self::Standard(StandardEntry {
                icon,
                title,
                subtitle,
                warning: None,
                rows,
            });
        };
        match &overlay.header {
            None => Self::Standard(StandardEntry {
                icon,
                title,
                subtitle,
                warning: overlay.hint.clone(),
                rows,
            }),
            Some(header) => Self::Payment(PaymentEntry {
                merchant: header.counterparty.clone(),
                amount: header.amount.clone(),
                method_name: title,
                method_subtitle: subtitle,
                method_icon: icon,
                additional_info: overlay.hint.clone(),
                rows,
            }),
        }
    }

    /// A static entry's Standard entry: its card, no warning.
    #[must_use]
    pub fn of_static(entry: &StaticEntry) -> Self {
        let Card {
            icon,
            title,
            subtitle,
            rows,
        } = entry.card.clone();
        Self::Standard(StandardEntry {
            icon,
            title,
            subtitle,
            warning: None,
            rows,
        })
    }

    /// The entry's rows, its fields.
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
