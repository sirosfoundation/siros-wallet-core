//! Credential Manager's Standard and Payment entries, laid out from the core's consent entry.

use siros_openid4vp::consent::{Card, ConsentEntry};
use siros_openid4vp::matching::StaticEntry;
use siros_openid4vp::rows::{Icon, ImageMedia, Row};

/// An icon of a media type Credential Manager draws. Only [`EntryIcon::of`] makes one:
///
/// ```compile_fail,E0423
/// use siros_credman::EntryIcon;
/// use siros_openid4vp::rows::Icon;
///
/// fn forged(icon: Icon) -> EntryIcon {
///     EntryIcon(icon)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryIcon(Icon);

impl EntryIcon {
    /// The media types the matcher hands Credential Manager, which decodes an entry's icon from
    /// its bytes: PNG, which shows on a device (android-credman-sys ABI.md §5), and JPEG.
    pub const DRAWN: [ImageMedia; 2] = [ImageMedia::PNG, ImageMedia::JPEG];

    /// The card's icon when its media type is one of [`Self::DRAWN`]; the wallet's card icon
    /// otherwise, as for a card without a logo, since Credential Manager drops an entry without
    /// an icon (ABI.md §5).
    #[must_use]
    pub fn of(icon: &Icon) -> Self {
        if Self::DRAWN.contains(&icon.media) {
            Self(icon.clone())
        } else {
            Self(Icon::DEFAULT)
        }
    }

    /// The icon.
    #[must_use]
    pub const fn icon(&self) -> &Icon {
        &self.0
    }
}

/// A Standard entry (`AddEntryToSet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardEntry {
    /// The icon: the card's.
    pub icon: EntryIcon,
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
    pub method_icon: EntryIcon,
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
        let icon = EntryIcon::of(&icon);
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
            icon: EntryIcon::of(&icon),
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
    pub const fn icon(&self) -> &EntryIcon {
        match self {
            Self::Standard(entry) => &entry.icon,
            Self::Payment(entry) => &entry.method_icon,
        }
    }
}
