//! The matcher's entry emission: each choice of a display as Credential Manager draws it, every
//! text plain. The display's texts are those the matcher's context resolved, the wallet's code
//! path; the context resolves the empty choice's title. Every entry is laid out before the first
//! is added; an entry that does not show ends the emission or stays out of its slot, as the app's
//! [`OnRenderError`] states.

use siros_explain::Explain;
use siros_i18n::{Context, ResolveError, Text};
use siros_openid4vp::matching::{Choice, Display};
use siros_openid4vp::rows::{Icon, Row, WalletText};

use crate::entry::{CredmanEntry, EntryIcon, PaymentEntry, StandardEntry};
use crate::field::{Field, NoName};
use crate::registration::OnRenderError;

/// A Standard entry as Credential Manager draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardShown {
    /// The icon.
    pub icon: EntryIcon,
    /// The title.
    pub title: String,
    /// The subtitle.
    pub subtitle: Option<String>,
    /// The warning.
    pub warning: Option<String>,
    /// The fields.
    pub fields: Vec<Field>,
}

/// A Payment entry as Credential Manager draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentShown {
    /// The merchant.
    pub merchant: String,
    /// The amount.
    pub amount: String,
    /// The payment method's name.
    pub method_name: String,
    /// The payment method's subtitle.
    pub method_subtitle: Option<String>,
    /// The payment method's icon.
    pub method_icon: EntryIcon,
    /// The free text.
    pub additional_info: Option<String>,
    /// The fields.
    pub fields: Vec<Field>,
}

/// An entry as Credential Manager draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// A Standard entry.
    Standard(Box<StandardShown>),
    /// A Payment entry.
    Payment(Box<PaymentShown>),
}

/// The id of a choice of the display, which the platform returns when the End-User picks it.
/// Only [`emit`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryId(String);

impl EntryId {
    fn of(choice: &Choice<'_>) -> Self {
        Self(choice.id().as_str().to_owned())
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An entry that does not show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedEntry {
    /// The entry.
    pub id: EntryId,
    /// Why it does not show.
    pub reason: NotEmitted,
}

/// One choice of a slot as the matcher adds it, with the id the platform returns when the
/// End-User picks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emitted {
    /// An entry.
    Entry {
        /// The id.
        id: EntryId,
        /// What Credential Manager draws.
        shown: Shown,
    },
    /// The empty choice, "none": the wallet's icon for it, and its title, the context's
    /// [`WalletText::None`].
    Nothing {
        /// The id.
        id: EntryId,
        /// The icon, [`Icon::NONE`].
        icon: EntryIcon,
        /// The title.
        title: String,
    },
}

/// The display's sets as the matcher adds them: per set, per slot, its choices, and each entry
/// that does not show with its reason. Under [`OnRenderError::NoEntry`] an entry that does not
/// show leaves no set; under [`OnRenderError::Rendered`] it stays out of its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emission {
    sets: Vec<Vec<Vec<Emitted>>>,
    refused: Vec<RefusedEntry>,
}

impl Emission {
    /// The sets.
    #[must_use]
    pub fn sets(&self) -> &[Vec<Vec<Emitted>>] {
        &self.sets
    }

    /// Each entry that does not show.
    #[must_use]
    pub fn refused(&self) -> &[RefusedEntry] {
        &self.refused
    }
}

/// Why an entry does not show.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum NotEmitted {
    /// The context resolves no text for the entry.
    #[error("the matcher's context resolves no text for the entry")]
    #[explain(id = "emission.resolve")]
    Resolve {
        /// The refusal.
        #[source]
        cause: ResolveError,
    },
    /// A row's label is white space alone.
    #[error(transparent)]
    Field(#[from] NoName),
}

/// The display's choices as Credential Manager draws them, each text plain. `context` is the
/// matcher's, which resolved the display's texts; it resolves the empty choice's title.
/// `on_error` is the registration's.
#[must_use]
pub fn emit(display: &Display<'_>, context: &Context, on_error: OnRenderError) -> Emission {
    let mut none: Option<Result<Text, ResolveError>> = None;
    let mut sets = Vec::with_capacity(display.sets().len());
    let mut refused = Vec::new();
    for set in display.sets() {
        let mut slots = Vec::with_capacity(set.len());
        for slot in set {
            let mut choices = Vec::with_capacity(slot.len());
            for choice in slot {
                let id = EntryId::of(choice);
                match emitted(choice, &id, context, &mut none) {
                    Ok(emitted) => choices.push(emitted),
                    Err(reason) => refused.push(RefusedEntry { id, reason }),
                }
            }
            slots.push(choices);
        }
        sets.push(slots);
    }
    if !refused.is_empty() && on_error == OnRenderError::NoEntry {
        sets.clear();
    }
    Emission { sets, refused }
}

/// The choice `id` names as the matcher adds it. `none` holds the empty choice's title once
/// `context` resolved it.
fn emitted(
    choice: &Choice<'_>,
    id: &EntryId,
    context: &Context,
    none: &mut Option<Result<Text, ResolveError>>,
) -> Result<Emitted, NotEmitted> {
    let entry = match choice {
        Choice::Nothing => {
            let title = none
                .get_or_insert_with(|| context.resolve(&WalletText::None))
                .clone()
                .map_err(|cause| NotEmitted::Resolve { cause })?;
            return Ok(Emitted::Nothing {
                id: id.clone(),
                icon: EntryIcon::of(&Icon::NONE),
                title: title.to_string(),
            });
        }
        Choice::Static(entry) => CredmanEntry::of_static(entry),
        Choice::Entry(view) => CredmanEntry::of(&view.entry),
    };
    Ok(Emitted::Entry {
        id: id.clone(),
        shown: shown(&entry)?,
    })
}

/// An entry's texts as plain text.
fn shown(entry: &CredmanEntry) -> Result<Shown, NotEmitted> {
    let plain = |text: &Text| text.to_string();
    let optional = |text: &Option<Text>| text.as_ref().map(plain);
    let fields =
        |rows: &[Row]| -> Result<Vec<Field>, NoName> { rows.iter().map(Field::of).collect() };
    Ok(match entry {
        CredmanEntry::Standard(StandardEntry {
            icon,
            title,
            subtitle,
            warning,
            rows,
        }) => Shown::Standard(Box::new(StandardShown {
            icon: icon.clone(),
            title: plain(title),
            subtitle: optional(subtitle),
            warning: optional(warning),
            fields: fields(rows)?,
        })),
        CredmanEntry::Payment(PaymentEntry {
            merchant,
            amount,
            method_name,
            method_subtitle,
            method_icon,
            additional_info,
            rows,
        }) => Shown::Payment(Box::new(PaymentShown {
            merchant: plain(merchant),
            amount: plain(amount),
            method_name: plain(method_name),
            method_subtitle: optional(method_subtitle),
            method_icon: method_icon.clone(),
            additional_info: optional(additional_info),
            fields: fields(rows)?,
        })),
    })
}
