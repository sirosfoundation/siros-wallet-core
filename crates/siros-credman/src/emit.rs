//! The matcher's entry emission: each choice of a display as Credential Manager draws it, every
//! text plain. The display's texts are those the matcher's context resolved, the wallet's code
//! path; the context resolves the empty choice's title. Every entry is laid out before the first
//! is added, and a choice that does not emit fails the emission: its cause is a defect of the
//! wallet's wording or of a converter.

use siros_explain::Explain;
use siros_i18n::{Context, ResolveError, Text};
use siros_openid4vp::matching::{Choice, Display};
use siros_openid4vp::rows::{Icon, Row, WalletText};

use crate::entry::{CredmanEntry, EntryIcon, PaymentEntry, StandardEntry};
use crate::field::{Field, NoName};

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

/// The display's sets as the matcher adds them: per set, per slot, its choices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emission {
    sets: Vec<Vec<Vec<Emitted>>>,
}

impl Emission {
    /// The sets.
    #[must_use]
    pub fn sets(&self) -> &[Vec<Vec<Emitted>>] {
        &self.sets
    }
}

/// A choice of the display that does not emit, which fails the emission.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[error("the entry {entry} does not emit")]
#[explain(id = "emission.entry")]
pub struct NotEmitted {
    /// The choice.
    pub entry: EntryId,
    /// Why it does not emit.
    #[source]
    pub cause: Unshown,
}

/// Why a choice does not emit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Unshown {
    /// The context resolves no title for the empty choice.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// A row's label holds no visible character.
    #[error(transparent)]
    Field(#[from] NoName),
}

/// The display's choices as Credential Manager draws them, each text plain. `context` is the
/// matcher's, which resolved the display's texts; it resolves the empty choice's title.
///
/// # Errors
///
/// [`NotEmitted`] for the first choice, in the display's order, that does not emit.
pub fn emit(display: &Display<'_>, context: &Context) -> Result<Emission, NotEmitted> {
    let mut sets = Vec::with_capacity(display.sets().len());
    for set in display.sets() {
        let mut slots = Vec::with_capacity(set.len());
        for slot in set {
            slots.push(
                slot.iter()
                    .map(|choice| {
                        emitted(choice, context).map_err(|cause| NotEmitted {
                            entry: EntryId::of(choice),
                            cause,
                        })
                    })
                    .collect::<Result<Vec<Emitted>, NotEmitted>>()?,
            );
        }
        sets.push(slots);
    }
    Ok(Emission { sets })
}

/// The choice as the matcher adds it.
///
/// # Errors
///
/// [`Unshown`]: `context` resolves no title for the empty choice, or a row's label is white
/// space alone.
fn emitted(choice: &Choice<'_>, context: &Context) -> Result<Emitted, Unshown> {
    let id = EntryId::of(choice);
    let entry = match choice {
        Choice::Nothing => {
            return Ok(Emitted::Nothing {
                id,
                icon: EntryIcon::of(&Icon::NONE),
                title: context.resolve(&WalletText::None)?.to_string(),
            });
        }
        Choice::Static(entry) => CredmanEntry::of_static(entry),
        Choice::Entry(view) => CredmanEntry::of(&view.entry),
    };
    Ok(Emitted::Entry {
        id,
        shown: shown(&entry)?,
    })
}

/// An entry's texts as plain text.
fn shown(entry: &CredmanEntry) -> Result<Shown, NoName> {
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
