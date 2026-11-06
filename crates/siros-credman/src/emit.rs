//! The matcher's entry emission (section 4.14 of the design, "DC API precomputation"): each choice
//! of a display as Credential Manager draws it, every text plain, a card's texts read from the
//! registration's package as held and the request's rendered from its compiled messages. Every
//! entry renders before the first is added; an entry whose texts do not render ends the emission
//! or stays out of its slot, as the app's `RenderOptions::on_error` states.

use siros_explain::{DefinedModule, Explain, IntoArg, Text, kind};
use siros_i18n::{RenderError, Renderer};
use siros_openid4vp::consent::Card;
use siros_openid4vp::matching::{Choice, Display};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::rendering::{Rendering, Unrendered};
use siros_openid4vp::rows::{Env, OnRenderError, RenderingInputs, Row, Selected, Value};

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

impl IntoArg for EntryId {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}

/// An entry that did not render.
#[derive(Debug)]
pub struct RefusedEntry {
    /// The entry.
    pub id: EntryId,
    /// Why it did not render.
    pub reason: NotEmitted,
}

/// One choice of a slot as the matcher adds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emitted {
    /// An entry, with the id the platform returns when the End-User picks it.
    Entry {
        /// The id.
        id: EntryId,
        /// What Credential Manager draws.
        shown: Shown,
    },
    /// The empty choice, "none".
    Nothing,
}

/// The display's sets as the matcher adds them: per set, per slot, its choices, and each entry
/// that did not render with its reason. Under [`OnRenderError::NoEntry`] an entry that does not
/// render leaves no set; under [`OnRenderError::Rendered`] it stays out of its slot.
#[derive(Debug, Default)]
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

    /// Each entry that did not render.
    #[must_use]
    pub fn refused(&self) -> &[RefusedEntry] {
        &self.refused
    }
}

/// Why an entry does not render.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "credman.emission")]
pub enum NotEmitted {
    /// A text does not render.
    #[error(transparent)]
    Render(#[from] RenderError),
    /// A row's label is white space alone.
    #[error(transparent)]
    Field(#[from] NoName),
    /// No language serves the entry's modules.
    #[error(transparent)]
    Unrendered(#[from] Unrendered),
}

/// Why the matcher emits nothing: the core's screen faults, an entry's renderer takes other
/// inputs than its record commits to, or the registration's package does not hold a card's text
/// precomputed.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "credman.emit")]
pub enum EmitError {
    /// The core's screen faults.
    #[error(transparent)]
    Fault(#[from] Fault),
    /// An entry's renderer takes other inputs than its record commits to.
    #[error("the renderer of the entry {0} takes other inputs than its record")]
    Inputs(#[explain(name = "entry")] EntryId),
    /// A text of an entry's card, which no request changes, is not held precomputed in the
    /// language its screen shows: the registration's package was built for other cards.
    #[error("a card text of the entry {0} is not held in its language")]
    NotHeld(#[explain(name = "entry")] EntryId),
}

/// The texts of a card no request changes: its title and subtitle, and each row's label, value
/// and section. The registration's package holds them precomputed, and the matcher reads them as
/// held.
pub fn held(card: &Card) -> impl Iterator<Item = &Text> {
    std::iter::once(&card.title)
        .chain(&card.subtitle)
        .chain(card.rows.iter().flat_map(|row| {
            std::iter::once(&row.label)
                .chain(row.value.as_ref().and_then(Value::text))
                .chain(&row.section)
        }))
}

/// The display's choices, each entry's texts rendered as Credential Manager draws them: plain
/// text through `rendering`, the registration's package, in the language its record commits to,
/// with `env`'s options, which are the registration's. Every entry renders before the emission
/// returns.
///
/// # Errors
///
/// [`EmitError`]: the core's screen faults, an entry's renderer takes other inputs than its
/// record commits to, or a card's text is not held.
pub fn emit(
    display: &Display<'_>,
    rendering: &Rendering<'_>,
    env: &Env,
) -> Result<Emission, EmitError> {
    let mut sets = Vec::with_capacity(display.sets().len());
    let mut refused = Vec::new();
    for set in display.sets() {
        let mut slots = Vec::with_capacity(set.len());
        for slot in set {
            let mut choices = Vec::with_capacity(slot.len());
            for choice in slot {
                let id = EntryId::of(choice);
                let shown = match choice {
                    Choice::Nothing => {
                        choices.push(Emitted::Nothing);
                        continue;
                    }
                    Choice::Static(entry) => {
                        let screen = Screen {
                            selected: None,
                            card_module: None,
                            credential: None,
                            card: &entry.card,
                            committed: None,
                        };
                        screen.drawn(&CredmanEntry::of_static(entry), &id, rendering, env)?
                    }
                    Choice::Entry(view) => {
                        let screen = Screen {
                            selected: view.selected,
                            card_module: view.card_module,
                            credential: Some(view.record.credential().as_str()),
                            card: view.entry.card(),
                            committed: Some(view.record.inputs()),
                        };
                        let entry = CredmanEntry::of(&view.entry);
                        screen.drawn(&entry, &id, rendering, env)?
                    }
                };
                match shown {
                    Ok(shown) => choices.push(Emitted::Entry { id, shown }),
                    Err(reason) => refused.push(RefusedEntry { id, reason }),
                }
            }
            slots.push(choices);
        }
        sets.push(slots);
    }
    if !refused.is_empty() && env.options().on_error == OnRenderError::NoEntry {
        sets.clear();
    }
    Ok(Emission { sets, refused })
}

/// What an entry's renderer is made for: the module its profile selected, its credential, its
/// card, and the inputs its record commits to.
struct Screen<'s> {
    selected: Option<&'s Selected>,
    card_module: Option<DefinedModule>,
    credential: Option<&'s str>,
    card: &'s Card,
    committed: Option<&'s RenderingInputs>,
}

impl Screen<'_> {
    /// The entry's texts rendered on its screen, once its renderer takes the inputs its record
    /// commits to and holds every card text: the module its profile selected in its locale, the
    /// others in the language the registration's lists choose.
    fn drawn(
        &self,
        entry: &CredmanEntry,
        id: &EntryId,
        rendering: &Rendering<'_>,
        env: &Env,
    ) -> Result<Result<Shown, NotEmitted>, EmitError> {
        let renderer =
            match rendering.renderer(self.selected, self.card_module, self.credential, env)? {
                Ok(renderer) => renderer,
                Err(unrendered) => return Ok(Err(unrendered.into())),
            };
        if self
            .committed
            .is_some_and(|committed| renderer.inputs() != *committed)
        {
            return Err(EmitError::Inputs(id.clone()));
        }
        for text in held(self.card) {
            match renderer.holds(text) {
                Ok(true) => {}
                Ok(false) => return Err(EmitError::NotHeld(id.clone())),
                Err(refused) => return Ok(Err(refused.into())),
            }
        }
        Ok(shown(entry, &renderer))
    }
}

/// An entry's texts as plain text.
fn shown(entry: &CredmanEntry, renderer: &Renderer<'_>) -> Result<Shown, NotEmitted> {
    let plain = |text: &Text| renderer.plain(text);
    let optional = |text: &Option<Text>| text.as_ref().map(plain).transpose();
    let fields = |rows: &[Row]| -> Result<Vec<Field>, NotEmitted> {
        let mut plain = |text: &Text| renderer.plain(text);
        rows.iter()
            .map(|row| Ok(Field::of(row, &mut plain)??))
            .collect()
    };
    Ok(match entry {
        CredmanEntry::Standard(StandardEntry {
            icon,
            title,
            subtitle,
            warning,
            rows,
        }) => Shown::Standard(Box::new(StandardShown {
            icon: icon.clone(),
            title: plain(title)?,
            subtitle: optional(subtitle)?,
            warning: optional(warning)?,
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
            merchant: plain(merchant)?,
            amount: plain(amount)?,
            method_name: plain(method_name)?,
            method_subtitle: optional(method_subtitle)?,
            method_icon: method_icon.clone(),
            additional_info: optional(additional_info)?,
            fields: fields(rows)?,
        })),
    })
}
