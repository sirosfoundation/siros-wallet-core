//! The matcher's entry emission (section 4.14 of the design, "DC API precomputation"): each choice
//! of a display as Credential Manager draws it, every text plain, read from the registration's
//! package as held or rendered from its compiled messages. Every entry renders before the first
//! is added; an entry whose texts do not render ends the emission or stays out of its slot, as
//! the app's `RenderOptions::on_error` states.

use siros_explain::{Explain, Text};
use siros_i18n::{RenderError, Renderer};
use siros_openid4vp::matching::{Choice, Display};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::rendering::{Rendering, Unrendered};
use siros_openid4vp::rows::{Env, OnRenderError, Row, Selected};

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

/// One choice of a slot as the matcher adds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emitted {
    /// An entry, with the id the platform returns when the End-User picks it.
    Entry {
        /// The id.
        id: String,
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
    refused: Vec<(String, NotEmitted)>,
}

impl Emission {
    /// The sets.
    #[must_use]
    pub fn sets(&self) -> &[Vec<Vec<Emitted>>] {
        &self.sets
    }

    /// Each entry that did not render, by its id, with its reason.
    #[must_use]
    pub fn refused(&self) -> &[(String, NotEmitted)] {
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

/// Why the matcher emits nothing: the core's screen faults, or an entry's renderer takes other
/// inputs than its record commits to.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "credman.emit")]
pub enum EmitError {
    /// The core's screen faults.
    #[error(transparent)]
    Fault(#[from] Fault),
    /// An entry's renderer takes other inputs than its record commits to.
    #[error("the renderer of the entry {0} takes other inputs than its record")]
    Inputs(#[explain(name = "entry")] String),
}

/// The display's choices, each entry's texts rendered as Credential Manager draws them: plain
/// text through `rendering` in the language its record commits to, with `env`'s options. Every
/// entry renders before the emission returns.
///
/// # Errors
///
/// [`EmitError`]: the core's screen faults, or an entry's renderer takes other inputs than its
/// record commits to.
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
                let shown = match choice {
                    Choice::Nothing => {
                        choices.push(Emitted::Nothing);
                        continue;
                    }
                    Choice::Static(entry) => {
                        drawn(&CredmanEntry::of_static(entry), None, rendering, env)?
                    }
                    Choice::Entry(view) => {
                        let shown = drawn(
                            &CredmanEntry::of(&view.entry),
                            view.selected,
                            rendering,
                            env,
                        )?;
                        match shown {
                            Ok((shown, inputs)) if inputs != *view.record.inputs => {
                                drop(shown);
                                return Err(EmitError::Inputs(
                                    view.record.id().as_str().to_owned(),
                                ));
                            }
                            other => other,
                        }
                    }
                };
                match shown {
                    Ok((shown, _)) => choices.push(Emitted::Entry {
                        id: choice.id().to_owned(),
                        shown,
                    }),
                    Err(reason) => refused.push((choice.id().to_owned(), reason)),
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

/// An entry drawn through the renderer of its screen, with the inputs the renderer took.
type Drawn = Result<(Shown, siros_openid4vp::rows::RenderingInputs), NotEmitted>;

/// An entry's texts rendered on its screen: the module its profile selected in its locale, the
/// others in the language `env`'s lists choose.
fn drawn(
    entry: &CredmanEntry,
    selected: Option<&Selected>,
    rendering: &Rendering<'_>,
    env: &Env,
) -> Result<Drawn, EmitError> {
    let renderer = match rendering.renderer(selected, env)? {
        Ok(renderer) => renderer,
        Err(unrendered) => return Ok(Err(unrendered.into())),
    };
    Ok(shown(entry, &renderer).map(|shown| (shown, renderer.inputs())))
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
