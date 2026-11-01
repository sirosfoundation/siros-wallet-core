//! The character and length rules of labels, by role and by the rules their source follows
//! (PaSO Proof Metadata, Section 3.3; EC TS12 v1.0.1, Section 3.3.3), and the directional rule
//! of descriptions and of a payload's strings.

use std::fmt;
use std::marker::PhantomData;

/// What a label or a payload string breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum TextFault {
    /// A label holds this C0 control, DEL or C1 control character.
    Control(char),
    /// The text holds this directional embedding or override character, U+202A to U+202E.
    DirectionalOverride(char),
    /// A directional isolate, U+2066 to U+2068, has no U+2069 that terminates it.
    IsolateUnterminated,
    /// The label is this long, in the unit of its limit, more than its role allows.
    TooLong(usize),
    /// The label, interpolated when a template, is white space alone: a host refuses a blank
    /// field name.
    Blank,
}

impl TextFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Control(_) => "label_control_character",
            Self::DirectionalOverride(_) => "text_directional_override",
            Self::IsolateUnterminated => "text_isolate_unterminated",
            Self::TooLong(_) => "label_too_long",
            Self::Blank => "label_blank",
        }
    }
}

/// The rules a definition's labels follow, which its source sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelRules {
    /// PaSO Proof Metadata, Section 3.3: limits in extended grapheme clusters for every role.
    /// Signed and ad-hoc metadata JWTs and the host's configuration follow them.
    Paso,
    /// EC TS12 v1.0.1, Section 3.3.3: limits in characters for the UI elements it names, and
    /// none for claim names or other elements. TS12 type metadata follows them.
    Ts12,
}

/// The most length of a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    /// At most this many extended grapheme clusters (UAX #29).
    Graphemes(usize),
    /// At most this many Unicode scalar values.
    Characters(usize),
}

impl Limit {
    /// Checks that `text` is within the limit.
    ///
    /// # Errors
    ///
    /// [`TextFault::TooLong`], with the length in the limit's unit.
    fn check(self, text: &str) -> Result<(), TextFault> {
        let (length, max) = match self {
            Self::Graphemes(max) => (super::grapheme_clusters(text), max),
            Self::Characters(max) => (text.chars().count(), max),
        };
        if length > max {
            Err(TextFault::TooLong(length))
        } else {
            Ok(())
        }
    }
}

/// The role of a label, which sets its limit under each set of rules.
pub trait LabelRole {
    /// The limit under `rules`; `None` for a label of any length.
    fn limit(rules: LabelRules) -> Option<Limit>;
}

/// The `name` of a claim `display` entry: 60 under PaSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimName {}

/// `transaction_title`: 100 under PaSO, 50 characters under TS12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionTitle {}

/// `affirmative_action_label` and `denial_action_label`: 40 under PaSO, 30 characters under
/// TS12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionLabel {}

/// `security_hint`: plain text, 160 under PaSO, 250 characters under TS12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityHint {}

/// A UI element another specification or a rulebook defines: 100 under PaSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtherUiElement {}

impl LabelRole for ClaimName {
    fn limit(rules: LabelRules) -> Option<Limit> {
        match rules {
            LabelRules::Paso => Some(Limit::Graphemes(60)),
            LabelRules::Ts12 => None,
        }
    }
}

impl LabelRole for TransactionTitle {
    fn limit(rules: LabelRules) -> Option<Limit> {
        Some(match rules {
            LabelRules::Paso => Limit::Graphemes(100),
            LabelRules::Ts12 => Limit::Characters(50),
        })
    }
}

impl LabelRole for ActionLabel {
    fn limit(rules: LabelRules) -> Option<Limit> {
        Some(match rules {
            LabelRules::Paso => Limit::Graphemes(40),
            LabelRules::Ts12 => Limit::Characters(30),
        })
    }
}

impl LabelRole for SecurityHint {
    fn limit(rules: LabelRules) -> Option<Limit> {
        Some(match rules {
            LabelRules::Paso => Limit::Graphemes(160),
            LabelRules::Ts12 => Limit::Characters(250),
        })
    }
}

impl LabelRole for OtherUiElement {
    fn limit(rules: LabelRules) -> Option<Limit> {
        match rules {
            LabelRules::Paso => Some(Limit::Graphemes(100)),
            LabelRules::Ts12 => None,
        }
    }
}

/// Whether a label's text is final or a template whose interpolated result the length rule
/// governs (Section 3.3; PaSO View, Section 3, `template:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelLength {
    /// The text is shown as it is: its length is checked now.
    Final,
    /// The text holds placeholders: its length is checked after interpolation.
    Template,
}

/// A label of role `R`: no C0 control, DEL or C1 control, no directional embedding or
/// override, every isolate terminated, and, when final, a character other than white space and
/// within its role's limit.
pub struct LabelText<R> {
    text: String,
    role: PhantomData<R>,
}

impl<R: LabelRole> LabelText<R> {
    /// The label `text` under `rules`, whose length rule `length` says when to check.
    ///
    /// # Errors
    ///
    /// [`TextFault`]: the first rule `text` breaks.
    pub fn parse(text: &str, length: LabelLength, rules: LabelRules) -> Result<Self, TextFault> {
        if let Some(control) = text.chars().find(|c| is_control(*c)) {
            return Err(TextFault::Control(control));
        }
        bidi(text)?;
        if length == LabelLength::Final {
            if text.chars().all(char::is_whitespace) {
                return Err(TextFault::Blank);
            }
            fits::<R>(text, rules)?;
        }
        Ok(Self {
            text: text.to_owned(),
            role: PhantomData,
        })
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<R> Clone for LabelText<R> {
    fn clone(&self) -> Self {
        Self {
            text: self.text.clone(),
            role: PhantomData,
        }
    }
}

impl<R> PartialEq for LabelText<R> {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl<R> Eq for LabelText<R> {}

impl<R> fmt::Debug for LabelText<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LabelText").field(&self.text).finish()
    }
}

/// Checks that `text`, a label of role `R`, is within the role's limit under `rules`.
///
/// # Errors
///
/// [`TextFault::TooLong`].
pub(crate) fn fits<R: LabelRole>(text: &str, rules: LabelRules) -> Result<(), TextFault> {
    R::limit(rules).map_or(Ok(()), |limit| limit.check(text))
}

/// Checks the directional characters of `text`, a label or a payload string value: none of
/// U+202A to U+202E, and each isolate U+2066 to U+2068 terminated by U+2069 (Section 3.3). A
/// U+2069 without an isolate to terminate is left as it is.
///
/// # Errors
///
/// [`TextFault`]: the first directional rule `text` breaks.
pub(crate) fn bidi(text: &str) -> Result<(), TextFault> {
    let mut open = 0usize;
    for c in text.chars() {
        match c {
            '\u{202a}'..='\u{202e}' => return Err(TextFault::DirectionalOverride(c)),
            '\u{2066}'..='\u{2068}' => open += 1,
            '\u{2069}' => open = open.saturating_sub(1),
            _ => {}
        }
    }
    if open == 0 {
        Ok(())
    } else {
        Err(TextFault::IsolateUnterminated)
    }
}

/// Whether `c` is a C0 control (U+0000 to U+001F), DEL (U+007F) or a C1 control (U+0080 to
/// U+009F).
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// A claim's `description` (EC TS12 v1.0.1, Section 3.3.2; SD-JWT VC, Section 9.2): plain text
/// of any length, line breaks included, under the directional rule of Section 3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description(String);

impl Description {
    /// The description `text`.
    ///
    /// # Errors
    ///
    /// [`TextFault`]: the first directional rule `text` breaks.
    pub fn parse(text: &str) -> Result<Self, TextFault> {
        bidi(text)?;
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
