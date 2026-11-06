//! A `Content-Type` value (RFC 9110 §8.3.1): `media-type = type "/" subtype parameters`, the
//! parameters `*( OWS ";" OWS [ parameter ] )` of RFC 9110 §5.6.6, each value a token or a
//! quoted-string (§5.6.4).

use std::fmt;

use siros_explain::{Explain, IntoArg, kind};

/// A media type as received: the text a `Content-Type` field carried. Only [`MediaType::parse`]
/// makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    text: String,
    essence: String,
}

/// The rule of RFC 9110 a text breaks, at its byte offset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.media_type")]
pub enum NotMediaType {
    /// `type = token` (§8.3.1).
    #[error("{text:?} is no media type: no token for the type at byte {at} (RFC 9110 §8.3.1)")]
    Type {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// The `"/"` between type and subtype (§8.3.1).
    #[error("{text:?} is no media type: no \"/\" after the type at byte {at} (RFC 9110 §8.3.1)")]
    Slash {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// `subtype = token` (§8.3.1).
    #[error("{text:?} is no media type: no token for the subtype at byte {at} (RFC 9110 §8.3.1)")]
    Subtype {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// `OWS ";" OWS` before each parameter, a parameter starting with its name (§5.6.6).
    #[error(
        "{text:?} is no media type: no \";\" before a parameter at byte {at} (RFC 9110 §5.6.6)"
    )]
    Separator {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// The `"="` after a parameter name (§5.6.6).
    #[error(
        "{text:?} is no media type: no \"=\" after a parameter name at byte {at} (RFC 9110 §5.6.6)"
    )]
    Equals {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// `parameter-value = ( token / quoted-string )` (§5.6.6).
    #[error(
        "{text:?} is no media type: no token or quoted-string for a parameter value at byte {at} (RFC 9110 §5.6.6)"
    )]
    ParameterValue {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
    /// `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` (§5.6.4).
    #[error(
        "{text:?} is no media type: a quoted-string breaks its rule at byte {at} (RFC 9110 §5.6.4)"
    )]
    QuotedString {
        /// The text.
        text: String,
        /// The offset.
        at: usize,
    },
}

/// The rule a parse step requires, named for its error.
#[derive(Clone, Copy)]
enum Rule {
    Type,
    Slash,
    Subtype,
    Separator,
    Equals,
    ParameterValue,
    QuotedString,
}

impl Rule {
    fn broken(self, text: &str, at: usize) -> NotMediaType {
        let text = text.to_owned();
        match self {
            Self::Type => NotMediaType::Type { text, at },
            Self::Slash => NotMediaType::Slash { text, at },
            Self::Subtype => NotMediaType::Subtype { text, at },
            Self::Separator => NotMediaType::Separator { text, at },
            Self::Equals => NotMediaType::Equals { text, at },
            Self::ParameterValue => NotMediaType::ParameterValue { text, at },
            Self::QuotedString => NotMediaType::QuotedString { text, at },
        }
    }
}

/// `tchar` (§5.6.2).
const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// `qdtext` (§5.6.4): HTAB, SP, `!`, `#` to `[`, `]` to `~`, obs-text.
const fn is_qdtext(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!' | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff)
}

/// The byte a quoted-pair escapes (§5.6.4): HTAB, SP, VCHAR, obs-text.
const fn is_escapable(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff)
}

/// A reading position in the text.
struct Cursor<'t> {
    text: &'t str,
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn broken(&self, rule: Rule) -> NotMediaType {
        rule.broken(self.text, self.at)
    }

    /// `1*tchar`; the rule broken when no tchar starts here.
    fn token(&mut self, rule: Rule) -> Result<(), NotMediaType> {
        let start = self.at;
        while self.peek().is_some_and(is_tchar) {
            self.at += 1;
        }
        if self.at == start {
            Err(self.broken(rule))
        } else {
            Ok(())
        }
    }

    /// The byte expected here, the rule broken otherwise.
    fn expect(&mut self, byte: u8, rule: Rule) -> Result<(), NotMediaType> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.broken(rule))
        }
    }

    /// `OWS = *( SP / HTAB )`.
    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    /// A quoted-string after its opening DQUOTE, through its closing one.
    fn quoted(&mut self) -> Result<(), NotMediaType> {
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.at += 1;
                    if !self.peek().is_some_and(is_escapable) {
                        return Err(self.broken(Rule::QuotedString));
                    }
                    self.at += 1;
                }
                Some(byte) if is_qdtext(byte) => self.at += 1,
                _ => return Err(self.broken(Rule::QuotedString)),
            }
        }
    }

    /// `parameter = parameter-name "=" parameter-value`, its name's first tchar at the cursor.
    fn parameter(&mut self) -> Result<(), NotMediaType> {
        self.token(Rule::Separator)?;
        self.expect(b'=', Rule::Equals)?;
        if self.peek() == Some(b'"') {
            self.at += 1;
            self.quoted()
        } else {
            self.token(Rule::ParameterValue)
        }
    }

    /// `parameters = *( OWS ";" OWS [ parameter ] )`, to the end of the text.
    fn parameters(&mut self) -> Result<(), NotMediaType> {
        while self.at < self.text.len() {
            self.whitespace();
            self.expect(b';', Rule::Separator)?;
            self.whitespace();
            if self.peek().is_some_and(is_tchar) {
                self.parameter()?;
            }
        }
        Ok(())
    }
}

impl MediaType {
    /// The media type of a `Content-Type` value.
    ///
    /// # Errors
    ///
    /// The text breaks RFC 9110 §8.3.1's `media-type`; the error names the rule and the byte
    /// where it breaks.
    pub fn parse(text: &str) -> Result<Self, NotMediaType> {
        let mut cursor = Cursor { text, at: 0 };
        cursor.token(Rule::Type)?;
        cursor.expect(b'/', Rule::Slash)?;
        cursor.token(Rule::Subtype)?;
        let end = cursor.at;
        cursor.parameters()?;
        let essence = text
            .get(..end)
            .ok_or_else(|| Rule::Subtype.broken(text, end))?
            .to_ascii_lowercase();
        Ok(Self {
            text: text.to_owned(),
            essence,
        })
    }

    /// `type/subtype`, lowercased: what a profile compares (`image/png`, `application/pdf`).
    #[must_use]
    pub fn essence(&self) -> &str {
        &self.essence
    }

    /// The text as received.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// `application/x-www-form-urlencoded` (§5.10, §8.2).
    #[must_use]
    pub fn form() -> Self {
        Self {
            text: FORM.to_owned(),
            essence: FORM.to_owned(),
        }
    }

    /// Whether the essence is `application/x-www-form-urlencoded`.
    #[must_use]
    pub fn is_form(&self) -> bool {
        self.essence == FORM
    }
}

/// The form media type's essence.
const FORM: &str = "application/x-www-form-urlencoded";

/// A media type is named by its text as received.
impl IntoArg for MediaType {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}
