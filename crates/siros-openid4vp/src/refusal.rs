//! Refusals: the request rules a request breaks, each with the error code a Verifier receives
//! when the wallet reports it (OpenID4VP 1.0 §8.5, RFC 6749 §4.1.2.1).
//!
//! A refusal's text quotes request strings and lists the way the reference model writes them
//! ([`Quoted`], [`QuotedList`], [`ReprList`]), so the texts compare with the model's.

use std::fmt;

use siros_explain::{
    AllOf, Arg, Args, Explain, Explained, IntoArg, ListKind, Listed, MessageId, kind,
};
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::json::Node;

/// The error codes a wallet returns to a Verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `invalid_request`.
    InvalidRequest,
    /// `unsupported_response_type`.
    UnsupportedResponseType,
    /// `invalid_scope`.
    InvalidScope,
    /// `invalid_request_uri` (RFC 9101 §7).
    InvalidRequestUri,
    /// `invalid_request_object` (RFC 9101 §7).
    InvalidRequestObject,
    /// `request_not_supported` (RFC 9101 §7).
    RequestNotSupported,
    /// `invalid_request_uri_method`.
    InvalidRequestUriMethod,
    /// `invalid_transaction_data`.
    InvalidTransactionData,
    /// `vp_formats_not_supported`.
    VpFormatsNotSupported,
    /// `access_denied`.
    AccessDenied,
}

impl ErrorCode {
    /// The code as the error response writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::RequestNotSupported => "request_not_supported",
            Self::InvalidRequestUriMethod => "invalid_request_uri_method",
            Self::InvalidTransactionData => "invalid_transaction_data",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::AccessDenied => "access_denied",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request rule: its message, and the one code the Verifier receives for it (OpenID4VP 1.0
/// §8.5).
pub trait RequestRule: Explained {
    /// The rule's code.
    fn code(&self) -> ErrorCode;
}

/// A request rule the request breaks. The rule stays itself until a text is needed: its
/// `Display` is the English text of a log line and, sanitized, of the Verifier's
/// `error_description`; its message is the End-User's.
#[derive(Debug)]
pub struct Refusal(Box<dyn RequestRule>);

impl Refusal {
    /// The refusal of a rule.
    pub fn new(rule: impl RequestRule) -> Self {
        Self(Box::new(rule))
    }

    /// The code the Verifier receives: the rule's.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.0.code()
    }

    /// The rule.
    #[must_use]
    pub fn rule(&self) -> &dyn RequestRule {
        &*self.0
    }

    /// What the rule found, naming the rule: its English text.
    #[must_use]
    pub fn text(&self) -> String {
        self.0.to_string()
    }
}

/// A refusal's message is its rule's.
impl Explain for Refusal {
    fn id(&self) -> MessageId {
        self.0.id()
    }

    fn args(&self) -> Args<'_> {
        self.0.args()
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.code())
    }
}

/// The rules a request breaks, at least one, in the order the rules run.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp")]
#[error("the request breaks {} rule(s), the first: {}", .refusals.items().len(), first(.refusals))]
pub struct Refused {
    refusals: AllOf<Refusal>,
}

fn first(refusals: &AllOf<Refusal>) -> &dyn fmt::Display {
    refusals
        .items()
        .first()
        .map_or(&"none" as &dyn fmt::Display, |refusal| {
            refusal as &dyn fmt::Display
        })
}

impl Refused {
    /// The refusals, `None` when there is none.
    #[must_use]
    pub fn of(refusals: Vec<Refusal>) -> Option<Self> {
        AllOf::new(refusals).map(|refusals| Self { refusals })
    }

    /// The refusals, one or more.
    #[must_use]
    pub const fn all(refusals: AllOf<Refusal>) -> Self {
        Self { refusals }
    }

    /// One refusal.
    #[must_use]
    pub fn one(refusal: Refusal) -> Self {
        Self {
            refusals: AllOf::one(refusal),
        }
    }

    /// The refusals found so far, then one more.
    #[must_use]
    pub fn adding(refusals: Vec<Refusal>, last: Refusal) -> Self {
        let last = AllOf::one(last);
        let refusals = match AllOf::new(refusals) {
            Some(found) => found.and(last),
            None => last,
        };
        Self { refusals }
    }

    /// The refusals in rule order.
    #[must_use]
    pub fn refusals(&self) -> &[Refusal] {
        self.refusals.items()
    }

    /// The refusals in rule order, by value.
    #[must_use]
    pub fn into_refusals(self) -> Vec<Refusal> {
        self.refusals.into_items()
    }

    /// The refusals' texts in rule order.
    pub fn texts(&self) -> impl Iterator<Item = String> {
        self.refusals.items().iter().map(Refusal::text)
    }
}

/// A string quoted as Python's `repr` writes it.
pub struct Quoted<'s>(pub &'s str);

/// Strings listed as Python's `repr` of a list of strings writes them.
pub struct QuotedList<'s, T>(pub &'s [T]);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let quote = if self.0.contains('\'') && !self.0.contains('"') {
            '"'
        } else {
            '\''
        };
        f.write_fmt(format_args!("{quote}"))?;
        for c in self.0.chars() {
            match c {
                c if c == quote || c == '\\' => write!(f, "\\{c}")?,
                '\t' => f.write_str("\\t")?,
                '\n' => f.write_str("\\n")?,
                '\r' => f.write_str("\\r")?,
                c if u32::from(c) < 0x20 || u32::from(c) == 0x7f => {
                    write!(f, "\\x{:02x}", u32::from(c))?
                }
                c if c.is_ascii() || printable(c) => write!(f, "{c}")?,
                c if u32::from(c) <= 0xff => write!(f, "\\x{:02x}", u32::from(c))?,
                c if u32::from(c) <= 0xffff => write!(f, "\\u{:04x}", u32::from(c))?,
                c => write!(f, "\\U{:08x}", u32::from(c))?,
            }
        }
        f.write_fmt(format_args!("{quote}"))
    }
}

/// Python's `str.isprintable` for one character beyond ASCII.
fn printable(c: char) -> bool {
    !matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

impl<T: AsRef<str>> fmt::Display for QuotedList<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (k, item) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", Quoted(item.as_ref()))?;
        }
        f.write_str("]")
    }
}

/// Values a rule names, in their order. A rule's text writes them as Python's `repr` of the
/// list; its message names them as an and-list of raw texts, absent when there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReprList(Vec<ReprItem>);

/// One value of a [`ReprList`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReprItem {
    /// A string, quoted in the list's `repr`.
    Text(String),
    /// Another JSON value, as Python writes the value `json` reads.
    Value(String),
}

impl ReprList {
    /// Strings.
    #[must_use]
    pub fn strings<S: AsRef<str>>(items: &[S]) -> Self {
        Self(
            items
                .iter()
                .map(|item| ReprItem::Text(item.as_ref().to_owned()))
                .collect(),
        )
    }

    /// JSON values: strings, and others as Python writes the values `json` reads.
    #[must_use]
    pub fn json(items: &[Node<'_>]) -> Self {
        Self(
            items
                .iter()
                .map(|item| {
                    item.as_str().map_or_else(
                        || ReprItem::Value(item.python_text().to_string()),
                        |text| ReprItem::Text(text.to_owned()),
                    )
                })
                .collect(),
        )
    }
}

impl ReprItem {
    fn text(&self) -> &str {
        match self {
            Self::Text(text) | Self::Value(text) => text,
        }
    }
}

impl fmt::Display for ReprItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => write!(f, "{}", Quoted(text)),
            Self::Value(value) => f.write_str(value),
        }
    }
}

impl fmt::Display for ReprList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (k, item) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{item}")?;
        }
        f.write_str("]")
    }
}

impl IntoArg for ReprItem {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        self.text()
    }
}

impl IntoArg for ReprList {
    type Kind = kind::Optional<kind::List>;

    fn arg(&self) -> Option<Listed<'_>> {
        AllOf::new(self.0.iter().map(Arg::of).collect())
            .map(|items| Listed::new(ListKind::And, items))
    }
}
