//! Refusals: the request rules a request breaks, each with the error code a Verifier receives
//! when the wallet reports it (OpenID4VP 1.0 §8.5, RFC 6749 §4.1.2.1).
//!
//! A refusal's text quotes request strings and lists the way the reference model writes them
//! ([`Quoted`], [`QuotedList`], [`ReprList::repr`]), so the texts compare with the model's.

use std::error::Error;
use std::fmt;

use icu_properties::{CodePointMapData, props::GeneralCategory};
use siros_explain::Explain;
use siros_syntax::AllOf;

use crate::json::Node;

/// Whether `text` is `1*NQSCHAR` (RFC 6749 Appendix A.7, A.8), the syntax of `error` and
/// `error_description`: one or more of `%x20-21`, `%x23-5B`, `%x5D-7E`.
#[must_use]
pub const fn is_nqschars(text: &str) -> bool {
    let mut rest = text.as_bytes();
    if rest.is_empty() {
        return false;
    }
    while let [byte, tail @ ..] = rest {
        if !is_nqschar(*byte) {
            return false;
        }
        rest = tail;
    }
    true
}

/// Whether `byte` is an `NQSCHAR` (RFC 6749 Appendix A.7, A.8): `%x20-21`, `%x23-5B`,
/// `%x5D-7E`.
const fn is_nqschar(byte: u8) -> bool {
    matches!(byte, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}

/// An error code a wallet returns to a Verifier (RFC 6749 §4.1.2.1, §8.5: extensions' codes "MAY
/// be defined"): one or more of RFC 6749 Appendix A.7's `NQSCHAR`. The constants are RFC 6749's,
/// RFC 9101 §7's and OpenID4VP 1.0 §8.5's codes; a plug-in makes its own specification's with
/// `checked!(ErrorCode, "...")`; a code outside Appendix A.7's syntax
/// fails its build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// `invalid_request` (RFC 6749 §4.1.2.1).
    pub const INVALID_REQUEST: Self = siros_syntax::checked!(ErrorCode, "invalid_request");
    /// `unauthorized_client` (RFC 6749 §4.1.2.1).
    pub const UNAUTHORIZED_CLIENT: Self = siros_syntax::checked!(ErrorCode, "unauthorized_client");
    /// `access_denied` (RFC 6749 §4.1.2.1).
    pub const ACCESS_DENIED: Self = siros_syntax::checked!(ErrorCode, "access_denied");
    /// `unsupported_response_type` (RFC 6749 §4.1.2.1).
    pub const UNSUPPORTED_RESPONSE_TYPE: Self =
        siros_syntax::checked!(ErrorCode, "unsupported_response_type");
    /// `invalid_scope` (RFC 6749 §4.1.2.1).
    pub const INVALID_SCOPE: Self = siros_syntax::checked!(ErrorCode, "invalid_scope");
    /// `server_error` (RFC 6749 §4.1.2.1).
    pub const SERVER_ERROR: Self = siros_syntax::checked!(ErrorCode, "server_error");
    /// `temporarily_unavailable` (RFC 6749 §4.1.2.1).
    pub const TEMPORARILY_UNAVAILABLE: Self =
        siros_syntax::checked!(ErrorCode, "temporarily_unavailable");
    /// `invalid_request_uri` (RFC 9101 §7).
    pub const INVALID_REQUEST_URI: Self = siros_syntax::checked!(ErrorCode, "invalid_request_uri");
    /// `invalid_request_object` (RFC 9101 §7).
    pub const INVALID_REQUEST_OBJECT: Self =
        siros_syntax::checked!(ErrorCode, "invalid_request_object");
    /// `request_not_supported` (RFC 9101 §7).
    pub const REQUEST_NOT_SUPPORTED: Self =
        siros_syntax::checked!(ErrorCode, "request_not_supported");
    /// `request_uri_not_supported` (RFC 9101 §7).
    pub const REQUEST_URI_NOT_SUPPORTED: Self =
        siros_syntax::checked!(ErrorCode, "request_uri_not_supported");
    /// `invalid_client` (OpenID4VP 1.0 §8.5); no rule of the core returns it.
    pub const INVALID_CLIENT: Self = siros_syntax::checked!(ErrorCode, "invalid_client");
    /// `vp_formats_not_supported` (OpenID4VP 1.0 §8.5).
    pub const VP_FORMATS_NOT_SUPPORTED: Self =
        siros_syntax::checked!(ErrorCode, "vp_formats_not_supported");
    /// `invalid_request_uri_method` (OpenID4VP 1.0 §8.5).
    pub const INVALID_REQUEST_URI_METHOD: Self =
        siros_syntax::checked!(ErrorCode, "invalid_request_uri_method");
    /// `invalid_transaction_data` (OpenID4VP 1.0 §8.5).
    pub const INVALID_TRANSACTION_DATA: Self =
        siros_syntax::checked!(ErrorCode, "invalid_transaction_data");
    /// `wallet_unavailable` (OpenID4VP 1.0 §8.5).
    pub const WALLET_UNAVAILABLE: Self = siros_syntax::checked!(ErrorCode, "wallet_unavailable");

    /// The code, when `code` is one or more of RFC 6749 Appendix A.7's `NQSCHAR` (`%x20-21`,
    /// `%x23-5B`, `%x5D-7E`).
    #[must_use]
    pub const fn new(code: &'static str) -> Option<Self> {
        if is_nqschars(code) {
            Some(Self(code))
        } else {
            None
        }
    }

    /// The code as the error response writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An `error_description` (RFC 6749 §4.1.2.1): one or more of Appendix A.8's characters,
/// `%x20-21`, `%x23-5B`, `%x5D-7E`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct ErrorDescription(String);

impl ErrorDescription {
    /// A description as an error response holds it; `None` for an empty text or one outside
    /// Appendix A.8.
    #[must_use]
    pub fn parse(text: String) -> Option<Self> {
        is_nqschars(&text).then_some(Self(text))
    }

    /// The wallet's description of a refusal's text: every character outside Appendix A.8 a
    /// `?`; `None` for an empty text.
    #[must_use]
    pub fn sanitized(text: &str) -> Option<Self> {
        let text: String = text
            .chars()
            .map(|c| match u8::try_from(c) {
                Ok(byte) if is_nqschar(byte) => c,
                _ => '?',
            })
            .collect();
        (!text.is_empty()).then_some(Self(text))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ErrorDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A request rule: its message, and the one code the Verifier receives for it (OpenID4VP 1.0
/// §8.5).
pub trait RequestRule: Explain {
    /// The rule's code.
    fn code(&self) -> ErrorCode;
}

/// A request rule the request breaks. The rule stays itself until a text is needed: its
/// `Display` is the English text of a log line and, sanitized, of the Verifier's
/// `error_description`; its id, arguments and source are the rule's.
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

impl Error for Refusal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Explain for Refusal {
    fn id(&self) -> &'static str {
        self.0.id()
    }

    fn args(&self, arg: &mut dyn FnMut(&'static str, &dyn fmt::Display)) {
        self.0.args(arg);
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.code())
    }
}

/// The rules a request breaks, at least one, in the order the rules run.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(id = "refused")]
#[error("the request breaks {} rule(s), the first: {}", .refusals.items().len(), first(.refusals))]
pub struct Refused {
    #[explain(skip)]
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
        CodePointMapData::<GeneralCategory>::new().get(c),
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

/// Values a rule names, in their order. Its `Display`, a message's argument, writes each value as
/// its sender wrote it, separated by `, `, and nothing for no value; [`ReprList::repr_text`]
/// writes Python's `repr` of the list for the rule's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReprList(Vec<ReprItem>);

/// A received value a rule names. Its `Display`, a message's argument, which the End-User may
/// read, writes it as its sender wrote it; [`ReprItem::repr_text`] writes it for the rule's text,
/// in Python's `repr` or as [`Node::json_spaced`] writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReprItem {
    repr: String,
    written: String,
}

/// A received value a rule names when the request may leave it out. Its `Display`, a message's
/// argument, writes nothing for an absent one; [`ReprOption::repr_text`] writes Python's `None`
/// for the rule's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReprOption(Option<ReprItem>);

impl ReprList {
    /// Strings.
    #[must_use]
    pub fn strings<S: AsRef<str>>(items: &[S]) -> Self {
        Self(
            items
                .iter()
                .map(|item| ReprItem {
                    repr: Quoted(item.as_ref()).to_string(),
                    written: item.as_ref().to_owned(),
                })
                .collect(),
        )
    }

    /// JSON values: strings as Python's `repr`, others as [`Node::json_spaced`] writes them.
    #[must_use]
    pub fn json(items: &[Node<'_>]) -> Self {
        Self(
            items
                .iter()
                .map(|item| {
                    item.as_str().map_or_else(
                        || ReprItem::json(item),
                        |text| ReprItem::pair(Quoted(text), item),
                    )
                })
                .collect(),
        )
    }

    /// JSON values as Python's `sorted` list of their `str`s, in that order.
    #[must_use]
    pub fn names(items: &[Node<'_>]) -> Self {
        let mut named: Vec<(String, &Node<'_>)> = items
            .iter()
            .map(|item| {
                let name = item
                    .as_str()
                    .map_or_else(|| item.json_spaced().to_string(), str::to_owned);
                (name, item)
            })
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        Self(
            named
                .into_iter()
                .map(|(name, item)| ReprItem::pair(Quoted(&name), item))
                .collect(),
        )
    }

    /// Python's `repr` of the list, as the rule's text writes it.
    #[must_use]
    pub fn repr_text(&self) -> impl fmt::Display + '_ {
        ListRepr(&self.0)
    }
}

impl ReprItem {
    /// A JSON value the rule's text writes as [`Node::python_repr`].
    #[must_use]
    pub fn repr(value: &Node<'_>) -> Self {
        Self::pair(value.python_repr(), value)
    }

    /// A JSON value the rule's text writes as [`Node::json_spaced`].
    #[must_use]
    pub fn json(value: &Node<'_>) -> Self {
        Self::pair(value.json_spaced(), value)
    }

    fn pair(repr: impl fmt::Display, value: &Node<'_>) -> Self {
        Self {
            repr: repr.to_string(),
            written: value.written_text(),
        }
    }

    /// The value as the rule's text writes it.
    #[must_use]
    pub fn repr_text(&self) -> &str {
        &self.repr
    }
}

impl ReprOption {
    /// A member's value, as [`ReprItem::repr`] writes it.
    #[must_use]
    pub fn of(value: Option<&Node<'_>>) -> Self {
        Self(value.map(ReprItem::repr))
    }

    /// The value as the rule's text writes it: Python's `None` when absent.
    #[must_use]
    pub fn repr_text(&self) -> &str {
        self.0.as_ref().map_or("None", ReprItem::repr_text)
    }
}

/// Python's `repr` of a list of items.
struct ListRepr<'l>(&'l [ReprItem]);

impl fmt::Display for ListRepr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (k, item) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            f.write_str(&item.repr)?;
        }
        f.write_str("]")
    }
}

impl fmt::Display for ReprItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.written)
    }
}

impl fmt::Display for ReprOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_ref().map_or(Ok(()), |item| item.fmt(f))
    }
}

impl fmt::Display for ReprList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, item) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            item.fmt(f)?;
        }
        Ok(())
    }
}
