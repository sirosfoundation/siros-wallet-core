//! Claims path pointers, read by the semantics of the credential's format and parsed where they
//! enter.
//!
//! `ClaimsPath` reads an issuer's pointer (OpenID4VCI 1.0 Appendix C): "a non-empty array of
//! strings, nulls and integers", by Appendix C.1 for a JSON-based Credential and by Appendix C.2
//! for an ISO mdoc. `PresentationClaimsPath` reads a presentation request's pointer (OpenID4VP
//! 1.0 §7): "a non-empty array of strings, nulls and non-negative integers", by §7.1 for a
//! JSON-based Credential and by §7.2 for an ISO mdoc. A pointer into a Credential of a format
//! OpenID4VCI 1.0 Appendix A does not define keeps its specification's grammar alone.
//!
//! §7.1 reads a pointer into a JSON-based Credential as Appendix C.1 does. The two differ twice:
//! §7 admits no negative integer in any format, and §7.2.1 admits exactly two components into an
//! ISO mdoc, where Appendix C.2 continues into the data element's value.

use std::num::IntErrorKind;

use serde_json::{Number, Value};

use crate::oid4vci::types::CredentialFormat;

/// An issuer's claims path pointer (OpenID4VCI 1.0 Appendix C), parsed by the semantics of its
/// credential's format. Two pointers are equal when their components are, whatever the spelling
/// of their integers.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClaimsPath {
    /// A pointer into a JSON-based Credential (Appendix C.1).
    Json(Vec<JsonComponent>),
    /// A pointer into an ISO mdoc (Appendix C.2).
    Mdoc {
        /// The namespace: the first component.
        namespace: String,
        /// The data element identifier: the second component.
        data_element: String,
        /// The components that select within the data element's value: a string selects the
        /// entry of a map with that key, an integer the entry of a map with that key or, when
        /// non-negative and the selected element is an array, the element at that position,
        /// and null every element of an array.
        within: Vec<Component>,
    },
    /// A pointer into a Credential of a format Appendix A does not define: the components
    /// Appendix C admits, without semantics.
    OtherFormat(Vec<Component>),
}

/// A presentation request's claims path pointer (OpenID4VP 1.0 §7), parsed by the semantics of
/// its credential's format.
#[derive(Debug)]
pub(crate) enum PresentationClaimsPath {
    /// A pointer into a JSON-based Credential (§7.1).
    Json(Vec<JsonComponent>),
    /// A pointer into an ISO mdoc (§7.2): "exactly two components", each a string.
    Mdoc {
        /// The namespace: the first component.
        namespace: String,
        /// The data element identifier: the second component.
        data_element: String,
    },
    /// A pointer into a Credential of a format OpenID4VCI 1.0 Appendix A does not define, or of
    /// no format: the components §7 admits, without semantics.
    OtherFormat(Vec<PresentationComponent>),
}

/// A component as OpenID4VP 1.0 §7 writes it, in a pointer into a Credential of a format
/// OpenID4VCI 1.0 Appendix A does not define, or of no format.
#[derive(Debug)]
pub(crate) enum PresentationComponent {
    /// A JSON string.
    Key(String),
    /// A JSON number whose value is a non-negative integer.
    Integer(u64),
    /// JSON `null`.
    Null,
}

/// A component of a pointer into a JSON-based Credential (Appendix C.1, OpenID4VP 1.0 §7.1).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JsonComponent {
    /// Selects the member of an object with this key: a JSON string.
    Key(String),
    /// Selects the element of an array at this position, from 0: a non-negative integer.
    Index(u64),
    /// Selects every element of an array: JSON `null`.
    AllElements,
}

/// A component as Appendix C writes it, in a pointer into an ISO mdoc after its data element
/// identifier, or into a Credential of a format Appendix A does not define.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Component {
    /// A JSON string.
    Key(String),
    /// A JSON number whose value is an integer.
    Integer(CborInteger),
    /// JSON `null`.
    Null,
}

/// An integer of CBOR major type 0 or 1 (RFC 8949 §3.1): from −2^64 to 2^64 − 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CborInteger {
    /// The integer n, from 0 to 2^64 − 1.
    Unsigned(u64),
    /// The integer −1 − n, from −2^64 to −1.
    Negative(u64),
}

impl ClaimsPath {
    /// The pointer the JSON value `value` writes into a Credential of the format `format`;
    /// `None` is a format Appendix A does not define.
    pub(crate) fn parse(
        value: &Value,
        format: Option<CredentialFormat>,
    ) -> Result<Self, ClaimsPathError> {
        let items = items_of(value)?;
        match format {
            Some(
                CredentialFormat::JwtVcJson
                | CredentialFormat::LdpVc
                | CredentialFormat::JwtVcJsonLd
                | CredentialFormat::DcSdJwt,
            ) => components(items.iter().enumerate(), JsonComponent::parse).map(Self::Json),
            Some(CredentialFormat::MsoMdoc) => Self::parse_mdoc(items),
            None => components(items.iter().enumerate(), Component::parse).map(Self::OtherFormat),
        }
    }

    /// A pointer into an ISO mdoc (Appendix C.2): "at least two path components of type
    /// string", the namespace and the data element identifier, then the components within the
    /// data element's value.
    fn parse_mdoc(items: &[Value]) -> Result<Self, ClaimsPathError> {
        let namespace = mdoc_name(items, 0)?;
        let data_element = mdoc_name(items, 1)?;
        let within = components(items.iter().enumerate().skip(2), Component::parse)?;
        Ok(Self::Mdoc {
            namespace,
            data_element,
            within,
        })
    }
}

impl PresentationClaimsPath {
    /// The pointer the JSON value `value` writes into a Credential of the format `format`;
    /// `None` is a format OpenID4VCI 1.0 Appendix A does not define, or no format.
    pub(crate) fn parse(
        value: &Value,
        format: Option<CredentialFormat>,
    ) -> Result<Self, ClaimsPathError> {
        let items = items_of(value)?;
        match format {
            Some(
                CredentialFormat::JwtVcJson
                | CredentialFormat::LdpVc
                | CredentialFormat::JwtVcJsonLd
                | CredentialFormat::DcSdJwt,
            ) => components(items.iter().enumerate(), JsonComponent::parse).map(Self::Json),
            Some(CredentialFormat::MsoMdoc) => Self::parse_mdoc(items),
            None => components(items.iter().enumerate(), PresentationComponent::parse)
                .map(Self::OtherFormat),
        }
    }

    /// A pointer into an ISO mdoc (§7.2.1): "If the claims path pointer does not contain exactly
    /// two components or one of the components is not a string then abort processing and return
    /// an error."
    fn parse_mdoc(items: &[Value]) -> Result<Self, ClaimsPathError> {
        let namespace = mdoc_name(items, 0)?;
        let data_element = mdoc_name(items, 1)?;
        if items.len() > 2 {
            return Err(ClaimsPathError::MdocTooLong);
        }
        Ok(Self::Mdoc {
            namespace,
            data_element,
        })
    }
}

impl JsonComponent {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            Value::Number(number) => non_negative_integer(number).map(Self::Index),
            Value::Null => Ok(Self::AllElements),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(ComponentError::WrongType),
        }
    }
}

impl PresentationComponent {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            Value::Number(number) => non_negative_integer(number).map(Self::Integer),
            Value::Null => Ok(Self::Null),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(ComponentError::WrongType),
        }
    }
}

/// The components of the pointer the JSON value `value` writes: "a non-empty array" (Appendix
/// C, OpenID4VP 1.0 §7).
fn items_of(value: &Value) -> Result<&[Value], ClaimsPathError> {
    let Value::Array(items) = value else {
        return Err(ClaimsPathError::NotArray);
    };
    if items.is_empty() {
        return Err(ClaimsPathError::Empty);
    }
    Ok(items)
}

/// The components `items` write, each read by `parse`, with its position in the pointer.
fn components<'a, T>(
    items: impl Iterator<Item = (usize, &'a Value)>,
    parse: fn(&Value) -> Result<T, ComponentError>,
) -> Result<Vec<T>, ClaimsPathError> {
    items
        .map(|(at, item)| parse(item).map_err(|why| ClaimsPathError::Component { at, why }))
        .collect()
}

/// The namespace, `at` 0, or the data element identifier, `at` 1, of a pointer into an ISO
/// mdoc: a string (Appendix C.2, OpenID4VP 1.0 §7.2).
fn mdoc_name(items: &[Value], at: usize) -> Result<String, ClaimsPathError> {
    match items.get(at) {
        Some(Value::String(name)) => Ok(name.clone()),
        Some(_) => Err(ClaimsPathError::Component {
            at,
            why: ComponentError::NotString,
        }),
        // Appendix C.2.1: "If the path contains fewer than two path components, abort
        // processing and return an error." §7.2.1 asks for "exactly two components".
        None => Err(ClaimsPathError::MdocTooShort),
    }
}

/// The non-negative integer a JSON number writes, at most 2^64 − 1.
fn non_negative_integer(number: &Number) -> Result<u64, ComponentError> {
    match whole_number_of(number)? {
        WholeNumber::InRange(CborInteger::Unsigned(integer)) => Ok(integer),
        // Appendix C.1: "Negative integer values are not used for JSON-based credentials."
        // OpenID4VP 1.0 §7: "non-negative integers", in every format.
        WholeNumber::InRange(CborInteger::Negative(_)) | WholeNumber::Below => {
            Err(ComponentError::Negative)
        }
        WholeNumber::Above => Err(ComponentError::OutOfRange),
    }
}

impl Component {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            // Appendix C: "integers"; in an ISO mdoc, a map key is a "string or integer" and an
            // array index a non-negative integer (C.2).
            Value::Number(number) => match whole_number_of(number)? {
                WholeNumber::InRange(integer) => Ok(Self::Integer(integer)),
                WholeNumber::Above | WholeNumber::Below => Err(ComponentError::OutOfRange),
            },
            Value::Null => Ok(Self::Null),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(ComponentError::WrongType),
        }
    }
}

/// A JSON number whose value is an integer, placed against the range of a CBOR integer.
#[derive(Clone, Copy)]
enum WholeNumber {
    /// From −2^64 to 2^64 − 1.
    InRange(CborInteger),
    /// Above 2^64 − 1.
    Above,
    /// Below −2^64.
    Below,
}

/// The integer a JSON number writes.
///
/// The number's decimal text decides (RFC 8259 §6), digit by digit, so no rounding turns a
/// fraction into an integer: `1`, `1.0` and `10e-1` are 1, `-0` is 0, and
/// `1.0000000000000001` is a fraction.
fn whole_number_of(number: &Number) -> Result<WholeNumber, ComponentError> {
    let text = number.to_string();
    // serde_json holds the text of a JSON number; any other text is no number.
    let NumberText {
        negative,
        whole,
        fraction,
        exponent,
    } = NumberText::split(&text).ok_or(ComponentError::WrongType)?;
    // The value is `digits` × 10^(`exponent` − `fraction.len()`).
    let digits = [whole, fraction].concat();
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        // Zero, whatever its sign and exponent.
        return Ok(WholeNumber::InRange(CborInteger::Unsigned(0)));
    }
    let beyond = if negative {
        WholeNumber::Below
    } else {
        WholeNumber::Above
    };
    // A nonzero value times a power of ten beyond i64 is a fraction, or beyond every CBOR
    // integer.
    let exponent = match exponent.parse::<i64>() {
        Ok(exponent) => exponent,
        Err(error) => {
            return match error.kind() {
                IntErrorKind::PosOverflow => Ok(beyond),
                IntErrorKind::NegOverflow => Err(ComponentError::Fraction),
                _ => Err(ComponentError::WrongType),
            }
        }
    };
    // `significant` is `kept` × 10^`zeros`, and `kept` ends in a nonzero digit.
    let kept = significant.trim_end_matches('0');
    let zeros = significant.len() - kept.len();
    let scale = i128::from(exponent) + zeros as i128 - fraction.len() as i128;
    if scale < 0 {
        // 10 does not divide `kept`.
        return Err(ComponentError::Fraction);
    }
    let kept = match kept.parse::<u128>() {
        Ok(kept) => kept,
        Err(error) => {
            return match error.kind() {
                IntErrorKind::PosOverflow => Ok(beyond),
                _ => Err(ComponentError::WrongType),
            }
        }
    };
    let Some(magnitude) = u32::try_from(scale)
        .ok()
        .and_then(|scale| 10_u128.checked_pow(scale))
        .and_then(|power| kept.checked_mul(power))
    else {
        return Ok(beyond);
    };
    // `kept` is at least 1, and so is `magnitude`.
    let in_range = if negative {
        u64::try_from(magnitude - 1).ok().map(CborInteger::Negative)
    } else {
        u64::try_from(magnitude).ok().map(CborInteger::Unsigned)
    };
    Ok(in_range.map_or(beyond, WholeNumber::InRange))
}

/// The parts of a JSON number's text (RFC 8259 §6): `[-] whole [. fraction] [e [+|-] digits]`.
struct NumberText<'a> {
    /// The text starts with a minus sign.
    negative: bool,
    /// The digits before the decimal point.
    whole: &'a str,
    /// The digits after the decimal point, empty when there is none.
    fraction: &'a str,
    /// The exponent with its sign, `0` when there is none.
    exponent: &'a str,
}

impl<'a> NumberText<'a> {
    /// The parts of `text`, or `None` when `text` is no JSON number.
    fn split(text: &'a str) -> Option<Self> {
        let (negative, magnitude) = match text.strip_prefix('-') {
            Some(magnitude) => (true, magnitude),
            None => (false, text),
        };
        let (mantissa, exponent) = match magnitude.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => {
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                (mantissa, is_digits(digits).then_some(exponent)?)
            }
            None => (magnitude, "0"),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (whole, is_digits(fraction).then_some(fraction)?),
            None => (mantissa, ""),
        };
        is_digits(whole).then_some(Self {
            negative,
            whole,
            fraction,
            exponent,
        })
    }
}

/// Whether `text` is one ASCII digit or more.
fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Why a JSON value is no claims path pointer into a Credential of its format (OpenID4VCI 1.0
/// Appendix C, or OpenID4VP 1.0 §7 for a presentation request's pointer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsPathError {
    /// The value is no array.
    #[error("the path is no array")]
    NotArray,
    /// The array is empty.
    #[error("the path is an empty array")]
    Empty,
    /// A pointer into an ISO mdoc has one component: it lacks the data element identifier
    /// (Appendix C.2.1, OpenID4VP 1.0 §7.2.1).
    #[error("the mdoc path has fewer than two components")]
    MdocTooShort,
    /// A presentation request's pointer into an ISO mdoc has a component after the data element
    /// identifier: OpenID4VP 1.0 §7.2.1 admits "exactly two components".
    #[error("the mdoc path has more than two components")]
    MdocTooLong,
    /// A component is none its position admits.
    #[error("path component {at} is {why}")]
    Component {
        /// The component's position in the array, from 0.
        at: usize,
        /// Why its position does not admit it.
        why: ComponentError,
    },
}

/// Why a JSON value is no component of a claims path pointer at its position (OpenID4VCI 1.0
/// Appendix C, or OpenID4VP 1.0 §7 for a presentation request's pointer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComponentError {
    /// No string, `null` or number.
    #[error("no string, null or number")]
    WrongType,
    /// A number whose value has a nonzero fractional part.
    #[error("a fraction")]
    Fraction,
    /// A negative integer in a pointer into a JSON-based Credential (Appendix C.1), or in a
    /// presentation request's pointer (OpenID4VP 1.0 §7).
    #[error("a negative integer")]
    Negative,
    /// An integer above 2^64 − 1, the largest index, or, in an issuer's pointer outside a
    /// JSON-based Credential, below −2^64, the smallest CBOR integer (RFC 8949 §3.1).
    #[error("an integer out of range")]
    OutOfRange,
    /// The namespace or the data element identifier of a pointer into an ISO mdoc is no string
    /// (Appendix C.2, OpenID4VP 1.0 §7.2.1).
    #[error("no string")]
    NotString,
}
