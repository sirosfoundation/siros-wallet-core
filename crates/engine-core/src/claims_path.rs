//! Claims path pointers (OpenID4VCI 1.0 Appendix C): "a non-empty array of strings, nulls and
//! integers", read by the semantics of the credential's format: Appendix C.1 for a JSON-based
//! Credential, Appendix C.2 for an ISO mdoc. A pointer is parsed where it enters.

use std::num::IntErrorKind;

use serde_json::{Number, Value};

use crate::oid4vci::types::CredentialFormat;

/// A claims path pointer, parsed by the semantics of its credential's format. Two pointers are
/// equal when their components are, whatever the spelling of their integers.
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
        /// The components that select within the data element's value.
        within: Vec<MdocComponent>,
    },
}

/// A component of a pointer into a JSON-based Credential (Appendix C.1).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JsonComponent {
    /// Selects the member of an object with this key: a JSON string.
    Key(String),
    /// Selects the element of an array at this position, from 0: a non-negative integer.
    Index(u64),
    /// Selects every element of an array: JSON `null`.
    AllElements,
}

/// A component after the data element identifier of a pointer into an ISO mdoc (Appendix C.2).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MdocComponent {
    /// Selects the entry of a map with this text key: a JSON string.
    Key(String),
    /// Selects the entry of a map with this integer key. A non-negative integer selects the
    /// element of an array at this position when the selected element is an array.
    Integer(CborInteger),
    /// Selects every element of an array: JSON `null`.
    AllElements,
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
    /// The pointer the JSON value `value` writes into a Credential of the format `format`.
    pub(crate) fn parse(value: &Value, format: CredentialFormat) -> Result<Self, ClaimsPathError> {
        let Value::Array(items) = value else {
            return Err(ClaimsPathError::NotArray);
        };
        if items.is_empty() {
            return Err(ClaimsPathError::Empty);
        }
        match format {
            CredentialFormat::JwtVcJson
            | CredentialFormat::LdpVc
            | CredentialFormat::JwtVcJsonLd
            | CredentialFormat::DcSdJwt => Self::parse_json(items),
            CredentialFormat::MsoMdoc => Self::parse_mdoc(items),
        }
    }

    /// A pointer into a JSON-based Credential (Appendix C.1).
    fn parse_json(items: &[Value]) -> Result<Self, ClaimsPathError> {
        items
            .iter()
            .enumerate()
            .map(|(at, item)| {
                JsonComponent::parse(item).map_err(|why| ClaimsPathError::Component { at, why })
            })
            .collect::<Result<_, _>>()
            .map(Self::Json)
    }

    /// A pointer into an ISO mdoc (Appendix C.2): "at least two path components of type
    /// string", the namespace and the data element identifier, then the components within the
    /// data element's value.
    fn parse_mdoc(items: &[Value]) -> Result<Self, ClaimsPathError> {
        let name = |at: usize| match items.get(at) {
            Some(Value::String(name)) => Ok(name.clone()),
            Some(_) => Err(ClaimsPathError::Component {
                at,
                why: ComponentError::NotString,
            }),
            // Appendix C.2.1: "If the path contains fewer than two path components, abort
            // processing and return an error."
            None => Err(ClaimsPathError::MdocTooShort),
        };
        let namespace = name(0)?;
        let data_element = name(1)?;
        let within = items
            .iter()
            .enumerate()
            .skip(2)
            .map(|(at, item)| {
                MdocComponent::parse(item).map_err(|why| ClaimsPathError::Component { at, why })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self::Mdoc {
            namespace,
            data_element,
            within,
        })
    }
}

impl JsonComponent {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            Value::Number(number) => match whole_number_of(number)? {
                WholeNumber::InRange(CborInteger::Unsigned(index)) => Ok(Self::Index(index)),
                // Appendix C.1: "Negative integer values are not used for JSON-based
                // credentials."
                WholeNumber::InRange(CborInteger::Negative(_)) | WholeNumber::Below => {
                    Err(ComponentError::Negative)
                }
                WholeNumber::Above => Err(ComponentError::OutOfRange),
            },
            Value::Null => Ok(Self::AllElements),
            Value::Bool(_) | Value::Array(_) | Value::Object(_) => Err(ComponentError::WrongType),
        }
    }
}

impl MdocComponent {
    /// The component the JSON value `value` writes.
    fn parse(value: &Value) -> Result<Self, ComponentError> {
        match value {
            Value::String(key) => Ok(Self::Key(key.clone())),
            // Appendix C.2: a map key is a "string or integer", an array index a non-negative
            // integer.
            Value::Number(number) => match whole_number_of(number)? {
                WholeNumber::InRange(integer) => Ok(Self::Integer(integer)),
                WholeNumber::Above | WholeNumber::Below => Err(ComponentError::OutOfRange),
            },
            Value::Null => Ok(Self::AllElements),
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
/// Appendix C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsPathError {
    /// The value is no array.
    #[error("the path is no array")]
    NotArray,
    /// The array is empty.
    #[error("the path is an empty array")]
    Empty,
    /// A pointer into an ISO mdoc has one component: it lacks the data element identifier
    /// (Appendix C.2.1).
    #[error("the mdoc path has fewer than two components")]
    MdocTooShort,
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
/// Appendix C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComponentError {
    /// No string, `null` or number.
    #[error("no string, null or number")]
    WrongType,
    /// A number whose value has a nonzero fractional part.
    #[error("a fraction")]
    Fraction,
    /// A negative integer in a pointer into a JSON-based Credential (Appendix C.1).
    #[error("a negative integer in a JSON-based credential's path")]
    Negative,
    /// An integer above 2^64 − 1, the largest index, or, in a pointer into an ISO mdoc, below
    /// −2^64, the smallest CBOR integer (RFC 8949 §3.1).
    #[error("an integer out of range")]
    OutOfRange,
    /// The namespace or the data element identifier of a pointer into an ISO mdoc is no string
    /// (Appendix C.2).
    #[error("no string")]
    NotString,
}
