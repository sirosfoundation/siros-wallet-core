//! A payload's typed parse (TS12 §4.3.1, §4.3.2, and the schemas their sources publish) and the
//! same values in PaSO's forms (View §3). Any member TS12 does not list is refused at any depth
//! (PaSO Core §7.4.2 step 2).

use std::borrow::Cow;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use siros_explain::{Count, Currency, Explain, IntoArg, kind};
use siros_openid4vp::json::{Node, Number, Object};
use siros_openid4vp::known_object;
use siros_openid4vp::rows::HttpsUrl;
use siros_paso::frequency::Frequency;
use siros_paso::value::{FormattedKind, Written, formatted};

use crate::document::Ts12Type;
use crate::field::{
    ACTION, AMOUNT, AMOUNT_EARMARKED, AMOUNT_ESTIMATED, AMOUNT_VARIABLE, APR, CURRENCY, DATE_TIME,
    END_DATE, EXECUTION_DATE, FREQUENCY, FieldPath, INITIAL_AMOUNT, INITIAL_AMOUNT_NUMBER,
    MAX_AMOUNT, MIN_AMOUNT, MIT_OPTIONS, NUMBER, PAYEE, PAYEE_ID, PAYEE_LOGO, PAYEE_LOGO_INTEGRITY,
    PAYEE_NAME, PAYEE_WEBSITE, PAYLOAD, PISP, PISP_BRAND_NAME, PISP_DOMAIN_NAME, PISP_LEGAL_NAME,
    RECURRENCE, SCT_INST, SERVICE, START_DATE, TOTAL_AMOUNT, TRANSACTION_ID,
};

/// An exact decimal's digits in PaSO's amounts (View §3).
const MAX_DIGITS: i64 = 38;
/// The schemas' `transaction_id` `maxLength`.
const TRANSACTION_ID_MAX: MaxChars = MaxChars(36);
/// The login schema's `service` `maxLength`.
const SERVICE_MAX: MaxChars = MaxChars(100);
/// The login schema's `action` `maxLength`.
const ACTION_MAX: MaxChars = MaxChars(140);

/// A schema's `maxLength`, in characters (JSON Schema §6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxChars(usize);

impl MaxChars {
    /// The length.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl fmt::Display for MaxChars {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A length is named as a count in a message.
impl IntoArg for MaxChars {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        self.0.arg()
    }
}

/// The form TS12 lists for a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// A JSON object.
    Object,
    /// A JSON string.
    String,
    /// A JSON boolean.
    Boolean,
    /// A JSON number.
    Number,
    /// A number without fraction or exponent, not negative, within 64 bits.
    Integer,
    /// A number not negative, its exact decimal value within 38 digits.
    Decimal,
    /// An https URL.
    HttpsUrl,
    /// A data URL.
    DataUrl,
    /// A data URL or an https URL.
    DataOrHttpsUrl,
}

impl Expected {
    const fn name(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::String => "string",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Decimal => "decimal",
            Self::HttpsUrl => "https URL",
            Self::DataUrl => "data URL",
            Self::DataOrHttpsUrl => "data URL or https URL",
        }
    }
}

impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A form is named as the code fixes it.
impl IntoArg for Expected {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// The ISO 8601 form a date member takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateForm {
    /// A calendar date.
    Calendar,
    /// A date and time.
    DateTime,
}

impl DateForm {
    const fn name(self) -> &'static str {
        match self {
            Self::Calendar => "calendar date",
            Self::DateTime => "date-time",
        }
    }
}

impl fmt::Display for DateForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A form is named as the code fixes it.
impl IntoArg for DateForm {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// Why a payload is refused: the entry is not compatible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.payload")]
pub enum PayloadRefusal {
    /// A member TS12 does not list in that object, at any depth.
    #[error("{within}: {name} is a member TS12 does not list")]
    Member {
        /// The object.
        within: FieldPath,
        /// The member's name as written.
        name: String,
    },
    /// A required member absent.
    #[error("{path} is required")]
    Required {
        /// The member.
        path: FieldPath,
    },
    /// A member of another form than TS12's.
    #[error("{path} is no {kind}")]
    Kind {
        /// The member.
        path: FieldPath,
        /// What TS12 lists.
        kind: Expected,
    },
    /// A string outside the lengths TS12's schema gives its member: at most `max` characters, and
    /// at least one for `transaction_id`.
    #[error("{path} is outside its length, at most {max} characters")]
    Length {
        /// The member.
        path: FieldPath,
        /// The schema's `maxLength`.
        max: MaxChars,
    },
    /// An amount with more fractional digits than its currency's minor unit, or beyond an exact
    /// decimal's 38 digits.
    #[error("{path} has more digits than its currency")]
    Digits {
        /// The member.
        path: FieldPath,
    },
    /// A negative amount: TS12 defines no negative payment.
    #[error("{path} is negative")]
    Negative {
        /// The member.
        path: FieldPath,
    },
    /// `execution_date` beside `recurrence` (TS12 §4.3.1).
    #[error("execution_date beside recurrence")]
    ExecutionAndRecurrence,
    /// A date that is no ISO 8601 calendar date, or a date-time that is none.
    #[error("{path} is no ISO 8601 {form}")]
    Date {
        /// The member.
        path: FieldPath,
        /// The form TS12 lists.
        form: DateForm,
    },
    /// An https `payee.logo` without a valid `payee.logo#integrity` (View §3 `image`).
    #[error("payee.logo is an https URL without a valid payee.logo#integrity")]
    LogoIntegrity,
    /// A frequency code outside TS12 §4.3.1's list.
    #[error("{value} is no frequency code of TS12")]
    Frequency {
        /// The value as written.
        value: String,
    },
    /// A currency code outside the core's ISO 4217 table.
    #[error("{value} is no ISO 4217 code of the table")]
    Currency {
        /// The value as written.
        value: String,
    },
}

/// A data URL (RFC 2397): `data:`, a media type and its parameters, `;base64` when written, `,`,
/// then the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUrl(String);

impl DataUrl {
    /// The data URL; `None` outside RFC 2397's grammar.
    #[must_use]
    pub fn parse(text: String) -> Option<Self> {
        let rest = text.strip_prefix("data:")?;
        let (head, data) = rest.split_once(',')?;
        let media = head.strip_suffix(";base64");
        let well_formed = match media {
            Some(_) => STANDARD.decode(data).is_ok(),
            None => data.is_ascii(),
        };
        (well_formed && media_type(media.unwrap_or(head))).then_some(Self(text))
    }
}

/// RFC 2397's `[ mediatype ]`: empty, or `type/subtype` then `;attribute=value` parameters.
fn media_type(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let mut parts = text.split(';');
    let essence = parts.next().and_then(|essence| essence.split_once('/'));
    essence.is_some_and(|(kind, subtype)| token(kind) && token(subtype))
        && parts.all(|parameter| {
            parameter
                .split_once('=')
                .is_some_and(|(name, value)| token(name) && !value.is_empty())
        })
}

/// An RFC 2045 token.
fn token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&byte))
}

/// A Subresource Integrity value (W3C SRI §3.5): one or more hash expressions, each an algorithm
/// of `sha256`, `sha384` or `sha512`, `-`, and base64 of a digest of its length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity(String);

impl Integrity {
    /// The value as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The integrity value; `None` outside W3C SRI's grammar or with a digest of another length
    /// than its algorithm's.
    #[must_use]
    pub fn parse(text: String) -> Option<Self> {
        let well_formed = {
            let mut expressions = text.split_ascii_whitespace();
            let first = expressions.next()?;
            std::iter::once(first)
                .chain(expressions)
                .all(hash_expression)
        };
        well_formed.then_some(Self(text))
    }
}

/// W3C SRI's `hash-expression`, its digest the length its algorithm gives.
fn hash_expression(expression: &str) -> bool {
    let Some((algorithm, digest)) = expression.split_once('-') else {
        return false;
    };
    let octets = match algorithm {
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        _ => return false,
    };
    STANDARD
        .decode(digest)
        .is_ok_and(|digest| digest.len() == octets)
}

/// A JSON number's exact decimal value, its sign aside: its digits without leading or trailing
/// zeros, and how many of the value's digits stand before its point.
struct Exact {
    significant: String,
    point: i64,
}

impl Exact {
    /// The value of a number as written; `None` for an exponent beyond 64 bits.
    fn of(text: &str) -> Option<Self> {
        let text = text.strip_prefix('-').unwrap_or(text);
        let (mantissa, exponent) = match text.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, Some(exponent)),
            None => (text, None),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let written = format!("{whole}{fraction}");
        let significant = written.trim_start_matches('0');
        let leading = written.len() - significant.len();
        let significant = significant.trim_end_matches('0');
        if significant.is_empty() {
            return Some(Self {
                significant: String::new(),
                point: 0,
            });
        }
        let exponent: i64 = match exponent {
            Some(exponent) => exponent.parse().ok()?,
            None => 0,
        };
        let before = i64::try_from(whole.len()).ok()?;
        let leading = i64::try_from(leading).ok()?;
        Some(Self {
            significant: significant.to_owned(),
            point: before.saturating_add(exponent).saturating_sub(leading),
        })
    }

    /// The digits the value holds after its point.
    fn fraction_digits(&self) -> i64 {
        i64::try_from(self.significant.len())
            .unwrap_or(i64::MAX)
            .saturating_sub(self.point)
            .max(0)
    }

    /// The digits before its point and those after, in full; `None` beyond what a text can hold.
    fn parts(&self) -> Option<(String, String)> {
        if self.point <= 0 {
            let zeros = usize::try_from(self.point.checked_neg()?).ok()?;
            return Some((
                "0".to_owned(),
                format!("{}{}", "0".repeat(zeros), self.significant),
            ));
        }
        let at = usize::try_from(self.point).ok()?;
        if at >= self.significant.len() {
            let zeros = "0".repeat(at - self.significant.len());
            return Some((format!("{}{zeros}", self.significant), String::new()));
        }
        let (units, cents) = self.significant.split_at_checked(at)?;
        Some((units.to_owned(), cents.to_owned()))
    }
}

/// An amount, with exactly its currency's minor-unit digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount(String);

impl Amount {
    /// The exact decimal value of a JSON number as written, with at most `minor` fractional
    /// digits, and exactly that many in the text.
    fn parse(
        number: &Number<'_>,
        minor: MinorDigits,
        path: FieldPath,
    ) -> Result<Self, PayloadRefusal> {
        let digits = || PayloadRefusal::Digits { path };
        let text = number.text();
        if text.starts_with('-') {
            return Err(PayloadRefusal::Negative { path });
        }
        let exact = Exact::of(text).ok_or_else(digits)?;
        if exact.fraction_digits() > i64::from(minor.0)
            || exact.point.saturating_add(i64::from(minor.0)) > MAX_DIGITS
        {
            return Err(digits());
        }
        let (units, cents) = exact.parts().ok_or_else(digits)?;
        Ok(Self(with_minor(&units, &cents, usize::from(minor.0))))
    }

    /// The amount's number.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `mit_options.apr`: the exact decimal value of a JSON number, not negative, within 38 digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apr(String);

impl Apr {
    fn parse(number: &Number<'_>) -> Result<Self, PayloadRefusal> {
        let refused = || PayloadRefusal::Kind {
            path: APR,
            kind: Expected::Decimal,
        };
        let text = number.text();
        if text.starts_with('-') {
            return Err(refused());
        }
        let exact = Exact::of(text).ok_or_else(refused)?;
        if exact.point.max(0).saturating_add(exact.fraction_digits()) > MAX_DIGITS {
            return Err(refused());
        }
        let (units, cents) = exact.parts().ok_or_else(refused)?;
        Ok(Self(with_minor(&units, &cents, cents.len())))
    }
}

/// `units`, then `cents` padded to `minor` digits.
fn with_minor(units: &str, cents: &str, minor: usize) -> String {
    if minor == 0 {
        units.to_owned()
    } else {
        format!("{units}.{cents:0<minor$}")
    }
}

/// An ISO 4217 code of the core's table, as `^[A-Z]{3}$` (TS12's schema) writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyCode {
    code: String,
    minor: MinorDigits,
}

/// A currency's minor-unit digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinorDigits(u8);

/// An ISO 8601 calendar date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarDate(String);

/// An ISO 8601 date-time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateTime(String);

/// `payee.logo`: a data URL, or an https URL with its SRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Logo {
    /// A data URL.
    Data(DataUrl),
    /// An https URL and `payee.logo#integrity`.
    Https {
        /// The URL.
        url: HttpsUrl,
        /// The SRI value.
        integrity: Integrity,
    },
}

/// Declares the type of a member whose value holds its role alone.
macro_rules! role {
    ($($(#[$doc:meta])* $name:ident($value:ty);)+) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct $name($value);
        )+
    };
}

role! {
    /// `transaction_id`: one to 36 characters (the schemas' `minLength` and `maxLength`).
    TransactionId(String);
    /// `service`: at most 100 characters (the login schema's `maxLength`).
    Service(String);
    /// `action`: at most 140 characters (the login schema's `maxLength`).
    Action(String);
    /// `payee.name`.
    PayeeName(String);
    /// `payee.id`.
    PayeeId(String);
    /// `pisp.legal_name`.
    PispLegalName(String);
    /// `pisp.brand_name`.
    PispBrandName(String);
    /// `pisp.domain_name`.
    PispDomainName(String);
    /// `recurrence.number`.
    RecurrenceNumber(u64);
    /// `mit_options.initial_amount_number`.
    InitialAmountNumber(u64);
    /// `amount_estimated`.
    AmountEstimated(bool);
    /// `amount_earmarked`.
    AmountEarmarked(bool);
    /// `sct_inst`.
    SctInst(bool);
    /// `mit_options.amount_variable`.
    AmountVariable(bool);
}

/// `payee`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payee {
    name: PayeeName,
    id: PayeeId,
    logo: Option<Logo>,
    website: Option<HttpsUrl>,
}

/// `pisp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pisp {
    legal_name: PispLegalName,
    brand_name: PispBrandName,
    domain_name: PispDomainName,
}

/// `recurrence.mit_options`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitOptions {
    amount_variable: Option<AmountVariable>,
    min_amount: Option<Amount>,
    max_amount: Option<Amount>,
    total_amount: Option<Amount>,
    initial_amount: Option<Amount>,
    initial_amount_number: Option<InitialAmountNumber>,
    apr: Option<Apr>,
}

/// `recurrence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recurrence {
    start_date: Option<CalendarDate>,
    end_date: Option<CalendarDate>,
    number: Option<RecurrenceNumber>,
    frequency: Frequency,
    mit_options: Option<MitOptions>,
}

/// When a payment executes: on a date, recurring, or unstated; TS12 §4.3.1 forbids both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Execution {
    /// Neither `execution_date` nor `recurrence`.
    Unstated,
    /// `execution_date`.
    On(CalendarDate),
    /// `recurrence`.
    Recurring(Box<Recurrence>),
}

/// A `urn:eudi:sca:payment:1` payload (TS12 §4.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    transaction_id: TransactionId,
    date_time: Option<DateTime>,
    payee: Payee,
    pisp: Option<Pisp>,
    execution: Execution,
    currency: CurrencyCode,
    amount: Amount,
    amount_estimated: Option<AmountEstimated>,
    amount_earmarked: Option<AmountEarmarked>,
    sct_inst: Option<SctInst>,
}

/// A `urn:eudi:sca:login_risk_transaction:1` payload (TS12 §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRisk {
    transaction_id: TransactionId,
    date_time: Option<DateTime>,
    service: Option<Service>,
    action: Action,
}

/// A typed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ts12Payload {
    /// A payment.
    Payment(Box<Payment>),
    /// An action.
    LoginRisk(LoginRisk),
}

/// An object's members, each read once, closed to a list of fields.
struct Closed<'n> {
    object: &'n Object<'n>,
}

impl<'n> Closed<'n> {
    fn of(node: &'n Node<'n>, at: FieldPath, listed: &[FieldPath]) -> Result<Self, PayloadRefusal> {
        let object = node.as_object().ok_or(PayloadRefusal::Kind {
            path: at,
            kind: Expected::Object,
        })?;
        if let Some(name) = object
            .names()
            .find(|name| !listed.iter().any(|field| field.name() == *name))
        {
            return Err(PayloadRefusal::Member {
                within: at,
                name: name.to_owned(),
            });
        }
        Ok(Self { object })
    }

    fn get(&self, field: FieldPath) -> Option<&'n Node<'n>> {
        self.object.get(field.name())
    }

    fn required(&self, field: FieldPath) -> Result<&'n Node<'n>, PayloadRefusal> {
        self.get(field)
            .ok_or(PayloadRefusal::Required { path: field })
    }

    fn text_of(field: FieldPath, node: &'n Node<'n>) -> Result<&'n str, PayloadRefusal> {
        node.as_str().ok_or(PayloadRefusal::Kind {
            path: field,
            kind: Expected::String,
        })
    }

    fn text(&self, field: FieldPath) -> Result<Option<&'n str>, PayloadRefusal> {
        self.get(field)
            .map(|node| Self::text_of(field, node))
            .transpose()
    }

    fn required_text(&self, field: FieldPath) -> Result<&'n str, PayloadRefusal> {
        Self::text_of(field, self.required(field)?)
    }

    /// `transaction_id`, of the object the field table lists it in.
    fn transaction_id(&self) -> Result<TransactionId, PayloadRefusal> {
        let id = self.required_text(TRANSACTION_ID)?;
        if id.is_empty() {
            return Err(PayloadRefusal::Length {
                path: TRANSACTION_ID,
                max: TRANSACTION_ID_MAX,
            });
        }
        bounded(TRANSACTION_ID, id, TRANSACTION_ID_MAX).map(TransactionId)
    }

    fn boolean(&self, field: FieldPath) -> Result<Option<bool>, PayloadRefusal> {
        match self.get(field) {
            None => Ok(None),
            Some(Node::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(PayloadRefusal::Kind {
                path: field,
                kind: Expected::Boolean,
            }),
        }
    }

    fn number(&self, field: FieldPath) -> Result<Option<&'n Number<'n>>, PayloadRefusal> {
        match self.get(field) {
            None => Ok(None),
            Some(Node::Number(number)) => Ok(Some(number)),
            Some(_) => Err(PayloadRefusal::Kind {
                path: field,
                kind: Expected::Number,
            }),
        }
    }

    /// A number without fraction or exponent, not negative.
    fn integer(&self, field: FieldPath) -> Result<Option<u64>, PayloadRefusal> {
        self.number(field)?
            .map(|number| {
                number.text().parse().map_err(|_| PayloadRefusal::Kind {
                    path: field,
                    kind: Expected::Integer,
                })
            })
            .transpose()
    }

    fn amount(
        &self,
        field: FieldPath,
        currency: &CurrencyCode,
    ) -> Result<Option<Amount>, PayloadRefusal> {
        self.number(field)?
            .map(|number| Amount::parse(number, currency.minor, field))
            .transpose()
    }

    fn date(&self, field: FieldPath) -> Result<Option<CalendarDate>, PayloadRefusal> {
        self.text(field)?
            .map(|text| {
                formatted(FormattedKind::Date, Written::Text(text))
                    .map(|_| CalendarDate(text.to_owned()))
                    .map_err(|_| PayloadRefusal::Date {
                        path: field,
                        form: DateForm::Calendar,
                    })
            })
            .transpose()
    }

    fn date_time(&self, field: FieldPath) -> Result<Option<DateTime>, PayloadRefusal> {
        self.text(field)?
            .map(|text| {
                formatted(FormattedKind::DateTime, Written::Text(text))
                    .map(|_| DateTime(text.to_owned()))
                    .map_err(|_| PayloadRefusal::Date {
                        path: field,
                        form: DateForm::DateTime,
                    })
            })
            .transpose()
    }
}

/// The text within the schema's `maxLength`, counted in characters (JSON Schema §6.3.1).
fn bounded(path: FieldPath, text: &str, max: MaxChars) -> Result<String, PayloadRefusal> {
    if text.chars().count() > max.0 {
        return Err(PayloadRefusal::Length { path, max });
    }
    Ok(text.to_owned())
}

/// A string of PaSO's payload.
fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

/// An integer as PaSO's plain value: its decimal text.
fn integer(value: u64) -> Node<'static> {
    text(&value.to_string())
}

impl Ts12Payload {
    /// The payload of a type, parsed per its field table.
    ///
    /// # Errors
    ///
    /// [`PayloadRefusal`]: the rule the payload breaks.
    pub fn parse(kind: Ts12Type, payload: &Node<'_>) -> Result<Self, PayloadRefusal> {
        match kind {
            Ts12Type::Payment => Payment::parse(payload).map(|p| Self::Payment(Box::new(p))),
            Ts12Type::LoginRisk => LoginRisk::parse(payload).map(Self::LoginRisk),
        }
    }

    /// The payload in PaSO's value forms: an amount with its currency as `iso_currency_amount`
    /// text, an integer and `apr` as their decimal text.
    #[must_use]
    pub fn paso_payload(&self) -> Object<'static> {
        match self {
            Self::Payment(payment) => payment.paso(),
            Self::LoginRisk(login) => login.paso(),
        }
    }

    /// `payee.logo`.
    #[must_use]
    pub fn logo(&self) -> Option<&Logo> {
        match self {
            Self::Payment(payment) => payment.payee.logo.as_ref(),
            Self::LoginRisk(_) => None,
        }
    }
}

impl LoginRisk {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(node, PAYLOAD, &[TRANSACTION_ID, DATE_TIME, SERVICE, ACTION])?;
        let action = at.required_text(ACTION)?;
        Ok(Self {
            transaction_id: at.transaction_id()?,
            date_time: at.date_time(DATE_TIME)?,
            service: at
                .text(SERVICE)?
                .map(|service| bounded(SERVICE, service, SERVICE_MAX).map(Service))
                .transpose()?,
            action: Action(bounded(ACTION, action, ACTION_MAX)?),
        })
    }

    fn paso(&self) -> Object<'static> {
        known_object! {
            "transaction_id" => Some(text(&self.transaction_id.0)),
            "date_time" => self.date_time.as_ref().map(|date| text(&date.0)),
            "service" => self.service.as_ref().map(|service| text(&service.0)),
            "action" => Some(text(&self.action.0)),
        }
    }
}

impl Payment {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            PAYLOAD,
            &[
                TRANSACTION_ID,
                DATE_TIME,
                PAYEE,
                PISP,
                EXECUTION_DATE,
                CURRENCY,
                AMOUNT,
                AMOUNT_ESTIMATED,
                AMOUNT_EARMARKED,
                SCT_INST,
                RECURRENCE,
            ],
        )?;
        let currency = currency(at.required_text(CURRENCY)?)?;
        let amount = at
            .amount(AMOUNT, &currency)?
            .ok_or(PayloadRefusal::Required { path: AMOUNT })?;
        let execution = match (at.date(EXECUTION_DATE)?, at.get(RECURRENCE)) {
            (Some(_), Some(_)) => return Err(PayloadRefusal::ExecutionAndRecurrence),
            (Some(date), None) => Execution::On(date),
            (None, Some(recurrence)) => {
                Execution::Recurring(Box::new(Recurrence::parse(recurrence, &currency)?))
            }
            (None, None) => Execution::Unstated,
        };
        Ok(Self {
            transaction_id: at.transaction_id()?,
            date_time: at.date_time(DATE_TIME)?,
            payee: Payee::parse(at.required(PAYEE)?)?,
            pisp: at.get(PISP).map(Pisp::parse).transpose()?,
            execution,
            currency,
            amount,
            amount_estimated: at.boolean(AMOUNT_ESTIMATED)?.map(AmountEstimated),
            amount_earmarked: at.boolean(AMOUNT_EARMARKED)?.map(AmountEarmarked),
            sct_inst: at.boolean(SCT_INST)?.map(SctInst),
        })
    }

    fn paso(&self) -> Object<'static> {
        let code = &self.currency;
        known_object! {
            "transaction_id" => Some(text(&self.transaction_id.0)),
            "date_time" => self.date_time.as_ref().map(|date| text(&date.0)),
            "payee" => Some(Node::Object(self.payee.paso())),
            "pisp" => self.pisp.as_ref().map(|pisp| Node::Object(pisp.paso())),
            "execution_date" => match &self.execution {
                Execution::On(date) => Some(text(&date.0)),
                Execution::Unstated | Execution::Recurring(_) => None,
            },
            "recurrence" => match &self.execution {
                Execution::Recurring(recurrence) => Some(Node::Object(recurrence.paso(code))),
                Execution::Unstated | Execution::On(_) => None,
            },
            "currency" => Some(text(&code.code)),
            "amount" => Some(with_code(&self.amount, code)),
            "amount_estimated" => self.amount_estimated.as_ref().map(|flag| Node::Bool(flag.0)),
            "amount_earmarked" => self.amount_earmarked.as_ref().map(|flag| Node::Bool(flag.0)),
            "sct_inst" => self.sct_inst.as_ref().map(|flag| Node::Bool(flag.0)),
        }
    }
}

/// An amount as `iso_currency_amount` text.
fn with_code(amount: &Amount, currency: &CurrencyCode) -> Node<'static> {
    text(&format!("{} {}", amount.as_str(), currency.code))
}

/// The code as the core's table reads it, which holds `^[A-Z]{3}$` (TS12's schema).
fn currency(code: &str) -> Result<CurrencyCode, PayloadRefusal> {
    let minor = Currency::from_code(code)
        .and_then(Currency::minor_units)
        .ok_or_else(|| PayloadRefusal::Currency {
            value: code.to_owned(),
        })?;
    Ok(CurrencyCode {
        code: code.to_owned(),
        minor: MinorDigits(minor),
    })
}

impl Payee {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            PAYEE,
            &[
                PAYEE_NAME,
                PAYEE_ID,
                PAYEE_LOGO,
                PAYEE_LOGO_INTEGRITY,
                PAYEE_WEBSITE,
            ],
        )?;
        let website = at
            .text(PAYEE_WEBSITE)?
            .map(|website| {
                HttpsUrl::parse(website).map_err(|_| PayloadRefusal::Kind {
                    path: PAYEE_WEBSITE,
                    kind: Expected::HttpsUrl,
                })
            })
            .transpose()?;
        Ok(Self {
            name: PayeeName(at.required_text(PAYEE_NAME)?.to_owned()),
            id: PayeeId(at.required_text(PAYEE_ID)?.to_owned()),
            logo: logo(&at)?,
            website,
        })
    }

    fn paso(&self) -> Object<'static> {
        let (logo, integrity) = match &self.logo {
            None => (None, None),
            Some(Logo::Data(url)) => (Some(text(&url.0)), None),
            Some(Logo::Https { url, integrity }) => {
                (Some(text(url.written())), Some(text(&integrity.0)))
            }
        };
        known_object! {
            "name" => Some(text(&self.name.0)),
            "id" => Some(text(&self.id.0)),
            "logo" => logo,
            "logo#integrity" => integrity,
            "website" => self.website.as_ref().map(|website| text(website.written())),
        }
    }
}

/// `payee.logo` with `payee.logo#integrity`, which stands beside an https URL alone.
fn logo(at: &Closed<'_>) -> Result<Option<Logo>, PayloadRefusal> {
    let stray = || PayloadRefusal::Member {
        within: PAYEE,
        name: PAYEE_LOGO_INTEGRITY.name().to_owned(),
    };
    let integrity = at.text(PAYEE_LOGO_INTEGRITY)?;
    let Some(written) = at.text(PAYEE_LOGO)? else {
        return match integrity {
            Some(_) => Err(stray()),
            None => Ok(None),
        };
    };
    if written.starts_with("data:") {
        if integrity.is_some() {
            return Err(stray());
        }
        return DataUrl::parse(written.to_owned())
            .map(|url| Some(Logo::Data(url)))
            .ok_or(PayloadRefusal::Kind {
                path: PAYEE_LOGO,
                kind: Expected::DataUrl,
            });
    }
    let url = HttpsUrl::parse(written).map_err(|_| PayloadRefusal::Kind {
        path: PAYEE_LOGO,
        kind: Expected::DataOrHttpsUrl,
    })?;
    let integrity = integrity
        .and_then(|integrity| Integrity::parse(integrity.to_owned()))
        .ok_or(PayloadRefusal::LogoIntegrity)?;
    Ok(Some(Logo::Https { url, integrity }))
}

impl Pisp {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            PISP,
            &[PISP_LEGAL_NAME, PISP_BRAND_NAME, PISP_DOMAIN_NAME],
        )?;
        Ok(Self {
            legal_name: PispLegalName(at.required_text(PISP_LEGAL_NAME)?.to_owned()),
            brand_name: PispBrandName(at.required_text(PISP_BRAND_NAME)?.to_owned()),
            domain_name: PispDomainName(at.required_text(PISP_DOMAIN_NAME)?.to_owned()),
        })
    }

    fn paso(&self) -> Object<'static> {
        known_object! {
            "legal_name" => Some(text(&self.legal_name.0)),
            "brand_name" => Some(text(&self.brand_name.0)),
            "domain_name" => Some(text(&self.domain_name.0)),
        }
    }
}

impl Recurrence {
    fn parse(node: &Node<'_>, currency: &CurrencyCode) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            RECURRENCE,
            &[START_DATE, END_DATE, NUMBER, FREQUENCY, MIT_OPTIONS],
        )?;
        let frequency = at.required_text(FREQUENCY)?;
        Ok(Self {
            start_date: at.date(START_DATE)?,
            end_date: at.date(END_DATE)?,
            number: at.integer(NUMBER)?.map(RecurrenceNumber),
            frequency: Frequency::parse(frequency).ok_or_else(|| PayloadRefusal::Frequency {
                value: frequency.to_owned(),
            })?,
            mit_options: at
                .get(MIT_OPTIONS)
                .map(|options| MitOptions::parse(options, currency))
                .transpose()?,
        })
    }

    fn paso(&self, currency: &CurrencyCode) -> Object<'static> {
        known_object! {
            "start_date" => self.start_date.as_ref().map(|date| text(&date.0)),
            "end_date" => self.end_date.as_ref().map(|date| text(&date.0)),
            "number" => self.number.as_ref().map(|number| integer(number.0)),
            "frequency" => Some(text(self.frequency.code())),
            "mit_options" => self
                .mit_options
                .as_ref()
                .map(|options| Node::Object(options.paso(currency))),
        }
    }
}

impl MitOptions {
    fn parse(node: &Node<'_>, currency: &CurrencyCode) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            MIT_OPTIONS,
            &[
                AMOUNT_VARIABLE,
                MIN_AMOUNT,
                MAX_AMOUNT,
                TOTAL_AMOUNT,
                INITIAL_AMOUNT,
                INITIAL_AMOUNT_NUMBER,
                APR,
            ],
        )?;
        Ok(Self {
            amount_variable: at.boolean(AMOUNT_VARIABLE)?.map(AmountVariable),
            min_amount: at.amount(MIN_AMOUNT, currency)?,
            max_amount: at.amount(MAX_AMOUNT, currency)?,
            total_amount: at.amount(TOTAL_AMOUNT, currency)?,
            initial_amount: at.amount(INITIAL_AMOUNT, currency)?,
            initial_amount_number: at.integer(INITIAL_AMOUNT_NUMBER)?.map(InitialAmountNumber),
            apr: at.number(APR)?.map(Apr::parse).transpose()?,
        })
    }

    fn paso(&self, currency: &CurrencyCode) -> Object<'static> {
        let amount =
            |amount: &Option<Amount>| amount.as_ref().map(|amount| with_code(amount, currency));
        known_object! {
            "amount_variable" => self.amount_variable.as_ref().map(|flag| Node::Bool(flag.0)),
            "min_amount" => amount(&self.min_amount),
            "max_amount" => amount(&self.max_amount),
            "total_amount" => amount(&self.total_amount),
            "initial_amount" => amount(&self.initial_amount),
            "initial_amount_number" => self
                .initial_amount_number
                .as_ref()
                .map(|number| integer(number.0)),
            "apr" => self.apr.as_ref().map(|apr| text(&apr.0)),
        }
    }
}
