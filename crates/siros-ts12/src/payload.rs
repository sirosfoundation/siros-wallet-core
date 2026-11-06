//! A payload's typed parse (TS12 §4.3.1, §4.3.2, and the schemas their sources publish) and the
//! same values in PaSO's forms (View §3). Any member TS12 does not list is refused at any depth
//! (PaSO Core §7.4.2 step 2).

use std::borrow::Cow;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use siros_explain::{Currency, Explain};
use siros_openid4vp::json::{JsonError, Node, Number, Object};
use siros_openid4vp::rows::HttpsUrl;
use siros_paso::frequency::Frequency;
use siros_paso::value::{FormattedKind, Written, formatted};

use crate::document::Ts12Type;

/// An exact decimal's digits in PaSO's amounts (View §3).
const MAX_DIGITS: i64 = 38;
/// The schemas' `transaction_id` `maxLength`.
const TRANSACTION_ID_MAX: usize = 36;
/// The login schema's `service` `maxLength`.
const SERVICE_MAX: usize = 100;
/// The login schema's `action` `maxLength`.
const ACTION_MAX: usize = 140;

/// Why a payload is refused: the entry is not compatible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "ts12.payload")]
pub enum PayloadRefusal {
    /// A member TS12 does not list, at any depth.
    #[error("{path}: a member TS12 does not list")]
    Member {
        /// The member.
        path: String,
    },
    /// A required member absent.
    #[error("{path} is required")]
    Required {
        /// The member.
        path: String,
    },
    /// A member of another JSON type than TS12's: its kind names what TS12 lists.
    #[error("{path} is no {kind}")]
    Kind {
        /// The member.
        path: String,
        /// What TS12 lists.
        kind: &'static str,
    },
    /// A string outside the length TS12's schema gives its member.
    #[error("{path} holds no 1 to {max} characters")]
    Length {
        /// The member.
        path: String,
        /// The schema's `maxLength`.
        max: usize,
    },
    /// An amount with more fractional digits than its currency's minor unit, or beyond an exact
    /// decimal's 38 digits.
    #[error("{path} has more digits than its currency")]
    Digits {
        /// The member.
        path: String,
    },
    /// A negative amount: TS12 defines no negative payment.
    #[error("{path} is negative")]
    Negative {
        /// The member.
        path: String,
    },
    /// `execution_date` beside `recurrence` (TS12 §4.3.1).
    #[error("execution_date beside recurrence")]
    ExecutionAndRecurrence,
    /// A date that is no ISO 8601 calendar date, or a date-time that is none.
    #[error("{path} is no ISO 8601 {form}")]
    Date {
        /// The member.
        path: String,
        /// `calendar date` or `date-time`.
        form: &'static str,
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

/// An amount, with exactly its currency's minor-unit digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount(String);

impl Amount {
    /// The exact decimal value of a JSON number as written, with at most `minor` fractional
    /// digits, and exactly that many in the text.
    fn parse(number: &Number<'_>, minor: u8, path: &str) -> Result<Self, PayloadRefusal> {
        let digits = || PayloadRefusal::Digits {
            path: path.to_owned(),
        };
        let text = number.text();
        if text.starts_with('-') {
            return Err(PayloadRefusal::Negative {
                path: path.to_owned(),
            });
        }
        let (mantissa, exponent) = match text.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, Some(exponent)),
            None => (text, None),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let written = format!("{whole}{fraction}");
        let significant = written.trim_start_matches('0');
        let leading = written.len() - significant.len();
        let significant = significant.trim_end_matches('0');
        let minor_digits = usize::from(minor);
        if significant.is_empty() {
            return Ok(Self(with_minor("0", "", minor_digits)));
        }
        let exponent: i64 = match exponent {
            Some(exponent) => exponent.parse().map_err(|_| digits())?,
            None => 0,
        };
        let before = i64::try_from(whole.len()).map_err(|_| digits())?;
        let leading = i64::try_from(leading).map_err(|_| digits())?;
        // Where the decimal point falls after `significant`'s first digit's position.
        let point = before.saturating_add(exponent).saturating_sub(leading);
        let held = i64::try_from(significant.len()).map_err(|_| digits())?;
        if held.saturating_sub(point) > i64::from(minor)
            || point.saturating_add(i64::from(minor)) > MAX_DIGITS
        {
            return Err(digits());
        }
        let padded;
        let (units, cents): (&str, String) = if point <= 0 {
            let zeros = usize::try_from(-point).map_err(|_| digits())?;
            ("0", format!("{}{significant}", "0".repeat(zeros)))
        } else {
            let at = usize::try_from(point).map_err(|_| digits())?;
            if at >= significant.len() {
                padded = format!("{significant}{}", "0".repeat(at - significant.len()));
                (padded.as_str(), String::new())
            } else {
                let units = significant.get(..at).ok_or_else(digits)?;
                let cents = significant.get(at..).ok_or_else(digits)?;
                (units, cents.to_owned())
            }
        };
        Ok(Self(with_minor(units, &cents, minor_digits)))
    }

    /// The amount's number.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

/// An ISO 4217 code of the core's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyCode {
    code: String,
    minor: u8,
}

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

/// `payee`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payee {
    name: String,
    id: String,
    logo: Option<Logo>,
    website: Option<HttpsUrl>,
}

/// `pisp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pisp {
    legal_name: String,
    brand_name: String,
    domain_name: String,
}

/// `recurrence.mit_options`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitOptions {
    amount_variable: Option<bool>,
    min_amount: Option<Amount>,
    max_amount: Option<Amount>,
    total_amount: Option<Amount>,
    initial_amount: Option<Amount>,
    initial_amount_number: Option<u64>,
    apr: Option<String>,
}

/// `recurrence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recurrence {
    start_date: Option<CalendarDate>,
    end_date: Option<CalendarDate>,
    number: Option<u64>,
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
    transaction_id: String,
    date_time: Option<DateTime>,
    payee: Payee,
    pisp: Option<Pisp>,
    execution: Execution,
    currency: CurrencyCode,
    amount: Amount,
    amount_estimated: Option<bool>,
    amount_earmarked: Option<bool>,
    sct_inst: Option<bool>,
}

/// A `urn:eudi:sca:login_risk_transaction:1` payload (TS12 §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRisk {
    transaction_id: String,
    date_time: Option<DateTime>,
    service: Option<String>,
    action: String,
}

/// A typed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ts12Payload {
    /// A payment.
    Payment(Box<Payment>),
    /// An action.
    LoginRisk(LoginRisk),
}

/// An object's members, each read once, closed to a list of names.
struct Closed<'n> {
    object: &'n Object<'n>,
    at: &'static str,
}

impl<'n> Closed<'n> {
    fn of(node: &'n Node<'n>, at: &'static str, listed: &[&str]) -> Result<Self, PayloadRefusal> {
        let object = node.as_object().ok_or_else(|| PayloadRefusal::Kind {
            path: display_path(at, ""),
            kind: "object",
        })?;
        if let Some(name) = object.names().find(|name| !listed.contains(name)) {
            return Err(PayloadRefusal::Member {
                path: display_path(at, name),
            });
        }
        Ok(Self { object, at })
    }

    fn path(&self, name: &str) -> String {
        display_path(self.at, name)
    }

    fn get(&self, name: &str) -> Option<&'n Node<'n>> {
        self.object.get(name)
    }

    fn required(&self, name: &str) -> Result<&'n Node<'n>, PayloadRefusal> {
        self.get(name).ok_or_else(|| PayloadRefusal::Required {
            path: self.path(name),
        })
    }

    fn kind(&self, name: &str, kind: &'static str) -> PayloadRefusal {
        PayloadRefusal::Kind {
            path: self.path(name),
            kind,
        }
    }

    fn text_of(&self, name: &str, node: &'n Node<'n>) -> Result<&'n str, PayloadRefusal> {
        node.as_str().ok_or_else(|| self.kind(name, "string"))
    }

    fn text(&self, name: &str) -> Result<Option<&'n str>, PayloadRefusal> {
        self.get(name)
            .map(|node| self.text_of(name, node))
            .transpose()
    }

    fn required_text(&self, name: &str) -> Result<&'n str, PayloadRefusal> {
        self.text_of(name, self.required(name)?)
    }

    fn bounded(&self, name: &str, text: &str, max: usize) -> Result<String, PayloadRefusal> {
        let characters = text.chars().count();
        if characters == 0 || characters > max {
            return Err(PayloadRefusal::Length {
                path: self.path(name),
                max,
            });
        }
        Ok(text.to_owned())
    }

    fn boolean(&self, name: &str) -> Result<Option<bool>, PayloadRefusal> {
        match self.get(name) {
            None => Ok(None),
            Some(Node::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(self.kind(name, "boolean")),
        }
    }

    fn number(&self, name: &str) -> Result<Option<&'n Number<'n>>, PayloadRefusal> {
        match self.get(name) {
            None => Ok(None),
            Some(Node::Number(number)) => Ok(Some(number)),
            Some(_) => Err(self.kind(name, "number")),
        }
    }

    /// A number without fraction or exponent, not negative.
    fn integer(&self, name: &str) -> Result<Option<u64>, PayloadRefusal> {
        self.number(name)?
            .map(|number| {
                number
                    .text()
                    .parse()
                    .map_err(|_| self.kind(name, "integer"))
            })
            .transpose()
    }

    fn amount(
        &self,
        name: &str,
        currency: &CurrencyCode,
    ) -> Result<Option<Amount>, PayloadRefusal> {
        self.number(name)?
            .map(|number| Amount::parse(number, currency.minor, &self.path(name)))
            .transpose()
    }

    fn date(&self, name: &str) -> Result<Option<CalendarDate>, PayloadRefusal> {
        self.text(name)?
            .map(|text| {
                formatted(FormattedKind::Date, Written::Text(text))
                    .map(|_| CalendarDate(text.to_owned()))
                    .map_err(|_| PayloadRefusal::Date {
                        path: self.path(name),
                        form: "calendar date",
                    })
            })
            .transpose()
    }

    fn date_time(&self, name: &str) -> Result<Option<DateTime>, PayloadRefusal> {
        self.text(name)?
            .map(|text| {
                formatted(FormattedKind::DateTime, Written::Text(text))
                    .map(|_| DateTime(text.to_owned()))
                    .map_err(|_| PayloadRefusal::Date {
                        path: self.path(name),
                        form: "date-time",
                    })
            })
            .transpose()
    }
}

fn display_path(at: &str, name: &str) -> String {
    match (at.is_empty(), name.is_empty()) {
        (true, _) => name.to_owned(),
        (false, true) => at.to_owned(),
        (false, false) => format!("{at}.{name}"),
    }
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
    ///
    /// # Errors
    ///
    /// A member name repeated, which the field tables exclude.
    pub fn paso_payload(&self) -> Result<Node<'static>, JsonError> {
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
        let at = Closed::of(
            node,
            "",
            &["transaction_id", "date_time", "service", "action"],
        )?;
        let id = at.required_text("transaction_id")?;
        let action = at.required_text("action")?;
        Ok(Self {
            transaction_id: at.bounded("transaction_id", id, TRANSACTION_ID_MAX)?,
            date_time: at.date_time("date_time")?,
            service: at
                .text("service")?
                .map(|service| at.bounded("service", service, SERVICE_MAX))
                .transpose()?,
            action: at.bounded("action", action, ACTION_MAX)?,
        })
    }

    fn paso(&self) -> Result<Node<'static>, JsonError> {
        let mut out = Out::default();
        out.text("transaction_id", &self.transaction_id);
        out.text_of("date_time", self.date_time.as_ref().map(|d| d.0.as_str()));
        out.text_of("service", self.service.as_deref());
        out.text("action", &self.action);
        out.node()
    }
}

impl Payment {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            "",
            &[
                "transaction_id",
                "date_time",
                "payee",
                "pisp",
                "execution_date",
                "currency",
                "amount",
                "amount_estimated",
                "amount_earmarked",
                "sct_inst",
                "recurrence",
            ],
        )?;
        let id = at.required_text("transaction_id")?;
        let currency = currency(at.required_text("currency")?)?;
        let amount = at
            .amount("amount", &currency)?
            .ok_or_else(|| PayloadRefusal::Required {
                path: "amount".to_owned(),
            })?;
        let execution = match (at.date("execution_date")?, at.get("recurrence")) {
            (Some(_), Some(_)) => return Err(PayloadRefusal::ExecutionAndRecurrence),
            (Some(date), None) => Execution::On(date),
            (None, Some(recurrence)) => {
                Execution::Recurring(Box::new(Recurrence::parse(recurrence, &currency)?))
            }
            (None, None) => Execution::Unstated,
        };
        Ok(Self {
            transaction_id: at.bounded("transaction_id", id, TRANSACTION_ID_MAX)?,
            date_time: at.date_time("date_time")?,
            payee: Payee::parse(at.required("payee")?)?,
            pisp: at.get("pisp").map(Pisp::parse).transpose()?,
            execution,
            currency,
            amount,
            amount_estimated: at.boolean("amount_estimated")?,
            amount_earmarked: at.boolean("amount_earmarked")?,
            sct_inst: at.boolean("sct_inst")?,
        })
    }

    fn paso(&self) -> Result<Node<'static>, JsonError> {
        let code = &self.currency.code;
        let mut out = Out::default();
        out.text("transaction_id", &self.transaction_id);
        out.text_of("date_time", self.date_time.as_ref().map(|d| d.0.as_str()));
        out.member("payee", self.payee.paso()?);
        if let Some(pisp) = &self.pisp {
            out.member("pisp", pisp.paso()?);
        }
        match &self.execution {
            Execution::Unstated => {}
            Execution::On(date) => out.text("execution_date", &date.0),
            Execution::Recurring(recurrence) => out.member("recurrence", recurrence.paso(code)?),
        }
        out.text("currency", code);
        out.text("amount", &with_code(&self.amount, code));
        out.boolean("amount_estimated", self.amount_estimated);
        out.boolean("amount_earmarked", self.amount_earmarked);
        out.boolean("sct_inst", self.sct_inst);
        out.node()
    }
}

fn with_code(amount: &Amount, code: &str) -> String {
    format!("{} {code}", amount.as_str())
}

/// The code as `^[A-Z]{3}$` (TS12's schema) and the core's table read it.
fn currency(code: &str) -> Result<CurrencyCode, PayloadRefusal> {
    let refused = || PayloadRefusal::Currency {
        value: code.to_owned(),
    };
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(refused());
    }
    let minor = Currency::from_code(code)
        .and_then(Currency::minor_units)
        .ok_or_else(refused)?;
    Ok(CurrencyCode {
        code: code.to_owned(),
        minor,
    })
}

impl Payee {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            "payee",
            &["name", "id", "logo", "logo#integrity", "website"],
        )?;
        let website = at
            .text("website")?
            .map(|website| HttpsUrl::parse(website).map_err(|_| at.kind("website", "https URL")))
            .transpose()?;
        Ok(Self {
            name: at.required_text("name")?.to_owned(),
            id: at.required_text("id")?.to_owned(),
            logo: logo(&at)?,
            website,
        })
    }

    fn paso(&self) -> Result<Node<'static>, JsonError> {
        let mut out = Out::default();
        out.text("name", &self.name);
        out.text("id", &self.id);
        match &self.logo {
            None => {}
            Some(Logo::Data(url)) => out.text("logo", &url.0),
            Some(Logo::Https { url, integrity }) => {
                out.text("logo", url.written());
                out.text("logo#integrity", &integrity.0);
            }
        }
        if let Some(website) = &self.website {
            out.text("website", website.written());
        }
        out.node()
    }
}

/// `payee.logo` with `payee.logo#integrity`, which stands beside an https URL alone.
fn logo(at: &Closed<'_>) -> Result<Option<Logo>, PayloadRefusal> {
    let integrity = at.text("logo#integrity")?;
    let Some(text) = at.text("logo")? else {
        return match integrity {
            Some(_) => Err(PayloadRefusal::Member {
                path: at.path("logo#integrity"),
            }),
            None => Ok(None),
        };
    };
    if text.starts_with("data:") {
        if integrity.is_some() {
            return Err(PayloadRefusal::Member {
                path: at.path("logo#integrity"),
            });
        }
        return DataUrl::parse(text.to_owned())
            .map(|url| Some(Logo::Data(url)))
            .ok_or_else(|| at.kind("logo", "data URL"));
    }
    let url = HttpsUrl::parse(text).map_err(|_| at.kind("logo", "data URL or https URL"))?;
    let integrity = integrity
        .and_then(|integrity| Integrity::parse(integrity.to_owned()))
        .ok_or(PayloadRefusal::LogoIntegrity)?;
    Ok(Some(Logo::Https { url, integrity }))
}

impl Pisp {
    fn parse(node: &Node<'_>) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(node, "pisp", &["legal_name", "brand_name", "domain_name"])?;
        Ok(Self {
            legal_name: at.required_text("legal_name")?.to_owned(),
            brand_name: at.required_text("brand_name")?.to_owned(),
            domain_name: at.required_text("domain_name")?.to_owned(),
        })
    }

    fn paso(&self) -> Result<Node<'static>, JsonError> {
        let mut out = Out::default();
        out.text("legal_name", &self.legal_name);
        out.text("brand_name", &self.brand_name);
        out.text("domain_name", &self.domain_name);
        out.node()
    }
}

impl Recurrence {
    fn parse(node: &Node<'_>, currency: &CurrencyCode) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            "recurrence",
            &[
                "start_date",
                "end_date",
                "number",
                "frequency",
                "mit_options",
            ],
        )?;
        let frequency = at.required_text("frequency")?;
        Ok(Self {
            start_date: at.date("start_date")?,
            end_date: at.date("end_date")?,
            number: at.integer("number")?,
            frequency: Frequency::parse(frequency).ok_or_else(|| PayloadRefusal::Frequency {
                value: frequency.to_owned(),
            })?,
            mit_options: at
                .get("mit_options")
                .map(|options| MitOptions::parse(options, currency))
                .transpose()?,
        })
    }

    fn paso(&self, code: &str) -> Result<Node<'static>, JsonError> {
        let mut out = Out::default();
        out.text_of("start_date", self.start_date.as_ref().map(|d| d.0.as_str()));
        out.text_of("end_date", self.end_date.as_ref().map(|d| d.0.as_str()));
        out.integer("number", self.number);
        out.text("frequency", self.frequency.code());
        if let Some(options) = &self.mit_options {
            out.member("mit_options", options.paso(code)?);
        }
        out.node()
    }
}

impl MitOptions {
    fn parse(node: &Node<'_>, currency: &CurrencyCode) -> Result<Self, PayloadRefusal> {
        let at = Closed::of(
            node,
            "recurrence.mit_options",
            &[
                "amount_variable",
                "min_amount",
                "max_amount",
                "total_amount",
                "initial_amount",
                "initial_amount_number",
                "apr",
            ],
        )?;
        Ok(Self {
            amount_variable: at.boolean("amount_variable")?,
            min_amount: at.amount("min_amount", currency)?,
            max_amount: at.amount("max_amount", currency)?,
            total_amount: at.amount("total_amount", currency)?,
            initial_amount: at.amount("initial_amount", currency)?,
            initial_amount_number: at.integer("initial_amount_number")?,
            apr: at.number("apr")?.map(|apr| apr.text().to_owned()),
        })
    }

    fn paso(&self, code: &str) -> Result<Node<'static>, JsonError> {
        let mut out = Out::default();
        out.boolean("amount_variable", self.amount_variable);
        let amounts = [
            ("min_amount", &self.min_amount),
            ("max_amount", &self.max_amount),
            ("total_amount", &self.total_amount),
            ("initial_amount", &self.initial_amount),
        ];
        for (name, amount) in amounts {
            if let Some(amount) = amount {
                out.text(name, &with_code(amount, code));
            }
        }
        out.integer("initial_amount_number", self.initial_amount_number);
        out.text_of("apr", self.apr.as_deref());
        out.node()
    }
}

/// A PaSO payload object under construction, in the field table's order.
#[derive(Default)]
struct Out(Vec<(Cow<'static, str>, Node<'static>)>);

impl Out {
    fn member(&mut self, name: &'static str, value: Node<'static>) {
        self.0.push((Cow::Borrowed(name), value));
    }

    fn text(&mut self, name: &'static str, text: &str) {
        self.member(name, Node::String(Cow::Owned(text.to_owned())));
    }

    fn text_of(&mut self, name: &'static str, text: Option<&str>) {
        if let Some(text) = text {
            self.text(name, text);
        }
    }

    fn boolean(&mut self, name: &'static str, value: Option<bool>) {
        if let Some(value) = value {
            self.member(name, Node::Bool(value));
        }
    }

    fn integer(&mut self, name: &'static str, value: Option<u64>) {
        if let Some(value) = value {
            self.text(name, &value.to_string());
        }
    }

    fn node(self) -> Result<Node<'static>, JsonError> {
        Node::object(self.0)
    }
}
