//! `urn:eudi:sca:payment:1`: payment confirmation (EC TS12 v1.0.1, Section 4.3.1).

use siros_codec::date::{Date, DateTime};
use siros_codec::json::{Json, JsonNumber};

use crate::currency::CurrencyCode;
use crate::definition::Prominence;
use crate::payload::Frequency;
use crate::ts12::leaves::Leaves;
use crate::ts12::read::{self as json, optional, Fields};
use crate::ts12::read::{MemberPath, Members, Ts12PayloadFault};
use crate::ts12::rules::{self, Amount, DateTimeText, DomainName, LogoUrl, WebUrl};
use crate::ts12::{member, transaction_id, Payload, TransactionId};

/// A payment: the payload of `urn:eudi:sca:payment:1`, also the `payment_payload` of an
/// e-mandate.
pub(crate) struct Payment {
    transaction_id: TransactionId,
    date_time: Option<DateTimeText>,
    payee: Payee,
    pisp: Option<Party>,
    execution_date: Option<Date>,
    currency: CurrencyCode,
    amount: Amount,
    amount_estimated: Option<bool>,
    amount_earmarked: Option<bool>,
    sct_inst: Option<bool>,
    recurrence: Option<Recurrence>,
}

/// `payee`. Its schema leaves further members open.
struct Payee {
    name: String,
    id: String,
    logo: Option<LogoUrl>,
    website: Option<WebUrl>,
    rest: Vec<(String, Json)>,
}

/// A third party: the `pisp` of a payment, the `aisp` of an account access. Its schema leaves
/// further members open.
pub(crate) struct Party {
    legal_name: String,
    brand_name: String,
    domain_name: DomainName,
    rest: Vec<(String, Json)>,
}

/// The paths of a party's members.
pub(crate) struct PartyPaths {
    pub(crate) legal_name: MemberPath,
    pub(crate) brand_name: MemberPath,
    pub(crate) domain_name: MemberPath,
}

/// `recurrence`. Its schema leaves further members open.
struct Recurrence {
    start_date: Option<Date>,
    end_date: Option<Date>,
    number: Option<JsonNumber>,
    frequency: Frequency,
    mit_options: Option<MitOptions>,
    rest: Vec<(String, Json)>,
}

/// `recurrence.mit_options`. Its schema leaves further members open.
struct MitOptions {
    amount_variable: Option<bool>,
    min_amount: Option<Amount>,
    max_amount: Option<Amount>,
    total_amount: Option<Amount>,
    initial_amount: Option<Amount>,
    initial_amount_number: Option<JsonNumber>,
    apr: Option<JsonNumber>,
    rest: Vec<(String, Json)>,
}

const PISP: PartyPaths = PartyPaths {
    legal_name: MemberPath::new("pisp.legal_name"),
    brand_name: MemberPath::new("pisp.brand_name"),
    domain_name: MemberPath::new("pisp.domain_name"),
};

impl Payload for Payment {
    /// The payment of `fields` at the time `now`.
    ///
    /// Besides its schema, Section 4.3.1 requires: `currency` an ISO 4217 code; `amount` and the
    /// amounts of `mit_options` in the currency's minor unit; `execution_date` a date not before
    /// the UTC date of `now`, and absent when `recurrence` is present; dates and dates and times
    /// in ISO 8601; `payee.logo` a resolvable or `data` URL, `payee.website` a resolvable URL;
    /// `pisp.domain_name` a domain name.
    fn parse(mut fields: Fields, now: DateTime) -> Result<Self, Ts12PayloadFault> {
        let currency = rules::currency(
            fields.require_member("currency", member("currency"))?,
            member("currency"),
        )?;
        let payment = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(
                &mut fields,
                "date_time",
                member("date_time"),
                rules::date_time,
            )?,
            payee: Payee::parse(json::object(
                fields.require_member("payee", member("payee"))?,
                member("payee"),
            )?)?,
            pisp: optional(&mut fields, "pisp", member("pisp"), |value, path| {
                Party::parse(json::object(value, path)?, &PISP)
            })?,
            execution_date: optional(
                &mut fields,
                "execution_date",
                member("execution_date"),
                |value, path| {
                    let date = rules::date(value, path)?;
                    if date < now.date() {
                        return Err(Ts12PayloadFault::Invalid(path));
                    }
                    Ok(date)
                },
            )?,
            currency,
            amount: rules::amount(
                fields.require_member("amount", member("amount"))?,
                member("amount"),
                currency,
            )?,
            amount_estimated: optional(
                &mut fields,
                "amount_estimated",
                member("amount_estimated"),
                json::boolean,
            )?,
            amount_earmarked: optional(
                &mut fields,
                "amount_earmarked",
                member("amount_earmarked"),
                json::boolean,
            )?,
            sct_inst: optional(&mut fields, "sct_inst", member("sct_inst"), json::boolean)?,
            recurrence: optional(
                &mut fields,
                "recurrence",
                member("recurrence"),
                |value, path| Recurrence::parse(json::object(value, path)?, currency),
            )?,
        };
        fields.finish()?;
        if payment.execution_date.is_some() && payment.recurrence.is_some() {
            return Err(Ts12PayloadFault::NotAllowed(member("execution_date")));
        }
        Ok(payment)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text(
            "transaction_id",
            &self.transaction_id,
            Some(Prominence::Main),
        );
        leaves.optional_date_time("date_time", self.date_time.as_ref());
        leaves.object("payee", |payee| {
            payee.text("name", &self.payee.name, Some(Prominence::Prominent));
            payee.text("id", &self.payee.id, Some(Prominence::Main));
            payee.optional_logo("logo", self.payee.logo.as_ref());
            payee.optional_text("website", self.payee.website.as_ref());
            payee.rest(&self.payee.rest);
        });
        if let Some(pisp) = &self.pisp {
            leaves.object("pisp", |leaves| pisp.leaves(leaves));
        }
        leaves.optional_date("execution_date", self.execution_date);
        leaves.currency("currency", self.currency, Some(Prominence::Prominent));
        leaves.number("amount", self.amount.number(), Some(Prominence::Prominent));
        leaves.optional_boolean("amount_estimated", self.amount_estimated);
        leaves.optional_boolean("amount_earmarked", self.amount_earmarked);
        leaves.optional_boolean("sct_inst", self.sct_inst);
        if let Some(recurrence) = &self.recurrence {
            leaves.object("recurrence", |leaves| recurrence.leaves(leaves));
        }
    }
}

impl Payee {
    fn parse(mut fields: Fields) -> Result<Self, Ts12PayloadFault> {
        const NAME: MemberPath = MemberPath::new("payee.name");
        const ID: MemberPath = MemberPath::new("payee.id");
        Ok(Self {
            name: json::text(fields.require_member("name", NAME)?, NAME)?,
            id: json::text(fields.require_member("id", ID)?, ID)?,
            logo: optional(
                &mut fields,
                "logo",
                MemberPath::new("payee.logo"),
                rules::image,
            )?,
            website: optional(
                &mut fields,
                "website",
                MemberPath::new("payee.website"),
                rules::url,
            )?,
            rest: fields.rest(),
        })
    }
}

impl Party {
    /// The party of `fields`, its members at `paths`.
    pub(crate) fn parse(mut fields: Fields, paths: &PartyPaths) -> Result<Self, Ts12PayloadFault> {
        Ok(Self {
            legal_name: json::text(
                fields.require_member("legal_name", paths.legal_name)?,
                paths.legal_name,
            )?,
            brand_name: json::text(
                fields.require_member("brand_name", paths.brand_name)?,
                paths.brand_name,
            )?,
            domain_name: rules::domain_name(
                fields.require_member("domain_name", paths.domain_name)?,
                paths.domain_name,
            )?,
            rest: fields.rest(),
        })
    }

    /// Its leaves.
    pub(crate) fn leaves(&self, leaves: &mut Leaves) {
        leaves.text("legal_name", &self.legal_name, None);
        leaves.text("brand_name", &self.brand_name, None);
        leaves.text("domain_name", &self.domain_name, None);
        leaves.rest(&self.rest);
    }
}

impl Recurrence {
    /// The recurrence of `fields` of a payment in `currency`.
    fn parse(mut fields: Fields, currency: CurrencyCode) -> Result<Self, Ts12PayloadFault> {
        Ok(Self {
            start_date: optional(
                &mut fields,
                "start_date",
                MemberPath::new("recurrence.start_date"),
                rules::date,
            )?,
            end_date: optional(
                &mut fields,
                "end_date",
                MemberPath::new("recurrence.end_date"),
                rules::date,
            )?,
            number: optional(
                &mut fields,
                "number",
                MemberPath::new("recurrence.number"),
                json::integer,
            )?,
            frequency: frequency(
                fields.require_member("frequency", MemberPath::new("recurrence.frequency"))?,
            )?,
            mit_options: optional(
                &mut fields,
                "mit_options",
                MemberPath::new("recurrence.mit_options"),
                |value, path| MitOptions::parse(json::object(value, path)?, currency),
            )?,
            rest: fields.rest(),
        })
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.optional_date("start_date", self.start_date);
        leaves.optional_date("end_date", self.end_date);
        leaves.optional_number("number", self.number.as_ref());
        leaves.frequency("frequency", self.frequency);
        if let Some(options) = &self.mit_options {
            leaves.object("mit_options", |leaves| options.leaves(leaves));
        }
        leaves.rest(&self.rest);
    }
}

impl MitOptions {
    /// The options of `fields`, their amounts in `currency`.
    fn parse(mut fields: Fields, currency: CurrencyCode) -> Result<Self, Ts12PayloadFault> {
        let amount = |value: Json, path: MemberPath| rules::amount(value, path, currency);
        const AMOUNT_VARIABLE: MemberPath =
            MemberPath::new("recurrence.mit_options.amount_variable");
        const MIN_AMOUNT: MemberPath = MemberPath::new("recurrence.mit_options.min_amount");
        const MAX_AMOUNT: MemberPath = MemberPath::new("recurrence.mit_options.max_amount");
        const TOTAL_AMOUNT: MemberPath = MemberPath::new("recurrence.mit_options.total_amount");
        const INITIAL_AMOUNT: MemberPath = MemberPath::new("recurrence.mit_options.initial_amount");
        const INITIAL_AMOUNT_NUMBER: MemberPath =
            MemberPath::new("recurrence.mit_options.initial_amount_number");
        const APR: MemberPath = MemberPath::new("recurrence.mit_options.apr");
        Ok(Self {
            amount_variable: optional(
                &mut fields,
                "amount_variable",
                AMOUNT_VARIABLE,
                json::boolean,
            )?,
            min_amount: optional(&mut fields, "min_amount", MIN_AMOUNT, amount)?,
            max_amount: optional(&mut fields, "max_amount", MAX_AMOUNT, amount)?,
            total_amount: optional(&mut fields, "total_amount", TOTAL_AMOUNT, amount)?,
            initial_amount: optional(&mut fields, "initial_amount", INITIAL_AMOUNT, amount)?,
            initial_amount_number: optional(
                &mut fields,
                "initial_amount_number",
                INITIAL_AMOUNT_NUMBER,
                json::integer,
            )?,
            apr: optional(&mut fields, "apr", APR, json::number)?,
            rest: fields.rest(),
        })
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.optional_boolean("amount_variable", self.amount_variable);
        leaves.optional_number("min_amount", self.min_amount.as_ref().map(Amount::number));
        leaves.optional_number("max_amount", self.max_amount.as_ref().map(Amount::number));
        leaves.optional_number(
            "total_amount",
            self.total_amount.as_ref().map(Amount::number),
        );
        leaves.optional_number(
            "initial_amount",
            self.initial_amount.as_ref().map(Amount::number),
        );
        leaves.optional_number("initial_amount_number", self.initial_amount_number.as_ref());
        leaves.optional_number("apr", self.apr.as_ref());
        leaves.rest(&self.rest);
    }
}

/// `recurrence.frequency`: one of the ISO 20022 codes the schema enumerates.
fn frequency(value: Json) -> Result<Frequency, Ts12PayloadFault> {
    const PATH: MemberPath = MemberPath::new("recurrence.frequency");
    Frequency::named(&json::text(value, PATH)?).ok_or(Ts12PayloadFault::Invalid(PATH))
}
