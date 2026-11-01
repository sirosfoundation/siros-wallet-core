//! `urn:eudi:sca:login_risk_transaction:1`, `urn:eudi:sca:account_access:1` and
//! `urn:eudi:sca:emandate:1` (EC TS12 v1.0.1, Sections 4.3.2 to 4.3.4).

use siros_codec::date::DateTime;

use crate::definition::Prominence;
use crate::ts12::leaves::Leaves;
use crate::ts12::payment::{Party, PartyPaths, Payment};
use crate::ts12::read::{self as json, optional, Fields};
use crate::ts12::read::{MemberPath, Members, Ts12PayloadFault};
use crate::ts12::rules::{self, DateOrDateTime, DateTimeText, Text};
use crate::ts12::{member, transaction_id, Payload, TransactionId};

/// Login and risk-based authentication (Section 4.3.2).
pub(crate) struct LoginRisk {
    transaction_id: TransactionId,
    date_time: Option<DateTimeText>,
    service: Option<Text<0, 100>>,
    action: Text<0, 140>,
}

/// Payment account information access (Section 4.3.3).
pub(crate) struct AccountAccess {
    transaction_id: TransactionId,
    date_time: Option<DateTimeText>,
    aisp: Option<Party>,
    description: Option<Text<0, 140>>,
}

/// E-mandate (Section 4.3.4).
pub(crate) struct Emandate {
    transaction_id: TransactionId,
    date_time: Option<DateTimeText>,
    start_date: Option<DateOrDateTime>,
    end_date: Option<DateOrDateTime>,
    reference_number: Option<Text<1, 50>>,
    creditor_id: Option<Text<1, 50>>,
    purpose: Option<Text<0, 1000>>,
    payment_payload: Option<Payment>,
}

const AISP: PartyPaths = PartyPaths {
    legal_name: MemberPath::new("aisp.legal_name"),
    brand_name: MemberPath::new("aisp.brand_name"),
    domain_name: MemberPath::new("aisp.domain_name"),
};

impl Payload for LoginRisk {
    /// Besides its schema, Section 4.3.2 requires `date_time` in ISO 8601.
    fn parse(mut fields: Fields, _now: DateTime) -> Result<Self, Ts12PayloadFault> {
        let login = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(
                &mut fields,
                "date_time",
                member("date_time"),
                rules::date_time,
            )?,
            service: optional(&mut fields, "service", member("service"), Text::parse)?,
            action: Text::parse(
                fields.require_member("action", member("action"))?,
                member("action"),
            )?,
        };
        fields.finish()?;
        Ok(login)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text(
            "transaction_id",
            &self.transaction_id,
            Some(Prominence::Main),
        );
        leaves.optional_date_time("date_time", self.date_time.as_ref());
        leaves.optional_text("service", self.service.as_ref());
        leaves.text("action", &self.action, Some(Prominence::Prominent));
    }
}

impl Payload for AccountAccess {
    /// Besides its schema, Section 4.3.3 requires `date_time` in ISO 8601 and
    /// `aisp.domain_name` a domain name.
    fn parse(mut fields: Fields, _now: DateTime) -> Result<Self, Ts12PayloadFault> {
        let access = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(
                &mut fields,
                "date_time",
                member("date_time"),
                rules::date_time,
            )?,
            aisp: optional(&mut fields, "aisp", member("aisp"), |value, path| {
                Party::parse(json::object(value, path)?, &AISP)
            })?,
            description: optional(
                &mut fields,
                "description",
                member("description"),
                Text::parse,
            )?,
        };
        fields.finish()?;
        Ok(access)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text(
            "transaction_id",
            &self.transaction_id,
            Some(Prominence::Main),
        );
        leaves.optional_date_time("date_time", self.date_time.as_ref());
        if let Some(aisp) = &self.aisp {
            leaves.object("aisp", |leaves| aisp.leaves(leaves));
        }
        leaves.optional_text("description", self.description.as_ref());
    }
}

impl Payload for Emandate {
    /// Besides its schema, Section 4.3.4 requires `date_time` in ISO 8601, `start_date` and
    /// `end_date` an ISO 8601 date or date and time, `purpose` when there is no
    /// `payment_payload`, and `payment_payload` a payment of Section 4.3.1 at the time `now`.
    fn parse(mut fields: Fields, now: DateTime) -> Result<Self, Ts12PayloadFault> {
        let mandate = Self {
            transaction_id: transaction_id(&mut fields)?,
            date_time: optional(
                &mut fields,
                "date_time",
                member("date_time"),
                rules::date_time,
            )?,
            start_date: optional(
                &mut fields,
                "start_date",
                member("start_date"),
                rules::date_or_date_time,
            )?,
            end_date: optional(
                &mut fields,
                "end_date",
                member("end_date"),
                rules::date_or_date_time,
            )?,
            reference_number: optional(
                &mut fields,
                "reference_number",
                member("reference_number"),
                Text::parse,
            )?,
            creditor_id: optional(
                &mut fields,
                "creditor_id",
                member("creditor_id"),
                Text::parse,
            )?,
            purpose: optional(&mut fields, "purpose", member("purpose"), Text::parse)?,
            // The schema's `$ref` to the payment schema.
            payment_payload: optional(
                &mut fields,
                "payment_payload",
                member("payment_payload"),
                |value, path| Payment::parse(json::object(value, path)?, now),
            )?,
        };
        fields.finish()?;
        // `purpose` is "REQUIRED when `payment` is not present": the payment is
        // `payment_payload`, the only payment member.
        if mandate.purpose.is_none() && mandate.payment_payload.is_none() {
            return Err(Ts12PayloadFault::Member(
                member("purpose"),
                siros_codec::member::MemberFault::Absent,
            ));
        }
        Ok(mandate)
    }

    fn leaves(&self, leaves: &mut Leaves) {
        leaves.text(
            "transaction_id",
            &self.transaction_id,
            Some(Prominence::Main),
        );
        leaves.optional_date_time("date_time", self.date_time.as_ref());
        leaves.optional_date_or_time("start_date", self.start_date.as_ref());
        leaves.optional_date_or_time("end_date", self.end_date.as_ref());
        leaves.optional_text("reference_number", self.reference_number.as_ref());
        leaves.optional_text("creditor_id", self.creditor_id.as_ref());
        leaves.optional_text("purpose", self.purpose.as_ref());
        if let Some(payment) = &self.payment_payload {
            leaves.object("payment_payload", |leaves| payment.leaves(leaves));
        }
    }
}
