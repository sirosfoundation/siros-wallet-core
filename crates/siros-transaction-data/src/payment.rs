//! The payee and the amount of a payment: what a payment entry of the credential picker shows
//! for an entry of a payment rulebook, EC TS12 v1.0.1's `urn:eudi:sca:payment:1` or PaSO's
//! `urn:paso:sca:global:payment:1`.

use siros_codec::json::Json;

use crate::currency::CurrencyCode;
use crate::payload::{CurrencyAmount, PayloadText};
use crate::sources::Rulebook;
use crate::type_id::{Ts12Type, TypeId};

/// The type identifier of PaSO's Payment rulebook (Payment, Section 1).
const PASO_PAYMENT: &str = "urn:paso:sca:global:payment:1";

/// The payee and the amount of a payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    payee: PayloadText,
    amount: PaymentAmount,
}

/// An amount and its currency, the amount as the payload writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAmount {
    amount: String,
    currency: CurrencyCode,
}

impl Payment {
    /// The payment of `payload`, an entry of `type_id` under `rulebook`: `payee.name` and
    /// `amount` with `currency` under TS12's payment rulebook, `payee.name` and the
    /// `iso_currency_amount` `amount` under PaSO's. `None` for another type, and for a payload
    /// without them in their form.
    pub(crate) fn of(type_id: &TypeId, rulebook: Rulebook, payload: &Json) -> Option<Self> {
        let text = |value: Option<&Json>| match value? {
            Json::String(text) => PayloadText::parse(text.clone()).ok(),
            _ => None,
        };
        let payee = text(
            payload
                .member("payee")
                .and_then(|payee| payee.member("name")),
        )?;
        let amount = match rulebook {
            Rulebook::Ts12(Ts12Type::Payment) => {
                let Some(Json::Number(amount)) = payload.member("amount") else {
                    return None;
                };
                let currency = text(payload.member("currency"))?;
                PaymentAmount {
                    amount: amount.text().to_owned(),
                    currency: CurrencyCode::of(currency.as_str())?,
                }
            }
            Rulebook::Ts12(_) => return None,
            Rulebook::Generic if type_id.as_str() == PASO_PAYMENT => {
                let amount = CurrencyAmount::parse(text(payload.member("amount"))?.as_str())?;
                PaymentAmount {
                    amount: amount.amount().to_owned(),
                    currency: amount.currency(),
                }
            }
            Rulebook::Generic => return None,
        };
        Some(Self { payee, amount })
    }

    /// `payee.name`.
    #[must_use]
    pub fn payee(&self) -> &PayloadText {
        &self.payee
    }

    /// The amount and its currency.
    #[must_use]
    pub fn amount(&self) -> &PaymentAmount {
        &self.amount
    }
}

impl PaymentAmount {
    /// The amount, as the payload writes it.
    #[must_use]
    pub fn amount(&self) -> &str {
        &self.amount
    }

    /// The currency.
    #[must_use]
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }

    /// The amount and the currency's code, as PaSO's `iso_currency_amount` writes them:
    /// `49.99 EUR`.
    #[must_use]
    pub fn text(&self) -> String {
        format!("{} {}", self.amount, self.currency.as_str())
    }
}
