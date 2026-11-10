//! The members TS12 §4.3.1 and §4.3.2 list, each by its dotted path below `payload`.

use std::fmt;

/// A member of TS12's field tables, or `payload` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldPath(&'static str);

impl FieldPath {
    /// The dotted path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The path's steps below `payload`.
    pub(crate) fn steps(self) -> impl Iterator<Item = &'static str> + Clone {
        self.0.split('.')
    }

    /// The member's name in its object.
    pub(crate) fn name(self) -> &'static str {
        self.0.rsplit_once('.').map_or(self.0, |(_, name)| name)
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

macro_rules! fields {
    ($($name:ident = $path:literal),+ $(,)?) => {
        $(pub(crate) const $name: FieldPath = FieldPath($path);)+
    };
}

fields! {
    PAYLOAD = "payload",
    TRANSACTION_ID = "transaction_id",
    DATE_TIME = "date_time",
    PAYEE = "payee",
    PAYEE_NAME = "payee.name",
    PAYEE_ID = "payee.id",
    PAYEE_LOGO = "payee.logo",
    PAYEE_LOGO_INTEGRITY = "payee.logo#integrity",
    PAYEE_WEBSITE = "payee.website",
    PISP = "pisp",
    PISP_LEGAL_NAME = "pisp.legal_name",
    PISP_BRAND_NAME = "pisp.brand_name",
    PISP_DOMAIN_NAME = "pisp.domain_name",
    EXECUTION_DATE = "execution_date",
    CURRENCY = "currency",
    AMOUNT = "amount",
    AMOUNT_ESTIMATED = "amount_estimated",
    AMOUNT_EARMARKED = "amount_earmarked",
    SCT_INST = "sct_inst",
    RECURRENCE = "recurrence",
    START_DATE = "recurrence.start_date",
    END_DATE = "recurrence.end_date",
    NUMBER = "recurrence.number",
    FREQUENCY = "recurrence.frequency",
    MIT_OPTIONS = "recurrence.mit_options",
    AMOUNT_VARIABLE = "recurrence.mit_options.amount_variable",
    MIN_AMOUNT = "recurrence.mit_options.min_amount",
    MAX_AMOUNT = "recurrence.mit_options.max_amount",
    TOTAL_AMOUNT = "recurrence.mit_options.total_amount",
    INITIAL_AMOUNT = "recurrence.mit_options.initial_amount",
    INITIAL_AMOUNT_NUMBER = "recurrence.mit_options.initial_amount_number",
    APR = "recurrence.mit_options.apr",
    SERVICE = "service",
    ACTION = "action",
}
