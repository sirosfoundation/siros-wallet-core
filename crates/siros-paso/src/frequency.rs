//! ISO 20022's frequency codes, PaSO View §3's `frequency` value type (and TS12 §4.3.1's
//! recurrence).

use siros_explain::Explain;

/// An ISO 20022 frequency code (PaSO View §3 `frequency`): a message of the crate's module, in
/// the words of its definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, Explain)]
#[explain(domain = "paso.frequency")]
pub enum Frequency {
    /// `INDA`.
    #[error("intraday")]
    #[explain(id = "inda")]
    Intraday,
    /// `DAIL`.
    #[error("daily")]
    #[explain(id = "dail")]
    Daily,
    /// `WEEK`.
    #[error("weekly")]
    #[explain(id = "week")]
    Weekly,
    /// `TOWK`.
    #[error("every two weeks")]
    #[explain(id = "towk")]
    EveryTwoWeeks,
    /// `TWMN`.
    #[error("twice a month")]
    #[explain(id = "twmn")]
    TwiceAMonth,
    /// `MNTH`.
    #[error("monthly")]
    #[explain(id = "mnth")]
    Monthly,
    /// `TOMN`.
    #[error("every two months")]
    #[explain(id = "tomn")]
    EveryTwoMonths,
    /// `QUTR`.
    #[error("quarterly")]
    #[explain(id = "qutr")]
    Quarterly,
    /// `FOMN`.
    #[error("every four months")]
    #[explain(id = "fomn")]
    EveryFourMonths,
    /// `SEMI`.
    #[error("twice a year")]
    #[explain(id = "semi")]
    TwiceAYear,
    /// `YEAR`.
    #[error("yearly")]
    #[explain(id = "year")]
    Yearly,
    /// `TYEA`.
    #[error("every two years")]
    #[explain(id = "tyea")]
    EveryTwoYears,
}

impl Frequency {
    /// Every frequency, with its code.
    const CODES: [(Self, &'static str); 12] = [
        (Self::Intraday, "INDA"),
        (Self::Daily, "DAIL"),
        (Self::Weekly, "WEEK"),
        (Self::EveryTwoWeeks, "TOWK"),
        (Self::TwiceAMonth, "TWMN"),
        (Self::Monthly, "MNTH"),
        (Self::EveryTwoMonths, "TOMN"),
        (Self::Quarterly, "QUTR"),
        (Self::EveryFourMonths, "FOMN"),
        (Self::TwiceAYear, "SEMI"),
        (Self::Yearly, "YEAR"),
        (Self::EveryTwoYears, "TYEA"),
    ];

    /// The frequency of a code.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::CODES
            .iter()
            .find(|(_, known)| *known == code)
            .map(|(frequency, _)| *frequency)
    }

    /// The code.
    #[must_use]
    pub fn code(self) -> &'static str {
        Self::CODES
            .iter()
            .find(|(known, _)| *known == self)
            .map_or("", |(_, code)| code)
    }
}
