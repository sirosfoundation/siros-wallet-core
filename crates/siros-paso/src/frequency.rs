//! ISO 20022's frequency codes, PaSO View §3's `frequency` value type (and TS12 §4.3.1's
//! recurrence).

use siros_explain::Explain;

/// A payment's frequency, shown for its ISO 20022 code (PaSO View §3 `frequency`): a message of
/// the crate's module, one per code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Explain)]
#[explain(domain = "paso.frequency")]
pub enum Frequency {
    /// The code `INDA`.
    #[explain(id = "inda")]
    Intraday,
    /// The code `DAIL`.
    #[explain(id = "dail")]
    Daily,
    /// The code `WEEK`.
    #[explain(id = "week")]
    Weekly,
    /// The code `TOWK`.
    #[explain(id = "towk")]
    EveryTwoWeeks,
    /// The code `TWMN`.
    #[explain(id = "twmn")]
    TwiceAMonth,
    /// The code `MNTH`.
    #[explain(id = "mnth")]
    Monthly,
    /// The code `TOMN`.
    #[explain(id = "tomn")]
    EveryTwoMonths,
    /// The code `QUTR`.
    #[explain(id = "qutr")]
    Quarterly,
    /// The code `FOMN`.
    #[explain(id = "fomn")]
    EveryFourMonths,
    /// The code `SEMI`.
    #[explain(id = "semi")]
    TwiceAYear,
    /// The code `YEAR`.
    #[explain(id = "year")]
    Yearly,
    /// The code `TYEA`.
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
