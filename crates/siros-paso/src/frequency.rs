//! ISO 20022's frequency codes, PaSO View §3's `frequency` value type.

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
    const ALL: [Self; 12] = [
        Self::Intraday,
        Self::Daily,
        Self::Weekly,
        Self::EveryTwoWeeks,
        Self::TwiceAMonth,
        Self::Monthly,
        Self::EveryTwoMonths,
        Self::Quarterly,
        Self::EveryFourMonths,
        Self::TwiceAYear,
        Self::Yearly,
        Self::EveryTwoYears,
    ];

    /// The frequency of a code.
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|frequency| frequency.code() == code)
    }

    /// The code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Intraday => "INDA",
            Self::Daily => "DAIL",
            Self::Weekly => "WEEK",
            Self::EveryTwoWeeks => "TOWK",
            Self::TwiceAMonth => "TWMN",
            Self::Monthly => "MNTH",
            Self::EveryTwoMonths => "TOMN",
            Self::Quarterly => "QUTR",
            Self::EveryFourMonths => "FOMN",
            Self::TwiceAYear => "SEMI",
            Self::Yearly => "YEAR",
            Self::EveryTwoYears => "TYEA",
        }
    }
}
