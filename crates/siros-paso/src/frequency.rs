//! ISO 20022's frequency codes, PaSO View §3's `frequency` value type.

use siros_i18n::Message;

/// A payment's frequency, shown for its ISO 20022 code (PaSO View §3 `frequency`): a message of
/// the crate's module, one per code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Message)]
pub enum Frequency {
    /// The code `INDA`.
    #[message(id = "frequency.inda")]
    Intraday,
    /// The code `DAIL`.
    #[message(id = "frequency.dail")]
    Daily,
    /// The code `WEEK`.
    #[message(id = "frequency.week")]
    Weekly,
    /// The code `TOWK`.
    #[message(id = "frequency.towk")]
    EveryTwoWeeks,
    /// The code `TWMN`.
    #[message(id = "frequency.twmn")]
    TwiceAMonth,
    /// The code `MNTH`.
    #[message(id = "frequency.mnth")]
    Monthly,
    /// The code `TOMN`.
    #[message(id = "frequency.tomn")]
    EveryTwoMonths,
    /// The code `QUTR`.
    #[message(id = "frequency.qutr")]
    Quarterly,
    /// The code `FOMN`.
    #[message(id = "frequency.fomn")]
    EveryFourMonths,
    /// The code `SEMI`.
    #[message(id = "frequency.semi")]
    TwiceAYear,
    /// The code `YEAR`.
    #[message(id = "frequency.year")]
    Yearly,
    /// The code `TYEA`.
    #[message(id = "frequency.tyea")]
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
