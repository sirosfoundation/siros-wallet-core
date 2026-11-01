//! The alphabetic codes of ISO 4217 and the number of digits of their minor unit.
//!
//! Generated from list one of the ISO 4217 maintenance agency (SIX Financial Information,
//! <https://www.six-group.com/dam/download/financial-information/data-center/iso-currrency/lists/list-one.xml>),
//! published 2026-09-17, SHA-256 `33139b438657d1cee116ba737807ea71d19d6de4b90f799a09c56f0cc6a1b0ff`.

/// The minor unit of a currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Minor {
    /// The digits after the decimal point.
    Digits(u8),
    /// `N.A.` in the list: the currency has no minor unit.
    Undefined,
}

/// Each code with its minor unit.
const MINOR_UNITS: [(&str, Minor); 178] = [
    ("AED", Minor::Digits(2)),
    ("AFN", Minor::Digits(2)),
    ("ALL", Minor::Digits(2)),
    ("AMD", Minor::Digits(2)),
    ("AOA", Minor::Digits(2)),
    ("ARS", Minor::Digits(2)),
    ("AUD", Minor::Digits(2)),
    ("AWG", Minor::Digits(2)),
    ("AZN", Minor::Digits(2)),
    ("BAM", Minor::Digits(2)),
    ("BBD", Minor::Digits(2)),
    ("BDT", Minor::Digits(2)),
    ("BHD", Minor::Digits(3)),
    ("BIF", Minor::Digits(0)),
    ("BMD", Minor::Digits(2)),
    ("BND", Minor::Digits(2)),
    ("BOB", Minor::Digits(2)),
    ("BOV", Minor::Digits(2)),
    ("BRL", Minor::Digits(2)),
    ("BSD", Minor::Digits(2)),
    ("BTN", Minor::Digits(2)),
    ("BWP", Minor::Digits(2)),
    ("BYN", Minor::Digits(2)),
    ("BZD", Minor::Digits(2)),
    ("CAD", Minor::Digits(2)),
    ("CDF", Minor::Digits(2)),
    ("CHE", Minor::Digits(2)),
    ("CHF", Minor::Digits(2)),
    ("CHW", Minor::Digits(2)),
    ("CLF", Minor::Digits(4)),
    ("CLP", Minor::Digits(0)),
    ("CNY", Minor::Digits(2)),
    ("COP", Minor::Digits(2)),
    ("COU", Minor::Digits(2)),
    ("CRC", Minor::Digits(2)),
    ("CUP", Minor::Digits(2)),
    ("CVE", Minor::Digits(2)),
    ("CZK", Minor::Digits(2)),
    ("DJF", Minor::Digits(0)),
    ("DKK", Minor::Digits(2)),
    ("DOP", Minor::Digits(2)),
    ("DZD", Minor::Digits(2)),
    ("EGP", Minor::Digits(2)),
    ("ERN", Minor::Digits(2)),
    ("ETB", Minor::Digits(2)),
    ("EUR", Minor::Digits(2)),
    ("FJD", Minor::Digits(2)),
    ("FKP", Minor::Digits(2)),
    ("GBP", Minor::Digits(2)),
    ("GEL", Minor::Digits(2)),
    ("GHS", Minor::Digits(2)),
    ("GIP", Minor::Digits(2)),
    ("GMD", Minor::Digits(2)),
    ("GNF", Minor::Digits(0)),
    ("GTQ", Minor::Digits(2)),
    ("GYD", Minor::Digits(2)),
    ("HKD", Minor::Digits(2)),
    ("HNL", Minor::Digits(2)),
    ("HTG", Minor::Digits(2)),
    ("HUF", Minor::Digits(2)),
    ("IDR", Minor::Digits(2)),
    ("ILS", Minor::Digits(2)),
    ("INR", Minor::Digits(2)),
    ("IQD", Minor::Digits(3)),
    ("IRR", Minor::Digits(2)),
    ("ISK", Minor::Digits(0)),
    ("JMD", Minor::Digits(2)),
    ("JOD", Minor::Digits(3)),
    ("JPY", Minor::Digits(0)),
    ("KES", Minor::Digits(2)),
    ("KGS", Minor::Digits(2)),
    ("KHR", Minor::Digits(2)),
    ("KMF", Minor::Digits(0)),
    ("KPW", Minor::Digits(2)),
    ("KRW", Minor::Digits(0)),
    ("KWD", Minor::Digits(3)),
    ("KYD", Minor::Digits(2)),
    ("KZT", Minor::Digits(2)),
    ("LAK", Minor::Digits(2)),
    ("LBP", Minor::Digits(2)),
    ("LKR", Minor::Digits(2)),
    ("LRD", Minor::Digits(2)),
    ("LSL", Minor::Digits(2)),
    ("LYD", Minor::Digits(3)),
    ("MAD", Minor::Digits(2)),
    ("MDL", Minor::Digits(2)),
    ("MGA", Minor::Digits(2)),
    ("MKD", Minor::Digits(2)),
    ("MMK", Minor::Digits(2)),
    ("MNT", Minor::Digits(2)),
    ("MOP", Minor::Digits(2)),
    ("MRU", Minor::Digits(2)),
    ("MUR", Minor::Digits(2)),
    ("MVR", Minor::Digits(2)),
    ("MWK", Minor::Digits(2)),
    ("MXN", Minor::Digits(2)),
    ("MXV", Minor::Digits(2)),
    ("MYR", Minor::Digits(2)),
    ("MZN", Minor::Digits(2)),
    ("NAD", Minor::Digits(2)),
    ("NGN", Minor::Digits(2)),
    ("NIO", Minor::Digits(2)),
    ("NOK", Minor::Digits(2)),
    ("NPR", Minor::Digits(2)),
    ("NZD", Minor::Digits(2)),
    ("OMR", Minor::Digits(3)),
    ("PAB", Minor::Digits(2)),
    ("PEN", Minor::Digits(2)),
    ("PGK", Minor::Digits(2)),
    ("PHP", Minor::Digits(2)),
    ("PKR", Minor::Digits(2)),
    ("PLN", Minor::Digits(2)),
    ("PYG", Minor::Digits(0)),
    ("QAR", Minor::Digits(2)),
    ("RON", Minor::Digits(2)),
    ("RSD", Minor::Digits(2)),
    ("RUB", Minor::Digits(2)),
    ("RWF", Minor::Digits(0)),
    ("SAR", Minor::Digits(2)),
    ("SBD", Minor::Digits(2)),
    ("SCR", Minor::Digits(2)),
    ("SDG", Minor::Digits(2)),
    ("SEK", Minor::Digits(2)),
    ("SGD", Minor::Digits(2)),
    ("SHP", Minor::Digits(2)),
    ("SLE", Minor::Digits(2)),
    ("SOS", Minor::Digits(2)),
    ("SRD", Minor::Digits(2)),
    ("SSP", Minor::Digits(2)),
    ("STN", Minor::Digits(2)),
    ("SVC", Minor::Digits(2)),
    ("SYP", Minor::Digits(2)),
    ("SZL", Minor::Digits(2)),
    ("THB", Minor::Digits(2)),
    ("TJS", Minor::Digits(2)),
    ("TMT", Minor::Digits(2)),
    ("TND", Minor::Digits(3)),
    ("TOP", Minor::Digits(2)),
    ("TRY", Minor::Digits(2)),
    ("TTD", Minor::Digits(2)),
    ("TWD", Minor::Digits(2)),
    ("TZS", Minor::Digits(2)),
    ("UAH", Minor::Digits(2)),
    ("UGX", Minor::Digits(0)),
    ("USD", Minor::Digits(2)),
    ("USN", Minor::Digits(2)),
    ("UYI", Minor::Digits(0)),
    ("UYU", Minor::Digits(2)),
    ("UYW", Minor::Digits(4)),
    ("UZS", Minor::Digits(2)),
    ("VED", Minor::Digits(2)),
    ("VES", Minor::Digits(2)),
    ("VND", Minor::Digits(0)),
    ("VUV", Minor::Digits(0)),
    ("WST", Minor::Digits(2)),
    ("XAD", Minor::Digits(2)),
    ("XAF", Minor::Digits(0)),
    ("XAG", Minor::Undefined),
    ("XAU", Minor::Undefined),
    ("XBA", Minor::Undefined),
    ("XBB", Minor::Undefined),
    ("XBC", Minor::Undefined),
    ("XBD", Minor::Undefined),
    ("XCD", Minor::Digits(2)),
    ("XCG", Minor::Digits(2)),
    ("XDR", Minor::Undefined),
    ("XOF", Minor::Digits(0)),
    ("XPD", Minor::Undefined),
    ("XPF", Minor::Digits(0)),
    ("XPT", Minor::Undefined),
    ("XSU", Minor::Undefined),
    ("XTS", Minor::Undefined),
    ("XUA", Minor::Undefined),
    ("XXX", Minor::Undefined),
    ("YER", Minor::Digits(2)),
    ("ZAR", Minor::Digits(2)),
    ("ZMW", Minor::Digits(2)),
    ("ZWG", Minor::Digits(2)),
];

/// Whether an amount must write the digits of its currency's minor unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Fraction {
    /// It must: `iso_currency_amount` (PaSO View, Section 3).
    Required,
    /// It may leave them out: a TS12 `amount` (EC TS12 v1.0.1, Section 4.3.1).
    Optional,
}

/// An ISO 4217 alphabetic code of the list, with its minor unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrencyCode {
    code: &'static str,
    minor: Minor,
}

impl CurrencyCode {
    /// The code `code`; `None` for a code the list lacks.
    pub(crate) fn of(code: &str) -> Option<Self> {
        MINOR_UNITS
            .iter()
            .find(|(listed, _)| *listed == code)
            .map(|&(code, minor)| Self { code, minor })
    }

    /// The code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.code
    }

    /// Whether the unsigned decimal `amount` is an amount of this currency: the major units,
    /// and a decimal point with exactly the digits of the minor unit, which `fraction` says
    /// whether the amount may leave out. A currency without a minor unit takes no fraction.
    pub(crate) fn admits(self, amount: &str, fraction: Fraction) -> bool {
        let (major, written) = match amount.split_once('.') {
            Some((major, written)) => (major, Some(written)),
            None => (amount, None),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let fraction_fits = match (written, self.minor) {
            (None, Minor::Digits(n)) if n > 0 => fraction == Fraction::Optional,
            (None, Minor::Digits(_) | Minor::Undefined) => true,
            (Some(written), Minor::Digits(n)) => {
                n > 0 && digits(written) && written.len() == usize::from(n)
            }
            (Some(_), Minor::Undefined) => false,
        };
        digits(major) && fraction_fits
    }
}
