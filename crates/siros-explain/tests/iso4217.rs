//! The remapped ISO 4217 table answers as iso_currency for every three-letter code.

use iso_currency::IntoEnumIterator;
use siros_explain::Currency;

#[test]
fn the_remapped_table_equals_iso_currency() {
    let mut listed = 0;
    for currency in iso_currency::Currency::iter() {
        let ours = Currency::from_code(currency.code()).expect("listed");
        assert_eq!(
            ours.code(),
            <[u8; 3]>::try_from(currency.code().as_bytes()).expect("three letters")
        );
        assert_eq!(
            ours.minor_units().map(u16::from),
            currency.exponent(),
            "{}",
            currency.code()
        );
        listed += 1;
    }
    let mut refused = 0;
    for a in b'A'..=b'Z' {
        for b in b'A'..=b'Z' {
            for c in b'A'..=b'Z' {
                let code = String::from_utf8(vec![a, b, c]).expect("ascii");
                if iso_currency::Currency::from_code(&code).is_none() {
                    assert_eq!(Currency::from_code(&code), None, "{code}");
                    refused += 1;
                }
            }
        }
    }
    assert_eq!(listed + refused, 26 * 26 * 26);
}
