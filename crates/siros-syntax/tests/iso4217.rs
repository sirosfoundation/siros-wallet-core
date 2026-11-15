//! The currency table against a second reading of List One, `list-one.xml`: each listed code
//! parses with the minor units the file gives it, and every other three-letter code is refused.

use siros_syntax::{Currency, Malformed};

/// The text between `<name>` and `</name>` in `entry`.
fn field<'a>(entry: &'a str, name: &str) -> Option<&'a str> {
    let (_, after) = entry.split_once(&format!("<{name}>"))?;
    let (text, _) = after.split_once(&format!("</{name}>"))?;
    Some(text)
}

/// Each alphabetic code of the file with its minor units as written, ascending by code.
fn listed() -> Vec<(&'static str, &'static str)> {
    let mut listed = Vec::new();
    for entry in include_str!("../list-one.xml").split("<CcyNtry>").skip(1) {
        let entry = entry.split_once("</CcyNtry>").expect("a closed entry").0;
        if let Some(code) = field(entry, "Ccy") {
            listed.push((code, field(entry, "CcyMnrUnts").expect("minor units")));
        }
    }
    listed.sort_unstable();
    listed.dedup();
    for pair in listed.windows(2) {
        assert_ne!(pair[0].0, pair[1].0, "a code listed with two minor units");
    }
    listed
}

#[test]
fn the_table_is_list_one() {
    let listed = listed();
    let mut wrong = Vec::new();
    for a in b'A'..=b'Z' {
        for b in b'A'..=b'Z' {
            for c in b'A'..=b'Z' {
                let code = String::from_utf8(vec![a, b, c]).expect("ascii");
                let parsed = Currency::parse(&code);
                let units = listed
                    .binary_search_by_key(&code.as_str(), |&(code, _)| code)
                    .map(|index| listed[index].1);
                let expected = match units.ok() {
                    None => Err(Malformed {
                        of: "Currency",
                        at: 0,
                    }),
                    Some("N.A.") => Ok(None),
                    Some(units) => Ok(Some(units.parse::<u8>().expect("minor units"))),
                };
                let read = parsed.map(|currency| {
                    assert_eq!(currency.code(), [a, b, c]);
                    currency.minor_units()
                });
                if read != expected {
                    wrong.push(format!("{code}: {read:?}, List One {expected:?}"));
                }
            }
        }
    }
    assert!(!listed.is_empty());
    assert!(wrong.is_empty(), "{wrong:#?}");
}
