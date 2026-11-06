//! And-lists and or-lists of one to five items, among them the initials of the
//! special cases, in the test app's languages and in Spanish and Hebrew, whose special cases the
//! list module's conditions decide.

use icu_list::ListFormatter;
use icu_list::options::{ListFormatterOptions, ListLength};
use icu_locale_core::Locale;
use siros_explain::{AllOf, AnyOf, ListKind, Text};
use writeable::Writeable as _;

use crate::{Differences, LANGUAGES, module, plain, renderer};

#[derive(Debug, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "probe")]
enum Probe {
    #[error("{items:?}")]
    And { items: AllOf<String> },
    #[error("{items:?}")]
    Or { items: AnyOf<String> },
}

const MESSAGES: &str = "[probe]\nand = {$items :siros:list}\nor = {$items :siros:list}";

/// Items that start each special case's condition, and items that start none.
const ITEMS: [&str; 16] = [
    "iglesia", "Hielo", "hiena", "hierro", "hoja", "ocho", "8", "80", "11", "110", "11.000",
    "11,5", "agua", "Berlin", "שלום", "York",
];

#[test]
#[ignore = "the per-merge tier: CI's per-merge job runs it with --ignored"]
fn and_and_or_lists_equal_icu4x() {
    let formats = crate::cldr::formats(&[]);
    let mut differences = Differences::default();
    let languages = LANGUAGES.iter().chain(&["es", "he"]);
    for &language in languages {
        let module = module::<Probe>(language, MESSAGES);
        let renderer = renderer(&module, language, &formats);
        let locale: Locale = language.parse().expect("a locale");
        let options = ListFormatterOptions::default().with_length(ListLength::Wide);
        let and = ListFormatter::try_new_and((&locale).into(), options).expect("data");
        let or = ListFormatter::try_new_or((&locale).into(), options).expect("data");
        for length in 1..=5 {
            for start in 0..ITEMS.len() {
                let items: Vec<&str> = ITEMS
                    .iter()
                    .cycle()
                    .skip(start)
                    .take(length)
                    .copied()
                    .collect();
                for (kind, formatter) in [(ListKind::And, &and), (ListKind::Or, &or)] {
                    let texts = items
                        .iter()
                        .map(|item| Text::Raw((*item).to_owned()))
                        .collect();
                    let text = Text::List {
                        kind,
                        items: AllOf::new(texts).expect("items"),
                    };
                    let ours = renderer.plain(&text).expect("renders");
                    let theirs = formatter
                        .format(items.iter())
                        .write_to_string()
                        .into_owned();
                    differences.check(&format!("{language} {kind:?} {items:?}"), &ours, &theirs);
                    let owned: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();
                    let message = match kind {
                        ListKind::And => Probe::And {
                            items: AllOf::new(owned).expect("items"),
                        },
                        ListKind::Or => Probe::Or {
                            items: AnyOf::new(owned).expect("items"),
                        },
                    };
                    let at = format!("{language} {kind:?} message {items:?}");
                    differences.check(&at, &plain(&renderer, &message), &theirs);
                }
            }
        }
    }
    differences.assert_none("lists");
}
