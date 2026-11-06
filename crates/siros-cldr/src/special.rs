//! The list patterns' special cases, which CLDR's JSON does not carry: Unicode TR35 Part 2, "List
//! Patterns", names them in prose, and ICU4X 2.4's data generator writes them as conditions on
//! the item after the conjunction.

/// A special case: the condition on the following item, and the pattern it selects.
pub(crate) struct Special {
    pub(crate) condition: String,
    pub(crate) pattern: &'static str,
}

/// Hebrew's characters as class ranges (Unicode 17.0 Scripts.txt, Script=Hebrew), written as
/// the characters themselves: a resource value carries no regular-expression escape.
const HEBREW: &str = "\u{591}-\u{5C7}\u{5D0}-\u{5EA}\u{5EF}-\u{5F4}\u{FB1D}-\u{FB36}\
\u{FB38}-\u{FB3C}\u{FB3E}\u{FB40}-\u{FB41}\u{FB43}-\u{FB44}\u{FB46}-\u{FB4F}";

/// A list's conjunction.
#[derive(Clone, Copy)]
pub(crate) enum Conjunction {
    And,
    Or,
}

/// The special case of a language's list of `conjunction` whose end pattern is `end`.
pub(crate) fn special(language: &str, conjunction: Conjunction, end: &str) -> Option<Special> {
    match (language, conjunction, end) {
        ("es", Conjunction::And, "{0} y {1}") => Some(Special {
            condition: "^[iI]|(?:[hH][iI](?:[^aeAE]|$))".to_owned(),
            pattern: "{0} e {1}",
        }),
        ("es", Conjunction::Or, "{0} o {1}") => Some(Special {
            condition:
                "^[oO]|[hH][oO]|8|(?:11(?:[.\u{a0} ]?[0-9]{3})*(?:,[0-9]*)?(?:[^.,[0-9]]|$))"
                    .to_owned(),
            pattern: "{0} u {1}",
        }),
        ("he", Conjunction::And, "{0} \u{5D5}{1}") => Some(Special {
            condition: format!("^[^{HEBREW}]"),
            pattern: "{0} \u{5D5}\u{2011}{1}",
        }),
        _ => None,
    }
}
