//! Python's whitespace, as the reference model reads display texts.

/// Python's `\s` and `str.isspace`: Unicode whitespace and the separators U+001C to U+001F.
#[must_use]
pub fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
