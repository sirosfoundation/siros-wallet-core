//! A text written as a resource value that resolves to it.

/// The resource value that resolves to exactly `text`: MF2's quoted pattern `{{…}}` of the text,
/// `\`, `{` and `}` escaped, and LF, CR and the other characters a resource line takes only
/// escaped written as the resource format's escapes. Markup, placeholders and declarations in
/// `text` resolve as the characters they are written with. A converter writes each text it
/// takes from an issuer through it.
///
/// MF2 has no text that holds U+0000: a value with it fails to load
/// ([`LoadError::Syntax`](crate::LoadError::Syntax)).
///
/// ```
/// use siros_i18n::{Context, escape};
///
/// struct Issued;
///
/// impl siros_i18n::Message for Issued {
///     fn id(&self) -> &str {
///         "issuer.title"
///     }
///
///     fn args(&self, _arg: &mut dyn FnMut(&str, &dyn std::fmt::Display)) {}
/// }
///
/// let title = "{$amount :currency} {#strong}now{/strong}\n.match";
/// let source = format!("@locale en\n---\nissuer.title = {}\n", escape(title));
/// let text = Context::new().module(&source)?.resolve(&Issued)?;
/// assert_eq!(text.to_string(), title);
/// assert_eq!(text.spans().len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn escape(text: &str) -> String {
    let mut value = String::with_capacity(text.len() + 4);
    value.push_str("{{");
    for c in text.chars() {
        match c {
            '\\' => value.push_str("\\\\"),
            '{' => value.push_str("\\{"),
            '}' => value.push_str("\\}"),
            '\n' => value.push_str("\\n"),
            '\r' => value.push_str("\\r"),
            ' '
            | '\t'
            | '\u{21}'..='\u{7E}'
            | '\u{A0}'..='\u{2027}'
            | '\u{202A}'..='\u{10FFFF}' => {
                value.push(c);
            }
            c => {
                // A character a resource line takes only escaped: a control, U+2028, U+2029.
                let code = u32::from(c);
                value.push_str(&if code <= 0xFF {
                    format!("\\x{code:02X}")
                } else {
                    format!("\\u{code:04X}")
                });
            }
        }
    }
    value.push_str("}}");
    value
}
