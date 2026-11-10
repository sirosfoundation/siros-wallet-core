//! The CLDR tool's output as a context's format module.

use siros_i18n::{Bidi, Context, LoadError};

/// The tool's output for `locale`'s language, one of the fixtures in `tests/cldr`, under
/// `@locale {locale}`: a module of format sections alone. `None` for a language without a
/// fixture.
pub fn formats(locale: &str) -> Option<String> {
    let language = locale.split('-').next()?;
    let dir = env!("CARGO_MANIFEST_DIR");
    let text = std::fs::read_to_string(format!("{dir}/tests/cldr/{language}.mf2")).ok()?;
    let mut module = String::with_capacity(text.len());
    for line in text.lines() {
        if line.starts_with("@locale") {
            module.push_str("@locale ");
            module.push_str(locale);
        } else {
            module.push_str(line);
        }
        module.push('\n');
    }
    Some(module)
}

/// A context in `locale` with `bidi`: the fixture's formats when the language has one, then a
/// module of `messages` under the fixture's `@dir`.
pub fn context(locale: &str, bidi: Bidi, messages: &str) -> Result<Context, LoadError> {
    let mut context = Context::new().bidi(bidi);
    let mut head = format!("@locale {locale}\n");
    if let Some(formats) = formats(locale) {
        if let Some(dir) = formats.lines().find(|line| line.starts_with("@dir")) {
            head.push_str(dir);
            head.push('\n');
        }
        context = context.module(&formats)?;
    }
    context.module(&format!("{head}---\n{messages}\n"))
}
