//! The CLDR tool's output as a context's format module.

use siros_i18n::{Bidi, Context, Formatters, LoadError};

/// The format functions of the build.
const FUNCTIONS: &[&str] = &[
    #[cfg(feature = "number")]
    "number",
    #[cfg(feature = "number")]
    "integer",
    #[cfg(feature = "currency")]
    "currency",
    #[cfg(feature = "date")]
    "siros:date",
    #[cfg(feature = "date")]
    "siros:time",
    #[cfg(feature = "date")]
    "siros:datetime",
];

/// A `String` argument taking each format function of the build by name: the fixtures give
/// each argument as text.
pub fn strings() -> Formatters {
    FUNCTIONS
        .iter()
        .try_fold(Formatters::new(), |formatters, name| {
            formatters.formatter::<String>(name)
        })
        .expect("the build has each function")
}

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

/// A context in `locale` with `bidi` and [`strings`]' formatters: the fixture's formats when the
/// language has one, then a module of `messages` under the fixture's `@dir`.
pub fn context(locale: &str, bidi: Bidi, messages: &str) -> Result<Context, LoadError> {
    let mut context = Context::new().bidi(bidi).formatters(strings());
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
