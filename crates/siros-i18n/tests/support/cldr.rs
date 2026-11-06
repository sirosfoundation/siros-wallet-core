//! Modules over the CLDR tool's output: a language's head and format sections, and a module of
//! given messages that takes the sections its formats need.

use siros_explain::ModuleId;
use siros_i18n::{
    CURRENCY, Compilers, DATE, Declaration, FormatCompiler, FormatRenderer, Formats, LIST,
    LanguagePolicy, Module, ModuleError, NUMBER, OFFSET,
};

/// The format modules' load halves.
pub const COMPILERS: [&dyn FormatCompiler; 5] = [&NUMBER, &CURRENCY, &OFFSET, &DATE, &LIST];
/// The format modules' render halves.
pub const RENDERERS: [&dyn FormatRenderer; 5] = [&NUMBER, &CURRENCY, &OFFSET, &DATE, &LIST];

/// The tool's output for a language: its metadata after `@locale`, and its sections.
pub struct Cldr {
    head: Vec<String>,
    sections: Vec<(String, String)>,
}

impl Cldr {
    /// The output for `language`, one of the fixtures in `tests/cldr`; `None` for another.
    pub fn of(language: &str) -> Option<Self> {
        let dir = env!("CARGO_MANIFEST_DIR");
        let text = std::fs::read_to_string(format!("{dir}/tests/cldr/{language}.mf2")).ok()?;
        let (head, body) = text.split_once("\n---\n").expect("a frontmatter");
        let head = head
            .lines()
            .filter(|line| line.starts_with('@') && !line.starts_with("@locale"))
            .map(str::to_owned)
            .collect();
        let mut sections = Vec::new();
        for part in body.split("\n[formats.").skip(1) {
            let (format, options) = part.split_once("]\n").expect("a section head");
            sections.push((format.to_owned(), options.to_owned()));
        }
        Some(Self { head, sections })
    }

    /// A resource in `locale` of `messages`, with the sections of `formats`.
    fn resource(&self, locale: &str, messages: &str, formats: &[String]) -> String {
        let mut text = format!("@locale {locale}\n");
        for line in &self.head {
            text.push_str(line);
            text.push('\n');
        }
        text.push_str("---\n");
        text.push_str(messages);
        text.push('\n');
        for format in formats {
            let (_, options) = self
                .sections
                .iter()
                .find(|(name, _)| name == format)
                .expect("the tool writes every format");
            text.push_str(&format!("\n[formats.{format}]\n{options}"));
        }
        text
    }
}

/// A module of `messages` in `locale`, with the tool's sections of each format its messages
/// use, found by the loader's refusals of a missing option.
pub fn load(
    id: ModuleId,
    declaration: &Declaration,
    locale: &str,
    messages: &str,
    compilers: &Compilers,
) -> Result<Module, ModuleError> {
    let language = locale.split('-').next().unwrap_or(locale);
    let cldr = Cldr::of(language);
    let mut formats: Vec<String> = Vec::new();
    loop {
        let source = match &cldr {
            Some(cldr) => cldr.resource(locale, messages, &formats),
            None => format!("@locale {locale}\n---\n{messages}\n"),
        };
        match Module::load(id, declaration, &[&source], LanguagePolicy::Any, compilers) {
            Err(ModuleError::Option { format, .. })
                if cldr.is_some() && !formats.iter().any(|f| f == format) =>
            {
                formats.push(format.to_owned());
            }
            result => return result,
        }
    }
}

/// The build's format modules beside the given ones.
pub fn formats(more: &[&'static dyn FormatRenderer]) -> Formats {
    let all: Vec<&'static dyn FormatRenderer> = RENDERERS
        .iter()
        .copied()
        .chain(more.iter().copied())
        .collect();
    Formats::new(&all).expect("formats")
}

/// The build's load halves beside the given ones.
pub fn compilers(more: &[&'static dyn FormatCompiler]) -> Compilers {
    let all: Vec<&'static dyn FormatCompiler> = COMPILERS
        .iter()
        .copied()
        .chain(more.iter().copied())
        .collect();
    Compilers::new(&all).expect("compilers")
}
