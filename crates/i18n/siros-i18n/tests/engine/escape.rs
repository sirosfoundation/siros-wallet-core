//! `escape`: a text written through it as a resource value resolves to exactly that text, one span
//! without style, whatever MF2 or the resource format would read in it.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use siros_i18n::{Context, LoadError, ResolveError, Style, Styles, Text, escape};

use crate::Given;

/// The pieces the texts are drawn from: MF2's and the resource format's syntax, the characters
/// the resource format takes only escaped, bidi controls, MF2's whitespace, text outside NFC, and
/// characters of each UTF-8 length.
const PIECES: [&str; 47] = [
    "a",
    "Z",
    "0",
    " ",
    "\t",
    "\n",
    "\r",
    "\r\n",
    "{",
    "}",
    "\\",
    "|",
    ".",
    "@",
    "#",
    "/",
    "$",
    ":",
    "=",
    "*",
    "{{",
    "}}",
    "{#strong}",
    "{/strong}",
    "{$amount :currency}",
    ".match",
    ".local $x = {1}",
    ".input {$x}",
    "\u{1}",
    "\u{7f}",
    "\u{85}",
    "\u{a0}",
    "\u{2028}",
    "\u{2029}",
    "\u{2066}",
    "\u{2068}",
    "\u{2069}",
    "\u{3000}",
    "\u{feff}",
    "D\u{323}\u{307}",
    "\u{1e0c}\u{307}",
    "\u{e9}",
    "\u{20ac}",
    "\u{d7ff}",
    "\u{e000}",
    "\u{1f600}",
    "\u{10ffff}",
];

/// The message `issued` of a module whose resource value is `value`, resolved.
fn resolved(value: &str) -> Result<Result<Text, ResolveError>, LoadError> {
    let context = Context::new().module(&format!("@locale en\n---\nissued = {value}\n"))?;
    Ok(context.resolve(&Given::bare("issued")))
}

#[test]
fn an_escaped_text_resolves_to_itself() {
    // Written raw, the issuer's texts below are MF2: a placeholder and markup.
    let strong = resolved("{#strong}x{/strong}")
        .expect("loads")
        .expect("a text");
    assert_eq!(
        strong.spans()[0].styles,
        Styles::empty().with(Style::Strong)
    );
    assert!(matches!(
        resolved("{$amount :currency}"),
        Err(LoadError::Option { .. })
    ));
    let mut rng = ChaCha8Rng::seed_from_u64(0x5150);
    let random: Vec<String> = (0..1000)
        .map(|_| {
            let pieces = rng.random_range(1..=24);
            (0..pieces)
                .map(|_| PIECES[rng.random_range(0..PIECES.len())])
                .collect()
        })
        .collect();
    let fixed = ["{$amount :currency}", "{#strong}x{/strong}", ""].map(str::to_owned);
    for text in fixed.into_iter().chain(random) {
        let resolved = resolved(&escape(&text))
            .unwrap_or_else(|error| panic!("{text:?} does not load: {error}"))
            .unwrap_or_else(|error| panic!("{text:?} does not resolve: {error}"));
        assert_eq!(resolved.to_string(), text);
        match resolved.spans() {
            [] => assert!(text.is_empty(), "{text:?} resolves to no span"),
            [span] => assert_eq!(span.styles, Styles::empty(), "{text:?}"),
            spans => panic!("{text:?} resolves to {} spans", spans.len()),
        }
    }
}
