//! The suite tests the engine does not run, each with its reason.

/// A skipped test: its suite, its message, and why.
pub struct Skip {
    pub suite: &'static str,
    pub src: &'static str,
    pub reason: &'static str,
}

/// The markup rule.
const MARKUP: &str =
    "markup names a style the context applies, `strong`, `emphasis` or `underline`";

/// The default formatter rule.
const DEFAULT: &str = "a selector without a function over an argument selects by the default \
     formatter of the argument's type";

pub const SKIPS: &[Skip] = &[
    Skip {
        suite: "bidi.json",
        src: "{\u{200f} #b \u{200e} }",
        reason: MARKUP,
    },
    Skip {
        suite: "bidi.json",
        src: "{\u{200f} /b \u{200e} }",
        reason: MARKUP,
    },
    Skip {
        suite: "data-model-errors.json",
        src: ".input {$foo} .match $foo one {{one}} * {{other}}",
        reason: DEFAULT,
    },
    Skip {
        suite: "data-model-errors.json",
        src: ".local $foo = {$bar} .match $foo one {{one}} * {{other}}",
        reason: DEFAULT,
    },
    Skip {
        suite: "data-model-errors.json",
        src: ".input {$bar} .local $foo = {$bar} .match $foo one {{one}} * {{other}}",
        reason: DEFAULT,
    },
    Skip {
        suite: "syntax.json",
        src: "{#a @c}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{ #a}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{ /a}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#a }",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#a/}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{/a }",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{/a}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#ns:tag}content{/ns:tag}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#tag a:foo=|foo| b:bar=$bar}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#tag}content",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{/tag}content",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#tag foo=bar/}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#tag foo=bar}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{/tag foo=bar}",
        reason: MARKUP,
    },
    Skip {
        suite: "syntax.json",
        src: "{#tag}",
        reason: MARKUP,
    },
    Skip {
        suite: "u-options.json",
        src: "{#tag u:dir=rtl}content{/ns:tag}",
        reason: MARKUP,
    },
    Skip {
        suite: "u-options.json",
        src: "{#tag u:id=x}content{/ns:tag u:id=x}",
        reason: MARKUP,
    },
];
