//! The suite tests the engine does not run, each with its reason.

/// A skipped test: its suite, its message, and why.
pub struct Skip {
    pub suite: &'static str,
    pub src: &'static str,
    pub reason: &'static str,
}

/// Section 4.14's markup rule.
const MARKUP: &str = "section 4.14 and I30: markup names a style the renderer applies, `strong`, `emphasis` or `underline`";
/// Part 1's option rule.
const LITERAL: &str = "section 4.14: an option's value is a literal, so the loader compiles each placeholder; the test's value is a variable";
/// Section 4.13's argument names.
const TOKENS: &str =
    "section 4.13: an argument's name is siros-explain tokens, and the param's is not";
/// Section 4.14's argument rule.
const UNDECLARED: &str = "section 4.14 and I30: a message names declared arguments only, and the test gives no value to declare";

pub const SKIPS: &[Skip] = &[
    Skip {
        suite: "functions/number.json",
        src: "hello {4.2 :number minimumFractionDigits=$foo}",
        reason: LITERAL,
    },
    Skip {
        suite: "functions/number.json",
        src: "hello {|4.2| :number minimumFractionDigits=$foo}",
        reason: LITERAL,
    },
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
        src: "hello {$place-.}",
        reason: TOKENS,
    },
    Skip {
        suite: "syntax.json",
        src: ".input {$Ḍ\u{307}} {{{$D\u{323}\u{307}}}}",
        reason: TOKENS,
    },
    Skip {
        suite: "syntax.json",
        src: ".input {$D\u{323}\u{307}} {{{$Ḍ\u{307}}}}",
        reason: TOKENS,
    },
    Skip {
        suite: "syntax.json",
        src: ".input{$x} .input{$y}{{}}",
        reason: UNDECLARED,
    },
    Skip {
        suite: "syntax.json",
        src: ".input{$x}.input{$y}{{}}",
        reason: UNDECLARED,
    },
    Skip {
        suite: "syntax.json",
        src: ".input {$x}{{}}",
        reason: UNDECLARED,
    },
    Skip {
        suite: "syntax.json",
        src: ".input{$x}{{}}",
        reason: UNDECLARED,
    },
    Skip {
        suite: "syntax.json",
        src: ".local $x ={a}.input{$y}{{}}",
        reason: UNDECLARED,
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
        suite: "syntax.json",
        src: "\t.input{$x}{{}}\n",
        reason: UNDECLARED,
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
