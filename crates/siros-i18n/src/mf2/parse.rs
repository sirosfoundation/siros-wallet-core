//! MF2's syntax (spec/message.abnf), parsed by recursive descent.

use super::ast::{
    Body, Declaration, Expression, Function, Key, Markup, MarkupKind, Message, Operand, Opt, Part,
    Pattern, Variant,
};
use crate::normal::{Hold, Unnormalized};

/// Why a message does not parse.
#[derive(Debug)]
pub(crate) enum Unparsed {
    /// The byte offset where the message leaves MF2's grammar.
    Syntax(usize),
    /// A name or a variant key the parse's [`Hold`] refuses.
    Unnormalized(Unnormalized),
}

/// Parses a message, its names and variant keys held by `hold`.
pub(crate) fn parse(source: &str, hold: Hold) -> Result<Message, Unparsed> {
    let mut parser = Parser {
        source,
        rest: source,
        hold,
    };
    parser.o();
    let message = if parser.rest.starts_with('.') || parser.rest.starts_with("{{") {
        parser.complex()?
    } else {
        parser.rest = source;
        let pattern = parser.pattern(false)?;
        Message {
            declarations: Vec::new(),
            body: Body::Pattern(pattern),
        }
    };
    if parser.rest.is_empty() {
        Ok(message)
    } else {
        parser.fail()
    }
}

/// A parser of `source`; `rest` is the suffix of `source` it has yet to read, and `hold` holds
/// its names and variant keys.
struct Parser<'s> {
    source: &'s str,
    rest: &'s str,
    hold: Hold,
}

impl<'s> Parser<'s> {
    /// The next character, and the text after it.
    fn next(&self) -> Option<(char, &'s str)> {
        let mut chars = self.rest.chars();
        chars.next().map(|c| (c, chars.as_str()))
    }

    fn peek(&self) -> Option<char> {
        self.rest.chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let (c, rest) = self.next()?;
        self.rest = rest;
        Some(c)
    }

    /// Steps over one bidi mark, when the next character is one.
    fn skip_bidi(&mut self) {
        if let Some((c, rest)) = self.next()
            && bidi(c)
        {
            self.rest = rest;
        }
    }

    fn eat(&mut self, c: char) -> bool {
        self.eat_str(c.encode_utf8(&mut [0; 4]))
    }

    fn eat_str(&mut self, text: &str) -> bool {
        match self.rest.strip_prefix(text) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    fn expect(&mut self, c: char) -> Result<(), Unparsed> {
        if self.eat(c) { Ok(()) } else { self.fail() }
    }

    /// An error at the start of `rest`.
    const fn fail<T>(&self) -> Result<T, Unparsed> {
        Err(Unparsed::Syntax(self.source.len() - self.rest.len()))
    }

    /// `text`, a name or a variant key, as the parse holds it.
    fn held(&self, text: String) -> Result<String, Unparsed> {
        self.hold.hold(text).map_err(Unparsed::Unnormalized)
    }

    /// `o`: optional whitespace and bidi marks.
    fn o(&mut self) {
        self.rest = self.rest.trim_start_matches(|c| ws(c) || bidi(c));
    }

    /// `s`: required whitespace, with bidi marks around it; the position stays when it fails.
    fn s(&mut self) -> bool {
        let after = self.rest.trim_start_matches(bidi);
        if after.starts_with(ws) {
            self.rest = after;
            self.o();
            true
        } else {
            false
        }
    }

    /// `s` followed by a character `next` admits; the position stays when either fails.
    fn s_then(&mut self, next: impl Fn(char) -> bool) -> bool {
        let start = self.rest;
        if self.s() && self.peek().is_some_and(next) {
            true
        } else {
            self.rest = start;
            false
        }
    }

    fn complex(&mut self) -> Result<Message, Unparsed> {
        let mut declarations = Vec::new();
        loop {
            self.o();
            if self.eat_str(".input") {
                self.o();
                self.expect('{')?;
                self.o();
                self.expect('$')?;
                let name = self.name()?;
                let function = self.annotation()?;
                self.close()?;
                declarations.push(Declaration::Input { name, function });
            } else if self.eat_str(".local") {
                if !self.s() {
                    return self.fail();
                }
                self.expect('$')?;
                let name = self.name()?;
                self.o();
                self.expect('=')?;
                self.o();
                self.expect('{')?;
                let expression = self.expression()?;
                declarations.push(Declaration::Local { name, expression });
            } else if self.eat_str(".match") {
                let body = self.matcher()?;
                return Ok(Message { declarations, body });
            } else if self.eat_str("{{") {
                let pattern = self.pattern(true)?;
                self.quoted_end()?;
                return Ok(Message {
                    declarations,
                    body: Body::Pattern(pattern),
                });
            } else {
                return self.fail();
            }
        }
    }

    fn quoted_end(&mut self) -> Result<(), Unparsed> {
        if self.eat_str("}}") {
            self.o();
            Ok(())
        } else {
            self.fail()
        }
    }

    fn matcher(&mut self) -> Result<Body, Unparsed> {
        let mut selectors = Vec::new();
        while self.s_then(|c| c == '$') {
            self.expect('$')?;
            selectors.push(self.name()?);
        }
        if selectors.is_empty() || !self.s() {
            return self.fail();
        }
        let mut variants = Vec::new();
        loop {
            let mut keys = vec![self.key()?];
            while self.s_then(|c| c == '*' || c == '|' || name_char(c)) {
                keys.push(self.key()?);
            }
            self.o();
            if !self.eat_str("{{") {
                return self.fail();
            }
            let pattern = self.pattern(true)?;
            if !self.eat_str("}}") {
                return self.fail();
            }
            variants.push(Variant { keys, pattern });
            self.o();
            if self.peek().is_none() {
                return Ok(Body::Matcher {
                    selectors,
                    variants,
                });
            }
        }
    }

    fn key(&mut self) -> Result<Key, Unparsed> {
        if self.eat('*') {
            Ok(Key::CatchAll)
        } else {
            let literal = self.literal()?;
            Ok(Key::Literal(self.held(literal)?))
        }
    }

    /// A pattern, up to the end of the message or, in a quoted pattern, to its `}`.
    fn pattern(&mut self, quoted: bool) -> Result<Pattern, Unparsed> {
        let mut parts = Vec::new();
        let mut text = String::new();
        loop {
            match self.next() {
                None if quoted => return self.fail(),
                None => break,
                Some(('}', _)) if quoted => break,
                Some(('}' | '\0', _)) => return self.fail(),
                Some(('{', rest)) => {
                    self.rest = rest;
                    if !text.is_empty() {
                        parts.push(Part::Text(std::mem::take(&mut text)));
                    }
                    parts.push(self.placeholder()?);
                }
                Some(('\\', rest)) => {
                    self.rest = rest;
                    text.push(self.escaped()?);
                }
                Some((c, rest)) => {
                    self.rest = rest;
                    text.push(c);
                }
            }
        }
        if !text.is_empty() {
            parts.push(Part::Text(text));
        }
        Ok(parts)
    }

    /// The character after a backslash: `\`, `{`, `|` or `}`.
    fn escaped(&mut self) -> Result<char, Unparsed> {
        match self.next() {
            Some((c @ ('\\' | '{' | '|' | '}'), rest)) => {
                self.rest = rest;
                Ok(c)
            }
            _ => self.fail(),
        }
    }

    /// A placeholder after its `{`.
    fn placeholder(&mut self) -> Result<Part, Unparsed> {
        self.o();
        let kind = if self.eat('#') {
            MarkupKind::Open
        } else if self.eat('/') {
            MarkupKind::Close
        } else {
            return Ok(Part::Expression(self.expression_body()?));
        };
        let name = self.identifier()?;
        let options = self.options()?;
        self.attributes()?;
        self.o();
        let kind = if kind == MarkupKind::Open && self.eat('/') {
            MarkupKind::Standalone
        } else {
            kind
        };
        self.expect('}')?;
        Ok(Part::Markup(Markup {
            kind,
            name,
            options,
        }))
    }

    /// An expression after its `{`.
    fn expression(&mut self) -> Result<Expression, Unparsed> {
        self.o();
        self.expression_body()
    }

    fn expression_body(&mut self) -> Result<Expression, Unparsed> {
        if self.peek() == Some(':') {
            let function = self.function()?;
            self.close()?;
            return Ok(Expression::Function(function));
        }
        let operand = self.operand()?;
        let function = self.annotation()?;
        self.close()?;
        Ok(Expression::Operand { operand, function })
    }

    /// `[s function]` after an operand.
    fn annotation(&mut self) -> Result<Option<Function>, Unparsed> {
        if self.s_then(|c| c == ':') {
            self.function().map(Some)
        } else {
            Ok(None)
        }
    }

    /// `*(s attribute) o "}"`.
    fn close(&mut self) -> Result<(), Unparsed> {
        self.attributes()?;
        self.o();
        self.expect('}')
    }

    fn operand(&mut self) -> Result<Operand, Unparsed> {
        if self.eat('$') {
            Ok(Operand::Variable(self.name()?))
        } else {
            Ok(Operand::Literal(self.literal()?))
        }
    }

    fn function(&mut self) -> Result<Function, Unparsed> {
        self.expect(':')?;
        let name = self.identifier()?;
        let options = self.options()?;
        Ok(Function { name, options })
    }

    /// `*(s option)`.
    fn options(&mut self) -> Result<Vec<Opt>, Unparsed> {
        let mut options = Vec::new();
        while self.s_then(|c| name_start(c) || bidi(c)) {
            let name = self.identifier()?;
            self.o();
            self.expect('=')?;
            self.o();
            let value = self.operand()?;
            options.push(Opt { name, value });
        }
        Ok(options)
    }

    /// `*(s attribute)`: read and dropped.
    fn attributes(&mut self) -> Result<(), Unparsed> {
        while self.s_then(|c| c == '@') {
            self.expect('@')?;
            drop(self.identifier()?);
            let start = self.rest;
            self.o();
            if self.eat('=') {
                self.o();
                drop(self.literal()?);
            } else {
                self.rest = start;
            }
        }
        Ok(())
    }

    /// `[namespace ":"] name`.
    fn identifier(&mut self) -> Result<String, Unparsed> {
        let mut identifier = self.name()?;
        if self.eat(':') {
            identifier.push(':');
            identifier.push_str(&self.name()?);
        }
        Ok(identifier)
    }

    /// `[bidi] name-start *name-char [bidi]`, held as the parse holds names.
    fn name(&mut self) -> Result<String, Unparsed> {
        self.skip_bidi();
        if !self.peek().is_some_and(name_start) {
            return self.fail();
        }
        let written: String = self.rest.chars().take_while(|&c| name_char(c)).collect();
        let name = self.held(written)?;
        self.rest = self.rest.trim_start_matches(name_char);
        self.skip_bidi();
        Ok(name)
    }

    /// A quoted or an unquoted literal's string value.
    fn literal(&mut self) -> Result<String, Unparsed> {
        if self.eat('|') {
            let mut value = String::new();
            loop {
                match self.bump() {
                    Some('|') => return Ok(value),
                    Some('\\') => value.push(self.escaped()?),
                    Some('\0') | None => return self.fail(),
                    Some(c) => value.push(c),
                }
            }
        }
        let literal: String = self.rest.chars().take_while(|&c| name_char(c)).collect();
        if literal.is_empty() {
            return self.fail();
        }
        self.rest = self.rest.trim_start_matches(name_char);
        Ok(literal)
    }
}

/// `ws`.
const fn ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{3000}')
}

/// `bidi`: ALM, LRM, RLM, LRI, RLI, FSI and PDI.
const fn bidi(c: char) -> bool {
    matches!(
        c,
        '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{2066}'..='\u{2069}'
    )
}

/// `name-start`.
const fn name_start(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphabetic() || c == '+' || c == '_';
    }
    let code = c as u32;
    // Every plane's last two code points are noncharacters.
    if code >= 0x10000 && code & 0xFFFE == 0xFFFE {
        return false;
    }
    matches!(c, '\u{A1}'..='\u{61B}' | '\u{61D}'..='\u{167F}' | '\u{1681}'..='\u{1FFF}'
        | '\u{200B}'..='\u{200D}' | '\u{2010}'..='\u{2027}' | '\u{2030}'..='\u{205E}'
        | '\u{2060}'..='\u{2065}' | '\u{206A}'..='\u{2FFF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{E000}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFD}')
}

/// `name-char`.
const fn name_char(c: char) -> bool {
    name_start(c) || c.is_ascii_digit() || c == '-' || c == '.'
}
