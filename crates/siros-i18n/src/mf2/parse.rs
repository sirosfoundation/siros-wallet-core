//! MF2's syntax (spec/message.abnf), parsed by recursive descent.

use unicode_normalization::UnicodeNormalization;

use super::ast::{
    Body, Declaration, Expression, Function, Key, Markup, MarkupKind, Message, Operand, Opt, Part,
    Pattern, Variant,
};

/// The byte offset where a message leaves MF2's grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyntaxError(pub(crate) usize);

/// Parses a message.
pub(crate) fn parse(source: &str) -> Result<Message, SyntaxError> {
    let mut parser = Parser { source, at: 0 };
    parser.o();
    let message = if parser.rest().starts_with('.') || parser.rest().starts_with("{{") {
        parser.complex()?
    } else {
        parser.at = 0;
        let pattern = parser.pattern(false)?;
        Message {
            declarations: Vec::new(),
            body: Body::Pattern(pattern),
        }
    };
    if parser.at == source.len() {
        Ok(message)
    } else {
        parser.fail()
    }
}

struct Parser<'s> {
    source: &'s str,
    at: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        self.source.get(self.at..).unwrap_or_default()
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += c.len_utf8();
        Some(c)
    }

    /// Steps over one bidi mark, when the next character is one.
    fn skip_bidi(&mut self) {
        if let Some(mark) = self.peek().filter(|&c| bidi(c)) {
            self.at += mark.len_utf8();
        }
    }

    fn eat(&mut self, c: char) -> bool {
        self.eat_str(c.encode_utf8(&mut [0; 4]))
    }

    fn eat_str(&mut self, text: &str) -> bool {
        let found = self.rest().starts_with(text);
        if found {
            self.at += text.len();
        }
        found
    }

    fn expect(&mut self, c: char) -> Result<(), SyntaxError> {
        if self.eat(c) { Ok(()) } else { self.fail() }
    }

    const fn fail<T>(&self) -> Result<T, SyntaxError> {
        Err(SyntaxError(self.at))
    }

    /// `o`: optional whitespace and bidi marks.
    fn o(&mut self) {
        while self.peek().is_some_and(|c| ws(c) || bidi(c)) {
            self.at += self.peek().map_or(0, char::len_utf8);
        }
    }

    /// `s`: required whitespace, with bidi marks around it; the position stays when it fails.
    fn s(&mut self) -> bool {
        let start = self.at;
        while self.peek().is_some_and(bidi) {
            self.at += self.peek().map_or(0, char::len_utf8);
        }
        if self.peek().is_some_and(ws) {
            self.o();
            true
        } else {
            self.at = start;
            false
        }
    }

    /// `s` followed by a character `next` admits; the position stays when either fails.
    fn s_then(&mut self, next: impl Fn(char) -> bool) -> bool {
        let start = self.at;
        if self.s() && self.peek().is_some_and(next) {
            true
        } else {
            self.at = start;
            false
        }
    }

    fn complex(&mut self) -> Result<Message, SyntaxError> {
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

    fn quoted_end(&mut self) -> Result<(), SyntaxError> {
        if self.eat_str("}}") {
            self.o();
            Ok(())
        } else {
            self.fail()
        }
    }

    fn matcher(&mut self) -> Result<Body, SyntaxError> {
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

    fn key(&mut self) -> Result<Key, SyntaxError> {
        if self.eat('*') {
            Ok(Key::CatchAll)
        } else {
            Ok(Key::Literal(self.literal()?.nfc().collect()))
        }
    }

    /// A pattern, up to the end of the message or, in a quoted pattern, to its `}`.
    fn pattern(&mut self, quoted: bool) -> Result<Pattern, SyntaxError> {
        let mut parts = Vec::new();
        let mut text = String::new();
        loop {
            match self.peek() {
                None if quoted => return self.fail(),
                None => break,
                Some('}') if quoted => break,
                Some('}' | '\0') => return self.fail(),
                Some('{') => {
                    self.at += 1;
                    if !text.is_empty() {
                        parts.push(Part::Text(std::mem::take(&mut text)));
                    }
                    parts.push(self.placeholder()?);
                }
                Some('\\') => {
                    self.at += 1;
                    text.push(self.escaped()?);
                }
                Some(c) => {
                    self.at += c.len_utf8();
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
    fn escaped(&mut self) -> Result<char, SyntaxError> {
        match self.peek() {
            Some(c @ ('\\' | '{' | '|' | '}')) => {
                self.at += 1;
                Ok(c)
            }
            _ => self.fail(),
        }
    }

    /// A placeholder after its `{`.
    fn placeholder(&mut self) -> Result<Part, SyntaxError> {
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
    fn expression(&mut self) -> Result<Expression, SyntaxError> {
        self.o();
        self.expression_body()
    }

    fn expression_body(&mut self) -> Result<Expression, SyntaxError> {
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
    fn annotation(&mut self) -> Result<Option<Function>, SyntaxError> {
        if self.s_then(|c| c == ':') {
            self.function().map(Some)
        } else {
            Ok(None)
        }
    }

    /// `*(s attribute) o "}"`.
    fn close(&mut self) -> Result<(), SyntaxError> {
        self.attributes()?;
        self.o();
        self.expect('}')
    }

    fn operand(&mut self) -> Result<Operand, SyntaxError> {
        if self.eat('$') {
            Ok(Operand::Variable(self.name()?))
        } else {
            Ok(Operand::Literal(self.literal()?))
        }
    }

    fn function(&mut self) -> Result<Function, SyntaxError> {
        self.expect(':')?;
        let name = self.identifier()?;
        let options = self.options()?;
        Ok(Function { name, options })
    }

    /// `*(s option)`.
    fn options(&mut self) -> Result<Vec<Opt>, SyntaxError> {
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
    fn attributes(&mut self) -> Result<(), SyntaxError> {
        while self.s_then(|c| c == '@') {
            self.at += 1;
            drop(self.identifier()?);
            let start = self.at;
            self.o();
            if self.eat('=') {
                self.o();
                drop(self.literal()?);
            } else {
                self.at = start;
            }
        }
        Ok(())
    }

    /// `[namespace ":"] name`.
    fn identifier(&mut self) -> Result<String, SyntaxError> {
        let mut identifier = self.name()?;
        if self.eat(':') {
            identifier.push(':');
            identifier.push_str(&self.name()?);
        }
        Ok(identifier)
    }

    /// `[bidi] name-start *name-char [bidi]`, in NFC.
    fn name(&mut self) -> Result<String, SyntaxError> {
        self.skip_bidi();
        let start = self.at;
        if !self.peek().is_some_and(name_start) {
            return self.fail();
        }
        while self.peek().is_some_and(name_char) {
            self.at += self.peek().map_or(0, char::len_utf8);
        }
        let name = self
            .source
            .get(start..self.at)
            .unwrap_or_default()
            .nfc()
            .collect();
        self.skip_bidi();
        Ok(name)
    }

    /// A quoted or an unquoted literal's string value.
    fn literal(&mut self) -> Result<String, SyntaxError> {
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
        let start = self.at;
        while self.peek().is_some_and(name_char) {
            self.at += self.peek().map_or(0, char::len_utf8);
        }
        match self.source.get(start..self.at) {
            Some(literal) if !literal.is_empty() => Ok(literal.to_owned()),
            _ => self.fail(),
        }
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
