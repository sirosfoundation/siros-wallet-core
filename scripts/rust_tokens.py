"""Rust source as a list of tokens, as far as the scripts in this directory
read it: identifiers, lifetimes, numbers, string and character literals, and
punctuation. Comments are dropped, doc comments included, so a doctest is
never read as code.

`tokens` raises `LexError`, which names the line, on an unterminated comment
or literal.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

OPENERS = {"(": ")", "[": "]", "{": "}"}
CLOSERS = frozenset(OPENERS.values())

# Longest first: each is one token, so `..` is never read as a method call's
# dot and `!=` never as a macro's bang.
MULTI_CHARACTER_PUNCTUATION = ("..=", "...", "::", "..", "!=", "=>", "->")


class LexError(ValueError):
    """Source that ends inside a comment or a literal opened on `line`."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


class Kind(Enum):
    IDENT = auto()
    LIFETIME = auto()
    NUMBER = auto()
    STRING = auto()
    CHAR = auto()
    PUNCT = auto()


@dataclass(frozen=True)
class Token:
    kind: Kind
    text: str
    line: int

    def is_punct(self, text: str) -> bool:
        return self.kind is Kind.PUNCT and self.text == text

    def is_ident(self, text: str) -> bool:
        return self.kind is Kind.IDENT and self.text == text


def _is_ident_start(char: str) -> bool:
    return char == "_" or char.isalpha()


def _is_ident_continue(char: str) -> bool:
    return char == "_" or char.isalnum()


class _Lexer:
    def __init__(self, source: str) -> None:
        self.source = source
        self.at = 0
        self.line = 1
        self.out: list[Token] = []

    def peek(self, ahead: int = 0) -> str:
        index = self.at + ahead
        return self.source[index] if index < len(self.source) else ""

    def advance(self, count: int = 1) -> str:
        taken = self.source[self.at:self.at + count]
        self.line += taken.count("\n")
        self.at += count
        return taken

    def emit(self, kind: Kind, start: int, line: int) -> None:
        self.out.append(Token(kind, self.source[start:self.at], line))

    def run(self) -> list[Token]:
        while self.at < len(self.source):
            self.step()
        return self.out

    def step(self) -> None:
        char, line, start = self.peek(), self.line, self.at
        if char.isspace():
            self.advance()
        elif self.source.startswith("//", self.at):
            while self.peek() not in ("", "\n"):
                self.advance()
        elif self.source.startswith("/*", self.at):
            self.block_comment(line)
        elif self.raw_string_ahead():
            self.raw_string(line)
            self.emit(Kind.STRING, start, line)
        elif self.source.startswith("r#", self.at) and _is_ident_start(self.peek(2)):
            self.advance(2)
            self.identifier()
            self.out.append(Token(Kind.IDENT, self.source[start + 2:self.at], line))
        elif char in "bc" and self.peek(1) == '"':
            self.advance()
            self.quoted('"', line)
            self.emit(Kind.STRING, start, line)
        elif char == "b" and self.peek(1) == "'":
            self.advance()
            self.quoted("'", line)
            self.emit(Kind.CHAR, start, line)
        elif char == '"':
            self.quoted('"', line)
            self.emit(Kind.STRING, start, line)
        elif char == "'":
            self.quote_or_lifetime(start, line)
        elif char.isdigit():
            self.number()
            self.emit(Kind.NUMBER, start, line)
        elif _is_ident_start(char):
            self.identifier()
            self.emit(Kind.IDENT, start, line)
        else:
            self.punctuation()
            self.emit(Kind.PUNCT, start, line)

    def block_comment(self, line: int) -> None:
        depth = 0
        while True:
            if self.at >= len(self.source):
                raise LexError(line, "unterminated block comment")
            if self.source.startswith("/*", self.at):
                depth += 1
                self.advance(2)
            elif self.source.startswith("*/", self.at):
                depth -= 1
                self.advance(2)
                if depth == 0:
                    return
            else:
                self.advance()

    def raw_string_ahead(self) -> bool:
        prefix = 0
        if self.peek() in "bc" and self.peek(1) == "r":
            prefix = 1
        if self.peek(prefix) != "r":
            return False
        hashes = prefix + 1
        while self.peek(hashes) == "#":
            hashes += 1
        return self.peek(hashes) == '"'

    def raw_string(self, line: int) -> None:
        while self.peek() != "r":
            self.advance()
        self.advance()
        hashes = 0
        while self.peek() == "#":
            hashes += 1
            self.advance()
        self.advance()
        closing = '"' + "#" * hashes
        end = self.source.find(closing, self.at)
        if end < 0:
            raise LexError(line, "unterminated raw string")
        self.advance(end + len(closing) - self.at)

    def quoted(self, quote: str, line: int) -> None:
        self.advance()
        while True:
            char = self.peek()
            if char == "":
                raise LexError(line, f"unterminated {quote} literal")
            self.advance()
            if char == "\\":
                self.advance()
            elif char == quote:
                return

    def quote_or_lifetime(self, start: int, line: int) -> None:
        if self.peek(1) == "\\" or (self.peek(1) != "" and self.peek(2) == "'"):
            self.quoted("'", line)
            self.emit(Kind.CHAR, start, line)
            return
        self.advance()
        self.identifier()
        self.emit(Kind.LIFETIME, start, line)

    def number(self) -> None:
        while _is_ident_continue(self.peek()):
            self.advance()
        if self.peek() == "." and self.peek(1).isdigit():
            self.advance()
            while _is_ident_continue(self.peek()):
                self.advance()

    def identifier(self) -> None:
        while _is_ident_continue(self.peek()):
            self.advance()

    def punctuation(self) -> None:
        for text in MULTI_CHARACTER_PUNCTUATION:
            if self.source.startswith(text, self.at):
                self.advance(len(text))
                return
        self.advance()


def tokens(source: str) -> list[Token]:
    """The tokens of `source`, comments dropped."""
    return _Lexer(source).run()


def matching_closer(items: list[Token], opener: int) -> int:
    """The index of the token that closes the bracket at `opener`."""
    depth = 0
    for index in range(opener, len(items)):
        token = items[index]
        if token.kind is Kind.PUNCT and token.text in OPENERS:
            depth += 1
        elif token.kind is Kind.PUNCT and token.text in CLOSERS:
            depth -= 1
            if depth == 0:
                return index
    raise LexError(items[opener].line, f"unclosed {items[opener].text}")
