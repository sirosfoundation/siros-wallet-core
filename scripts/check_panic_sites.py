#!/usr/bin/env python3
"""Fail on a panic site outside test code in a crate of a normal flow.

    python3 scripts/check_panic_sites.py Cargo.toml

Only the DC API matcher may panic: Credential Manager shows nothing when it
traps, so its crates (MATCHER_CRATES) keep each panic with the reason it
cannot recover. A test host (a crate named `*-testhost`) runs the matcher in
the tests, so its code is test code. Every other crate of the named
workspaces runs in a normal flow, where a panic crashes the wallet, and the
check covers it with no list to extend. Each root of its targets that ship
carries `#![cfg_attr(not(test), deny(...))]` over the lints in PANIC_LINTS,
and this check fails on a root without it and on an `allow`, `expect` or
`warn` of those lints outside test code: clippy then denies `panic!`,
`unreachable!`, `todo!`, `unimplemented!`, `unwrap`, `expect`, indexing, and
the std methods that clippy.toml's `disallowed-methods` names, which panic
and share their name with a method that does not. This check finds the rest
by name:

  - the `assert!` family and `debug_assert!` family;
  - `panic_any` and `resume_unwind`;
  - the std methods in METHODS, whose documentation lists a panic on an
    argument: an index, a length, a range, a radix, a divisor or a size. A
    call whose last argument is a literal that rules the panic out passes:
    a nonzero size or divisor, a radix from 2 to 36;
  - an index by reference, `map[&key]`, which panics on an absent key;
  - `/` and `%` by anything but a numeric literal, which panic on an
    integer 0: `checked_div` and `checked_rem` take a divisor that may be 0.
    The check reads no types, so it flags a float divisor too.

Test code is exempt: the integration tests, benches and examples, an item
under `#[test]` or under a `#[cfg(...)]` that implies `test` or a feature in
TEST_FEATURES, the module files such an item declares, and a file or inline
module that starts with such a `#![cfg(...)]`. The check walks each target's module tree
from its root, as cargo metadata names it, and fails on a `.rs` file under a
crate's `src/` that the walk does not reach.

The manifests are `Cargo.toml` files inside this repository. Prints the
count per crate and each site. Exits 1 on a site and on source the walk
cannot read, and 2 on a refused argument.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from repo_paths import PathRefused, existing_file
from rust_tokens import Kind, LexError, Token, matching_closer, tokens

MATCHER_CRATES = frozenset({"android-credman-sys", "android-credman", "siros-picker"})
TEST_HOST_SUFFIX = "-testhost"

# Targets whose code ships. Test, bench and example targets are test code.
SHIPPING_KINDS = frozenset({"lib", "rlib", "cdylib", "staticlib", "dylib", "proc-macro", "bin",
                            "custom-build"})

PANIC_MACROS = frozenset({"assert", "assert_eq", "assert_ne", "assert_matches", "debug_assert",
                          "debug_assert_eq", "debug_assert_ne", "debug_assert_matches"})
PANIC_FUNCTIONS = frozenset({"panic_any", "resume_unwind"})

PANIC_LINTS = frozenset({"panic", "unwrap_used", "expect_used", "unreachable", "todo",
                         "unimplemented", "indexing_slicing", "disallowed_methods"})
LEVELS_BELOW_DENY = frozenset({"allow", "expect", "warn"})

# Features that compile code for other crates' tests.
TEST_FEATURES = frozenset({"test-fixtures"})


@dataclass(frozen=True)
class Method:
    """A std method that panics on an argument; `safe_last` names the
    literal last argument that rules the panic out."""

    name: str
    safe_last: str = ""


def _methods(safe_last: str, *names: str) -> list[Method]:
    return [Method(name, safe_last) for name in names]


NONZERO = "a nonzero literal"
RADIX = "a radix literal from 2 to 36"
METHODS = {method.name: method for method in [
    *_methods("", "copy_from_slice", "clone_from_slice", "swap_with_slice", "copy_within",
              "split_at", "split_at_mut", "swap_remove", "split_off", "extend_from_within",
              "insert_str", "replace_range", "select_nth_unstable", "select_nth_unstable_by",
              "select_nth_unstable_by_key", "ilog", "ilog2", "ilog10", "from_secs_f32",
              "from_secs_f64", "mul_f32", "mul_f64", "div_f32", "div_f64"),
    *_methods(NONZERO, "chunks", "chunks_mut", "chunks_exact", "chunks_exact_mut", "rchunks",
              "rchunks_mut", "rchunks_exact", "rchunks_exact_mut", "windows", "step_by",
              "div_euclid", "rem_euclid", "div_ceil", "div_floor", "next_multiple_of"),
    *_methods(RADIX, "to_digit", "is_digit", "from_digit", "from_str_radix"),
]}

# Keywords after which `[` opens an array or a slice pattern, never an index.
NOT_AN_OPERAND = frozenset({"as", "box", "break", "const", "continue", "dyn", "else", "enum",
                            "extern", "fn", "for", "if", "impl", "in", "let", "loop", "match",
                            "mod", "move", "mut", "pub", "ref", "return", "static", "struct",
                            "trait", "type", "unsafe", "use", "where", "while", "yield"})


class SourceError(Exception):
    """Source the walk cannot read; the message names the file."""


@dataclass(frozen=True)
class Site:
    path: Path
    line: int
    message: str


@dataclass
class Walk:
    """What the walk of one crate found: the panic sites, the target roots
    without the panic lints, and every file it read as shipping code or as
    test code."""

    sites: list[Site] = field(default_factory=list)
    unlinted: list[Site] = field(default_factory=list)
    reached: set[Path] = field(default_factory=set)


# ---- attributes --------------------------------------------------------

def _predicate_implies_test(items: list[Token], start: int, end: int) -> bool:
    """Whether the cfg predicate `items[start:end]` holds only under `test` or
    a feature in TEST_FEATURES."""
    if end - start == 1:
        return items[start].is_ident("test")
    if end - start == 3 and items[start].is_ident("feature") and items[start + 1].is_punct("="):
        return items[start + 2].text.strip('"') in TEST_FEATURES
    head = items[start]
    if head.kind is not Kind.IDENT or not items[start + 1].is_punct("("):
        return False
    close = matching_closer(items, start + 1)
    parts = list(_arguments(items, start + 1, close))
    if head.text == "all":
        return any(_predicate_implies_test(items, a, b) for a, b in parts)
    if head.text == "any":
        return bool(parts) and all(_predicate_implies_test(items, a, b) for a, b in parts)
    return False


def _arguments(items: list[Token], opener: int, closer: int) -> Iterator[tuple[int, int]]:
    """The comma-separated ranges between `opener` and its `closer`."""
    depth, start = 0, opener + 1
    for index in range(opener + 1, closer):
        token = items[index]
        if token.kind is Kind.PUNCT and token.text in "([{":
            depth += 1
        elif token.kind is Kind.PUNCT and token.text in ")]}":
            depth -= 1
        elif depth == 0 and token.is_punct(","):
            yield start, index
            start = index + 1
    if start < closer:
        yield start, closer


def _attribute_gates_test(items: list[Token], opener: int, closer: int) -> bool:
    """Whether the attribute `#[...]` between `opener` and `closer` compiles
    its item for tests only."""
    path = [token.text for token in items[opener + 1:closer]]
    if path and path[-1] in ("test", "bench") and all(
            text == "::" or text.isidentifier() for text in path):
        return True
    if len(path) > 3 and path[0] == "cfg" and path[1] == "(":
        return _predicate_implies_test(items, opener + 3, closer - 1)
    return False


def _lowered_panic_lints(items: list[Token], start: int, end: int) -> str:
    """The `allow`, `expect` or `warn` of a panic lint the attribute body
    `items[start:end]` sets, and an empty text when it sets none. A
    `cfg_attr` whose predicate implies test code sets nothing outside it."""
    head = items[start]
    if end - start < 3 or not items[start + 1].is_punct("("):
        return ""
    parts = list(_arguments(items, start + 1, end - 1))
    if head.is_ident("cfg_attr") and parts:
        if _predicate_implies_test(items, *parts[0]):
            return ""
        return "".join(_lowered_panic_lints(items, a, b) for a, b in parts[1:])
    if head.text not in LEVELS_BELOW_DENY:
        return ""
    lints = [items[b - 1].text for a, b in parts
             if [t.text for t in items[a:b - 1]] == ["clippy", "::"]]
    named = sorted(set(lints) & PANIC_LINTS)
    return f"{head.text}(clippy::{', clippy::'.join(named)})" if named else ""


def _item_end(items: list[Token], start: int) -> int:
    """The index after the item, statement, field or arm at `start`."""
    depth = 0
    for index in range(start, len(items)):
        token = items[index]
        if token.kind is Kind.PUNCT and token.text in "([{":
            depth += 1
        elif token.kind is Kind.PUNCT and token.text in ")]}":
            if depth == 0:
                return index
            depth -= 1
            if depth == 0 and token.text == "}":
                return index + 1
        elif depth == 0 and token.kind is Kind.PUNCT and token.text in (";", ","):
            return index + 1
    return len(items)


# ---- sites -------------------------------------------------------------

def _literal_value(token: Token) -> float | None:
    if token.kind is not Kind.NUMBER:
        return None
    text = token.text.replace("_", "").lower()
    for prefix, base in (("0x", 16), ("0o", 8), ("0b", 2)):
        if text.startswith(prefix):
            digits = text[2:].rstrip("uisz0123456789")
            return float(int(digits or text[2:], base)) if digits else None
    number = text.rstrip("abcdefghijklmnopqrstuvwxyz0123456789")
    body = text[:len(text) - len(text.lstrip("0123456789."))] or number
    try:
        return float(body)
    except ValueError:
        return None


def _last_argument_rules_out(method: Method, items: list[Token], opener: int) -> bool:
    if not method.safe_last:
        return False
    parts = list(_arguments(items, opener, matching_closer(items, opener)))
    if not parts or parts[-1][1] - parts[-1][0] != 1:
        return False
    value = _literal_value(items[parts[-1][0]])
    if value is None:
        return False
    if method.safe_last == NONZERO:
        return value != 0
    return value == int(value) and 2 <= value <= 36


def _site_at(items: list[Token], index: int) -> str | None:
    """The panic site that starts at `items[index]`, if one does."""
    token = items[index]
    after = items[index + 1] if index + 1 < len(items) else None
    before = items[index - 1] if index > 0 else None
    if token.kind is Kind.IDENT and after is not None:
        if token.text in PANIC_MACROS and after.is_punct("!") and index + 2 < len(items) \
                and items[index + 2].text in "([{":
            return f"{token.text}!"
        if before is not None and before.is_ident("fn"):
            return None
        if token.text in PANIC_FUNCTIONS and after.is_punct("("):
            return f"{token.text}()"
        method = METHODS.get(token.text)
        if method is not None and after.is_punct("(") and before is not None \
                and before.kind is Kind.PUNCT and before.text in (".", "::") \
                and not _last_argument_rules_out(method, items, index + 1):
            return f"{token.text}()"
    if token.kind is Kind.PUNCT and token.text in ("/", "%"):
        divisor = index + 1
        while divisor < len(items) and items[divisor].kind is Kind.PUNCT \
                and items[divisor].text in ("=", "-"):
            divisor += 1
        if divisor >= len(items) or items[divisor].kind is not Kind.NUMBER:
            return f"{token.text} by a value that is not a literal"
    if token.is_punct("[") and after is not None and after.is_punct("&") and before is not None:
        operand = before.kind in (Kind.IDENT, Kind.NUMBER, Kind.STRING) \
            and before.text not in NOT_AN_OPERAND
        if operand or (before.kind is Kind.PUNCT and before.text in (")", "]", "?")):
            return "index by reference"
    return None


# ---- the module tree ---------------------------------------------------

@dataclass(frozen=True)
class ModuleFile:
    """A file of the module tree, `in_test` when only a test build compiles it.
    `directory` holds the files of the modules it declares."""

    path: Path
    directory: Path
    in_test: bool


class _Scanner:
    def __init__(self, module: ModuleFile, items: list[Token], walk: Walk) -> None:
        self.module = module
        self.items = items
        self.walk = walk
        self.declared: list[ModuleFile] = []

    def scan(self, start: int, end: int, in_test: bool, inline: tuple[str, ...]) -> None:
        index = start
        while index < end:
            index = self.step(index, end, in_test, inline)

    def step(self, index: int, end: int, in_test: bool, inline: tuple[str, ...]) -> int:
        items = self.items
        token = items[index]
        if token.is_punct("#"):
            return self.attribute(index, end, in_test, inline)
        if token.is_ident("mod") and index + 2 < end and items[index + 1].kind is Kind.IDENT:
            name, follower = items[index + 1].text, items[index + 2]
            if follower.is_punct(";"):
                self.declare(name, index, in_test, inline)
                return index + 3
            if follower.is_punct("{"):
                closer = matching_closer(items, index + 2)
                self.scan(index + 3, closer, in_test, (*inline, name))
                return closer + 1
        if not in_test:
            what = _site_at(items, index)
            if what is not None:
                self.walk.sites.append(Site(self.module.path, token.line, f"{what} panics"))
        return index + 1

    def attribute(self, index: int, end: int, in_test: bool, inline: tuple[str, ...]) -> int:
        items = self.items
        inner = index + 1 < end and items[index + 1].is_punct("!")
        opener = index + 2 if inner else index + 1
        if opener >= end or not items[opener].is_punct("["):
            return index + 1
        closer = matching_closer(items, opener)
        if not _attribute_gates_test(items, opener, closer):
            lowered = _lowered_panic_lints(items, opener + 1, closer)
            if lowered and not in_test:
                self.walk.sites.append(Site(self.module.path, items[index].line,
                                            f"{lowered} outside test code"))
            return closer + 1
        if inner:
            self.scan(closer + 1, end, True, inline)
            return end
        item_end = _item_end(items, self.next_item(closer + 1))
        self.scan(closer + 1, item_end, True, inline)
        return item_end

    def next_item(self, index: int) -> int:
        """The first token after the outer attributes that start at `index`."""
        while index < len(self.items) and self.items[index].is_punct("#"):
            index = matching_closer(self.items, index + 1) + 1
        return index

    def declare(self, name: str, index: int, in_test: bool, inline: tuple[str, ...]) -> None:
        directory = self.module.directory.joinpath(*inline)
        path_attribute = self.path_attribute(index)
        if path_attribute is not None:
            base = self.module.path.parent.joinpath(*inline)
            path = base / path_attribute
            self.declared.append(ModuleFile(path, path.parent / path.stem, in_test))
            return
        for path, child in ((directory / f"{name}.rs", directory / name),
                            (directory / name / "mod.rs", directory / name)):
            if path.is_file():
                self.declared.append(ModuleFile(path, child, in_test))
                return
        raise SourceError(f"{self.module.path}:{self.items[index].line}: module {name} has no file")

    def path_attribute(self, index: int) -> str | None:
        """The `#[path = "..."]` on the declaration at `index`, if it has one."""
        cursor = index - 1
        while cursor > 1 and self.items[cursor].is_punct("]"):
            opener = cursor
            while opener > 0 and not self.items[opener].is_punct("["):
                opener -= 1
            body = self.items[opener + 1:cursor]
            if len(body) == 3 and body[0].is_ident("path") and body[1].is_punct("="):
                return body[2].text.strip('"')
            cursor = opener - 2
        return None


def _denied_outside_tests(items: list[Token]) -> frozenset[str]:
    """The clippy lints an inner `#![cfg_attr(not(test), deny(...))]` names."""
    texts = [token.text for token in items]
    head = ["#", "!", "[", "cfg_attr", "(", "not", "(", "test", ")", ",", "deny", "("]
    found: set[str] = set()
    for start in range(len(texts) - len(head)):
        if texts[start:start + len(head)] != head:
            continue
        opener = start + len(head) - 1
        for begin, end in _arguments(items, opener, matching_closer(items, opener)):
            if texts[begin:end - 1] == ["clippy", "::"]:
                found.add(texts[end - 1])
    return frozenset(found)


def _read(path: Path) -> list[Token]:
    try:
        return tokens(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, LexError) as error:
        raise SourceError(f"{path}: {error}") from error


def _walk_tree(root: Path, walk: Walk) -> None:
    missing = PANIC_LINTS - _denied_outside_tests(_read(root))
    if missing:
        walk.unlinted.append(Site(root, 1, "the root lacks #![cfg_attr(not(test), deny(clippy::"
                                  + ", clippy::".join(sorted(missing)) + "))]"))
    pending = [ModuleFile(root, root.parent, in_test=False)]
    while pending:
        module = pending.pop()
        if module.path in walk.reached:
            continue
        walk.reached.add(module.path)
        items = _read(module.path)
        scanner = _Scanner(module, items, walk)
        scanner.scan(0, len(items), module.in_test, ())
        pending.extend(scanner.declared)


# ---- crates ------------------------------------------------------------

@dataclass(frozen=True)
class Crate:
    name: str
    directory: Path
    roots: tuple[Path, ...]


def _crates(manifest: Path) -> list[Crate]:
    command = ["cargo", "metadata", "--no-deps", "--offline", "--format-version", "1",
               "--manifest-path", str(manifest)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SourceError(f"{manifest}: cargo metadata failed:\n{result.stderr}")
    crates = []
    for package in json.loads(result.stdout)["packages"]:
        roots = []
        for target in package["targets"]:
            if SHIPPING_KINDS.intersection(target["kind"]):
                try:
                    roots.append(existing_file(target["src_path"], ".rs"))
                except PathRefused as refused:
                    raise SourceError(str(refused)) from refused
        directory = Path(package["manifest_path"]).parent
        crates.append(Crate(package["name"], directory, tuple(roots)))
    return crates


def check_crate(crate: Crate) -> Walk:
    walk = Walk()
    for root in crate.roots:
        _walk_tree(root, walk)
    unreached = sorted(set((crate.directory / "src").rglob("*.rs")) - walk.reached)
    if unreached:
        raise SourceError(f"{crate.name}: no target's module tree reaches "
                          + ", ".join(str(path) for path in unreached))
    return walk


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail on a panic site outside test code in a crate of a normal flow.")
    parser.add_argument("manifests", metavar="Cargo.toml", nargs="+",
                        help="a workspace manifest inside this repository")
    arguments = parser.parse_args(argv)
    try:
        manifests = [existing_file(argument, ".toml") for argument in arguments.manifests]
    except PathRefused as refused:
        parser.error(str(refused))
    sites = unlinted = 0
    try:
        for manifest in manifests:
            for crate in sorted(_crates(manifest), key=lambda crate: crate.name):
                if crate.name in MATCHER_CRATES:
                    print(f"{crate.name}: the DC API matcher, exempt")
                    continue
                if crate.name.endswith(TEST_HOST_SUFFIX):
                    print(f"{crate.name}: a test host, exempt as test code")
                    continue
                walk = check_crate(crate)
                print(f"{crate.name}: {len(walk.sites)} panic sites")
                for site in walk.unlinted + walk.sites:
                    print(f"::error file={site.path},line={site.line}::{site.message}")
                sites += len(walk.sites)
                unlinted += len(walk.unlinted)
    except SourceError as error:
        print(f"::error::{error}")
        return 1
    print(f"panic sites outside test code: {sites}; roots without the lints: {unlinted}")
    return 1 if sites or unlinted else 0


if __name__ == "__main__":
    sys.exit(main())
