"""Writes the two Unicode tables of the picker's crates from the tables of the crates that are
their test oracles, read from Cargo's registry:

- crates/siros-display/src/text/unsafe_ranges.rs, from unicode-general-category 1.1.0;
- crates/siros-transaction-data/src/definition/grapheme/runs.rs, from unicode-segmentation 1.12.0.

Run from the repository root after `cargo fetch`: python3 scripts/gen_unicode_tables.py
A new Unicode version takes the oracles' new versions here and in the crates' dev-dependencies.
"""
import glob
import os
import re

GENERAL_CATEGORY = "unicode-general-category-1.1.0"
SEGMENTATION = "unicode-segmentation-1.12.0"
UNICODE = "16.0"
CODE_POINTS = 0x110000
CARGO_HOME = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))


def source(crate):
    """The text of `src/tables.rs` of `crate`, as Cargo unpacked it."""
    found = glob.glob(os.path.join(CARGO_HOME, "registry/src/*", crate, "src/tables.rs"))
    if not found:
        raise SystemExit(f"{crate} is not in Cargo's registry: run `cargo fetch`")
    with open(found[0], encoding="utf-8") as f:
        return f.read()


def block(text, name):
    """The entries of the table `name` of `text`."""
    start = text.index(name)
    return text[start:text.index("];", start)]


def unsafe_ranges():
    """The ranges of Cc, Cf, Zl, Zp, Co, Cn and the surrogates, merged."""
    table = block(source(GENERAL_CATEGORY), "GENERAL_CATEGORY")
    entries = re.findall(r"\((\d+), (\d+), GeneralCategory::(\w+)\)", table)
    safe = [False] * CODE_POINTS
    unsafe = {"Control", "Format", "LineSeparator", "ParagraphSeparator", "PrivateUse",
              "Surrogate", "Unassigned"}
    for first, last, category in entries:
        if category not in unsafe:
            for code in range(int(first), int(last) + 1):
                safe[code] = True
    ranges = []
    for code in range(CODE_POINTS):
        if safe[code]:
            continue
        if ranges and ranges[-1][1] + 1 == code:
            ranges[-1][1] = code
        else:
            ranges.append([code, code])
    rows = [ranges[i:i + 4] for i in range(0, len(ranges), 4)]
    body = "\n".join("    " + " ".join(f"(0x{a:05X}, 0x{b:05X})," for a, b in row) for row in rows)
    return f"""//! The characters display text refuses: the code points of the general categories Cc
//! (control), Cf (format), Zl (line separator), Zp (paragraph separator), Co (private use) and Cn
//! (unassigned) of Unicode {UNICODE}, as `unicode-general-category` 1.1.0 gives them, with the
//! surrogates, which no `char` is. Inclusive ranges, sorted and disjoint, written by
//! `scripts/gen_unicode_tables.py`. The test of display text checks them against that crate for
//! every `char`.

/// The ranges.
#[rustfmt::skip]
pub(super) const UNSAFE: [(u32, u32); {len(ranges)}] = [
{body}
];
"""


def grapheme_runs():
    """The runs of the grapheme break property, Indic conjunct break split in, Hangul syllables
    continuing the run before them."""
    text = source(SEGMENTATION)
    entries = re.findall(r"\('\\u\{([0-9a-f]+)\}',\s*'\\u\{([0-9a-f]+)\}',\s*GC_(\w+)\)",
                         block(text, "const grapheme_cat_table"))
    linked = re.findall(r"\('\\u\{([0-9a-f]+)\}',\s*'\\u\{([0-9a-f]+)\}'\)",
                        block(text, "const InCB_Extend_table"))
    linkers = {int(c, 16) for c in re.findall(r"'\\u\{([0-9A-Fa-f]+)\}'",
                                              block(text, "pub fn is_incb_linker"))}
    category = ["Any"] * CODE_POINTS
    for first, last, name in entries:
        for code in range(int(first, 16), int(last, 16) + 1):
            category[code] = name
    extend_linked = {code for first, last in linked
                     for code in range(int(first, 16), int(last, 16) + 1)}
    names = {"Any": "Other", "CR": "Cr", "LF": "Lf", "Control": "Control", "Extend": "Extend",
             "ZWJ": "Zwj", "Regional_Indicator": "RegionalIndicator", "Prepend": "Prepend",
             "SpacingMark": "SpacingMark", "L": "L", "V": "V", "T": "T",
             "Extended_Pictographic": "Pictographic", "InCB_Consonant": "Consonant"}
    runs = []
    for code in range(CODE_POINTS):
        name = category[code]
        if 0xAC00 <= code <= 0xD7A3:
            assert name == ("LV" if (code - 0xAC00) % 28 == 0 else "LVT"), hex(code)
            continue
        if code in linkers:
            assert name == "Extend", hex(code)
            prop = "Linker"
        elif code in extend_linked:
            assert name in ("Extend", "ZWJ"), hex(code)
            prop = "Zwj" if name == "ZWJ" else "ExtendLinked"
        else:
            prop = names[name]
        if not runs or runs[-1][1] != prop:
            runs.append((code, prop))
    assert runs[0] == (0, "Control") and runs[1][0] == 0xA, runs[:2]
    runs = runs[1:]
    rows = [runs[i:i + 3] for i in range(0, len(runs), 3)]
    body = "\n".join("    " + " ".join(f"Run::new(0x{start:05X}, P::{prop})," for start, prop in row)
                     for row in rows)
    return f"""//! The grapheme break property of Unicode {UNICODE}, with the Indic conjunct break, by runs: each
//! run starts at a code point and lasts to the next run. Written by
//! `scripts/gen_unicode_tables.py` from the tables of `unicode-segmentation` 1.12.0; the test of
//! grapheme counts checks them against that crate for every `char`. The Hangul syllables are left
//! to arithmetic.

use super::{{Property as P, Run}};

/// The runs after U+0000 to U+0009, which are controls.
#[rustfmt::skip]
pub(super) static RUNS: [Run; {len(runs)}] = [
{body}
];
"""


def main():
    for path, text in [
        ("crates/siros-display/src/text/unsafe_ranges.rs", unsafe_ranges()),
        ("crates/siros-transaction-data/src/definition/grapheme/runs.rs", grapheme_runs()),
    ]:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


if __name__ == "__main__":
    main()
