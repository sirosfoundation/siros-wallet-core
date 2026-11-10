# siros-credman

Android Credential Manager's side of the SIROS wallet core's matcher: the registration the matcher
builds its wording from, the entries it adds for the core's consent display, and the delegation of
each set (A9, K4).

- [`Base::load`]: the entries every request reads, made by loading the wallet's MF2 sources into
  the matcher's `siros_i18n::Context` in the registration's locale. The context resolves every
  text on the wallet's code path.
- `register::write` (feature `register`): the wallet's writer of the registration. It writes once
  the source of each transaction type loads beside the base's, so every request's context loads.
- [`Registration`]: the matcher's reader of the registration, through `std::io::Read + Seek`. It
  reads the header, the directory and the base entries, then the source of each registered
  transaction type a request names ([`Registration::context`]), and no other byte. Every offset
  and length is checked against the blob's size; a registration that breaks a rule of its format
  is a [`Malformed`] naming the rule.
- [`emit`]: each choice of the core's display as Credential Manager draws it, a Standard or a
  Payment entry ([`CredmanEntry`]), each row a [`Field`] of at most [`FIELD_MAX`] characters, and
  the empty choice's title. The first choice that does not emit fails the emission
  ([`NotEmitted`]).
- [`WalletDisplay::of`] (A9) and [`Delegation::of`] (K4): whether a set needs the wallet's
  display, and the delegation the matcher sends for its entries. [`Fulfilment::check`]: the
  wallet refuses a background fulfilment of a set that needs its display with `access_denied`.

## Usage

The wallet writes the registration; the matcher opens it and builds its context for a request.

```rust
use std::io::Cursor;

use siros_credman::{Base, Registration};
use siros_i18n::{Bidi, LocaleTag};
use siros_syntax::{AllOf, Keyed};

let english = LocaleTag::parse("en")?;
// The wallet loads its sources, then writes the registration (feature `register`).
let base = Base::load(
    english.clone(),
    AllOf::one(english),
    Bidi::Default,
    AllOf::one("@locale en\n---\n".to_owned()),
)?;
let blob = siros_credman::register::write(&base, &Keyed::empty())?;

// The matcher opens it: it reads what every request reads and loads the base's context.
let registration = Registration::open(Cursor::new(blob))?;
assert_eq!(registration.base(), &base);
assert_eq!(registration.transactions().len(), 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a request, the matcher passes `registration.context(&request)` to `Match::run` and
`Views::of`, with an `Env` of the base's priority tags, and hands the display and the same context
to [`emit`].

## Features

| Feature | Default | Enables |
|---|---|---|
| `register` | off | `register::write` and `register::RegisterError`, the wallet's writer, and siros-i18n's `nfc` |

The reader and [`emit`] work with siros-i18n built without `nfc`, the matcher's build.

## Format

A registration is one blob: a header, a directory, then the entries' bytes. Every integer is
unsigned and little-endian. Offsets count bytes from the blob's start.

### Header

| Offset | Bytes | Field |
|---|---|---|
| 0 | 8 | The magic: `89 53 43 4D 0D 0A 1A 0A` |
| 8 | 4 | The version: `1` |
| 12 | 4 | The directory's length in bytes |

### Directory

The directory starts at offset 16 and holds the entries' records back to back, in the directory's
order. A record:

| Bytes | Field |
|---|---|
| 1 | The kind's code |
| 4 | The offset of the entry's bytes |
| 4 | The length of the entry's bytes |
| 2 | The name's length, `n` |
| `n` | The name, UTF-8 |

The entries' bytes follow the directory in the same order, back to back: the first starts where
the directory ends, each next one where the previous one ends, and the last one ends at the blob's
end.

### Kinds

The directory lists the kinds in ascending code order, and the transaction entries ascending by
their names' UTF-8 bytes.

| Code | Kind | Entries | Name | Bytes |
|---|---|---|---|---|
| 1 | locale | exactly 1 | empty | The tag of the locale the wallet wrote the registration in, every source's `@locale` |
| 2 | priority | exactly 1 | empty | The End-User's ranked tags, at least one, a comma (`0x2C`) between two |
| 3 | bidi | exactly 1 | empty | One byte: `0` MF2's Default Bidi Strategy, `1` none |
| 4 | source | 1 or more | empty | One of the wallet's MF2 resources, UTF-8; the entries in load order, the formats' options first |
| 5 | transaction | 0 or more | The transaction data type (OpenID4VP §5.1), each once | The type's converted View source, an MF2 resource, UTF-8 |

A tag is RFC 4647 §2.1's `1*8ALPHA *("-" 1*8alphanum)` in RFC 5646 §2.1.1's case, as
`siros_i18n::LocaleTag` writes it: the first subtag and every subtag after a one-character
subtag in lowercase; before that, a two-character subtag in uppercase, a four-letter subtag with
its first letter in uppercase and the rest in lowercase, any other in lowercase.

### Limits

- A registration holds at most 4,294,967,295 bytes.
- A name holds at most 65,535 bytes.

### Reading

A reader refuses a registration at the first rule it breaks, checked in this order; the
[`Malformed`] variant names the rule.

1. `Size`: the blob holds at most 4,294,967,295 bytes.
2. `Header`: the blob holds the 16 bytes of the header.
3. `Magic`: the blob starts with the magic.
4. `Version`: the version is 1. A reader of version 1 reads no other.
5. `Directory`: the directory ends within the blob.
6. For each record, in order:
   1. `Entry`: the directory holds the record whole, its name included.
   2. `Kind`: the kind's code is one of the table's.
   3. `Name`: the name is UTF-8.
   4. `Named`: only a transaction entry has a name; every other name is empty.
   5. `Span`: the entry's bytes end within the blob.
   6. `Tiling`: the entry's bytes start where the bytes before them end.
   7. `Order`: the kind's code is at least the previous record's, and a transaction's name is at
      least the previous transaction's name, compared by UTF-8 bytes.
   8. `Repeated`: no second locale, priority or bidi entry, and no transaction type twice.
7. `Trailing`: the last entry ends at the blob's end.
8. `Missing`: the directory lists a locale, a priority, a bidi and a source entry, checked in that
   order.
9. The entries' bytes, each read when it is needed: `Locale` and `Priority` for a tag that breaks
   the tag rule, `Bidi` for other than one byte `0` or `1`, `Text` for a source or a transaction
   source that is no UTF-8.
10. The sources, loaded into the matcher's context ([`ContextError`]): `Source` for a base source
    the context refuses, `Locale` for base sources whose `@locale` is not the locale entry's tag,
    `Transaction` for a transaction source the context refuses.

[`Registration::open`] reads the header, the directory and the base entries (locale, priority,
bidi and every source), checks every rule but a transaction source's, and loads the base sources
in their order into one context under the bidi choice ([`Base::load`]).
[`Registration::context`] reads the source of each registered type a request's `transaction_data`
names, and no other entry, and loads each into a clone of that context, ascending by type. It
loads a source byte-equal to one it loaded once: types whose metadata is one object convert to one
source.

### Writing

`register::write` writes a [`Base`], whose sources load. It loads the base's sources again in
their order, then each transaction source into a clone of that context, alone and after the
sources of the types before it, each through siros-i18n's `Context::module_in_nfc`. A source
byte-equal to an earlier type's loads once, and each type keeps its directory entry. It refuses the
first base source that holds a name, a variant key or a selector literal outside Unicode
Normalization Form C (`RegisterError::Source`), then the first transaction source that does not
load or holds one (`RegisterError::Transaction`). A distinct source that words an id of an earlier
type's source is refused (`LoadError::Repeated`). Every request's context then loads from what it
writes, and a matcher built without siros-i18n's `nfc` resolves it to the texts the wallet
resolves. A reader checks every rule of a blob it opens, whoever wrote it.
