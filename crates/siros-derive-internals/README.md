# siros-derive-internals

The field rules of `#[derive(Explain)]` (siros-explain-derive) and `#[derive(Message)]`
(siros-i18n-derive). A proc-macro crate exports only macros, so the two derive crates share this
library, as `serde_derive` shares `serde_derive_internals`.

## Usage

A derive crate implements [`Derive`] on a marker type and calls [`expand`] from its
`#[proc_macro_derive]` function:

```rust,no_run
use proc_macro2::TokenStream;
use quote::quote;
use siros_derive_internals::{Derive, Shape, expand, id, identified};
use syn::{Attribute, Error, Fields, Ident, Result};

struct Note;

impl Derive for Note {
    const ATTRIBUTE: &'static str = "note";
    const NOUN: &'static str = "note";
    const A_NOUN: &'static str = "a note";
    const CRATE: &'static str = "notes";
    const TRAIT: &'static str = "Note";
    const SCOPE: &'static str = "msg";
    const MARKER: &'static str = "__notes_note_id_";

    fn shape(path: TokenStream, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape> {
        let id = id::<Self>(attrs)?.ok_or_else(|| Error::new_spanned(name, "no id"))?;
        identified::<Self>(&path, &id, fields)
    }

    fn methods(id: &TokenStream, arg: &TokenStream) -> TokenStream {
        quote! {
            fn id(&self) -> &str { #id }
            fn arg(&self, __key: &str) -> ::core::option::Option<&dyn ::notes::Arg> {
                #arg
            }
        }
    }
}

let input: syn::DeriveInput = syn::parse_quote! {
    #[note(id = "saved")]
    struct Saved { name: String, #[note(skip)] index: usize }
};
expand::<Note>(&input)?;
# Ok::<(), Error>(())
```

## Contract

- Each struct, and each variant of an enum, is one shape (`Derive::shape`). The enum's own
  attribute takes no key, and a union is refused.
- [`id`] reads one non-empty `id = "…"` from the attributes named `Derive::ATTRIBUTE`, refusing
  any other key and a second `id`.
- [`identified`] writes a shape with its own id, `crate::__siros_scope!(<SCOPE> "<id>")`:
  - A named field is an argument under its name, `r#` dropped. A field marked
    `#[<ATTRIBUTE>(skip)]`, or one `Derive::left_out` names, stays out. A field `Derive::left_out`
    refuses fails the build with its error. A tuple field that is an argument is refused: "an
    argument is a named field: name it".
  - A key gives its field as `&dyn ::<CRATE>::Arg`; the impl bounds the field's type by
    `::<CRATE>::Arg`, so a type without `Display` fails there (E0277). A field spelled
    `Option<T>`, `std::option::Option<T>` or `core::option::Option<T>` gives its value when
    `Some` and `""` when `None`, bounding `T`.
  - Per id, a `#[macro_export]` marker macro named `<MARKER><text>`: the id's ASCII letters and
    digits as written, every other byte `_` and two hexadecimal digits. A second use of the id in
    the crate collides with it (E0428).
  - Per id, `::<CRATE>::__row!(<id>, [<keys>])`, the row the `check` feature registers.
- [`expand`] writes `impl ::<CRATE>::<TRAIT>` with the type's generics and where-clause,
  `Derive::bounds`, then each argument's bound, and `Derive::methods` given the `id` and `arg`
  match bodies.

The tests of siros-explain and siros-i18n, and the doc examples of the derive crates, reach every
rule except two: the `std::option::Option<T>` and `core::option::Option<T>`
spellings, and a zero-variant enum. siros-explain-derive refuses a transparent error with other than
one field; thiserror's derive refuses the same input, so no example isolates that refusal.
