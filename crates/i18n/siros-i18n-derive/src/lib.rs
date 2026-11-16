//! `#[derive(Message)]`: siros-i18n's `Message` for a statement, a text the wallet words that is no
//! error.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::quote;
use siros_derive_internals::{Derive, Shape, expand, id, identified};
use syn::{Attribute, DeriveInput, Error, Fields, Ident, Result, parse_macro_input};

/// Writes siros-i18n's `Message` for a statement.
///
/// - Each struct, and each variant of an enum, carries `#[message(id = "…")]`, any non-empty text.
///   Its id is `<scope>.<text>`, the scope being the one the crate's `siros_i18n::scope!` names.
/// - A named field is an argument under its name (`r#` dropped). A field marked
///   `#[message(skip)]` is no argument. A tuple field must be skipped.
/// - An argument's value is the field. A field whose type is spelled `Option<T>` gives its
///   value when `Some`, and `""` when `None`.
/// - An id names one statement of its crate: a second use fails the build (E0428).
/// - The impl keeps the type's generics and where-clause, and adds `T: Arg` for each argument of
///   type `T` or `Option<T>`.
/// - In a build with siros-i18n's `check`, each id registers its row: the id and its arguments'
///   keys.
///
/// # Refusals
///
/// Each refusal follows the snippet it breaks, which compiles.
///
/// An id is its crate's once:
///
/// ```standalone_crate
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "share")]
/// struct Share;
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "deny")]
/// struct Deny;
/// # fn main() {}
/// ```
///
/// ```compile_fail,E0428
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "share")]
/// struct Share;
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "share")]
/// struct Deny;
/// # fn main() {}
/// ```
///
/// A struct takes one non-empty `id`, an argument is a named field, and a field takes `skip`
/// alone:
///
/// ```standalone_crate
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks")]
/// struct Asks {
///     name: String,
///     #[message(skip)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks")]
/// struct Asks(String, #[message(skip)] usize);
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "")]
/// struct Asks {
///     name: String,
///     #[message(skip)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks", id = "requests")]
/// struct Asks {
///     name: String,
///     #[message(skip)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks")]
/// struct Asks {
///     name: String,
///     #[message(hidden)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks", hidden)]
/// struct Asks {
///     name: String,
///     #[message(skip)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks")]
/// struct Asks {
///     name: String,
///     #[message(skip, skip)]
///     index: usize,
/// }
/// # fn main() {}
/// ```
///
/// Each variant takes an `id`, and the enum takes none:
///
/// ```standalone_crate
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// enum Choice {
///     #[message(id = "share")]
///     Share { count: usize },
///     #[message(id = "deny")]
///     Deny,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// enum Choice {
///     #[message(id = "share")]
///     Share { count: usize },
///     Deny,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "choice")]
/// enum Choice {
///     #[message(id = "share")]
///     Share { count: usize },
///     #[message(id = "deny")]
///     Deny,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(hidden)]
/// enum Choice {
///     #[message(id = "share")]
///     Share { count: usize },
///     #[message(id = "deny")]
///     Deny,
/// }
/// # fn main() {}
/// ```
///
/// An argument shows by its `Display` (E0277):
///
/// ```compile_fail,E0277
/// siros_i18n::scope!("doc");
///
/// struct Opaque;
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "asks")]
/// struct Asks {
///     name: Opaque,
/// }
/// # fn main() {}
/// ```
///
/// A statement is no error: a type that derives siros-explain's `Explain` takes its `Message` from
/// it (E0119):
///
/// ```standalone_crate
/// siros_i18n::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// fn worded(message: &dyn siros_i18n::Message) -> &str {
///     message.id()
/// }
///
/// fn main() {
///     assert_eq!(worded(&Expired), "err.doc.expired");
/// }
/// ```
///
/// ```compile_fail,E0119
/// siros_i18n::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain, siros_i18n::Message)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// #[message(id = "expired")]
/// struct Expired;
/// # fn main() {}
/// ```
///
/// A union is no statement:
///
/// ```compile_fail
/// siros_i18n::scope!("doc");
///
/// #[derive(siros_i18n::Message)]
/// #[message(id = "bits")]
/// union Bits {
///     word: u32,
/// }
/// # fn main() {}
/// ```
#[proc_macro_derive(Message, attributes(message))]
pub fn derive_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::<Message>(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// siros-i18n's `Message`: each statement is named by its id.
struct Message;

impl Derive for Message {
    const ATTRIBUTE: &'static str = "message";
    const NOUN: &'static str = "statement";
    const A_NOUN: &'static str = "a statement";
    const CRATE: &'static str = "siros_i18n";
    const TRAIT: &'static str = "Message";
    const SCOPE: &'static str = "msg";
    const MARKER: &'static str = "__siros_message_id_";

    fn shape(path: Tokens, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape> {
        let id = id::<Self>(attrs)?.ok_or_else(|| {
            Error::new_spanned(
                name,
                "no id: name this statement with `#[message(id = \"…\")]`",
            )
        })?;
        identified::<Self>(&path, &id, fields)
    }

    fn methods(id: &Tokens, arg: &Tokens) -> Tokens {
        quote! {
            fn id(&self) -> &str {
                #id
            }

            fn arg(&self, __key: &str) -> ::core::option::Option<&dyn ::siros_i18n::Arg> {
                #arg
            }
        }
    }
}
