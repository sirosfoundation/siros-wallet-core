//! `#[derive(Explain)]`: siros-explain's `Explain` for an error type, beside
//! `#[derive(thiserror::Error)]`.

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
use siros_derive_internals::{Derive, Shape, attributes, expand, id, identified};
use syn::ext::IdentExt as _;
use syn::spanned::Spanned as _;
use syn::{
    Attribute, DeriveInput, Error, Field, Fields, Ident, Result, WherePredicate, parse_macro_input,
    parse_quote_spanned,
};

/// Writes siros-explain's `Explain`, beside `#[derive(thiserror::Error)]`.
///
/// - Each struct, and each variant of an enum, carries `#[explain(id = "…")]`, any non-empty text,
///   or thiserror's `#[error(transparent)]`. Its id is `err.<scope>.<text>`, the scope being the
///   one the crate's `siros_explain::scope!` names.
/// - A transparent error has one field, which implements `Explain`: `id` and `args` are the
///   field's.
/// - A named field is an argument under its name (`r#` dropped). A field marked `#[source]`,
///   `#[from]`, `#[backtrace]` or `#[explain(skip)]`, or named `source`, is no argument. A tuple
///   field must be one of these.
/// - An argument's value is its `Display`. A field whose type is spelled `Option<T>` gives its
///   value when `Some`, and `""` when `None`.
/// - An id names one error of its crate: a second use fails the build (E0428).
/// - The impl keeps the type's generics and where-clause, and adds `Self: Error + Send + Sync +
///   'static`, `T: Display` for each argument of type `T` or `Option<T>`, and `T: Explain` for a
///   transparent field of type `T`.
/// - In a build with siros-explain's `check`, each id registers its row: the id and its arguments'
///   keys.
///
/// # Refusals
///
/// Each refusal follows the snippet it breaks, which compiles.
///
/// An id is its crate's once:
///
/// ```standalone_crate
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential is revoked")]
/// #[explain(id = "revoked")]
/// struct Revoked;
/// # fn main() {}
/// ```
///
/// ```compile_fail,E0428
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential is revoked")]
/// #[explain(id = "expired")]
/// struct Revoked;
/// # fn main() {}
/// ```
///
/// A struct takes one non-empty `id`, an argument is a named field, and a field takes `skip`
/// alone:
///
/// ```standalone_crate
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the value holds {length} bytes")]
/// #[explain(id = "too_long")]
/// struct TooLong {
///     length: usize,
///     #[explain(skip)]
///     limit: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the value holds {0} bytes")]
/// #[explain(id = "too_long")]
/// struct TooLong(usize, #[explain(skip)] usize);
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the value holds {length} bytes")]
/// #[explain(id = "")]
/// struct TooLong {
///     length: usize,
///     #[explain(skip)]
///     limit: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the value holds {length} bytes")]
/// #[explain(id = "too_long", id = "long")]
/// struct TooLong {
///     length: usize,
///     #[explain(skip)]
///     limit: usize,
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the value holds {length} bytes")]
/// #[explain(id = "too_long")]
/// struct TooLong {
///     length: usize,
///     #[explain(hidden)]
///     limit: usize,
/// }
/// # fn main() {}
/// ```
///
/// Each variant takes an `id` or is transparent, never both; the enum takes none, and a
/// transparent variant's field takes no `#[explain]`:
///
/// ```standalone_crate
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// enum Refused {
///     #[error("the credential is revoked")]
///     #[explain(id = "revoked")]
///     Revoked,
///     #[error(transparent)]
///     Expired(#[from] Expired),
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// enum Refused {
///     #[error("the credential is revoked")]
///     Revoked,
///     #[error(transparent)]
///     Expired(#[from] Expired),
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// enum Refused {
///     #[error("the credential is revoked")]
///     #[explain(id = "revoked")]
///     Revoked,
///     #[error(transparent)]
///     #[explain(id = "expired_again")]
///     Expired(#[from] Expired),
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[explain(id = "refused")]
/// enum Refused {
///     #[error("the credential is revoked")]
///     #[explain(id = "revoked")]
///     Revoked,
///     #[error(transparent)]
///     Expired(#[from] Expired),
/// }
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// #[error("the credential expired")]
/// #[explain(id = "expired")]
/// struct Expired;
///
/// #[derive(Debug, thiserror::Error, siros_explain::Explain)]
/// enum Refused {
///     #[error("the credential is revoked")]
///     #[explain(id = "revoked")]
///     Revoked,
///     #[error(transparent)]
///     Expired(#[from] #[explain(skip)] Expired),
/// }
/// # fn main() {}
/// ```
///
/// A union is no error:
///
/// ```standalone_crate
/// siros_explain::scope!("doc");
///
/// #[derive(Debug, siros_explain::Explain)]
/// #[explain(id = "bits")]
/// struct Bits {
///     #[explain(skip)]
///     word: u32,
/// }
///
/// impl std::fmt::Display for Bits {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("bits")
///     }
/// }
///
/// impl std::error::Error for Bits {}
/// # fn main() {}
/// ```
///
/// ```compile_fail
/// siros_explain::scope!("doc");
///
/// #[derive(siros_explain::Explain)]
/// #[explain(id = "bits")]
/// union Bits {
///     word: u32,
/// }
///
/// impl std::fmt::Debug for Bits {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("Bits")
///     }
/// }
///
/// impl std::fmt::Display for Bits {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("bits")
///     }
/// }
///
/// impl std::error::Error for Bits {}
/// # fn main() {}
/// ```
#[proc_macro_derive(Explain, attributes(explain))]
pub fn derive_explain(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand::<Explain>(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// siros-explain's `Explain`: an error is named by its id or forwards to its one field.
struct Explain;

impl Derive for Explain {
    const ATTRIBUTE: &'static str = "explain";
    const NOUN: &'static str = "error";
    const A_NOUN: &'static str = "an error";
    const CRATE: &'static str = "siros_explain";
    const TRAIT: &'static str = "Explain";
    const SCOPE: &'static str = "err";
    const MARKER: &'static str = "__siros_explain_id_";

    /// A field marked `#[source]`, `#[from]` or `#[backtrace]`, or named `source`: thiserror's
    /// causes.
    fn left_out(field: &Field) -> bool {
        let cause = field.attrs.iter().any(|attr| {
            ["source", "from", "backtrace"]
                .iter()
                .any(|thiserror| attr.path().is_ident(thiserror))
        });
        cause
            || field
                .ident
                .as_ref()
                .is_some_and(|ident| ident.unraw() == "source")
    }

    fn shape(path: Tokens, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape> {
        let transparent = attrs.iter().any(|attr| {
            attr.path().is_ident("error")
                && attr
                    .parse_args::<Ident>()
                    .is_ok_and(|word| word == "transparent")
        });
        match (id::<Self>(attrs)?, transparent) {
            (Some(id), true) => Err(Error::new_spanned(
                &id,
                "an `id` beside `#[error(transparent)]`: a transparent error is its field's",
            )),
            (Some(id), false) => identified::<Self>(&path, &id, fields),
            (None, true) => forwarded(&path, name, fields),
            (None, false) => Err(Error::new_spanned(
                name,
                "no id: name this error with `#[explain(id = \"…\")]`, or forward it with \
                 `#[error(transparent)]`",
            )),
        }
    }

    /// `Self: Error + Send + Sync + 'static`.
    fn bounds(input: &DeriveInput) -> Vec<WherePredicate> {
        let name = &input.ident;
        let (_, ty_generics, _) = input.generics.split_for_impl();
        vec![parse_quote_spanned! {name.span()=>
            #name #ty_generics: ::std::error::Error
                + ::core::marker::Send
                + ::core::marker::Sync
                + 'static
        }]
    }

    fn methods(id: &Tokens, args: &Tokens) -> Tokens {
        quote! {
            fn id(&self) -> &'static str {
                #id
            }

            fn args(
                &self,
                __arg: &mut dyn ::core::ops::FnMut(&'static str, &dyn ::core::fmt::Display),
            ) {
                #args
            }
        }
    }
}

/// A transparent error, which forwards `id` and `args` to its one field.
fn forwarded(path: &Tokens, name: &Ident, fields: &Fields) -> Result<Shape> {
    let mut members = fields.members().zip(fields);
    let (Some((member, field)), None) = (members.next(), members.next()) else {
        return Err(Error::new_spanned(
            name,
            "a transparent error has exactly one field",
        ));
    };
    if let Some(attr) = attributes::<Explain>(&field.attrs).next() {
        return Err(Error::new_spanned(
            attr,
            "a transparent error's field takes no `#[explain]`: the error is its field's",
        ));
    }
    let ty = &field.ty;
    let pattern = quote!(#path { #member: __field, .. });
    Ok(Shape {
        id: quote!(#pattern => ::siros_explain::Explain::id(__field)),
        args: quote!(#pattern => ::siros_explain::Explain::args(__field, __arg)),
        bounds: vec![parse_quote_spanned!(ty.span()=> #ty: ::siros_explain::Explain)],
        items: Tokens::new(),
    })
}
