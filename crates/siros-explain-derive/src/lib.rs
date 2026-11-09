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
use quote::{format_ident, quote, quote_spanned};
use syn::ext::IdentExt as _;
use syn::spanned::Spanned as _;
use syn::{
    Attribute, Data, DeriveInput, Error, Field, Fields, GenericArgument, Ident, LitStr,
    PathArguments, Result, Type, WherePredicate, parse_macro_input, parse_quote_spanned,
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
///   field is one of these.
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
    expand(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// What names an error: its id, or, when it is transparent, its one field.
enum Naming {
    Id(LitStr),
    Transparent,
}

/// One error of the type, the struct or a variant: its arm of `id`, its arm of `args`, the bounds
/// its fields need, and the items its id adds.
struct Shape {
    id: Tokens,
    args: Tokens,
    bounds: Vec<WherePredicate>,
    items: Tokens,
}

fn expand(input: &DeriveInput) -> Result<Tokens> {
    let name = &input.ident;
    let shapes = match &input.data {
        Data::Struct(data) => vec![shape(quote!(Self), name, &input.attrs, &data.fields)?],
        Data::Enum(data) => {
            on_the_enum(&input.attrs)?;
            data.variants
                .iter()
                .map(|variant| {
                    let ident = &variant.ident;
                    shape(quote!(Self::#ident), ident, &variant.attrs, &variant.fields)
                })
                .collect::<Result<Vec<_>>>()?
        }
        Data::Union(data) => {
            return Err(Error::new_spanned(
                data.union_token,
                "a union is no error: derive `Explain` on a struct or an enum",
            ));
        }
    };
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    let predicates = &mut generics.make_where_clause().predicates;
    predicates.push(parse_quote_spanned! {name.span()=>
        #name #ty_generics: ::std::error::Error
            + ::core::marker::Send
            + ::core::marker::Sync
            + 'static
    });
    predicates.extend(shapes.iter().flat_map(|shape| shape.bounds.iter().cloned()));
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    let (id, args) = if shapes.is_empty() {
        (quote!(match *self {}), quote!(match *self {}))
    } else {
        let ids = shapes.iter().map(|shape| &shape.id);
        let args = shapes.iter().map(|shape| &shape.args);
        (
            quote!(match self { #(#ids,)* }),
            quote!(match self { #(#args,)* }),
        )
    };
    let items = shapes.iter().map(|shape| &shape.items);
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::siros_explain::Explain for #name #ty_generics #where_clause {
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

        #(#items)*
    })
}

/// The `#[explain]` attributes among `attrs`.
fn explain_attributes(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs.iter().filter(|attr| attr.path().is_ident("explain"))
}

/// An enum's own `#[explain]`, which takes no key: each variant names its error.
fn on_the_enum(attrs: &[Attribute]) -> Result<()> {
    for attr in explain_attributes(attrs) {
        attr.parse_nested_meta(|meta| {
            Err(if meta.path.is_ident("id") {
                meta.error("an enum-level `id`: each variant takes its own")
            } else {
                meta.error("unknown key: `#[explain]` sits on each variant")
            })
        })?;
    }
    Ok(())
}

/// The naming of the struct or the variant `name`, from its attributes.
fn naming(attrs: &[Attribute], name: &Ident) -> Result<Naming> {
    let mut id: Option<LitStr> = None;
    for attr in explain_attributes(attrs) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("id") {
                return Err(meta.error("unknown key: an error takes `id`"));
            }
            if id.is_some() {
                return Err(meta.error("`id` is given twice"));
            }
            let text: LitStr = meta.value()?.parse()?;
            if text.value().is_empty() {
                return Err(Error::new_spanned(
                    &text,
                    "an empty id: an id is non-empty text",
                ));
            }
            id = Some(text);
            Ok(())
        })?;
    }
    let transparent = attrs.iter().any(|attr| {
        attr.path().is_ident("error")
            && attr
                .parse_args::<Ident>()
                .is_ok_and(|word| word == "transparent")
    });
    match (id, transparent) {
        (Some(id), true) => Err(Error::new_spanned(
            &id,
            "an `id` beside `#[error(transparent)]`: a transparent error is its field's",
        )),
        (Some(id), false) => Ok(Naming::Id(id)),
        (None, true) => Ok(Naming::Transparent),
        (None, false) => Err(Error::new_spanned(
            name,
            "no id: name this error with `#[explain(id = \"…\")]`, or forward it with \
             `#[error(transparent)]`",
        )),
    }
}

/// The struct or the variant at `path`, named `name`.
fn shape(path: Tokens, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape> {
    match naming(attrs, name)? {
        Naming::Id(id) => identified(&path, &id, fields),
        Naming::Transparent => transparent(&path, name, fields),
    }
}

/// An error that forwards to its one field.
fn transparent(path: &Tokens, name: &Ident, fields: &Fields) -> Result<Shape> {
    let mut members = fields.members().zip(fields);
    let (Some((member, field)), None) = (members.next(), members.next()) else {
        return Err(Error::new_spanned(
            name,
            "a transparent error has exactly one field",
        ));
    };
    if let Some(attr) = explain_attributes(&field.attrs).next() {
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

/// An error with its own id, whose named fields are its arguments.
fn identified(path: &Tokens, id: &LitStr, fields: &Fields) -> Result<Shape> {
    let mut bindings = Vec::new();
    let mut statements = Vec::new();
    let mut bounds = Vec::new();
    let mut keys = Vec::new();
    for (index, (member, field)) in fields.members().zip(fields).enumerate() {
        let Some(key) = argument(field)? else {
            continue;
        };
        let local = format_ident!("__field{}", index);
        statements.push(match option(&field.ty) {
            Some(held) => {
                bounds.push(display(held));
                quote! {
                    match #local {
                        ::core::option::Option::Some(__value) => __arg(#key, __value),
                        ::core::option::Option::None => __arg(#key, &""),
                    }
                }
            }
            None => {
                bounds.push(display(&field.ty));
                quote!(__arg(#key, #local))
            }
        });
        bindings.push(quote!(#member: #local));
        keys.push(key);
    }
    let scoped = quote!(crate::__siros_scope!(err #id));
    let marker = marker(id);
    Ok(Shape {
        id: quote!(#path { .. } => #scoped),
        args: quote!(#path { #(#bindings,)* .. } => { #(#statements;)* }),
        bounds,
        items: quote! {
            #marker
            ::siros_explain::__row!(#scoped, [#(#keys),*]);
        },
    })
}

/// The key of `field` when it is an argument; `None` when the error leaves it out: a field marked
/// `#[source]`, `#[from]`, `#[backtrace]` or `#[explain(skip)]`, or named `source`.
fn argument(field: &Field) -> Result<Option<LitStr>> {
    let mut skip = false;
    for attr in explain_attributes(&field.attrs) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("skip") {
                return Err(meta.error("unknown key: a field takes `skip`"));
            }
            if skip {
                return Err(meta.error("`skip` is given twice"));
            }
            skip = true;
            Ok(())
        })?;
    }
    let cause = field.attrs.iter().any(|attr| {
        ["source", "from", "backtrace"]
            .iter()
            .any(|thiserror| attr.path().is_ident(thiserror))
    });
    let source = field
        .ident
        .as_ref()
        .is_some_and(|ident| ident.unraw() == "source");
    if skip || cause || source {
        return Ok(None);
    }
    match &field.ident {
        Some(ident) => Ok(Some(LitStr::new(&ident.unraw().to_string(), ident.span()))),
        None => Err(Error::new_spanned(
            field,
            "an argument is a named field: name it",
        )),
    }
}

/// `T` when `ty` is spelled `Option<T>`, `std::option::Option<T>` or `core::option::Option<T>`.
fn option(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segments: Vec<_> = path.path.segments.iter().collect();
    let last = match segments.as_slice() {
        [last] if path.qself.is_none() && path.path.leading_colon.is_none() => last,
        [root, module, last]
            if path.qself.is_none()
                && (root.ident == "std" || root.ident == "core")
                && root.arguments.is_none()
                && module.ident == "option"
                && module.arguments.is_none() =>
        {
            last
        }
        _ => return None,
    };
    let PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    let mut each = arguments.args.iter();
    match (last.ident == "Option", each.next(), each.next()) {
        (true, Some(GenericArgument::Type(held)), None) => Some(held),
        _ => None,
    }
}

/// `ty: Display`, spanned at `ty`, so an argument without `Display` is refused there (E0277).
fn display(ty: &Type) -> WherePredicate {
    parse_quote_spanned!(ty.span()=> #ty: ::core::fmt::Display)
}

/// The item a second use of `id` in the crate collides with (E0428): a macro named
/// `__siros_explain_id_` and the id's ASCII letters and digits as written, every other byte `_`
/// and its two hexadecimal digits, so two ids never share a name.
fn marker(id: &LitStr) -> Tokens {
    let mut name = String::from("__siros_explain_id_");
    for byte in id.value().bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push(char::from(byte));
        } else {
            name.push_str(&format!("_{byte:02x}"));
        }
    }
    let name = Ident::new(&name, id.span());
    quote_spanned! {id.span()=>
        #[doc(hidden)]
        #[allow(non_local_definitions)]
        #[macro_export]
        macro_rules! #name {
            () => {};
        }
    }
}
