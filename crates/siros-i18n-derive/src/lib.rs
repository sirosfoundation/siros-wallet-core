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
use quote::{format_ident, quote, quote_spanned};
use syn::ext::IdentExt as _;
use syn::spanned::Spanned as _;
use syn::{
    Attribute, Data, DeriveInput, Error, Field, Fields, GenericArgument, Ident, LitStr,
    PathArguments, Result, Type, WherePredicate, parse_macro_input, parse_quote_spanned,
};

/// Writes siros-i18n's `Message` for a statement.
///
/// - Each struct, and each variant of an enum, carries `#[message(id = "…")]`, any non-empty text.
///   Its id is `<scope>.<text>`, the scope being the one the crate's `siros_i18n::scope!` names.
/// - A named field is an argument under its name (`r#` dropped). A field marked
///   `#[message(skip)]` is no argument. A tuple field must be skipped.
/// - An argument's value is its `Display`. A field whose type is spelled `Option<T>` gives its
///   value when `Some`, and `""` when `None`.
/// - An id names one statement of its crate: a second use fails the build (E0428).
/// - The impl keeps the type's generics and where-clause, and adds `T: Display` for each argument
///   of type `T` or `Option<T>`.
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
    expand(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// One statement of the type, the struct or a variant: its arm of `id`, its arm of `args`, the
/// bounds its arguments need, and the items its id adds.
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
                "a union is no statement: derive `Message` on a struct or an enum",
            ));
        }
    };
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .extend(shapes.iter().flat_map(|shape| shape.bounds.iter().cloned()));
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
        impl #impl_generics ::siros_i18n::Message for #name #ty_generics #where_clause {
            fn id(&self) -> &str {
                #id
            }

            fn args(
                &self,
                __arg: &mut dyn ::core::ops::FnMut(&str, &dyn ::core::fmt::Display),
            ) {
                #args
            }
        }

        #(#items)*
    })
}

/// The `#[message]` attributes among `attrs`.
fn message_attributes(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs.iter().filter(|attr| attr.path().is_ident("message"))
}

/// An enum's own `#[message]`, which takes no key: each variant names its statement.
fn on_the_enum(attrs: &[Attribute]) -> Result<()> {
    for attr in message_attributes(attrs) {
        attr.parse_nested_meta(|meta| {
            Err(if meta.path.is_ident("id") {
                meta.error("an enum-level `id`: each variant takes its own")
            } else {
                meta.error("unknown key: `#[message]` sits on each variant")
            })
        })?;
    }
    Ok(())
}

/// The id of the struct or the variant `name`, from its attributes.
fn id(attrs: &[Attribute], name: &Ident) -> Result<LitStr> {
    let mut id: Option<LitStr> = None;
    for attr in message_attributes(attrs) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("id") {
                return Err(meta.error("unknown key: a statement takes `id`"));
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
    id.ok_or_else(|| {
        Error::new_spanned(
            name,
            "no id: name this statement with `#[message(id = \"…\")]`",
        )
    })
}

/// The struct or the variant at `path`, named `name`, whose named fields are its arguments.
fn shape(path: Tokens, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape> {
    let id = id(attrs, name)?;
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
    let scoped = quote!(crate::__siros_scope!(msg #id));
    let marker = marker(&id);
    Ok(Shape {
        id: quote!(#path { .. } => #scoped),
        args: quote!(#path { #(#bindings,)* .. } => { #(#statements;)* }),
        bounds,
        items: quote! {
            #marker
            ::siros_i18n::__row!(#scoped, [#(#keys),*]);
        },
    })
}

/// The key of `field` when it is an argument; `None` when it is marked `#[message(skip)]`.
fn argument(field: &Field) -> Result<Option<LitStr>> {
    let mut skip = false;
    for attr in message_attributes(&field.attrs) {
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
    if skip {
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
/// `__siros_message_id_` and the id's ASCII letters and digits as written, every other byte `_`
/// and its two hexadecimal digits, so two ids never share a name.
fn marker(id: &LitStr) -> Tokens {
    let mut name = String::from("__siros_message_id_");
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
        #[allow(
            non_local_definitions,
            reason = "a statement a function body defines holds its id there"
        )]
        #[macro_export]
        macro_rules! #name {
            () => {};
        }
    }
}
