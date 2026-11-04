//! `#[derive(Explain)]`: siros-explain's `Explain` and `Messages` for an error type, beside
//! `#[derive(thiserror::Error)]`. It reads thiserror's `#[error("…")]` literal as the English
//! template and `#[error(transparent)]` as a transparent variant.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{Attribute, Data, DeriveInput, Error, Fields, LitStr, Result, parse_macro_input};

/// Writes `Explain` and `Messages`. Attributes: `#[explain(domain = "…")]` on the type, required;
/// `#[explain(id = "…")]` on a variant or a struct, its name in snake case when absent;
/// `#[explain(transparent)]` or thiserror's `#[error(transparent)]` on a one-field variant, whose
/// message is its field's; `#[explain(name = "…")]` on a field, required on a tuple field;
/// `#[explain(skip)]` on a field the message does not name. It refuses a domain anywhere but on
/// the type, an `id` beside `transparent`, a field attribute on a transparent message, a key
/// given twice, an identifier outside
/// siros-explain's `tokens`, and an identifier repeated in a type. A message's argument names go
/// through `names!`, which fails the build (E0080) for a name outside `tokens` or a name given
/// twice.
#[proc_macro_derive(Explain, attributes(explain))]
pub fn derive_explain(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// How a message is named: by its identifier (its name in snake case when none is given), or by
/// its cause's when it is transparent.
enum Naming {
    Id(Option<LitStr>),
    Transparent,
}

/// Where the attributes sit, which decides the keys they may hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// An enum's type: `domain` alone.
    Enum,
    /// A struct's type: `domain`, and the message's naming.
    Struct,
    /// A variant: the message's naming alone.
    Variant,
}

/// The attributes of one place: its domain, when it may hold one, and its naming.
struct Attributes {
    domain: Option<LitStr>,
    naming: Naming,
}

/// The attributes at a place, refused for a key the place does not take or a key given twice.
fn parse(attrs: &[Attribute], place: Place) -> Result<Attributes> {
    let mut domain: Option<LitStr> = None;
    let mut naming: Option<Naming> = None;
    for attr in attrs {
        if attr.path().is_ident("explain") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("domain") {
                    if place == Place::Variant {
                        return Err(meta.error("`domain` belongs on the type"));
                    }
                    if domain.is_some() {
                        return Err(meta.error("`domain` is given twice"));
                    }
                    domain = Some(meta.value()?.parse()?);
                } else if meta.path.is_ident("id") {
                    if place == Place::Enum {
                        return Err(meta.error("`id` belongs on a variant"));
                    }
                    let id: LitStr = meta.value()?.parse()?;
                    naming = Some(match naming.take() {
                        None => Naming::Id(Some(id)),
                        Some(Naming::Id(_)) => return Err(meta.error("`id` is given twice")),
                        Some(Naming::Transparent) => {
                            return Err(
                                meta.error("a transparent message takes its cause's identifier")
                            );
                        }
                    });
                } else if meta.path.is_ident("transparent") {
                    if place == Place::Enum {
                        return Err(meta.error("`transparent` belongs on a variant"));
                    }
                    naming = Some(transparent(naming.take(), &meta.path)?);
                } else {
                    return Err(meta.error("expected `domain`, `id` or `transparent`"));
                }
                Ok(())
            })?;
        } else if attr.path().is_ident("error")
            && attr
                .parse_args::<syn::Ident>()
                .is_ok_and(|ident| ident == "transparent")
        {
            naming = Some(transparent(naming.take(), attr.path())?);
        }
    }
    Ok(Attributes {
        domain,
        naming: naming.unwrap_or(Naming::Id(None)),
    })
}

/// `transparent` given again, by explain's attribute or thiserror's, states the same naming; one
/// beside an `id` is refused.
fn transparent(naming: Option<Naming>, at: &syn::Path) -> Result<Naming> {
    match naming {
        None | Some(Naming::Transparent) => Ok(Naming::Transparent),
        Some(Naming::Id(_)) => Err(Error::new_spanned(
            at,
            "a transparent message takes its cause's identifier",
        )),
    }
}

/// thiserror's `#[error("…")]` literal, its format arguments left out; `None` for a type or a
/// variant without one, such as `#[error(transparent)]`.
fn template(attrs: &[Attribute]) -> Result<Option<LitStr>> {
    let Some(attr) = attrs.iter().find(|attr| attr.path().is_ident("error")) else {
        return Ok(None);
    };
    attr.parse_args_with(|input: syn::parse::ParseStream<'_>| {
        let literal = if input.peek(LitStr) {
            Some(input.parse::<LitStr>()?)
        } else {
            None
        };
        let _format_args: Tokens = input.parse()?;
        Ok(literal)
    })
}

/// What a field's attributes say: the name it is given, or that the message leaves it out.
enum FieldNaming {
    Unsaid,
    Name(LitStr),
    Skip,
}

/// A field's argument name; `None` for a skipped field.
fn argument(field: &syn::Field, index: usize) -> Result<Option<String>> {
    let mut said = FieldNaming::Unsaid;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("explain"))
    {
        attr.parse_nested_meta(|meta| {
            let next = if meta.path.is_ident("name") {
                FieldNaming::Name(meta.value()?.parse()?)
            } else if meta.path.is_ident("skip") {
                FieldNaming::Skip
            } else {
                return Err(meta.error("expected `name` or `skip`"));
            };
            if !matches!(said, FieldNaming::Unsaid) {
                return Err(meta.error("a field takes one `name` or one `skip`"));
            }
            said = next;
            Ok(())
        })?;
    }
    match said {
        FieldNaming::Skip => Ok(None),
        FieldNaming::Name(literal) => Ok(Some(literal.value())),
        FieldNaming::Unsaid => field
            .ident
            .as_ref()
            .map(|ident| Some(ident.to_string()))
            .ok_or_else(|| {
                Error::new_spanned(
                    field,
                    format!("field {index} needs #[explain(name = \"…\")] or #[explain(skip)]"),
                )
            }),
    }
}

/// Whether a segment is a token: a lowercase ASCII letter, then lowercase letters, digits and
/// underscores (siros-explain's `tokens`, one segment).
fn token(segment: &str) -> bool {
    let mut chars = segment.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `ResponseTypeAbsent` → `response_type_absent`.
fn snake(ident: &syn::Ident) -> String {
    let mut out = String::new();
    for (i, c) in ident.to_string().chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// One message's pieces: the pattern that binds its fields, the identifier, the arguments, the
/// statement that declares its messages, and the constant item that checks its argument names
/// when the crate is checked, whatever the type's generics.
struct Shape {
    pattern: Tokens,
    id: Tokens,
    args: Tokens,
    declares: Tokens,
    guard: Tokens,
}

/// A field and the local its pattern binds it to.
struct Binding<'f> {
    field: &'f syn::Field,
    index: usize,
    local: syn::Ident,
}

/// A field the message names: its argument name, its local and its type.
struct Argument<'f> {
    name: String,
    local: &'f syn::Ident,
    ty: &'f syn::Type,
}

/// One message's [`Shape`], from its path, its fields and attributes, and the identifiers the
/// type's earlier messages took.
fn shape(
    path: Tokens,
    fields: &Fields,
    naming: Naming,
    attrs: &[Attribute],
    domain: &LitStr,
    fallback: &syn::Ident,
    ids: &mut Vec<String>,
) -> Result<Shape> {
    let bindings: Vec<Binding<'_>> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| Binding {
            field,
            index,
            local: format_ident!("__field{}", index),
        })
        .collect();
    let pattern = match fields {
        Fields::Named(_) => {
            let pairs = bindings.iter().map(|Binding { field, local, .. }| {
                let ident = &field.ident;
                quote!(#ident: #local)
            });
            quote!(#path { #(#pairs),* })
        }
        Fields::Unnamed(_) => {
            let items = bindings.iter().map(|binding| &binding.local);
            quote!(#path ( #(#items),* ))
        }
        Fields::Unit => quote!(#path),
    };
    let id = match naming {
        Naming::Transparent => {
            let [Binding { field, local, .. }] = bindings.as_slice() else {
                return Err(Error::new_spanned(
                    &path,
                    "a transparent message has one field",
                ));
            };
            if let Some(attr) = field
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("explain"))
            {
                return Err(Error::new_spanned(
                    attr,
                    "a transparent message's field takes no `#[explain]`: its message is its cause's",
                ));
            }
            let ty = &field.ty;
            return Ok(Shape {
                pattern,
                id: quote!(::siros_explain::Explain::id(#local)),
                args: quote!(::siros_explain::Explain::args(#local)),
                declares: quote!(out.extend(<#ty as ::siros_explain::Messages>::messages());),
                guard: Tokens::new(),
            });
        }
        Naming::Id(id) => id.map_or_else(|| snake(fallback), |id| id.value()),
    };
    let mut named: Vec<Argument<'_>> = Vec::new();
    for binding in &bindings {
        if let Some(name) = argument(binding.field, binding.index)? {
            named.push(Argument {
                name,
                local: &binding.local,
                ty: &binding.field.ty,
            });
        }
    }
    if !token(&id) {
        return Err(Error::new_spanned(
            &path,
            format!("the identifier {id} is no lowercase token of letters, digits and underscores"),
        ));
    }
    if ids.contains(&id) {
        return Err(Error::new_spanned(
            &path,
            format!("the identifier {id} repeats in this type"),
        ));
    }
    ids.push(id.clone());
    let full = LitStr::new(&format!("{}.{}", domain.value(), id), domain.span());
    let count = named.len();
    let names = named.iter().map(|argument| &argument.name);
    let names = quote!(::siros_explain::names!(#(#names),*));
    let values = named
        .iter()
        .map(|Argument { local, .. }| quote!(::siros_explain::Arg::of(#local)));
    let kinds = named
        .iter()
        .map(|Argument { ty, .. }| quote!(::siros_explain::ParamKind::of::<#ty>()));
    let text = template(attrs)?.map_or_else(|| quote!(None), |literal| quote!(Some(#literal)));
    let checked = quote!(::siros_explain::checked!(::siros_explain::MessageId, #full));
    Ok(Shape {
        pattern,
        id: checked.clone(),
        args: quote!(::siros_explain::Args::new(#names, [#(#values),*])),
        declares: quote!(out.push(::siros_explain::Message::new(#checked, #text, #names, [#(#kinds),*]));),
        guard: quote!(const _: ::siros_explain::Names<#count> = #names;),
    })
}

fn expand(input: &DeriveInput) -> Result<Tokens> {
    let name = &input.ident;
    let place = match &input.data {
        Data::Enum(_) => Place::Enum,
        Data::Struct(_) => Place::Struct,
        Data::Union(_) => return Err(Error::new_spanned(name, "a union is no error")),
    };
    let Attributes { domain, naming } = parse(&input.attrs, place)?;
    let domain =
        domain.ok_or_else(|| Error::new_spanned(name, "#[explain(domain = \"…\")] is required"))?;
    if !domain.value().split('.').all(token) {
        return Err(Error::new_spanned(
            &domain,
            "a domain is dot-separated lowercase tokens of letters, digits and underscores",
        ));
    }
    let mut ids = Vec::new();
    let shapes = match &input.data {
        Data::Enum(data) => data
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                let Attributes { naming, .. } = parse(&variant.attrs, Place::Variant)?;
                shape(
                    quote!(Self::#ident),
                    &variant.fields,
                    naming,
                    &variant.attrs,
                    &domain,
                    ident,
                    &mut ids,
                )
            })
            .collect::<Result<Vec<_>>>()?,
        Data::Struct(data) => vec![shape(
            quote!(Self),
            &data.fields,
            naming,
            &input.attrs,
            &domain,
            name,
            &mut ids,
        )?],
        Data::Union(_) => return Err(Error::new_spanned(name, "a union is no error")),
    };
    let id_arms = shapes
        .iter()
        .map(|Shape { pattern, id, .. }| quote!(#[allow(unused_variables)] #pattern => #id));
    let args_arms = shapes
        .iter()
        .map(|Shape { pattern, args, .. }| quote!(#[allow(unused_variables)] #pattern => #args));
    let declares = shapes.iter().map(|shape| &shape.declares);
    let guards = shapes.iter().map(|shape| &shape.guard);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::siros_explain::Explain for #name #ty_generics #where_clause {
            fn id(&self) -> ::siros_explain::MessageId {
                match self { #(#id_arms,)* }
            }

            fn args(&self) -> ::siros_explain::Args<'_> {
                match self { #(#args_arms,)* }
            }
        }

        impl #impl_generics ::siros_explain::Messages for #name #ty_generics #where_clause {
            fn messages() -> ::std::vec::Vec<::siros_explain::Message> {
                let mut out = ::std::vec::Vec::new();
                #(#declares)*
                out
            }
        }

        #(#guards)*
    })
}
