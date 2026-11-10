#![doc = include_str!("../README.md")]
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

use proc_macro2::{Span, TokenStream as Tokens};
use quote::{format_ident, quote, quote_spanned};
use syn::ext::IdentExt as _;
use syn::spanned::Spanned as _;
use syn::{
    Attribute, Data, DeriveInput, Error, Field, Fields, GenericArgument, Ident, LitStr,
    PathArguments, Result, Type, WherePredicate, parse_quote_spanned,
};

/// One derive: what it names and writes beside the shared rules.
pub trait Derive {
    /// The attribute's name: `explain` reads `#[explain(..)]`.
    const ATTRIBUTE: &'static str;
    /// What one struct or variant is, in refusals: `error`.
    const NOUN: &'static str;
    /// [`Self::NOUN`] with its indefinite article: `an error`.
    const A_NOUN: &'static str;
    /// The crate at the root of the expansion's paths: `siros_explain`.
    const CRATE: &'static str;
    /// The trait `CRATE::TRAIT` the impl implements: `Explain`.
    const TRAIT: &'static str;
    /// The arm of the crate's `__siros_scope!` that scopes an id: `err`.
    const SCOPE: &'static str;
    /// The marker macro's name before the id's text: `__siros_explain_id_`.
    const MARKER: &'static str;

    /// Whether `field` stays out of the arguments beside `#[<attribute>(skip)]`.
    ///
    /// # Errors
    ///
    /// The refusal of a field the derive takes in no role.
    fn left_out(_field: &Field) -> Result<bool> {
        Ok(false)
    }

    /// The struct or the variant at `path` (`Self` or `Self::Variant`), named `name`. A shape with
    /// its own id comes from [`id`] and [`identified`].
    fn shape(path: Tokens, name: &Ident, attrs: &[Attribute], fields: &Fields) -> Result<Shape>;

    /// The where-predicates the impl takes before its arguments' `Display` bounds.
    fn bounds(_input: &DeriveInput) -> Vec<WherePredicate> {
        Vec::new()
    }

    /// The impl's items, given the body of `id` and the body of `args`. `args` reads its callback
    /// as `__arg`.
    fn methods(id: &Tokens, args: &Tokens) -> Tokens;
}

/// One struct or variant: its arm of `id`, its arm of `args`, the bounds its fields need, and the
/// items its id adds.
pub struct Shape {
    /// The arm of the `id` match.
    pub id: Tokens,
    /// The arm of the `args` match.
    pub args: Tokens,
    /// The where-predicates its fields need.
    pub bounds: Vec<WherePredicate>,
    /// The items beside the impl: the marker macro and the row.
    pub items: Tokens,
}

/// The impl of `D::TRAIT` for `input`, and each shape's items. A union is refused; an enum's own
/// attribute takes no key; each struct and variant is `D::shape`'s.
pub fn expand<D: Derive>(input: &DeriveInput) -> Result<Tokens> {
    let name = &input.ident;
    let shapes = match &input.data {
        Data::Struct(data) => vec![D::shape(quote!(Self), name, &input.attrs, &data.fields)?],
        Data::Enum(data) => {
            on_the_enum::<D>(&input.attrs)?;
            data.variants
                .iter()
                .map(|variant| {
                    let ident = &variant.ident;
                    D::shape(quote!(Self::#ident), ident, &variant.attrs, &variant.fields)
                })
                .collect::<Result<Vec<_>>>()?
        }
        Data::Union(data) => {
            return Err(Error::new_spanned(
                data.union_token,
                format!(
                    "a union is no {}: derive `{}` on a struct or an enum",
                    D::NOUN,
                    D::TRAIT
                ),
            ));
        }
    };
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    let predicates = &mut generics.make_where_clause().predicates;
    predicates.extend(D::bounds(input));
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
    let methods = D::methods(&id, &args);
    let krate = Ident::new(D::CRATE, Span::call_site());
    let implemented = Ident::new(D::TRAIT, Span::call_site());
    let items = shapes.iter().map(|shape| &shape.items);
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::#krate::#implemented for #name #ty_generics #where_clause {
            #methods
        }

        #(#items)*
    })
}

/// The `#[<D::ATTRIBUTE>]` attributes among `attrs`.
pub fn attributes<D: Derive>(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident(D::ATTRIBUTE))
}

/// Refuses any key in an enum's own attribute: each variant names its own.
fn on_the_enum<D: Derive>(attrs: &[Attribute]) -> Result<()> {
    for attr in attributes::<D>(attrs) {
        attr.parse_nested_meta(|meta| {
            Err(if meta.path.is_ident("id") {
                meta.error("an enum-level `id`: each variant takes its own")
            } else {
                meta.error(format!(
                    "unknown key: `#[{}]` sits on each variant",
                    D::ATTRIBUTE
                ))
            })
        })?;
    }
    Ok(())
}

/// The `id` that `attrs` give, if any. Refuses another key, a second `id` and an empty one.
pub fn id<D: Derive>(attrs: &[Attribute]) -> Result<Option<LitStr>> {
    let mut id: Option<LitStr> = None;
    for attr in attributes::<D>(attrs) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("id") {
                return Err(meta.error(format!("unknown key: {} takes `id`", D::A_NOUN)));
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
    Ok(id)
}

/// The struct or variant at `path` with its own `id`, whose named fields are its arguments.
///
/// Its `id` arm is `crate::__siros_scope!(<D::SCOPE> "<id>")`. Each argument gives its `Display`
/// under its name; an `Option<T>` field gives `""` for `None`. Its items are the id's marker macro,
/// which a second use of the id in the crate collides with (E0428), and its row through
/// `::<D::CRATE>::__row!`.
pub fn identified<D: Derive>(path: &Tokens, id: &LitStr, fields: &Fields) -> Result<Shape> {
    let mut bindings = Vec::new();
    let mut statements = Vec::new();
    let mut bounds = Vec::new();
    let mut keys = Vec::new();
    for (index, (member, field)) in fields.members().zip(fields).enumerate() {
        let Some(key) = argument::<D>(field)? else {
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
    let scope = Ident::new(D::SCOPE, Span::call_site());
    let scoped = quote!(crate::__siros_scope!(#scope #id));
    let marker = marker::<D>(id);
    let krate = Ident::new(D::CRATE, Span::call_site());
    Ok(Shape {
        id: quote!(#path { .. } => #scoped),
        args: quote!(#path { #(#bindings,)* .. } => { #(#statements;)* }),
        bounds,
        items: quote! {
            #marker
            ::#krate::__row!(#scoped, [#(#keys),*]);
        },
    })
}

/// The key of `field` when it is an argument: its name, `r#` dropped. `None` for a field marked
/// `#[<D::ATTRIBUTE>(skip)]` or [`Derive::left_out`]. Refuses a tuple field that is an argument,
/// and a field [`Derive::left_out`] refuses.
fn argument<D: Derive>(field: &Field) -> Result<Option<LitStr>> {
    let mut skip = false;
    for attr in attributes::<D>(&field.attrs) {
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
    if D::left_out(field)? || skip {
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

/// The macro a second use of `id` in the crate collides with (E0428): `D::MARKER` and the id's
/// ASCII letters and digits as written, every other byte `_` and its two hexadecimal digits, so two
/// ids never share a name.
fn marker<D: Derive>(id: &LitStr) -> Tokens {
    let mut name = String::from(D::MARKER);
    for byte in id.value().bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push(char::from(byte));
        } else {
            name.push_str(&format!("_{byte:02x}"));
        }
    }
    let name = Ident::new(&name, id.span());
    let reason = LitStr::new(
        &format!("{} a function body defines holds its id there", D::A_NOUN),
        id.span(),
    );
    quote_spanned! {id.span()=>
        #[doc(hidden)]
        #[allow(
            non_local_definitions,
            reason = #reason
        )]
        #[macro_export]
        macro_rules! #name {
            () => {};
        }
    }
}
