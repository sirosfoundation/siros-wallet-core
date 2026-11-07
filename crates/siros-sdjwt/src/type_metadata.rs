//! SD-JWT VC Type Metadata. [`extend`]: the effective metadata of a type that extends another
//! (§5.4), which the wallet registers a credential's view with. The consumer processes the extended
//! type first, so `base` is the extended type's effective metadata and a chain resolves one link at
//! a time. [`convert`]: a document's `display` as a defined module (section 4.14 of the design).

use std::borrow::Cow;

use sha2::{Digest, Sha256};
use siros_explain::{
    DefinedKey, DefinedModule, Domain, Entry, Explain, IntoArg, Keyed, MetadataDigest, checked,
    kind,
};
use siros_i18n::{Body, DefinedError, DefinedForm, LanguagePolicy, LocaleTag, MainLocale, Part};
use siros_openid4vp::claims::kit::{DisplayItem, format_entry};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::refusal::ReprItem;
use siros_openid4vp::text::lookup;

/// Type Metadata the extension rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.type_metadata")]
pub enum ExtendError {
    /// A document is no JSON object, or its `claims` no array of objects with a `path`.
    #[error("a Type Metadata document is no object whose claims are objects with a path")]
    Shape,
    /// The child changes `sd` of a claim the extended type marks `always` or `never` (§8.5.1).
    #[error(
        "the extending type changes sd of the claim {path}, which the extended type marks {} (§8.5.1)",
        base.name()
    )]
    Sd {
        /// The claim's path, as JSON.
        path: ReprItem,
        /// The extended type's `sd`.
        base: FixedSd,
    },
    /// The child makes a claim the extended type marks mandatory optional (§8.5.1).
    #[error("the extending type makes the mandatory claim {path} optional (§8.5.1)")]
    Mandatory {
        /// The claim's path, as JSON.
        path: ReprItem,
    },
}

/// An `sd` an extending type keeps (§8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixedSd {
    /// `always`.
    Always,
    /// `never`.
    Never,
}

impl FixedSd {
    /// The `sd` value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

impl IntoArg for FixedSd {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// The members of a child's document the effective metadata leaves out: the claims it combines
/// and the reference to the extended type.
const REPLACED: [&str; 3] = ["claims", "extends", "extends#integrity"];

/// The effective Type Metadata of `child`, which extends the type of `base`: the child's members
/// but `extends` and `extends#integrity`; the child's `display`, else the extended type's (§7.2);
/// then `claims`: the extended type's claims in their order, each combined with the child's
/// claim of the same path, the child's properties taking precedence and no property's content
/// merged (§8.5), then the child's other claims in their order. A child may change `sd` only from
/// `allowed` or absent, and `mandatory` only to true (§8.5.1).
pub fn extend<'a>(base: &Object<'a>, child: &Object<'a>) -> Result<Object<'a>, ExtendError> {
    let mut claims: Vec<Object<'a>> = claims_of(base)?.into_iter().cloned().collect();
    for claim in claims_of(child)? {
        let path = claim.get("path").ok_or(ExtendError::Shape)?;
        match claims
            .iter_mut()
            .find(|known| known.get("path") == Some(path))
        {
            Some(known) => *known = combined(known, claim, path)?,
            None => claims.push(claim.clone()),
        }
    }
    let mut effective = child.clone();
    effective.retain(|member| !REPLACED.contains(&member.name.as_ref()));
    if child.get("display").is_none()
        && let Some(display) = base.get("display")
    {
        effective.set(Cow::Borrowed("display"), display.clone());
    }
    effective.set(
        Cow::Borrowed("claims"),
        Node::Array(claims.into_iter().map(Node::Object).collect()),
    );
    Ok(effective)
}

/// A document's claims: an array of objects, each with a `path`; none when absent.
fn claims_of<'d, 'a>(document: &'d Object<'a>) -> Result<Vec<&'d Object<'a>>, ExtendError> {
    let Some(claims) = document.get("claims") else {
        return Ok(Vec::new());
    };
    claims
        .as_array()
        .ok_or(ExtendError::Shape)?
        .iter()
        .map(|claim| {
            claim
                .as_object()
                .filter(|claim| claim.get("path").is_some())
                .ok_or(ExtendError::Shape)
        })
        .collect()
}

/// The extended type's claim with the child's properties over it, refused when the child loosens
/// `sd` or `mandatory` (§8.5.1).
fn combined<'a>(
    base: &Object<'a>,
    child: &Object<'a>,
    path: &Node<'a>,
) -> Result<Object<'a>, ExtendError> {
    let shown = || ReprItem::json(path);
    if let (Some(fixed), Some(changed)) = (
        base.get("sd")
            .and_then(Node::as_str)
            .and_then(FixedSd::parse),
        child.get("sd"),
    ) && changed.as_str() != Some(fixed.name())
    {
        return Err(ExtendError::Sd {
            path: shown(),
            base: fixed,
        });
    }
    if base.get("mandatory") == Some(&Node::Bool(true))
        && child.get("mandatory") == Some(&Node::Bool(false))
    {
        return Err(ExtendError::Mandatory { path: shown() });
    }
    let mut effective = base.clone();
    for member in child.members() {
        effective.set(member.name.clone(), member.value.clone());
    }
    Ok(effective)
}

/// The plug-in whose conversions name SD-JWT VC's defined modules.
pub const PLUGIN: Domain = checked!(Domain, "sdjwt");

const NAME: Domain = checked!(Domain, "name");
const CLAIM: Domain = checked!(Domain, "claim");

/// Why a Type Metadata document's `display` converts to no defined module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.display")]
pub enum ConvertError {
    /// A display entry's `locale` is no language tag (§7, §8.2).
    #[error("a display entry's locale {0} is no language tag")]
    Locale(#[explain(name = "locale")] String),
    /// A main entry refuses a body.
    #[error(transparent)]
    Defined(#[from] DefinedError),
}

/// The defined module a Type Metadata document converts to: SD-JWT VC's, under the SHA-256 of its
/// compact JSON.
#[must_use]
pub fn module_of(document: &Object<'_>) -> DefinedModule {
    let digest = Sha256::digest(
        Node::Object(document.clone())
            .json_compact()
            .to_string()
            .as_bytes(),
    );
    DefinedModule::new(PLUGIN, MetadataDigest::new(digest.into()))
}

/// The key of `item`'s message in a converted module: `name`, or `claim_<position>`.
#[must_use]
pub fn key(item: DisplayItem) -> DefinedKey {
    match item {
        DisplayItem::Name => DefinedKey::numbered(NAME, &[]),
        DisplayItem::Claim(position) => DefinedKey::numbered(CLAIM, &[position]),
    }
}

/// A shown display array: its message's key, its entries, and the member holding the text.
struct Shown<'d, 'a> {
    item: DisplayItem,
    entries: &'d [Node<'a>],
    text: &'static str,
}

/// Each array that shows a text: `display`'s `name`s, and each claim's `label`s (§7, §8.2).
fn shown<'d, 'a>(document: &'d Object<'a>) -> Vec<Shown<'d, 'a>> {
    let array = |node: &'d Node<'a>, name: &str| node.get(name).and_then(Node::as_array);
    let mut out = Vec::new();
    if let Some(entries) = document.get("display").and_then(Node::as_array) {
        out.push(Shown {
            item: DisplayItem::Name,
            entries,
            text: "name",
        });
    }
    let claims = document.get("claims").and_then(Node::as_array);
    for (position, claim) in claims.unwrap_or(&[]).iter().enumerate() {
        if let Some(entries) = array(claim, "display") {
            out.push(Shown {
                item: DisplayItem::Claim(position),
                entries,
                text: "label",
            });
        }
    }
    out.retain(|array| {
        array
            .entries
            .iter()
            .any(|entry| entry.get(array.text).and_then(Node::as_str).is_some())
    });
    out
}

/// Converts a Type Metadata document's `display` into its defined module, for each tag it names
/// and each tag of the End-User's `priority` list. Each shown array is one literal message: in a
/// tag, the text of the entry [`format_entry`] takes over that tag and then `priority`, as the
/// claims kit's card reads the array; empty when that entry holds none, where the kit shows no
/// message. A locale's direction is the main module's entry RFC 4647 basic filtering finds for it,
/// in `main`.
/// `policy`: `Platform::language_policy`'s answer, no specification governing this module.
///
/// # Errors
///
/// [`ConvertError`]: a display entry's `locale` is no language tag.
pub fn convert(
    document: &Object<'_>,
    main: &[MainLocale],
    priority: &[LocaleTag],
    policy: LanguagePolicy,
) -> Result<DefinedForm, ConvertError> {
    let arrays = shown(document);
    let mut tags: Vec<LocaleTag> = Vec::new();
    for array in &arrays {
        for entry in array.entries {
            if let Some(locale) = entry.get("locale").and_then(Node::as_str) {
                let tag = LocaleTag::parse(locale)
                    .map_err(|_| ConvertError::Locale(locale.to_owned()))?;
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
    }
    for tag in priority {
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    let declaration = Keyed::first_of(
        arrays
            .iter()
            .map(|array| Entry::new(key(array.item), Keyed::first_of(Vec::new())))
            .collect::<Vec<_>>(),
    );
    let main_tags: Vec<&str> = main.iter().map(|entry| entry.locale().as_str()).collect();
    let mut builder = DefinedForm::builder(module_of(document), policy, declaration);
    for tag in tags {
        let list: Vec<LocaleTag> = std::iter::once(tag.clone())
            .chain(priority.iter().cloned())
            .collect();
        let bodies = arrays
            .iter()
            .map(|array| {
                let text = format_entry(array.entries, &list)
                    .and_then(|entry| entry.get(array.text))
                    .and_then(Node::as_str)
                    .unwrap_or_default();
                Entry::new(
                    key(array.item),
                    Body::Pattern(vec![Part::Text(text.to_owned())]),
                )
            })
            .collect::<Vec<_>>();
        let served = lookup(&tag, &main_tags)
            .and_then(|found| main.iter().find(|entry| entry.locale().as_str() == *found));
        builder.locale(tag, served, &Keyed::first_of(bodies))?;
    }
    Ok(builder.finish())
}
