//! The metadata a claims format's registration writes into a credential's view: the format's own
//! display document with the OpenID4VCI `credential_metadata` after it, per language.

use std::borrow::Cow;

use siros_explain::Explain;

use super::super::ClaimPath;
use crate::ids::LocaleTag;
use crate::json::{JsonError, Node, Object};

/// The member of a Credential Response's `credential_metadata` holding delivered secrets, which go
/// to the wallet's secret store.
const AUXILIARY_DATA: &str = "auxiliary_data";
/// The view's member holding the Credential Issuer's display entries, which no document merged into
/// `metadata` can state.
pub(super) const ISSUER_DISPLAY: &str = "issuer_display";

/// What OpenID4VCI states of a credential's display, as the wallet received it.
#[derive(Debug, Clone, Default)]
pub struct IssuedMetadata<'a> {
    /// The Credential Issuer Metadata's `display` (§12.2.4). A card's subtitle takes the name
    /// of its entry for the wallet's locales before the view's `issuer`.
    pub issuer_display: Option<Node<'a>>,
    /// The `credential_metadata` of the credential's configuration (§12.2.4).
    pub configuration: Option<Object<'a>>,
    /// The Credential Response's `credential_metadata`.
    pub response: Option<Object<'a>>,
}

impl IssuedMetadata<'_> {
    /// The value of the view's `issuer_display` member, [`IssuedMetadata::issuer_display`] without
    /// secrets; `None` when absent.
    ///
    /// # Errors
    ///
    /// [`MergeError`]: the display is no array of objects tagged with language tags.
    pub fn issuer_display_member(&self) -> Result<Option<Node<'static>>, MergeError> {
        let Some(display) = &self.issuer_display else {
            return Ok(None);
        };
        tagged_entries(display)?;
        Ok(Some(without_secrets(display)))
    }
}

/// How a format's view writes OpenID4VCI's display metadata.
pub trait IssuedShape {
    /// The claim display member holding the label, which OpenID4VCI names `name`.
    const LABEL: &'static str;

    /// A `credential_metadata.display` entry in the format's own shape.
    ///
    /// # Errors
    ///
    /// The entry states a member twice in that shape.
    fn entry(entry: &Node<'static>) -> Result<Node<'static>, JsonError> {
        Ok(entry.clone())
    }
}

/// Why a credential's display metadata makes no view.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum MergeError {
    /// The configuration's `credential_metadata` publishes delivered secrets.
    #[error("the configuration's credential_metadata holds auxiliary_data")]
    #[explain(id = "claims_kit.merge.auxiliary_data_published")]
    AuxiliaryDataPublished,
    /// `display` or `claims` is no array of objects.
    #[error("{member} is no array of objects")]
    #[explain(id = "claims_kit.merge.not_entries")]
    NotEntries {
        /// The member.
        member: &'static str,
    },
    /// A display entry's `locale` is no language tag.
    #[error("the display entry's locale {locale} is no language tag")]
    #[explain(id = "claims_kit.merge.locale")]
    Locale {
        /// The text it states.
        locale: String,
    },
    /// An entry of `claims` holds no claims path pointer (OpenID4VCI Appendix B.2).
    #[error("claims[{position}] holds no claims path pointer")]
    #[explain(id = "claims_kit.merge.path")]
    Path {
        /// The entry's position.
        position: usize,
    },
    /// The metadata states a member twice.
    #[error(transparent)]
    Json {
        /// The repeated member.
        #[from]
        cause: JsonError,
    },
}

/// The `metadata` of a credential's view. `auxiliary_data` leaves first, at every depth of every
/// input: the response's goes to the secret store. A configuration holding it as a member of its
/// own is refused. The response's members then replace the configuration's by name. The format's
/// display entries come first, and an OpenID4VCI entry follows for a language they do not answer
/// (OpenID4VCI §12.2.4).
///
/// # Errors
///
/// [`MergeError`]: the first rule the inputs break.
pub fn merge_metadata<S: IssuedShape>(
    format: Option<&Object<'_>>,
    issued: &IssuedMetadata<'_>,
) -> Result<Object<'static>, MergeError> {
    let format = format.map(object_without_secrets);
    match (format, issued_object::<S>(issued)?) {
        (None, None) => Ok(Object::default()),
        (Some(one), None) | (None, Some(one)) => {
            check(&one)?;
            Ok(one)
        }
        (Some(format), Some(credential)) => {
            check(&format)?;
            check(&credential)?;
            combined(&format, &credential, S::LABEL)
        }
    }
}

/// `node` with each object member named [`AUXILIARY_DATA`] left out, at every depth.
fn without_secrets(node: &Node<'_>) -> Node<'static> {
    match node {
        Node::Object(object) => Node::Object(object_without_secrets(object)),
        Node::Array(items) => Node::Array(items.iter().map(without_secrets).collect()),
        scalar => scalar.clone().into_owned(),
    }
}

fn object_without_secrets(object: &Object<'_>) -> Object<'static> {
    let mut kept = Object::default();
    for member in object.members() {
        if member.name != AUXILIARY_DATA {
            kept.set(
                Cow::Owned(member.name.to_string()),
                without_secrets(&member.value),
            );
        }
    }
    kept
}

/// The configuration's members with the response's over them, in the format's shape; `None` when
/// OpenID4VCI states neither.
fn issued_object<S: IssuedShape>(
    issued: &IssuedMetadata<'_>,
) -> Result<Option<Object<'static>>, MergeError> {
    let (configuration, response) = (issued.configuration.as_ref(), issued.response.as_ref());
    if configuration.is_some_and(|metadata| metadata.get(AUXILIARY_DATA).is_some()) {
        return Err(MergeError::AuxiliaryDataPublished);
    }
    if configuration.is_none() && response.is_none() {
        return Ok(None);
    }
    let mut merged = configuration.map_or_else(Object::default, object_without_secrets);
    if let Some(response) = response {
        for member in object_without_secrets(response).members() {
            merged.set(member.name.clone(), member.value.clone());
        }
    }
    let mut shaped = Object::default();
    for member in merged.members() {
        let value = match member.name.as_ref() {
            "display" => each_object(&member.value, S::entry)?,
            "claims" => each_object(&member.value, claim_in_shape::<S>)?,
            _ => member.value.clone(),
        };
        shaped.set(member.name.clone(), value);
    }
    Ok(Some(shaped))
}

/// An array with `shape` applied to each object; any other value as it stands, which [`check`]
/// then refuses.
fn each_object(
    value: &Node<'static>,
    shape: impl Fn(&Node<'static>) -> Result<Node<'static>, JsonError>,
) -> Result<Node<'static>, JsonError> {
    let Some(items) = value.as_array() else {
        return Ok(value.clone());
    };
    items
        .iter()
        .map(|item| match item {
            Node::Object(_) => shape(item),
            other => Ok(other.clone()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Node::Array)
}

/// A claims description with its display entries' `name` under the format's label member.
fn claim_in_shape<S: IssuedShape>(claim: &Node<'static>) -> Result<Node<'static>, JsonError> {
    let label = |entry: &Node<'static>| renamed(entry, S::LABEL);
    let members = claim
        .as_object()
        .map_or(&[][..], Object::members)
        .iter()
        .map(|member| {
            let value = if member.name == "display" {
                each_object(&member.value, label)?
            } else {
                member.value.clone()
            };
            Ok((member.name.clone(), value))
        })
        .collect::<Result<Vec<_>, JsonError>>()?;
    Node::object(members)
}

fn renamed(entry: &Node<'static>, label: &'static str) -> Result<Node<'static>, JsonError> {
    Node::object(
        entry
            .as_object()
            .map_or(&[][..], Object::members)
            .iter()
            .map(|member| {
                let name = if member.name == "name" {
                    Cow::Borrowed(label)
                } else {
                    member.name.clone()
                };
                (name, member.value.clone())
            }),
    )
}

/// The arrays the kit and a merge read: `display` and each claim's a list of objects tagged with
/// language tags, each claim with a pointer.
fn check(document: &Object<'_>) -> Result<(), MergeError> {
    document.get("display").map_or(Ok(()), tagged_entries)?;
    let Some(claims) = document.get("claims") else {
        return Ok(());
    };
    for (position, claim) in entries("claims", claims)?.iter().enumerate() {
        if path_of(claim).is_none() {
            return Err(MergeError::Path { position });
        }
        claim.get("display").map_or(Ok(()), tagged_entries)?;
    }
    Ok(())
}

fn tagged_entries(display: &Node<'_>) -> Result<(), MergeError> {
    entries("display", display)?
        .iter()
        .try_for_each(|entry| tag_of(entry).map(drop))
}

fn entries<'n, 'a>(
    member: &'static str,
    value: &'n Node<'a>,
) -> Result<&'n [Node<'a>], MergeError> {
    value
        .as_array()
        .filter(|items| items.iter().all(|item| item.as_object().is_some()))
        .ok_or(MergeError::NotEntries { member })
}

fn tag_of(entry: &Node<'_>) -> Result<Option<LocaleTag>, MergeError> {
    let Some(locale) = entry.get("locale") else {
        return Ok(None);
    };
    let refused = || MergeError::Locale {
        locale: locale.json_compact().to_string(),
    };
    let text = locale.as_str().ok_or_else(refused)?;
    LocaleTag::parse(text).map(Some).map_err(|_| refused())
}

fn path_of<'n>(claim: &'n Node<'_>) -> Option<ClaimPath<'n>> {
    claim.get("path").and_then(ClaimPath::parse)
}

/// The format's document with OpenID4VCI's after it, both read by [`check`].
fn combined(
    format: &Object<'static>,
    issued: &Object<'static>,
    label: &str,
) -> Result<Object<'static>, MergeError> {
    fn list(document: &Object<'static>, name: &str) -> Vec<Node<'static>> {
        document
            .get(name)
            .and_then(Node::as_array)
            .map_or_else(Vec::new, <[Node<'static>]>::to_vec)
    }
    let mut merged = Object::default();
    for member in format.members() {
        let value = match member.name.as_ref() {
            "display" => Node::Array(per_language(
                &list(format, "display"),
                &list(issued, "display"),
                "name",
            )?),
            "claims" => Node::Array(claims(
                &list(format, "claims"),
                &list(issued, "claims"),
                label,
            )?),
            _ => member.value.clone(),
        };
        merged.set(member.name.clone(), value);
    }
    for member in issued.members() {
        if format.get(&member.name).is_none() {
            merged.set(member.name.clone(), member.value.clone());
        }
    }
    Ok(merged)
}

/// The format's claims, each with the display of OpenID4VCI's claim of the same pointer after its
/// own and the members it leaves out, then OpenID4VCI's other claims.
fn claims(
    format: &[Node<'static>],
    issued: &[Node<'static>],
    label: &str,
) -> Result<Vec<Node<'static>>, MergeError> {
    let mut out = Vec::with_capacity(format.len());
    for claim in format {
        let same = issued.iter().find(|other| path_of(other) == path_of(claim));
        out.push(match same {
            Some(other) => one_claim(claim, other, label)?,
            None => claim.clone(),
        });
    }
    out.extend(
        issued
            .iter()
            .filter(|claim| !format.iter().any(|known| path_of(known) == path_of(claim)))
            .cloned(),
    );
    Ok(out)
}

fn one_claim(
    claim: &Node<'static>,
    other: &Node<'static>,
    label: &str,
) -> Result<Node<'static>, MergeError> {
    let display = |of: &Node<'static>| {
        of.get("display")
            .and_then(Node::as_array)
            .map_or_else(Vec::new, <[Node<'static>]>::to_vec)
    };
    let merged = per_language(&display(claim), &display(other), label)?;
    let mut members = Object::default();
    for member in claim.as_object().map_or(&[][..], Object::members) {
        if member.name != "display" {
            members.set(member.name.clone(), member.value.clone());
        }
    }
    for member in other.as_object().map_or(&[][..], Object::members) {
        if member.name != "display" && claim.get(&member.name).is_none() {
            members.set(member.name.clone(), member.value.clone());
        }
    }
    if !merged.is_empty() {
        members.set(Cow::Borrowed("display"), Node::Array(merged));
    }
    Ok(Node::Object(members))
}

/// The format's entries stating `text`, then the OpenID4VCI entries of a language those do not
/// answer: they hold no entry without a locale, and RFC 4647 Lookup over their tags finds none for
/// the entry's. The format's entries with no `text` follow, where they give way to the kit's next
/// choice. The kit's Lookup over the result gives the format's entry for every language the format's
/// entries answer.
fn per_language(
    format: &[Node<'static>],
    issued: &[Node<'static>],
    text: &str,
) -> Result<Vec<Node<'static>>, MergeError> {
    let (stating, silent): (Vec<_>, Vec<_>) = format.iter().cloned().partition(|entry| {
        entry
            .get(text)
            .and_then(Node::as_str)
            .is_some_and(|written| !written.trim().is_empty())
    });
    let mut tags = Vec::with_capacity(stating.len());
    for entry in &stating {
        match tag_of(entry)? {
            Some(tag) => tags.push(tag),
            None => return Ok(stating.into_iter().chain(silent).collect()),
        }
    }
    let mut out = stating;
    for entry in issued {
        let answered = tag_of(entry)?
            .is_some_and(|tag| tag.truncations().iter().any(|range| tags.contains(range)));
        if !answered {
            out.push(entry.clone());
        }
    }
    out.extend(silent);
    Ok(out)
}
