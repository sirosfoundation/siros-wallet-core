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

type Members = Vec<(Cow<'static, str>, Node<'static>)>;

/// What OpenID4VCI states of a credential's display, as the wallet received it.
#[derive(Debug, Clone, Default)]
pub struct IssuedMetadata<'a> {
    /// The Credential Issuer Metadata's `display` (§12.2.4). A card's subtitle takes the name
    /// of its entry for the wallet's locales before the view's `issuer`.
    pub issuer_display: Option<Node<'a>>,
    /// The `credential_metadata` of the credential's configuration (§12.2.4).
    pub configuration: Option<Node<'a>>,
    /// The Credential Response's `credential_metadata`.
    pub response: Option<Node<'a>>,
}

impl IssuedMetadata<'_> {
    /// The view's member holding [`IssuedMetadata::issuer_display`]; `None` when absent.
    ///
    /// # Errors
    ///
    /// [`MergeError`]: the display is no array of objects tagged with language tags.
    pub fn issuer_display_member(
        &self,
    ) -> Result<Option<(Cow<'static, str>, Node<'static>)>, MergeError> {
        let Some(display) = &self.issuer_display else {
            return Ok(None);
        };
        tagged_entries(display)?;
        Ok(Some((
            Cow::Borrowed(ISSUER_DISPLAY),
            without_secrets(display)?,
        )))
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
#[explain(domain = "openid4vp.claims_kit.merge")]
pub enum MergeError {
    /// The format's display document is no object.
    #[error("the format's display metadata is no object")]
    FormatNotObject,
    /// The configuration's `credential_metadata` is no object.
    #[error("the configuration's credential_metadata is no object")]
    ConfigurationNotObject,
    /// The Credential Response's `credential_metadata` is no object.
    #[error("the Credential Response's credential_metadata is no object")]
    ResponseNotObject,
    /// The configuration's `credential_metadata` publishes delivered secrets.
    #[error("the configuration's credential_metadata holds auxiliary_data")]
    AuxiliaryDataPublished,
    /// `display` or `claims` is no array of objects.
    #[error("{member} is no array of objects")]
    NotEntries {
        /// The member.
        member: &'static str,
    },
    /// A display entry's `locale` is no language tag.
    #[error("the display entry's locale {locale} is no language tag")]
    Locale {
        /// The text it states.
        locale: String,
    },
    /// An entry of `claims` holds no claims path pointer (OpenID4VCI Appendix B.2).
    #[error("claims[{position}] holds no claims path pointer")]
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
    format: Option<&Node<'_>>,
    issued: &IssuedMetadata<'_>,
) -> Result<Node<'static>, MergeError> {
    let format = format
        .map(|document| {
            let document = document.as_object().ok_or(MergeError::FormatNotObject)?;
            Ok::<_, MergeError>(members_without_secrets(document)?)
        })
        .transpose()?;
    let credential = issued_members::<S>(issued)?;
    let members = match (format, credential) {
        (None, None) => Members::new(),
        (Some(one), None) | (None, Some(one)) => {
            check(&Node::object(one.clone())?)?;
            one
        }
        (Some(format), Some(credential)) => {
            let (format, credential) = (Node::object(format)?, Node::object(credential)?);
            check(&format)?;
            check(&credential)?;
            combined(&format, &credential, S::LABEL)?
        }
    };
    Ok(Node::object(members)?)
}

/// `node` with each object member named [`AUXILIARY_DATA`] left out, at every depth.
fn without_secrets(node: &Node<'_>) -> Result<Node<'static>, JsonError> {
    match node {
        Node::Object(object) => Node::object(members_without_secrets(object)?),
        Node::Array(items) => items
            .iter()
            .map(without_secrets)
            .collect::<Result<Vec<_>, _>>()
            .map(Node::Array),
        scalar => Ok(scalar.clone().into_owned()),
    }
}

fn members_without_secrets(object: &Object<'_>) -> Result<Members, JsonError> {
    object
        .members()
        .iter()
        .filter(|member| member.name != AUXILIARY_DATA)
        .map(|member| {
            Ok((
                Cow::Owned(member.name.to_string()),
                without_secrets(&member.value)?,
            ))
        })
        .collect()
}

/// The configuration's members with the response's over them, in the format's shape; `None` when
/// OpenID4VCI states neither.
fn issued_members<S: IssuedShape>(
    issued: &IssuedMetadata<'_>,
) -> Result<Option<Members>, MergeError> {
    let configuration = issued
        .configuration
        .as_ref()
        .map(|metadata| {
            metadata
                .as_object()
                .ok_or(MergeError::ConfigurationNotObject)
        })
        .transpose()?;
    let response = issued
        .response
        .as_ref()
        .map(|metadata| metadata.as_object().ok_or(MergeError::ResponseNotObject))
        .transpose()?;
    if configuration.is_some_and(|metadata| metadata.get(AUXILIARY_DATA).is_some()) {
        return Err(MergeError::AuxiliaryDataPublished);
    }
    if configuration.is_none() && response.is_none() {
        return Ok(None);
    }
    let mut members = configuration.map_or_else(|| Ok(Members::new()), members_without_secrets)?;
    let stated = response.map_or_else(|| Ok(Members::new()), members_without_secrets)?;
    for (name, value) in stated {
        match members.iter_mut().find(|(held, _)| *held == name) {
            Some(held) => held.1 = value,
            None => members.push((name, value)),
        }
    }
    members
        .into_iter()
        .map(|(name, value)| {
            let value = match name.as_ref() {
                "display" => each_object(&value, S::entry)?,
                "claims" => each_object(&value, claim_in_shape::<S>)?,
                _ => value,
            };
            Ok((name, value))
        })
        .collect::<Result<Members, MergeError>>()
        .map(Some)
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
fn check(document: &Node<'_>) -> Result<(), MergeError> {
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
        locale: locale.python_compact().to_string(),
    };
    let text = locale.as_str().ok_or_else(refused)?;
    LocaleTag::parse(text).map(Some).map_err(|_| refused())
}

fn path_of<'n>(claim: &'n Node<'_>) -> Option<ClaimPath<'n>> {
    claim.get("path").and_then(ClaimPath::parse)
}

/// The format's document with OpenID4VCI's after it, both read by [`check`].
fn combined(format: &Node<'_>, issued: &Node<'_>, label: &str) -> Result<Members, MergeError> {
    let list = |document: &'_ Node<'_>, name: &str| -> Vec<Node<'static>> {
        document
            .get(name)
            .and_then(Node::as_array)
            .map_or_else(Vec::new, |items| {
                items.iter().map(|item| item.clone().into_owned()).collect()
            })
    };
    let (shared, stated) = (
        format.as_object().map_or(&[][..], Object::members),
        issued.as_object().map_or(&[][..], Object::members),
    );
    let mut members = Members::new();
    for member in shared {
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
            _ => member.value.clone().into_owned(),
        };
        members.push((Cow::Owned(member.name.to_string()), value));
    }
    for member in stated {
        if format.get(&member.name).is_none() {
            members.push((
                Cow::Owned(member.name.to_string()),
                member.value.clone().into_owned(),
            ));
        }
    }
    Ok(members)
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
    let mut members: Members = claim
        .as_object()
        .map_or(&[][..], Object::members)
        .iter()
        .filter(|member| member.name != "display")
        .map(|member| (member.name.clone(), member.value.clone()))
        .collect();
    members.extend(
        other
            .as_object()
            .map_or(&[][..], Object::members)
            .iter()
            .filter(|member| member.name != "display" && claim.get(&member.name).is_none())
            .map(|member| (member.name.clone(), member.value.clone())),
    );
    if !merged.is_empty() {
        members.push((Cow::Borrowed("display"), Node::Array(merged)));
    }
    Ok(Node::object(members)?)
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
