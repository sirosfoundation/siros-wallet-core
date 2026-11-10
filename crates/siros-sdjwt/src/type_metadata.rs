//! SD-JWT VC Type Metadata. [`extend`]: the effective metadata of a type that extends another
//! (§5.4), which the wallet registers a credential's view with. The consumer processes the extended
//! type first, so `base` is the extended type's effective metadata and a chain resolves one link at
//! a time.

use std::borrow::Cow;
use std::fmt;

use siros_explain::Explain;
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::refusal::ReprItem;

/// Type Metadata the extension rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum ExtendError {
    /// A document is no JSON object, or its `claims` no array of objects with a `path`.
    #[error("a Type Metadata document is no object whose claims are objects with a path")]
    #[explain(id = "type_metadata.shape")]
    Shape,
    /// The child changes `sd` of a claim the extended type marks `always` or `never` (§8.5.1).
    #[error(
        "the extending type changes sd of the claim {}, which the extended type marks {base} (§8.5.1)",
        .path.repr_text()
    )]
    #[explain(id = "type_metadata.sd")]
    Sd {
        /// The claim's path, as JSON.
        path: ReprItem,
        /// The extended type's `sd`.
        base: FixedSd,
    },
    /// The child makes a claim the extended type marks mandatory optional (§8.5.1).
    #[error(
        "the extending type makes the mandatory claim {} optional (§8.5.1)",
        .path.repr_text()
    )]
    #[explain(id = "type_metadata.mandatory")]
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

/// The `sd` value.
impl fmt::Display for FixedSd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
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
