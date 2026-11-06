//! SD-JWT VC Type Metadata of a type that extends another (§5.4): the effective metadata the
//! wallet registers a credential's view with. The consumer processes the extended type first, so
//! `base` is the extended type's effective metadata and a chain resolves one link at a time.

use std::borrow::Cow;

use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Member, Node, Object};
use siros_openid4vp::refusal::ReprItem;

/// Type Metadata the extension rules refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.type_metadata")]
pub enum ExtendError {
    /// A document is no JSON object, or its `claims` no array of objects with a `path`.
    #[error("a Type Metadata document is no object whose claims are objects with a path")]
    Shape,
    /// The child changes `sd` of a claim the extended type marks `always` or `never` (§8.5.1).
    #[error(
        "the extending type changes sd of the claim {path}, which the extended type marks {base} (§8.5.1)"
    )]
    Sd {
        /// The claim's path, as JSON.
        path: ReprItem,
        /// The extended type's `sd`.
        base: String,
    },
    /// The child makes a claim the extended type marks mandatory optional (§8.5.1).
    #[error("the extending type makes the mandatory claim {path} optional (§8.5.1)")]
    Mandatory {
        /// The claim's path, as JSON.
        path: ReprItem,
    },
    /// The effective metadata repeats a member name.
    #[error(transparent)]
    Json(#[from] JsonError),
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
pub fn extend<'a>(base: &Node<'a>, child: &Node<'a>) -> Result<Node<'a>, ExtendError> {
    let base_object = base.as_object().ok_or(ExtendError::Shape)?;
    let child_object = child.as_object().ok_or(ExtendError::Shape)?;
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
    let mut members: Vec<Member<'a>> = child_object
        .members()
        .iter()
        .filter(|member| !REPLACED.contains(&member.name.as_ref()))
        .cloned()
        .collect();
    if child_object.get("display").is_none()
        && let Some(display) = base_object.get("display")
    {
        members.push(Member {
            name: Cow::Borrowed("display"),
            value: display.clone(),
        });
    }
    members.push(Member {
        name: Cow::Borrowed("claims"),
        value: Node::Array(claims.into_iter().map(Node::Object).collect()),
    });
    Ok(Node::Object(Object::new(members)?))
}

/// A document's claims: an array of objects, each with a `path`; none when absent.
fn claims_of<'d, 'a>(document: &'d Node<'a>) -> Result<Vec<&'d Object<'a>>, ExtendError> {
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
    let shown = || ReprItem::new(path.python_text(), path);
    if let (Some(Node::String(fixed)), Some(changed)) = (base.get("sd"), child.get("sd"))
        && matches!(fixed.as_ref(), "always" | "never")
        && changed.as_str() != Some(fixed)
    {
        return Err(ExtendError::Sd {
            path: shown(),
            base: fixed.to_string(),
        });
    }
    if base.get("mandatory") == Some(&Node::Bool(true))
        && child.get("mandatory") == Some(&Node::Bool(false))
    {
        return Err(ExtendError::Mandatory { path: shown() });
    }
    let mut members: Vec<Member<'a>> = base
        .members()
        .iter()
        .map(|member| Member {
            name: member.name.clone(),
            value: child.get(&member.name).unwrap_or(&member.value).clone(),
        })
        .collect();
    members.extend(
        child
            .members()
            .iter()
            .filter(|member| base.get(&member.name).is_none())
            .cloned(),
    );
    Ok(Object::new(members)?)
}
