//! Paths over a payload: the claims path pointers of the metadata (Proof Metadata §3.1 through
//! OpenID4VCI B.2 and OpenID4VP §7), concrete paths of payload elements, and reading an element
//! at a concrete path.

use siros_explain::Explain;
use siros_openid4vp::claims::{ArrayIndex, ClaimPath, Concrete, ConcretePath, Step};
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::{Quoted, ReprItem};

use crate::conform::NullIndices;

/// A path read where its element has another kind: a member name in a non-object, an index or
/// `null` in a non-array (Core §7.4.2 step 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum Mismatch {
    /// A member name read in a non-object.
    #[error("path {} reads {} in a non-object", .path.repr_text(), Quoted(.key))]
    #[explain(id = "path.key")]
    Key {
        /// The path.
        path: ReprItem,
        /// The member name.
        key: String,
    },
    /// An index or `null` read in a non-array.
    #[error("path {} indexes a non-array", .path.repr_text())]
    #[explain(id = "path.index")]
    Index {
        /// The path.
        path: ReprItem,
    },
}

/// The element at a concrete path: `None` when an object lacks the member or an array the
/// index.
pub fn at<'n>(
    document: &'n Node<'n>,
    path: &[Concrete<'_>],
) -> Result<Option<&'n Node<'n>>, Mismatch> {
    let mut current = document;
    for part in path {
        let next = match part {
            Concrete::Key(key) => current
                .as_object()
                .ok_or_else(|| Mismatch::Key {
                    path: concrete_text(path),
                    key: key.to_string(),
                })?
                .get(key),
            Concrete::Index(index) => current
                .as_array()
                .ok_or_else(|| Mismatch::Index {
                    path: concrete_text(path),
                })?
                .get(index.position()),
        };
        match next {
            Some(node) => current = node,
            None => return Ok(None),
        }
    }
    Ok(Some(current))
}

/// §7.1 processing of a claims path pointer over the payload: the selected elements with their
/// concrete paths, in document order.
pub fn select<'n>(
    document: &'n Node<'n>,
    path: &ClaimPath<'_>,
) -> Result<Vec<(ConcretePath<'n>, &'n Node<'n>)>, Mismatch> {
    path.select(document).map_err(|refused| {
        let text = claim_text(path.steps());
        match path.steps().get(refused.step()) {
            Some(Step::Key(key)) => Mismatch::Key {
                path: text,
                key: key.to_string(),
            },
            _ => Mismatch::Index { path: text },
        }
    })
}

/// Whether the steps select the concrete parts, component by component over the shorter of
/// the two.
#[must_use]
pub fn selects(steps: &[Step<'_>], parts: &[Concrete<'_>]) -> bool {
    steps
        .iter()
        .zip(parts)
        .all(|(step, part)| step.matches(part))
}

/// The concrete path a claim's path names when its `k`-th `null` is the array index `indices[k]`
/// (View §2 expansion, View §3 template references); `None` when an index cannot exist (beyond
/// the platform's integers) or a `null` has no index.
#[must_use]
pub(crate) fn substitute<'p>(
    steps: &[Step<'p>],
    indices: &NullIndices,
) -> Option<ConcretePath<'p>> {
    let mut nulls = indices.iter();
    steps
        .iter()
        .map(|step| match step {
            Step::Key(key) => Some(Concrete::Key(key.clone())),
            Step::Index(index) => Some(Concrete::Index(*index)),
            Step::Beyond(_) => None,
            Step::All => nulls
                .next()
                .map(|index| Concrete::Index(ArrayIndex::new(index))),
        })
        .collect()
}

/// A claim path a rule names: its text writes Python's `repr` of the list, its message the
/// array as JSON (OpenID4VP §7.1).
#[must_use]
pub fn claim_text(steps: &[Step<'_>]) -> ReprItem {
    ReprItem::repr(&Node::Array(
        steps
            .iter()
            .map(|step| match step {
                Step::Key(key) => Node::String(key.clone()),
                Step::Index(index) => index_node(*index),
                Step::Beyond(number) => Node::Number(number.clone()),
                Step::All => Node::Null,
            })
            .collect(),
    ))
}

/// A concrete path a rule names, as [`claim_text`] names a claim path.
#[must_use]
pub fn concrete_text(parts: &[Concrete<'_>]) -> ReprItem {
    ReprItem::repr(&Node::Array(
        parts
            .iter()
            .map(|part| match part {
                Concrete::Key(key) => Node::String(key.clone()),
                Concrete::Index(index) => index_node(*index),
            })
            .collect(),
    ))
}

fn index_node(index: ArrayIndex) -> Node<'static> {
    Node::integer(index.position() as i128)
}
