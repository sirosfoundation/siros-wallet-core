//! Paths over a payload: the claims path pointers of the metadata (Proof Metadata §3.1 through
//! OpenID4VCI B.2 and OpenID4VP §7), concrete paths of payload elements, and reading an element
//! at a concrete path.

use std::fmt;

use siros_explain::Explain;
use siros_openid4vp::claims::{ClaimPath, Concrete, ConcretePath, Step};
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::Quoted;

use crate::conform::NullIndices;

/// A path read where its element has another kind: a member name in a non-object, an index or
/// `null` in a non-array (Core §7.4.2 step 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.path")]
pub enum Mismatch {
    /// A member name read in a non-object.
    #[error("path {path} reads {} in a non-object", Quoted(.key))]
    Key {
        /// The path, as Python writes the list.
        path: String,
        /// The member name.
        key: String,
    },
    /// An index or `null` read in a non-array.
    #[error("path {path} indexes a non-array")]
    Index {
        /// The path, as Python writes the list.
        path: String,
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
                .get(*index),
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
            Step::Index(index) => index.map(Concrete::Index),
            Step::All => nulls.next().map(Concrete::Index),
        })
        .collect()
}

/// A claim path as Python's `repr` of its list writes it.
#[must_use]
pub fn claim_text(steps: &[Step<'_>]) -> String {
    PythonList(
        steps
            .iter()
            .map(|step| match step {
                Step::Key(key) => Part::Key(key),
                Step::Index(index) => Part::Index(*index),
                Step::All => Part::Null,
            })
            .collect(),
    )
    .to_string()
}

/// A concrete path as Python's `repr` of its list writes it.
#[must_use]
pub fn concrete_text(parts: &[Concrete<'_>]) -> String {
    PythonList(
        parts
            .iter()
            .map(|part| match part {
                Concrete::Key(key) => Part::Key(key),
                Concrete::Index(index) => Part::Index(Some(*index)),
            })
            .collect(),
    )
    .to_string()
}

enum Part<'p> {
    Key(&'p str),
    Index(Option<usize>),
    Null,
}

struct PythonList<'p>(Vec<Part<'p>>);

impl fmt::Display for PythonList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (k, part) in self.0.iter().enumerate() {
            if k > 0 {
                f.write_str(", ")?;
            }
            match part {
                Part::Key(key) => write!(f, "{}", Quoted(key))?,
                Part::Index(Some(index)) => write!(f, "{index}")?,
                Part::Index(None) => f.write_str("...")?,
                Part::Null => f.write_str("None")?,
            }
        }
        f.write_str("]")
    }
}
