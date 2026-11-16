//! Claims path pointers — OpenID4VP 1.0 §7.
//!
//! A claims path pointer identifies one or more claims inside a credential. It is "a non-empty
//! array of strings, nulls and non-negative integers" (§7), and what those components mean
//! depends on the credential format: §7.1 defines JSON semantics, §7.2 defines ISO mdoc
//! semantics.
//!
//! The spec distinguishes *removing an element from the selection* from *aborting with an
//! error*, and [`resolve`] keeps that distinction. Any claim tree that implements
//! [`ClaimNode`] walks it, a JSON value and an SD-JWT claim tree alike.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// One component of a claims path pointer (§7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum PathComponent {
    /// A key to select within an object.
    Key(String),
    /// An index to select within an array.
    Index(u64),
    /// All elements of the currently selected array(s). JSON `null` on the wire.
    Null,
}

impl PathComponent {
    /// The key, if this component is one.
    #[must_use]
    pub fn as_key(&self) -> Option<&str> {
        match self {
            Self::Key(k) => Some(k),
            Self::Index(_) | Self::Null => None,
        }
    }
}

crate::position!(
    /// The position of a component within a claims path pointer, from 0.
    ComponentIndex
);

/// A claims path pointer (§7): its components, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ClaimPath(Vec<PathComponent>);

/// Why a value is no claims path pointer (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ClaimPathError {
    /// The value is no array.
    NotArray,
    /// The array is empty: "A claims path pointer MUST be a non-empty array" (§7).
    Empty,
    /// The component at this position is no string, `null` or non-negative integer.
    Component(ComponentIndex),
}

impl ClaimPathError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotArray => "path_not_array",
            Self::Empty => "path_empty",
            Self::Component(_) => "path_component",
        }
    }
}

impl ClaimPath {
    /// The pointer of `components`.
    ///
    /// # Errors
    ///
    /// [`ClaimPathError::Empty`] for no component.
    pub fn new(components: Vec<PathComponent>) -> Result<Self, ClaimPathError> {
        if components.is_empty() {
            return Err(ClaimPathError::Empty);
        }
        Ok(Self(components))
    }

    /// The pointer to the top-level claim `name`.
    #[must_use]
    pub fn key(name: &str) -> Self {
        Self(vec![PathComponent::Key(name.to_owned())])
    }

    /// The pointer the JSON value `value` writes.
    ///
    /// # Errors
    ///
    /// [`ClaimPathError`]: the value is no array, is empty, or holds another component.
    pub fn parse(value: &Value) -> Result<Self, ClaimPathError> {
        let Value::Array(components) = value else {
            return Err(ClaimPathError::NotArray);
        };
        let components = components
            .iter()
            .enumerate()
            .map(|(at, component)| match component {
                Value::String(key) => Ok(PathComponent::Key(key.clone())),
                Value::Null => Ok(PathComponent::Null),
                other => other
                    .as_u64()
                    .map(PathComponent::Index)
                    .ok_or(ClaimPathError::Component(ComponentIndex::new(at))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(components)
    }

    /// The components, at least one.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        &self.0
    }

    /// The components, taken.
    #[must_use]
    pub fn into_components(self) -> Vec<PathComponent> {
        self.0
    }
}

impl<'de> Deserialize<'de> for ClaimPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why processing a claims path pointer gives an error (§7.1.1, §7.2.1).
///
/// §7.1.1 aborts on a component of the wrong *type*, while a *missing* key or index removes
/// that element from the selection. Step 3 gives an error for an empty selection, which
/// ordinarily means the credential lacks the claim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// A component was applied to an element of the wrong kind: a string component to a
    /// non-object, or a null or integer to a non-array (§7.1.1, steps 2.1 to 2.3).
    #[error("{} at component {at}", self.code())]
    TypeMismatch {
        /// The component.
        at: ComponentIndex,
    },
    /// Nothing is selected once the pointer is processed (§7.1.1, step 3).
    #[error("{}", self.code())]
    Empty,
    /// An mdoc pointer "does not contain exactly two components or one of the components is
    /// not a string" (§7.2.1, step 1).
    #[error("{}", self.code())]
    MdocElement,
}

impl PathError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TypeMismatch { .. } => "path_type_mismatch",
            Self::Empty => "path_selects_nothing",
            Self::MdocElement => "path_malformed",
        }
    }
}

/// What one component of a claims path pointer finds at one node (§7.1.1, steps 2.1 and 2.3).
pub enum Lookup<N> {
    /// The member or element the component names.
    Found(N),
    /// The node has the right kind and lacks the member, or the position is out of range or
    /// withheld. The node leaves the selection.
    Absent,
    /// The node is no object (for a key) or no array (for an index). Processing aborts.
    WrongKind,
}

/// A node of a claim tree as a claims path pointer walks it (§7.1).
///
/// An array counts its issued positions. A position may be withheld, as an undisclosed
/// SD-JWT array element is.
pub trait ClaimNode: Sized {
    /// The present elements of an array node, in order.
    type Elements: Iterator<Item = Self>;

    /// The member named `key` of an object node.
    fn member(&self, key: &str) -> Lookup<Self>;

    /// The element at position `index` of an array node.
    fn element(&self, index: u64) -> Lookup<Self>;

    /// The present elements of an array node. `None` when the node is no array.
    fn elements(&self) -> Option<Self::Elements>;
}

/// The nodes `path` selects in the claim tree under `root` (§7.1.1).
///
/// A component of the wrong *type* aborts, and an absent key or index drops that
/// element from the selection. An index on a withheld position selects nothing, and `null`
/// selects the present elements.
///
/// # Errors
///
/// [`PathError::TypeMismatch`] per steps 2.1 to 2.3, and [`PathError::Empty`] per step 3 when
/// the selection ends up empty.
pub fn resolve<N: ClaimNode>(root: N, path: &ClaimPath) -> Result<Vec<N>, PathError> {
    // Step 1: select the root element.
    let mut selected = vec![root];

    // Step 2: process components from left to right.
    for (at, component) in path.components().iter().enumerate() {
        let at = ComponentIndex::new(at);
        let mut next = Vec::new();
        for node in &selected {
            match component {
                // 2.1: a string selects the key. A non-object aborts; a missing key removes
                // the element.
                PathComponent::Key(key) => take(node.member(key), &mut next, at)?,
                // 2.2: null selects all elements of the selected arrays. A non-array aborts;
                // an empty array contributes nothing.
                PathComponent::Null => {
                    next.extend(node.elements().ok_or(PathError::TypeMismatch { at })?);
                }
                // 2.3: an integer selects that index. A non-array aborts; an index past the
                // end removes the array.
                PathComponent::Index(i) => take(node.element(*i), &mut next, at)?,
            }
        }
        selected = next;
    }

    // Step 3: an empty selection is an error.
    if selected.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(selected)
}

/// Add what component `at` found to the selection `next`.
fn take<N>(found: Lookup<N>, next: &mut Vec<N>, at: ComponentIndex) -> Result<(), PathError> {
    match found {
        Lookup::Found(child) => next.push(child),
        Lookup::Absent => {}
        Lookup::WrongKind => return Err(PathError::TypeMismatch { at }),
    }
    Ok(())
}

impl<'a> ClaimNode for &'a Value {
    type Elements = std::slice::Iter<'a, Value>;

    fn member(&self, key: &str) -> Lookup<Self> {
        match self.as_object() {
            Some(object) => object.get(key).map_or(Lookup::Absent, Lookup::Found),
            None => Lookup::WrongKind,
        }
    }

    fn element(&self, index: u64) -> Lookup<Self> {
        match self.as_array() {
            Some(array) => usize::try_from(index)
                .ok()
                .and_then(|i| array.get(i))
                .map_or(Lookup::Absent, Lookup::Found),
            None => Lookup::WrongKind,
        }
    }

    fn elements(&self) -> Option<Self::Elements> {
        self.as_array().map(|array| array.iter())
    }
}

/// The values `path` selects in the JSON credential `root` (§7.1.1): [`resolve`] over a
/// [`serde_json::Value`].
///
/// # Errors
///
/// [`PathError`] as [`resolve`] gives it.
pub fn resolve_json<'a>(root: &'a Value, path: &ClaimPath) -> Result<Vec<&'a Value>, PathError> {
    resolve(root, path)
}

/// The `(namespace, data_element_identifier)` of an mdoc pointer (§7.2.1, step 1).
///
/// An mdoc pointer holds no `null` or index, and no flattened dotted string: ISO namespaces
/// contain dots themselves (`org.iso.18013.5.1`), so a flattened path cannot be split back.
///
/// # Errors
///
/// [`PathError::MdocElement`] unless the pointer is exactly two string components.
pub fn mdoc_components(path: &ClaimPath) -> Result<(&str, &str), PathError> {
    match path.components() {
        [PathComponent::Key(ns), PathComponent::Key(id)] => Ok((ns, id)),
        _ => Err(PathError::MdocElement),
    }
}
