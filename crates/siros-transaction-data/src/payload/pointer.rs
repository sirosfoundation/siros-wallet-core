//! Locations in a payload, and the values a claims path pointer selects there with their
//! locations (OpenID4VP 1.0, Section 7.1).

use std::cmp::Ordering;
use std::fmt;

use siros_codec::json::Json;
use siros_dcql::{ComponentIndex, PathComponent, PathError};

/// A step of a location: an object member or an array element.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Step {
    /// A member name.
    Key(String),
    /// An element position.
    Index(u64),
}

/// How what a claims path pointer addresses relates to a location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Reach {
    /// The pointer addresses the location.
    Addresses,
    /// The pointer addresses an ancestor of the location.
    Contains,
    /// The location lies on the way to what the pointer addresses.
    LeadsTo,
    /// The pointer addresses neither the location, nor an ancestor, nor a descendant.
    Apart,
}

/// The location of a value in a payload: the steps from the payload object to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Location(Vec<Step>);

impl Location {
    /// The location of `steps` from the payload object.
    #[must_use]
    pub fn new(steps: Vec<Step>) -> Self {
        Self(steps)
    }

    /// The steps.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.0
    }

    /// The location one step further.
    pub(crate) fn then(&self, step: Step) -> Self {
        let mut steps = self.0.clone();
        steps.push(step);
        Self(steps)
    }

    /// The location of the member `name` of the object at this location's parent: its
    /// sibling.
    pub(crate) fn sibling(&self, name: &str) -> Option<Self> {
        let (_, parent) = self.0.split_last()?;
        Some(Self(parent.to_vec()).then(Step::Key(name.to_owned())))
    }

    /// The last step's member name.
    pub(crate) fn last_key(&self) -> Option<&str> {
        match self.0.last()? {
            Step::Key(key) => Some(key),
            Step::Index(_) => None,
        }
    }

    /// How what `components` addresses relates to this location, `null` standing for any
    /// position.
    pub(crate) fn reach(&self, components: &[PathComponent]) -> Reach {
        let along = components.iter().zip(&self.0).all(|(c, s)| match (c, s) {
            (PathComponent::Key(key), Step::Key(step)) => key == step,
            (PathComponent::Index(index), Step::Index(step)) => index == step,
            (PathComponent::Null, Step::Index(_)) => true,
            (PathComponent::Key(_) | PathComponent::Index(_) | PathComponent::Null, _) => false,
        });
        match (along, components.len().cmp(&self.0.len())) {
            (false, _) => Reach::Apart,
            (true, Ordering::Equal) => Reach::Addresses,
            (true, Ordering::Less) => Reach::Contains,
            (true, Ordering::Greater) => Reach::LeadsTo,
        }
    }

    /// The locations from the payload object to this one, shortest first, this one included.
    pub(crate) fn prefixes(&self) -> impl Iterator<Item = Location> + '_ {
        (1..=self.0.len()).map(|length| Self(self.0.iter().take(length).cloned().collect()))
    }

    /// The location of `components` with each `null` taking the next of `indices`; `None` when
    /// `components` has more `null`s than `indices` positions.
    pub(crate) fn bound(components: &[PathComponent], indices: &[u64]) -> Option<Self> {
        let mut indices = indices.iter();
        components
            .iter()
            .map(|component| match component {
                PathComponent::Key(key) => Some(Step::Key(key.clone())),
                PathComponent::Index(index) => Some(Step::Index(*index)),
                PathComponent::Null => indices.next().map(|index| Step::Index(*index)),
            })
            .collect::<Option<Vec<_>>>()
            .map(Self)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, step) in self.0.iter().enumerate() {
            match step {
                Step::Key(key) if at == 0 => f.write_str(key)?,
                Step::Key(key) => write!(f, ".{key}")?,
                Step::Index(index) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

/// The values `components` selects under `root`, each with its location and the positions its
/// `null`s took (Section 7.1.1). A missing member or position leaves the selection; a component
/// of the wrong kind aborts.
///
/// # Errors
///
/// [`PathError::TypeMismatch`] for a key on a non-object or a `null` or an index on a
/// non-array.
pub(crate) fn select<'j>(
    root: &'j Json,
    components: &[PathComponent],
) -> Result<Vec<Selected<'j>>, PathError> {
    let mut selected = vec![Selected {
        location: Location::default(),
        wildcards: Vec::new(),
        value: root,
    }];
    for (at, component) in components.iter().enumerate() {
        let mismatch = PathError::TypeMismatch {
            at: ComponentIndex::new(at),
        };
        let mut next = Vec::new();
        for node in &selected {
            match (component, node.value) {
                (PathComponent::Key(key), Json::Object(members)) => {
                    if let Some((_, value)) = members.iter().find(|(name, _)| name == key) {
                        next.push(node.step(Step::Key(key.clone()), value, None));
                    }
                }
                (PathComponent::Index(index), Json::Array(items)) => {
                    let item = usize::try_from(*index).ok().and_then(|i| items.get(i));
                    if let Some(value) = item {
                        next.push(node.step(Step::Index(*index), value, None));
                    }
                }
                (PathComponent::Null, Json::Array(items)) => {
                    for (position, value) in (0u64..).zip(items) {
                        next.push(node.step(Step::Index(position), value, Some(position)));
                    }
                }
                (PathComponent::Key(_) | PathComponent::Index(_) | PathComponent::Null, _) => {
                    return Err(mismatch)
                }
            }
        }
        selected = next;
    }
    Ok(selected)
}

/// A value a claims path pointer selects.
#[derive(Debug, Clone)]
pub(crate) struct Selected<'j> {
    pub(crate) location: Location,
    /// The positions the pointer's `null`s took, in order.
    pub(crate) wildcards: Vec<u64>,
    pub(crate) value: &'j Json,
}

impl<'j> Selected<'j> {
    fn step(&self, step: Step, value: &'j Json, wildcard: Option<u64>) -> Self {
        let mut wildcards = self.wildcards.clone();
        wildcards.extend(wildcard);
        Self {
            location: self.location.then(step),
            wildcards,
            value,
        }
    }
}
