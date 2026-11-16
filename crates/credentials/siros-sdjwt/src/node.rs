//! The claim tree as a claims path pointer walks it (OpenID4VP 1.0, Section 7.1).
//!
//! [`siros_dcql::resolve`] walks [`Node`]s. An index counts issued positions, and a withheld
//! position selects nothing; `null` selects the present elements.

use siros_dcql::{ClaimNode, Lookup};

use crate::sd_jwt::SdJwt;
use crate::tree::{Claim, ClaimValue, Element, Object};

/// A node of the claim tree, with the disclosures on its path from the root, root first.
#[derive(Clone)]
pub struct Node<'a> {
    value: NodeValue<'a>,
    path: Vec<&'a str>,
}

/// What a [`Node`] holds.
#[derive(Clone, Copy)]
pub enum NodeValue<'a> {
    /// The processed payload, the root of every pointer.
    Payload(&'a Object),
    /// An object member or a present array element.
    Claim(&'a Claim),
}

impl SdJwt {
    /// The root node: the processed payload.
    pub fn root(&self) -> Node<'_> {
        Node {
            value: NodeValue::Payload(self.claims()),
            path: Vec::new(),
        }
    }
}

impl<'a> Node<'a> {
    /// The payload or the claim this node holds.
    pub fn value(&self) -> NodeValue<'a> {
        self.value
    }

    /// The disclosures on the path from the root to this node, root first. A claim's own
    /// disclosure comes last.
    pub(crate) fn path(&self) -> &[&'a str] {
        &self.path
    }

    pub(crate) fn shape(&self) -> Shape<'a> {
        match self.value {
            NodeValue::Payload(object) => Shape::Object(object),
            NodeValue::Claim(claim) => Shape::of(claim.value()),
        }
    }

    /// The node of `claim`, a child of this node.
    fn child(&self, claim: &'a Claim) -> Self {
        let mut path = self.path.clone();
        path.extend(claim.disclosure_text());
        Self {
            value: NodeValue::Claim(claim),
            path,
        }
    }
}

impl<'a> ClaimNode for Node<'a> {
    type Elements = Children<'a>;

    fn member(&self, key: &str) -> Lookup<Self> {
        match self.shape() {
            Shape::Object(object) => object
                .get(key)
                .map_or(Lookup::Absent, |claim| Lookup::Found(self.child(claim))),
            _ => Lookup::WrongKind,
        }
    }

    fn element(&self, index: u64) -> Lookup<Self> {
        let Shape::Array(elements) = self.shape() else {
            return Lookup::WrongKind;
        };
        match usize::try_from(index).ok().and_then(|i| elements.get(i)) {
            Some(Element::Present(claim)) => Lookup::Found(self.child(claim)),
            Some(Element::Withheld) | None => Lookup::Absent,
        }
    }

    fn elements(&self) -> Option<Children<'a>> {
        match self.shape() {
            Shape::Array(elements) => Some(Children {
                parent: self.clone(),
                elements: elements.iter(),
            }),
            _ => None,
        }
    }
}

/// The present elements of an array node.
pub struct Children<'a> {
    parent: Node<'a>,
    elements: std::slice::Iter<'a, Element>,
}

impl<'a> Iterator for Children<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let claim = present(&mut self.elements).next()?;
        Some(self.parent.child(claim))
    }
}

/// A value as a pointer component sees it.
#[derive(Clone, Copy)]
pub(crate) enum Shape<'a> {
    Object(&'a Object),
    Array(&'a [Element]),
    Leaf,
}

impl<'a> Shape<'a> {
    pub(crate) fn of(value: &'a ClaimValue) -> Self {
        match value {
            ClaimValue::Object(object) => Shape::Object(object),
            ClaimValue::Array(elements) => Shape::Array(elements),
            _ => Shape::Leaf,
        }
    }
}

/// The claims of the present elements among `elements`.
pub(crate) fn present<'a>(
    elements: impl Iterator<Item = &'a Element>,
) -> impl Iterator<Item = &'a Claim> {
    elements.filter_map(|element| match element {
        Element::Present(claim) => Some(claim),
        Element::Withheld => None,
    })
}
