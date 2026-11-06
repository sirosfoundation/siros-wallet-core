//! DCQL claims for the formats that use them: OpenID4VP 1.0 §7 claims path pointers, and the
//! §6.3-6.4 `claims` and `claim_sets` of a Credential Query. [`kit`] holds what those formats
//! share beyond matching: the Verifier's algorithms, the card and the rows of a credential, the
//! elements an option discloses.

#[cfg(feature = "claims")]
pub mod kit;

use std::borrow::Cow;

use siros_explain::Explain;

use crate::json::Node;
use crate::plugins::{OptionItems, Options};
use crate::request::Item;

/// One component of a claims path pointer (§7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<'a> {
    /// A member name of an object.
    Key(Cow<'a, str>),
    /// An index into an array; `None` for one past every array.
    Index(Option<usize>),
    /// Every element of an array (`null`).
    All,
}

/// A claims path pointer: a non-empty array of strings, non-negative integers and `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPath<'a>(Vec<Step<'a>>);

/// One component of the concrete path of a selected element.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Concrete<'a> {
    /// A member name.
    Key(Cow<'a, str>),
    /// An array index.
    Index(usize),
}

impl Concrete<'_> {
    /// The component, owning its member name.
    #[must_use]
    pub fn owned(&self) -> Concrete<'static> {
        match self {
            Self::Key(name) => Concrete::Key(Cow::Owned(name.as_ref().to_owned())),
            Self::Index(index) => Concrete::Index(*index),
        }
    }
}

/// The concrete path of a selected element.
pub type ConcretePath<'a> = Vec<Concrete<'a>>;

/// A path component that does not fit the element it is applied to (§7.1): what it reads, and
/// its position in the path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp")]
#[error("a claims path pointer reads {what} in an element of another kind at component {step}")]
pub struct PathError {
    what: &'static str,
    step: usize,
}

impl PathError {
    /// The position of the component in the path.
    #[must_use]
    pub const fn step(&self) -> usize {
        self.step
    }
}

impl<'a> Step<'a> {
    /// Whether the component selects a component of a concrete path.
    #[must_use]
    pub fn matches(&self, part: &Concrete<'_>) -> bool {
        match (self, part) {
            (Step::All, Concrete::Index(_)) => true,
            (Step::Key(key), Concrete::Key(name)) => key == name,
            (Step::Index(Some(index)), Concrete::Index(at)) => index == at,
            _ => false,
        }
    }
}

impl<'a> ClaimPath<'a> {
    /// The path of a first component and the components after it.
    #[must_use]
    pub fn of(first: Step<'a>, rest: impl IntoIterator<Item = Step<'a>>) -> Self {
        Self(std::iter::once(first).chain(rest).collect())
    }

    /// The path, when the node is a claims path pointer.
    #[must_use]
    pub fn parse(node: &Node<'a>) -> Option<Self> {
        let steps = node.as_array().filter(|steps| !steps.is_empty())?;
        steps
            .iter()
            .map(|step| match step {
                Node::String(key) => Some(Step::Key(key.clone())),
                Node::Null => Some(Step::All),
                Node::Number(number)
                    if number
                        .text()
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b == b'-') =>
                {
                    let digits = number.text();
                    if digits.starts_with('-') && digits != "-0" {
                        return None;
                    }
                    Some(Step::Index(
                        number
                            .as_u64()
                            .and_then(|index| usize::try_from(index).ok()),
                    ))
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Self)
    }

    /// The components.
    #[must_use]
    pub fn steps(&self) -> &[Step<'a>] {
        &self.0
    }

    /// §7.1 processing: the selected elements with their concrete paths, in document order;
    /// empty when nothing is selected. A string meeting a non-object, or an index a non-array,
    /// is an error.
    pub fn select<'n>(
        &self,
        document: &'n Node<'n>,
    ) -> Result<Vec<(ConcretePath<'n>, &'n Node<'n>)>, PathError> {
        let mut current: Vec<(ConcretePath<'n>, &'n Node<'n>)> = vec![(Vec::new(), document)];
        for (position, step) in self.0.iter().enumerate() {
            let refused = |what| PathError {
                what,
                step: position,
            };
            let mut next = Vec::new();
            for (path, value) in current {
                match step {
                    Step::Key(key) => {
                        let object = value.as_object().ok_or(refused("a member name"))?;
                        if let Some(member) =
                            object.members().iter().find(|member| member.name == *key)
                        {
                            next.push((
                                extended(&path, Concrete::Key(member.name.clone())),
                                &member.value,
                            ));
                        }
                    }
                    Step::Index(index) => {
                        let items = value.as_array().ok_or(refused("an index"))?;
                        if let Some((at, item)) =
                            index.and_then(|at| items.get(at).map(|item| (at, item)))
                        {
                            next.push((extended(&path, Concrete::Index(at)), item));
                        }
                    }
                    Step::All => {
                        let items = value.as_array().ok_or(refused("null"))?;
                        next.extend(
                            items
                                .iter()
                                .enumerate()
                                .map(|(at, item)| (extended(&path, Concrete::Index(at)), item)),
                        );
                    }
                }
            }
            current = next;
        }
        Ok(current)
    }

    /// Whether the pointer selects a concrete path.
    #[must_use]
    pub fn matches(&self, concrete: &[Concrete<'_>]) -> bool {
        self.0.len() == concrete.len()
            && self
                .0
                .iter()
                .zip(concrete)
                .all(|(step, part)| step.matches(part))
    }
}

fn extended<'n>(path: &[Concrete<'n>], step: Concrete<'n>) -> ConcretePath<'n> {
    let mut out = path.to_vec();
    out.push(step);
    out
}

/// A claims query (§6.3).
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    id: Option<Cow<'a, str>>,
    path: ClaimPath<'a>,
    values: Option<Vec<Node<'a>>>,
}

impl<'a> Claim<'a> {
    /// The `id`, required with `claim_sets`.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The `path`.
    #[must_use]
    pub const fn path(&self) -> &ClaimPath<'a> {
        &self.path
    }

    /// The `values`, at least one, one of which a selected element must equal.
    #[must_use]
    pub fn values(&self) -> Option<&[Node<'a>]> {
        self.values.as_deref()
    }

    /// §6.3: the path selects at least one element of the credential's values, and with
    /// `values` one of them equals one of the values (equal JSON of one type).
    #[must_use]
    pub fn found(&self, document: &Node<'_>) -> bool {
        match (self.path.select(document), &self.values) {
            (Err(_), _) => false,
            (Ok(selected), None) => !selected.is_empty(),
            (Ok(selected), Some(values)) => {
                selected.iter().any(|(_, element)| values.contains(element))
            }
        }
    }
}

/// The `claims` and `claim_sets` of a Credential Query.
#[derive(Debug, Clone)]
pub struct Claims<'a> {
    claims: Vec<Claim<'a>>,
    options: Options,
}

/// `claims` or `claim_sets` that break §6.3-6.4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.claims")]
pub enum ClaimsError {
    /// `claims` is no non-empty array of claims queries.
    #[error("claims is not a non-empty array of objects with a claims path pointer")]
    Claims,
    /// `values` is no non-empty array.
    #[error("claims[{0}].values is not a non-empty array")]
    Values(#[explain(name = "claim")] usize),
    /// `claim_sets` without `claims`, or not a non-empty array of non-empty arrays of claim ids.
    #[error("claim_sets is not a non-empty array of non-empty arrays of claim ids")]
    ClaimSets,
    /// More claims than an option can hold.
    #[error("more than 64 claims")]
    TooMany,
}

impl<'a> Claims<'a> {
    /// Parses the members of a query object: without `claim_sets`, one option holding every
    /// claim (§6.4.1).
    pub fn parse(query: &Node<'a>) -> Result<Self, ClaimsError> {
        let claims = match query.get("claims") {
            None => Vec::new(),
            Some(claims) => claims
                .as_array()
                .filter(|claims| !claims.is_empty())
                .ok_or(ClaimsError::Claims)?
                .iter()
                .enumerate()
                .map(|(k, claim)| Claim::parse(k, claim))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let item = |k: usize| Item::new(k).ok_or(ClaimsError::TooMany);
        let options = match query.get("claim_sets") {
            None => vec![OptionItems::new(
                (0..claims.len()).map(item).collect::<Result<_, _>>()?,
            )],
            Some(sets) => {
                let sets = sets
                    .as_array()
                    .filter(|sets| !sets.is_empty() && !claims.is_empty())
                    .ok_or(ClaimsError::ClaimSets)?;
                sets.iter()
                    .map(|set| {
                        let ids = set
                            .as_array()
                            .filter(|ids| !ids.is_empty())
                            .ok_or(ClaimsError::ClaimSets)?;
                        let items = ids
                            .iter()
                            .map(|id| {
                                let id = id.as_str().ok_or(ClaimsError::ClaimSets)?;
                                let k = claims
                                    .iter()
                                    .rposition(|claim| claim.id.as_deref() == Some(id))
                                    .ok_or(ClaimsError::ClaimSets)?;
                                item(k)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok(OptionItems::new(items))
                    })
                    .collect::<Result<Vec<_>, ClaimsError>>()?
            }
        };
        Ok(Self {
            claims,
            options: Options::new(options),
        })
    }

    /// The claims queries.
    #[must_use]
    pub fn claims(&self) -> &[Claim<'a>] {
        &self.claims
    }

    /// The claim of an item.
    #[must_use]
    pub fn claim(&self, item: Item) -> Option<&Claim<'a>> {
        self.claims.get(item.get())
    }

    /// The options as claim items.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }
}

impl<'a> Claim<'a> {
    fn parse(k: usize, node: &Node<'a>) -> Result<Self, ClaimsError> {
        let path = node
            .get("path")
            .and_then(ClaimPath::parse)
            .ok_or(ClaimsError::Claims)?;
        let id = match node.get("id") {
            None => None,
            Some(Node::String(id)) => Some(id.clone()),
            Some(_) => return Err(ClaimsError::Claims),
        };
        let values = node
            .get("values")
            .map(|values| {
                values
                    .as_array()
                    .filter(|values| !values.is_empty())
                    .map(<[_]>::to_vec)
                    .ok_or(ClaimsError::Values(k))
            })
            .transpose()?;
        Ok(Self { id, path, values })
    }
}
