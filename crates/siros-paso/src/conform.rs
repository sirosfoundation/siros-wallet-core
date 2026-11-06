//! Core §7.4.2 step 2, a payload's conformance to its metadata, and the claim instances a
//! rendering shows, in its rulebook's order (View §2, Generic §4, Mandate §2.1).

use std::borrow::Cow;
use std::fmt;

use crate::value::{ValueKind, Written, formatted};
use siros_explain::{Count, IntoArg, kind};
use siros_openid4vp::claims::{ArrayIndex, ClaimPath, Concrete, ConcretePath, Step};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::refusal::ReprItem;

use crate::entry::Payload;
use crate::labels::Directional;
use crate::metadata::{ClaimMeta, Displayed, Mandatory, Metadata, ValueType, kind_name};
use crate::outcome::NotCompatible;
use crate::path::{Mismatch, at, claim_text, concrete_text, select, selects};
use crate::rulebook::Rulebook;

/// A claim by its position in the metadata's `claims`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClaimIndex(pub(crate) usize);

impl ClaimIndex {
    /// The position in the metadata's `claims`.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl fmt::Display for ClaimIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoArg for ClaimIndex {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        self.0.arg()
    }
}

/// The array element each `null` of a claim's path resolved to, in path order.
#[derive(Debug, Clone, Default)]
pub(crate) struct NullIndices(Vec<usize>);

impl NullIndices {
    /// The indices with the next `null` resolved to `element`.
    fn then(&self, element: usize) -> Self {
        Self(self.0.iter().copied().chain([element]).collect())
    }

    /// How many `null`s resolved.
    pub(crate) const fn len(&self) -> usize {
        self.0.len()
    }

    /// The elements, in path order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = usize> {
        self.0.iter().copied()
    }
}

/// Whether an instance sits in the delimited section of an embedded `payment_payload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Placement {
    /// In the transaction's own rows.
    Main,
    /// In the embedded payment's section (Generic §3.2, Mandate §2.2).
    Embedded,
}

/// One claim instance a rendering shows: the claim and how it is displayed, the payload
/// element and its path, the array indices the claim path's `null`s resolved to, and where it
/// sits.
#[derive(Debug, Clone)]
pub struct Instance<'p> {
    /// The claim.
    pub claim: ClaimIndex,
    /// How the claim is displayed.
    pub display: &'p Displayed<'p>,
    /// The element's path.
    pub path: ConcretePath<'p>,
    /// The element.
    pub value: &'p Node<'p>,
    /// The element each `null` of the claim's path resolved to.
    pub(crate) nulls: NullIndices,
    /// Where it sits.
    pub placement: Placement,
}

/// A claim instance before its presence in the payload is read.
struct Candidate<'p> {
    claim: ClaimIndex,
    display: &'p Displayed<'p>,
    path: ConcretePath<'p>,
    nulls: NullIndices,
    placement: Placement,
}

/// A JSON value as a value of a kind reads it.
#[must_use]
pub fn written<'n>(node: &'n Node<'n>) -> Written<'n> {
    match node {
        Node::Bool(value) => Written::Boolean(*value),
        Node::String(text) => Written::Text(text),
        other => Written::Other(other),
    }
}

/// Whether a payload value conforms to a value type other than `label_only` and a template:
/// an image is a string, every other kind parses (View §3).
pub(crate) fn conforms(kind: ValueKind, value: &Node<'_>) -> Result<(), NotCompatible> {
    match kind {
        ValueKind::Image => match value {
            Node::String(_) => Ok(()),
            _ => Err(NotCompatible::ImageNotString(ReprItem::repr(value))),
        },
        ValueKind::Formatted(kind) => {
            formatted(kind, written(value))
                .map(drop)
                .map_err(|bad| NotCompatible::Value {
                    value_type: kind_name(ValueKind::Formatted(kind)),
                    bad,
                })
        }
    }
}

/// Core §7.4.2 step 2: every payload field is covered by a claim path, an `#integrity`
/// companion by its claim's; no payload string breaks the directional rule (Proof Metadata
/// §3.3); every mandatory claim is present; every displayed value conforms to its value type.
pub(crate) fn conform(
    payload: Payload<'_>,
    metadata: &Metadata<'_>,
    rulebook: &Rulebook<'_>,
) -> Result<(), NotCompatible> {
    Coverage {
        paths: metadata.claims.iter().map(|claim| &claim.path).collect(),
    }
    .walk(payload.node(), &mut Vec::new())?;
    for claim in &metadata.claims {
        let found = select(payload.node(), &claim.path)?;
        if claim.mandatory == Mandatory::Yes && found.is_empty() {
            return Err(NotCompatible::MandatoryAbsent(claim_text(
                claim.path.steps(),
            )));
        }
        let Some(display) = &claim.display else {
            continue;
        };
        for (path, value) in found {
            if display.value == ValueType::LabelOnly || rulebook.label_alone(&path, value) {
                continue;
            }
            match display.value {
                ValueType::Template(_) => {
                    if value.as_str().is_none() {
                        return Err(NotCompatible::TemplateNotString(claim_text(
                            claim.path.steps(),
                        )));
                    }
                }
                other => {
                    if let Some(kind) = other.rendered() {
                        conforms(kind, value)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// The claim paths that cover a payload.
struct Coverage<'c, 'm> {
    paths: Vec<&'c ClaimPath<'m>>,
}

impl Coverage<'_, '_> {
    /// A claim path selects the field or one of its ancestors.
    fn addressed(&self, field: &[Concrete<'_>]) -> bool {
        self.paths
            .iter()
            .any(|path| path.steps().len() <= field.len() && selects(path.steps(), field))
    }

    /// A claim path continues below the field.
    fn leads(&self, field: &[Concrete<'_>]) -> bool {
        self.paths
            .iter()
            .any(|path| path.steps().len() > field.len() && selects(path.steps(), field))
    }

    fn walk<'n>(
        &self,
        node: &'n Node<'n>,
        at: &mut Vec<Concrete<'n>>,
    ) -> Result<(), NotCompatible> {
        for (part, value) in children(node) {
            at.push(part);
            if let Some(violation) = value.as_str().and_then(Directional::find) {
                return Err(NotCompatible::PayloadDirectional {
                    path: concrete_text(at),
                    violation,
                });
            }
            let nested = matches!(value, Node::Object(_) | Node::Array(_));
            if self.addressed(at) {
                if nested {
                    strings(value, at)?;
                }
            } else if !self.companion(at) {
                if nested && self.leads(at) {
                    self.walk(value, at)?;
                } else {
                    return Err(NotCompatible::Uncovered(concrete_text(at)));
                }
            }
            drop(at.pop());
        }
        Ok(())
    }

    /// An `#integrity` member whose sibling without the suffix a claim covers.
    fn companion(&self, field: &[Concrete<'_>]) -> bool {
        let Some((Concrete::Key(key), parent)) = field.split_last() else {
            return false;
        };
        let Some(base) = key.strip_suffix("#integrity") else {
            return false;
        };
        let mut sibling = parent.to_vec();
        sibling.push(Concrete::Key(Cow::Borrowed(base)));
        self.addressed(&sibling)
    }
}

/// An object's members or an array's elements with their path parts.
fn children<'n>(node: &'n Node<'n>) -> Vec<(Concrete<'n>, &'n Node<'n>)> {
    match node {
        Node::Object(object) => object
            .members()
            .iter()
            .map(|member| {
                (
                    Concrete::Key(Cow::Borrowed(member.name.as_ref())),
                    &member.value,
                )
            })
            .collect(),
        Node::Array(items) => items
            .iter()
            .enumerate()
            .map(|(k, item)| (Concrete::Index(ArrayIndex::new(k)), item))
            .collect(),
        _ => Vec::new(),
    }
}

/// Every string below a covered field meets the directional rule.
fn strings<'n>(node: &'n Node<'n>, at: &mut Vec<Concrete<'n>>) -> Result<(), NotCompatible> {
    for (part, value) in children(node) {
        at.push(part);
        if let Some(violation) = value.as_str().and_then(Directional::find) {
            return Err(NotCompatible::PayloadDirectional {
                path: concrete_text(at),
                violation,
            });
        }
        strings(value, at)?;
        drop(at.pop());
    }
    Ok(())
}

/// A claim's path partly resolved: its `null`s before the first remaining one replaced by
/// array indices.
struct Partial<'m> {
    claim: ClaimIndex,
    display: &'m Displayed<'m>,
    steps: Vec<Step<'m>>,
    nulls: NullIndices,
}

/// The claim instances the payload holds, in the rulebook's order: claims order with View §2's
/// recursive rule for `null` paths, or the Generic rulebook's payload member order.
pub(crate) fn instances<'p>(
    rulebook: &Rulebook<'_>,
    metadata: &'p Metadata<'p>,
    payload: Payload<'p>,
) -> Result<Vec<Instance<'p>>, NotCompatible> {
    let candidates = match rulebook {
        Rulebook::Generic(_) => {
            let mut out = Vec::new();
            generic(
                &metadata.claims,
                payload.object(),
                &[],
                Placement::Main,
                &mut out,
            );
            out
        }
        _ => {
            let displayed = metadata
                .claims
                .iter()
                .enumerate()
                .filter_map(|(k, claim)| {
                    claim.display.as_ref().map(|display| Partial {
                        claim: ClaimIndex(k),
                        display,
                        steps: claim.path.steps().to_vec(),
                        nulls: NullIndices::default(),
                    })
                })
                .collect();
            let mut complete = Vec::new();
            expand(displayed, payload.node(), &mut complete)?;
            complete
                .into_iter()
                .filter_map(|partial| {
                    let path = concrete(&partial.steps)?;
                    let placement = match (rulebook, path.first()) {
                        (Rulebook::Mandate(_), Some(Concrete::Key(key)))
                            if key == "payment_payload" =>
                        {
                            Placement::Embedded
                        }
                        _ => Placement::Main,
                    };
                    Some(Candidate {
                        claim: partial.claim,
                        display: partial.display,
                        path,
                        nulls: partial.nulls,
                        placement,
                    })
                })
                .collect()
        }
    };
    let mut present = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if let Some(value) = at(payload.node(), &candidate.path)? {
            present.push(Instance {
                claim: candidate.claim,
                display: candidate.display,
                path: candidate.path,
                value,
                nulls: candidate.nulls,
                placement: candidate.placement,
            });
        }
    }
    Ok(present)
}

/// A fully resolved path as a concrete path; `None` when an index cannot exist.
fn concrete<'m>(steps: &[Step<'m>]) -> Option<ConcretePath<'m>> {
    steps
        .iter()
        .map(|step| match step {
            Step::Key(key) => Some(Concrete::Key(key.clone())),
            Step::Index(index) => Some(Concrete::Index(*index)),
            Step::Beyond(_) | Step::All => None,
        })
        .collect()
}

/// View §2's recursive rule: the claims without a remaining `null` in declared order, then each
/// group sharing the prefix up to its first `null`, in the order of its first claim, once per
/// element of the array there.
fn expand<'m>(
    items: Vec<Partial<'m>>,
    payload: &Node<'_>,
    out: &mut Vec<Partial<'m>>,
) -> Result<(), NotCompatible> {
    // Each group by the path to its array: the steps before the first `null`.
    let mut groups: Vec<(Vec<Step<'m>>, Vec<Partial<'m>>)> = Vec::new();
    for item in items {
        match item.steps.iter().position(|step| *step == Step::All) {
            None => out.push(item),
            Some(first) => {
                let parent: Vec<Step<'m>> = item.steps.iter().take(first).cloned().collect();
                match groups.iter_mut().find(|(known, _)| *known == parent) {
                    Some((_, members)) => members.push(item),
                    None => groups.push((parent, vec![item])),
                }
            }
        }
    }
    for (parent, members) in groups {
        // An index beyond the platform's integers names no element.
        let Some(array) = concrete(&parent) else {
            continue;
        };
        let Some(array) = at(payload, &array)? else {
            continue;
        };
        // Conformance selected every claim's path, so an array is there.
        let elements = array.as_array().ok_or_else(|| {
            let mut prefix = parent.clone();
            prefix.push(Step::All);
            Mismatch::Index {
                path: claim_text(&prefix),
            }
        })?;
        let position = parent.len();
        for element in 0..elements.len() {
            let resolved = members
                .iter()
                .map(|member| Partial {
                    claim: member.claim,
                    display: member.display,
                    steps: member
                        .steps
                        .iter()
                        .enumerate()
                        .map(|(k, step)| {
                            if k == position {
                                Step::Index(ArrayIndex::new(element))
                            } else {
                                step.clone()
                            }
                        })
                        .collect(),
                    nulls: member.nulls.then(element),
                })
                .collect();
            expand(resolved, payload, out)?;
        }
    }
    Ok(())
}

/// Generic §4: the payload's members in their order, `transaction_id` skipped, the embedded
/// `payment_payload` walked as its section (the rulebook refused one that is no object), an
/// object no claim names walked for the claims below it.
fn generic<'p>(
    claims: &'p [ClaimMeta<'p>],
    object: &'p Object<'static>,
    prefix: &[Concrete<'p>],
    placement: Placement,
    out: &mut Vec<Candidate<'p>>,
) {
    for member in object.members() {
        let mut path = prefix.to_vec();
        path.push(Concrete::Key(Cow::Borrowed(member.name.as_ref())));
        let top = |name: &str| matches!(path.as_slice(), [Concrete::Key(key)] if key == name);
        if top("transaction_id") {
            continue;
        }
        if top("payment_payload") {
            if let Node::Object(embedded) = &member.value {
                generic(claims, embedded, &path, Placement::Embedded, out);
            }
            continue;
        }
        match claims
            .iter()
            .enumerate()
            .find(|(_, claim)| claim.path.matches(&path))
        {
            Some((k, claim)) => {
                if let Some(display) = &claim.display {
                    out.push(Candidate {
                        claim: ClaimIndex(k),
                        display,
                        path,
                        nulls: NullIndices::default(),
                        placement,
                    });
                }
            }
            None => {
                if let Node::Object(inner) = &member.value {
                    generic(claims, inner, &path, placement, out);
                }
            }
        }
    }
}
