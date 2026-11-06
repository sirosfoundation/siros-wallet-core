//! The disclosures and embedded digests of an issued SD-JWT, processed (RFC 9901 §7.1, steps 3 to
//! 5) into its claim tree.

use rustc_hash::{FxHashMap, FxHashSet};
use siros_openid4vp::json::Node;

use crate::alg::Digest;
use crate::error::{Misplaced, ParseError, ReservedFault};
use crate::tree::{ClaimValue, Disclosure, DisclosureId, Element, IssuedClaim, Member, Object};

/// The deepest nesting of claims, the payload's root object at depth 0, disclosures included.
pub const MAX_DEPTH: usize = 32;

const SD: &str = "_sd";
pub(crate) const ELLIPSIS: &str = "...";
const SD_ALG: &str = "_sd_alg";

/// A disclosure no digest has referenced yet.
pub(crate) struct Pending {
    pub(crate) id: DisclosureId,
    pub(crate) encoded: String,
    pub(crate) content: Content,
}

/// What a disclosure reveals (§4.2.1, §4.2.2).
pub(crate) enum Content {
    /// An object property.
    Property { name: String, value: Node<'static> },
    /// An array element.
    Element(Node<'static>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Root,
    Nested,
}

/// The claim tree of the payload `root`, which consumes every disclosure of `pending`, keyed by
/// digest.
pub(crate) fn claims(
    root: &Node<'_>,
    pending: FxHashMap<Digest, Pending>,
) -> Result<Object, ParseError> {
    let mut processor = Processor {
        pending,
        seen: FxHashSet::default(),
    };
    let claims = processor.object(root, 0, Level::Root)?;
    match processor.pending.values().map(|pending| pending.id).min() {
        None => Ok(claims),
        Some(id) => Err(ParseError::UnreferencedDisclosure(id)),
    }
}

struct Processor {
    /// The disclosures no digest has referenced yet.
    pending: FxHashMap<Digest, Pending>,
    /// Every digest met so far, decoys included.
    seen: FxHashSet<Digest>,
}

impl Processor {
    /// The disclosure `digest` references, if the credential holds it (§7.1, step 3.c.i).
    fn reference(&mut self, digest: Digest) -> Result<Option<Pending>, ParseError> {
        if !self.seen.insert(digest.clone()) {
            return Err(ParseError::RepeatedDigest(digest));
        }
        Ok(self.pending.remove(&digest))
    }

    fn value(&mut self, json: &Node<'_>, depth: usize) -> Result<ClaimValue, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        Ok(match json {
            Node::Null => ClaimValue::Null,
            Node::Bool(value) => ClaimValue::Bool(*value),
            Node::Number(number) => ClaimValue::Number(number.clone().into_owned()),
            Node::String(text) => ClaimValue::String(text.to_string()),
            Node::Array(items) => ClaimValue::Array(
                items
                    .iter()
                    .map(|item| self.element(item, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Node::Object(_) => ClaimValue::Object(self.object(json, depth, Level::Nested)?),
        })
    }

    /// §7.1, step 3.c.ii: the object's own members, then those its `_sd` digests reveal.
    fn object(
        &mut self,
        json: &Node<'_>,
        depth: usize,
        level: Level,
    ) -> Result<Object, ParseError> {
        let mut digests = Vec::new();
        let mut plain = Vec::new();
        for member in json.as_object().into_iter().flat_map(|o| o.members()) {
            match member.name.as_ref() {
                SD => digests = digest_strings(&member.value)?,
                SD_ALG if level == Level::Root => {}
                SD_ALG => return Err(reserved(ReservedFault::NestedSdAlg)),
                ELLIPSIS => return Err(reserved(ReservedFault::Ellipsis)),
                _ => plain.push(member),
            }
        }
        let mut members = Vec::with_capacity(plain.len() + digests.len());
        for member in plain {
            members.push(Member {
                name: member.name.to_string(),
                claim: IssuedClaim::new(self.value(&member.value, depth + 1)?, None),
            });
        }
        for digest in digests {
            let Some(pending) = self.reference(digest)? else {
                continue;
            };
            let disclosure = Disclosure::new(pending.id, pending.encoded);
            let Content::Property { name, value } = pending.content else {
                return Err(ParseError::MisplacedDisclosure {
                    disclosure: disclosure.id(),
                    placement: Misplaced::ElementInObject,
                });
            };
            if matches!(name.as_str(), SD | ELLIPSIS | SD_ALG) {
                return Err(reserved(ReservedFault::Disclosed(name)));
            }
            let value = self.value(&value, depth + 1)?;
            members.push(Member {
                name,
                claim: IssuedClaim::new(value, Some(disclosure)),
            });
        }
        Object::new(members).map_err(|repeated| ParseError::ClaimNameExists(repeated.0))
    }

    /// §7.1, step 3.c.iii: an element `{"...": digest}` is the value its disclosure reveals, or
    /// withheld.
    fn element(&mut self, item: &Node<'_>, depth: usize) -> Result<Element, ParseError> {
        let digest = match item.as_object() {
            Some(members) if members.get(ELLIPSIS).is_some() => array_digest(item)?,
            _ => {
                return Ok(Element::Present(IssuedClaim::new(
                    self.value(item, depth)?,
                    None,
                )));
            }
        };
        let Some(pending) = self.reference(digest.clone())? else {
            return Ok(Element::Withheld(digest));
        };
        let disclosure = Disclosure::new(pending.id, pending.encoded);
        match pending.content {
            Content::Element(value) => {
                let value = self.value(&value, depth)?;
                Ok(Element::Present(IssuedClaim::new(value, Some(disclosure))))
            }
            Content::Property { .. } => Err(ParseError::MisplacedDisclosure {
                disclosure: disclosure.id(),
                placement: Misplaced::PropertyInArray,
            }),
        }
    }
}

fn reserved(fault: ReservedFault) -> ParseError {
    ParseError::ReservedClaimName(fault)
}

/// The digests of an `_sd` member, which holds an array of strings (§4.2.4.1).
fn digest_strings(value: &Node<'_>) -> Result<Vec<Digest>, ParseError> {
    value
        .as_array()
        .ok_or(reserved(ReservedFault::SdNotArray))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(Digest::new)
                .ok_or(reserved(ReservedFault::SdDigest))
        })
        .collect()
}

/// The digest of an array element `{"...": digest}`, whose only member is `...` (§4.2.4.2).
fn array_digest(element: &Node<'_>) -> Result<Digest, ParseError> {
    let members = element.as_object().map_or(&[][..], |o| o.members());
    match members {
        [only] => only
            .value
            .as_str()
            .map(Digest::new)
            .ok_or(reserved(ReservedFault::ElementDigest)),
        _ => Err(reserved(ReservedFault::ElementMembers)),
    }
}
