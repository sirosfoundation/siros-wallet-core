//! Processing the disclosures and embedded digests of a stored SD-JWT (RFC 9901, Section 7.1,
//! steps 3 to 5) into its claim tree.

use rustc_hash::{FxHashMap, FxHashSet};
use siros_codec::base64url::Base64Url;
use siros_codec::json::Json;

use crate::alg::Digest;
use crate::error::{ParseError, Placement, ReservedFault};
use crate::tree::{Claim, ClaimValue, Disclosure, DisclosureId, Element, Object};

/// The deepest nesting of claims, the payload's root object at depth 0, disclosures included.
pub const MAX_DEPTH: usize = 32;

const SD: &str = "_sd";
const ELLIPSIS: &str = "...";
const SD_ALG: &str = "_sd_alg";

/// A disclosure not yet referenced by a digest.
pub(crate) struct Pending {
    id: DisclosureId,
    encoded: Base64Url,
    content: Content,
}

impl Pending {
    pub(crate) fn new(id: DisclosureId, encoded: Base64Url, content: Content) -> Self {
        Self {
            id,
            encoded,
            content,
        }
    }

    fn disclosure(self) -> (Disclosure, Content) {
        (Disclosure::new(self.id, self.encoded), self.content)
    }
}

/// What a disclosure reveals (Sections 4.2.1 and 4.2.2).
pub(crate) enum Content {
    /// An object property.
    Property { name: String, value: Json },
    /// An array element.
    Element(Json),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Root,
    Nested,
}

/// The claim tree of the payload `root`, which consumes every disclosure of `pending`, keyed by
/// digest.
pub(crate) fn claims(
    root: Vec<(String, Json)>,
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
    /// The disclosure `digest` references, if the credential holds it (Section 7.1, step 3.c.i).
    fn reference(&mut self, digest: Digest) -> Result<Option<Pending>, ParseError> {
        if !self.seen.insert(digest.clone()) {
            return Err(ParseError::RepeatedDigest(digest));
        }
        Ok(self.pending.remove(&digest))
    }

    fn value(&mut self, json: Json, depth: usize) -> Result<ClaimValue, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        Ok(match json {
            Json::Null => ClaimValue::Null,
            Json::Bool(b) => ClaimValue::Bool(b),
            Json::Number(n) => ClaimValue::Number(n.into_number()),
            Json::String(s) => ClaimValue::String(s),
            Json::Array(items) => ClaimValue::Array(
                items
                    .into_iter()
                    .map(|item| self.element(item, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Json::Object(members) => {
                ClaimValue::Object(self.object(members, depth, Level::Nested)?)
            }
        })
    }

    /// Section 7.1, step 3.c.ii: the object's own members, then those its `_sd` digests reveal.
    fn object(
        &mut self,
        members: Vec<(String, Json)>,
        depth: usize,
        level: Level,
    ) -> Result<Object, ParseError> {
        let mut digests = Vec::new();
        let mut plain = Vec::with_capacity(members.len());
        for (name, value) in members {
            match name.as_str() {
                SD => digests = digest_strings(value)?,
                SD_ALG if level == Level::Root => {}
                SD_ALG => return Err(reserved(ReservedFault::NestedSdAlg)),
                ELLIPSIS => return Err(reserved(ReservedFault::Ellipsis)),
                _ => plain.push((name, value)),
            }
        }
        let mut names: FxHashSet<String> = plain.iter().map(|(name, _)| name.clone()).collect();
        let mut object = Object::new();
        for (name, value) in plain {
            let value = self.value(value, depth + 1)?;
            object.push(name, Claim::new(value, None));
        }
        for digest in digests {
            let Some(pending) = self.reference(digest)? else {
                continue;
            };
            let (disclosure, content) = pending.disclosure();
            let Content::Property { name, value } = content else {
                return Err(ParseError::MisplacedDisclosure {
                    disclosure: disclosure.id(),
                    placement: Placement::ElementInObject,
                });
            };
            if matches!(name.as_str(), SD | ELLIPSIS | SD_ALG) {
                return Err(reserved(ReservedFault::Disclosed(name)));
            }
            if !names.insert(name.clone()) {
                return Err(ParseError::ClaimNameExists(name));
            }
            let value = self.value(value, depth + 1)?;
            object.push(name, Claim::new(value, Some(disclosure)));
        }
        Ok(object)
    }

    /// Section 7.1, step 3.c.iii: an element `{"...": digest}` is the value its disclosure
    /// reveals, or withheld.
    fn element(&mut self, item: Json, depth: usize) -> Result<Element, ParseError> {
        let digest = match item {
            Json::Object(members) if members.iter().any(|(name, _)| name == ELLIPSIS) => {
                array_digest(members)?
            }
            other => {
                return Ok(Element::Present(Claim::new(
                    self.value(other, depth)?,
                    None,
                )))
            }
        };
        let Some(pending) = self.reference(digest)? else {
            return Ok(Element::Withheld);
        };
        match pending.disclosure() {
            (disclosure, Content::Element(value)) => {
                let value = self.value(value, depth)?;
                Ok(Element::Present(Claim::new(value, Some(disclosure))))
            }
            (disclosure, Content::Property { .. }) => Err(ParseError::MisplacedDisclosure {
                disclosure: disclosure.id(),
                placement: Placement::PropertyInArray,
            }),
        }
    }
}

fn reserved(fault: ReservedFault) -> ParseError {
    ParseError::ReservedClaimName(fault)
}

/// The digests of an `_sd` member, which holds an array of strings (Section 4.2.4.1).
fn digest_strings(value: Json) -> Result<Vec<Digest>, ParseError> {
    let Json::Array(items) = value else {
        return Err(reserved(ReservedFault::SdNotArray));
    };
    items
        .into_iter()
        .map(|item| match item {
            Json::String(digest) => Ok(Digest::listed(digest)),
            _ => Err(reserved(ReservedFault::SdDigest)),
        })
        .collect()
}

/// The digest of an array element `{"...": digest}`, whose only member is `...` (Section
/// 4.2.4.2).
fn array_digest(members: Vec<(String, Json)>) -> Result<Digest, ParseError> {
    let mut members = members.into_iter();
    match (members.next(), members.next()) {
        (Some((_, Json::String(digest))), None) => Ok(Digest::listed(digest)),
        (Some(_), None) => Err(reserved(ReservedFault::ElementDigest)),
        _ => Err(reserved(ReservedFault::ElementMembers)),
    }
}
