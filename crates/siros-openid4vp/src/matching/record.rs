//! The record a consent entry carries: what choosing it presents and what the response attests of
//! it. The platform returns it as the entry's id when the user picks the entry.

use siros_explain::Explain;

use crate::ids::{CredentialId, QueryId};
use crate::json::{JsonError, Node, quote};
use crate::plugins::{Attested, OptionIndex};
use crate::request::{EntryIndex, RequestDigest};
use crate::rows::{Language, RenderingInputs};

/// A record's id: the JSON array `[query, credential, option, entries, attested, request,
/// rendering]`, `rendering` the object `{"language": tag, "fallback": bool}`.
/// As an array it differs from "none" and from every static box's id; its pick tells it from
/// every other entry of its slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordId(String);

impl RecordId {
    /// The id's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a consent entry presents (the query, the credential, the option), the entries it
/// authorizes, the (name, text) pairs its profile attests of their display, the digest of the
/// request with its Origin the matcher displayed, and what its texts rendered with. Phase 2
/// trusts the user's choice of a record alone: it derives every record itself and answers only a
/// record equal to one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'m> {
    /// The query.
    pub query: &'m QueryId<'m>,
    /// The credential.
    pub credential: &'m CredentialId<'m>,
    /// The option.
    pub option: OptionIndex,
    /// The entries it authorizes; empty without a transaction.
    pub entries: &'m [EntryIndex],
    /// What it attests.
    pub attested: Option<&'m Attested>,
    /// The digest of the request.
    pub request: &'m RequestDigest,
    /// What its texts rendered with.
    pub inputs: &'m RenderingInputs,
    id: RecordId,
}

impl<'m> Record<'m> {
    /// The record and its id.
    #[must_use]
    pub fn new(
        query: &'m QueryId<'m>,
        credential: &'m CredentialId<'m>,
        option: OptionIndex,
        entries: &'m [EntryIndex],
        attested: Option<&'m Attested>,
        request: &'m RequestDigest,
        inputs: &'m RenderingInputs,
    ) -> Self {
        let indexes: Vec<String> = entries
            .iter()
            .map(|entry| entry.get().to_string())
            .collect();
        let pairs: Vec<String> = attested
            .map(|attested| {
                attested
                    .pairs()
                    .iter()
                    .map(|(name, text)| format!("{}:{}", quote(name), quote(text)))
                    .collect()
            })
            .unwrap_or_default();
        let (language, fallback) = match inputs.language() {
            Language::Understood(tag) => (tag, false),
            Language::Fallback(tag) => (tag, true),
        };
        let id = format!(
            "[{},{},{},[{}],{{{}}},{},{{\"language\":{},\"fallback\":{fallback}}}]",
            quote(query.as_str()),
            quote(credential.as_str()),
            option.0,
            indexes.join(","),
            pairs.join(","),
            quote(request.as_str()),
            quote(language.as_str()),
        );
        Self {
            query,
            credential,
            option,
            entries,
            attested,
            request,
            inputs,
            id: RecordId(id),
        }
    }

    /// The record's id.
    #[must_use]
    pub fn id(&self) -> &RecordId {
        &self.id
    }
}

/// An id the platform returned that is no record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.record")]
pub enum RecordError {
    /// No JSON with unique member names.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// JSON of another shape; the first 80 characters.
    #[error("not a record: {0}")]
    Shape(#[explain(name = "detail")] String),
}

/// An id returned as a record: a JSON array of two strings, a non-negative integer, an array of
/// non-negative integers, an object of strings, a string and an object.
#[derive(Debug, Clone, Copy)]
pub struct ReturnedRecord<'t>(&'t str);

impl<'t> ReturnedRecord<'t> {
    /// Parses a returned id.
    pub fn parse(text: &'t str) -> Result<Self, RecordError> {
        let node = Node::parse(text)?;
        let natural = |node: &Node<'_>| matches!(node, Node::Number(n) if n.text().bytes().all(|b| b.is_ascii_digit()) || n.text() == "-0");
        let shaped = match node.as_array() {
            Some(
                [
                    query,
                    credential,
                    option,
                    entries,
                    attested,
                    request,
                    rendering,
                ],
            ) => {
                query.as_str().is_some()
                    && credential.as_str().is_some()
                    && natural(option)
                    && entries
                        .as_array()
                        .is_some_and(|entries| entries.iter().all(natural))
                    && attested.as_object().is_some_and(|attested| {
                        attested
                            .members()
                            .iter()
                            .all(|m| m.value.as_str().is_some())
                    })
                    && request.as_str().is_some()
                    && rendering.as_object().is_some()
            }
            _ => false,
        };
        if shaped {
            Ok(Self(text))
        } else {
            Err(RecordError::Shape(text.chars().take(80).collect()))
        }
    }

    /// The id as returned.
    #[must_use]
    pub fn as_str(&self) -> &'t str {
        self.0
    }
}
