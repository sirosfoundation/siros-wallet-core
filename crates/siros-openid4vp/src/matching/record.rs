//! The record a consent entry carries: what choosing it presents and what the response attests of
//! it. The platform returns it as the entry's id when the user picks the entry.

use siros_explain::Explain;

use crate::ids::{CredentialId, QueryId};
use crate::json::{JsonError, Node, quote};
use crate::plugins::{Attested, OptionIndex};
use crate::request::{EntryIndex, RequestDigest};
use crate::rows::{Amounts, Bidi, Language, ModuleName, RenderingInputs};

/// A record's id: the JSON array `[query, credential, option, entries, attested, request,
/// rendering]`, `rendering` the object of its rendering inputs, members in this order:
/// `selected` (`null`, or the array of the name of the module a profile selected a locale for
/// and that locale), `language` (the tag), `fallback` (whether the language fell back),
/// `modules` (each module's name and the hexadecimal SHA-256 of its sources), `amounts`
/// (`formatted` or `written`), `bidi` (`default` or `none`) and `renderer` (the renderer's
/// version).
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
    query: &'m QueryId<'m>,
    credential: &'m CredentialId<'m>,
    option: OptionIndex,
    entries: &'m [EntryIndex],
    attested: Option<&'m Attested>,
    request: &'m RequestDigest,
    inputs: &'m RenderingInputs,
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
                    .map(|(name, text)| {
                        format!("{}:{}", quote(name.as_str()), quote(text.as_str()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let id = format!(
            "[{},{},{},[{}],{{{}}},{},{}]",
            quote(query.as_str()),
            quote(credential.as_str()),
            option.position(),
            indexes.join(","),
            pairs.join(","),
            quote(request.as_str()),
            Written::of(inputs).json(),
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

    /// The query.
    #[must_use]
    pub const fn query(&self) -> &'m QueryId<'m> {
        self.query
    }

    /// The credential.
    #[must_use]
    pub const fn credential(&self) -> &'m CredentialId<'m> {
        self.credential
    }

    /// The option.
    #[must_use]
    pub const fn option(&self) -> OptionIndex {
        self.option
    }

    /// The entries it authorizes; empty without a transaction.
    #[must_use]
    pub const fn entries(&self) -> &'m [EntryIndex] {
        self.entries
    }

    /// What it attests.
    #[must_use]
    pub const fn attested(&self) -> Option<&'m Attested> {
        self.attested
    }

    /// The digest of the request.
    #[must_use]
    pub const fn request(&self) -> &'m RequestDigest {
        self.request
    }

    /// What its texts rendered with.
    #[must_use]
    pub const fn inputs(&self) -> &'m RenderingInputs {
        self.inputs
    }

    /// The rendering input `returned` names differently, when it names this record's other
    /// items as this record does: the selected module and its locale, the language, its
    /// fallback flag, a module's digest or its presence, the amounts, the bidi strategy, or the
    /// renderer's version, in that order.
    #[must_use]
    pub fn other_input(&self, returned: &ReturnedRecord<'_>) -> Option<RenderingInput> {
        let own = Node::parse(self.id.as_str()).ok()?;
        let theirs = Node::parse(returned.as_str()).ok()?;
        let (Some([own_items @ .., _]), Some([their_items @ .., rendering])) =
            (own.as_array(), theirs.as_array())
        else {
            return None;
        };
        if own_items != their_items {
            return None;
        }
        Written::of(self.inputs).first_other(rendering)
    }
}

/// A rendering input a returned record names differently from the record phase 2 derives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderingInput {
    /// The module a profile selected a locale for, or that locale.
    Selected,
    /// The language.
    Language,
    /// Whether the language fell back.
    Fallback,
    /// A module, by its name: its digest, or its presence among the modules.
    Module(String),
    /// How amounts show.
    Amounts,
    /// The bidi strategy.
    Bidi,
    /// The renderer's version.
    Renderer,
}

/// A record's rendering inputs as its id writes them.
struct Written<'i> {
    inputs: &'i RenderingInputs,
    selected: String,
    language: &'i str,
    fallback: bool,
    amounts: &'static str,
    bidi: &'static str,
}

impl<'i> Written<'i> {
    fn of(inputs: &'i RenderingInputs) -> Self {
        let (language, fallback) = match inputs.language() {
            Language::Understood(tag) => (tag.as_str(), false),
            Language::Fallback(tag) => (tag.as_str(), true),
        };
        let selected = inputs.selected().map_or_else(
            || "null".to_owned(),
            |selected| {
                format!(
                    "[{},{}]",
                    quote(&ModuleName::of(selected.module()).to_string()),
                    quote(selected.locale().as_str())
                )
            },
        );
        Self {
            inputs,
            selected,
            language,
            fallback,
            amounts: match inputs.amounts() {
                Amounts::Formatted => "formatted",
                Amounts::Written => "written",
            },
            bidi: match inputs.bidi() {
                Bidi::Default => "default",
                Bidi::None => "none",
            },
        }
    }

    /// Each module's name and its digest in hexadecimal, in the inputs' order.
    fn modules(&self) -> impl Iterator<Item = (String, String)> + '_ {
        self.inputs.modules().entries().iter().map(|entry| {
            let digest = entry
                .value()
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            (ModuleName::of(*entry.key()).to_string(), digest)
        })
    }

    fn json(&self) -> String {
        let modules: Vec<String> = self
            .modules()
            .map(|(name, digest)| format!("{}:{}", quote(&name), quote(&digest)))
            .collect();
        format!(
            "{{\"selected\":{},\"language\":{},\"fallback\":{},\"modules\":{{{}}},\"amounts\":{},\"bidi\":{},\"renderer\":{}}}",
            self.selected,
            quote(self.language),
            self.fallback,
            modules.join(","),
            quote(self.amounts),
            quote(self.bidi),
            self.inputs.renderer().number(),
        )
    }

    /// The first input `rendering` names otherwise than these, by its members of those names.
    fn first_other(&self, rendering: &Node<'_>) -> Option<RenderingInput> {
        let text = |name: &str| rendering.get(name).and_then(Node::as_str);
        let own = Node::parse(&self.selected).ok();
        if rendering.get("selected") != own.as_ref() {
            return Some(RenderingInput::Selected);
        }
        if text("language") != Some(self.language) {
            return Some(RenderingInput::Language);
        }
        if rendering.get("fallback") != Some(&Node::Bool(self.fallback)) {
            return Some(RenderingInput::Fallback);
        }
        let theirs = rendering.get("modules").and_then(Node::as_object);
        for (name, digest) in self.modules() {
            let named = theirs.and_then(|modules| modules.get(&name));
            if named.and_then(Node::as_str) != Some(digest.as_str()) {
                return Some(RenderingInput::Module(name));
            }
        }
        let own: Vec<String> = self.modules().map(|(name, _)| name).collect();
        if let Some(extra) = theirs.and_then(|modules| {
            modules
                .names()
                .find(|name| !own.iter().any(|known| known == name))
                .map(str::to_owned)
        }) {
            return Some(RenderingInput::Module(extra));
        }
        if text("amounts") != Some(self.amounts) {
            return Some(RenderingInput::Amounts);
        }
        if text("bidi") != Some(self.bidi) {
            return Some(RenderingInput::Bidi);
        }
        let renderer = rendering.get("renderer").and_then(|node| match node {
            Node::Number(number) => number.as_u64(),
            _ => None,
        });
        if renderer != Some(u64::from(self.inputs.renderer().number())) {
            return Some(RenderingInput::Renderer);
        }
        None
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
