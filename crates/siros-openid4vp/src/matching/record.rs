//! The record a consent entry carries: what choosing it presents and what the response attests of
//! it. The platform returns it as the entry's id when the user picks the entry.

use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_i18n::Text;

use crate::consent::{Card, Header, Overlay};
use crate::ids::{CredentialId, QueryId};
use crate::json::{JsonError, Node, quote};
use crate::plugins::{Attested, OptionIndex};
use crate::request::{EntryIndex, RequestDigest};
use crate::rows::{Row, Value};

/// A record's id: the JSON array `[query, credential, option, entries, attested, request,
/// shown]`, `shown` the hexadecimal [`ShownDigest`] of the entry's texts.
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

/// The SHA-256 of the texts an entry shows, so a record commits to what the End-User read.
///
/// The hashed bytes encode, in this order, the card (its title, its subtitle, its rows), the
/// transaction's header when there is one (its title, its confirm and cancel actions) and the
/// transaction's overlay when there is one (its rows, its header when there is one, with its
/// counterparty, its amount and its rows, then its hint). Each part is written as follows; every
/// count and length is 8 bytes big-endian, so the encoding is injective:
/// - a part that may be absent: `0` when absent, else `1` and the part;
/// - a text: its span count, then per span its styles (bit 0 strong, bit 1 emphasis, bit 2
///   underline), its UTF-8 length and its UTF-8 bytes;
/// - rows: their count, then per row its label, its value (`0` for none, `1` for an image, `2`
///   and the text for a text) and its section as a part that may be absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShownDigest([u8; 32]);

impl ShownDigest {
    /// The digest of the texts of a card, its transaction's header and its overlay.
    #[must_use]
    pub fn of(card: &Card, header: Option<&Header>, overlay: Option<&Overlay>) -> Self {
        let mut shown = Shown(Sha256::new());
        shown.text(&card.title);
        shown.optional(card.subtitle.as_ref(), Shown::text);
        shown.rows(&card.rows);
        shown.optional(header, |shown, header| {
            shown.text(&header.title);
            shown.text(&header.confirm);
            shown.text(&header.cancel);
        });
        shown.optional(overlay, |shown, overlay| {
            shown.rows(&overlay.rows);
            shown.optional(overlay.header.as_ref(), |shown, header| {
                shown.text(&header.counterparty);
                shown.text(&header.amount);
                shown.rows(&header.rows);
            });
            shown.optional(overlay.hint.as_ref(), Shown::text);
        });
        Self(shown.0.finalize().into())
    }

    /// The digest in lowercase hexadecimal.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// The encoding [`ShownDigest`] hashes.
struct Shown(Sha256);

impl Shown {
    fn count(&mut self, count: usize) {
        self.0.update((count as u64).to_be_bytes());
    }

    fn optional<T>(&mut self, part: Option<T>, write: impl FnOnce(&mut Self, T)) {
        match part {
            None => self.0.update([0]),
            Some(part) => {
                self.0.update([1]);
                write(self, part);
            }
        }
    }

    fn text(&mut self, text: &Text) {
        self.count(text.spans().len());
        for span in text.spans() {
            let styles = [
                siros_i18n::Style::Strong,
                siros_i18n::Style::Emphasis,
                siros_i18n::Style::Underline,
            ]
            .iter()
            .enumerate()
            .filter(|(_, style)| span.styles.contains(**style))
            .fold(0u8, |bits, (bit, _)| bits | (1 << bit));
            self.0.update([styles]);
            self.count(span.text.len());
            self.0.update(span.text.as_bytes());
        }
    }

    fn rows(&mut self, rows: &[Row]) {
        self.count(rows.len());
        for row in rows {
            self.text(&row.label);
            match &row.value {
                None => self.0.update([0]),
                Some(Value::Image(_)) => self.0.update([1]),
                Some(Value::Text(text)) => {
                    self.0.update([2]);
                    self.text(text);
                }
            }
            self.optional(row.section.as_ref(), Shown::text);
        }
    }
}

/// What a consent entry presents (the query, the credential, the option), the entries it
/// authorizes, the (name, text) pairs its profile attests of their display, the digest of the
/// request with its Origin the matcher displayed, and the digest of the texts it shows. Phase 2
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
    shown: ShownDigest,
    /// The id's text before its `shown` member.
    head: String,
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
        shown: ShownDigest,
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
        let head = format!(
            "[{},{},{},[{}],{{{}}},{}",
            quote(query.as_str()),
            quote(credential.as_str()),
            option.position(),
            indexes.join(","),
            pairs.join(","),
            quote(request.as_str()),
        );
        let id = RecordId(format!("{head},{}]", quote(&shown.hex())));
        Self {
            query,
            credential,
            option,
            entries,
            attested,
            request,
            shown,
            head,
            id,
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

    /// The digest of the texts it shows.
    #[must_use]
    pub const fn shown(&self) -> ShownDigest {
        self.shown
    }

    /// Whether `returned` writes this record's every other member as this record's id does,
    /// and another `shown`: the End-User read other texts than this record's.
    #[must_use]
    pub fn shown_differs(&self, returned: &ReturnedRecord<'_>) -> bool {
        returned.as_str() != self.id.as_str()
            && returned
                .as_str()
                .strip_prefix(self.head.as_str())
                .is_some_and(|rest| rest.starts_with(','))
    }
}

/// An id the platform returned that is no record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum RecordError {
    /// No JSON with unique member names.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// JSON of another shape; the first 80 characters.
    #[error("not a record: {detail}")]
    #[explain(id = "record.shape")]
    Shape {
        /// What breaks the shape.
        detail: String,
    },
}

/// An id returned as a record: a JSON array of two strings, a non-negative integer, an array of
/// non-negative integers, an object of strings and two strings.
#[derive(Debug, Clone, Copy)]
pub struct ReturnedRecord<'t>(&'t str);

impl<'t> ReturnedRecord<'t> {
    /// Parses a returned id.
    pub fn parse(text: &'t str) -> Result<Self, RecordError> {
        let node = Node::parse(text)?;
        let natural = |node: &Node<'_>| matches!(node, Node::Number(n) if n.text().bytes().all(|b| b.is_ascii_digit()) || n.text() == "-0");
        let shaped = match node.as_array() {
            Some([query, credential, option, entries, attested, request, shown]) => {
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
                    && shown.as_str().is_some()
            }
            _ => false,
        };
        if shaped {
            Ok(Self(text))
        } else {
            Err(RecordError::Shape {
                detail: text.chars().take(80).collect(),
            })
        }
    }

    /// The id as returned.
    #[must_use]
    pub fn as_str(&self) -> &'t str {
        self.0
    }
}
