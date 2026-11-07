//! What the formats whose Credential Queries use DCQL claims share: their request rules, the
//! Verifier's algorithms, matching a credential's values, its card from display metadata, its
//! claims as rows, and the elements an option discloses. A [`ClaimsPlugin`] becomes a format
//! plug-in through [`query`]: the kit answers the core, the format adds its own rules, the
//! identifiers its presentation can match, its carriage of response members and its
//! presentation.
//!
//! A credential's view is a JSON object: `{"type", "metadata": {"display", "claims"}, "values",
//! "issuer"?, "issuer_display"?, "byte_strings"?, ...}`, the metadata in the format's own display
//! shape, which [`merge_metadata`] writes at registration.

mod display;
mod merge;
mod plugin;
mod rules;

use siros_explain::{
    AllOf, Count, DefinedKey, DefinedModule, Explained, Keyed, Query as ExplainQuery, Text,
};

pub use display::format_entry;
use display::{
    Described, byte_strings, issuer_display, label_text, metadata, metadata_texts, value_rows,
};
pub use merge::{IssuedMetadata, IssuedShape, MergeError, merge_metadata};
pub use plugin::{ClaimsPlugin, additions, query};
#[cfg(feature = "resolve")]
pub use plugin::{ClaimsPresent, Presenting, Revalidating, answer};
pub use rules::{CardError, KitRule, NoAlgorithm, QueryRule, RefusedText, VpFormatsMember};

use super::{Claim, ClaimPath, Claims, ConcretePath, PathError};
use crate::consent::Card;
use crate::ids::{CredentialType, FormatName, LocaleTag, QueryId};
use crate::json::Node;
use crate::plugins::{Clause, Exclude, Fault, Member, OptionIndex, Shown};
use crate::refusal::{Refusal, ReprList};
use crate::request::{Item, Query};
use crate::rows::{Env, Row, WalletText};
use crate::text::TextError;
use crate::wallet::Credential;
use crate::{FAULT, detail};

/// What sets one claims format apart from another.
pub trait ClaimsFormat {
    /// The format identifier, as refusals name it.
    fn id(&self) -> FormatName;
    /// The claim display member holding the label.
    fn label_key(&self) -> &'static str;
    /// The clause of OpenID4VP's appendix of the format that rules its `vp_formats_supported`.
    fn vp_formats_clause(&self) -> Clause;
    /// Whether a JSON value is an algorithm identifier of the format's `vp_formats_supported`.
    fn is_algorithm(&self, value: &Node<'_>) -> bool;
    /// The logo URI of a display entry.
    fn logo<'n>(&self, entry: &'n Node<'n>) -> Option<&'n str>;
    /// The query's `meta` as the format accepts it, or the format's rule it breaks.
    ///
    /// # Errors
    ///
    /// The format's rule on `meta`.
    fn read_meta<'n, 'm>(
        &self,
        meta: Option<&'n Node<'m>>,
    ) -> Result<&'n Node<'m>, Box<dyn Explained>>;
    /// The credential's types its view states: its `type`, then those a format's view adds
    /// ([`crate::plugins::ViewAdditions`]).
    ///
    /// # Errors
    ///
    /// The view states them in a shape the format does not read, a fault of the wallet's data.
    fn types<'n>(&self, view: &'n Node<'n>) -> Result<Vec<CredentialType<'n>>, Fault>;
    /// Whether the credential's types match the query's `meta`.
    fn meta_matches(&self, meta: &Node<'_>, types: &[CredentialType<'_>]) -> bool;
    /// Whether the claim names a response member the bound transaction writes.
    fn written(&self, claim: &Claim<'_>, provided: &[Member]) -> bool;
    /// The format's rule a claims path pointer breaks: it cannot address the format's
    /// credentials. `None` when it can.
    fn pointer_refusal(&self, path: &ClaimPath<'_>) -> Option<Box<dyn Explained>>;
    /// Whether an array element of the view's `values` marks a position the credential holds no
    /// value for: pointers select nothing there and the rows leave it out. A format whose views
    /// hold no such position keeps this answer.
    fn withheld(&self, _element: &Node<'_>) -> bool {
        false
    }
    /// The defined module a credential's display metadata loaded as (section 4.14 of the design),
    /// which then gives the card's title and the claims' labels. `None` shows the metadata's texts
    /// as written.
    ///
    /// # Errors
    ///
    /// The view names a module in no form the format writes.
    fn display_module(&self, _view: &Node<'_>) -> Result<Option<DefinedModule>, Fault> {
        Ok(None)
    }
    /// The key of `item`'s message in the module [`Self::display_module`] names.
    fn display_key(&self, _item: DisplayItem) -> Option<DefinedKey> {
        None
    }
}

/// A text of a credential's display metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayItem {
    /// The display entry's name, the card's title.
    Name,
    /// The label of the entry at this position of the metadata's `claims`.
    Claim(usize),
}

/// What gives a card's texts: the wallet's locales, the defined module the metadata loaded as, and
/// the view's byte strings.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Display<'d> {
    pub(crate) locales: &'d [LocaleTag],
    pub(crate) module: Option<&'d DefinedModule>,
    pub(crate) byte_strings: &'d [Node<'d>],
}

impl Display<'_> {
    /// The text of `item`, whose metadata wrote `written`: its message in the defined module, else
    /// as written.
    pub(crate) fn text(self, format: &impl ClaimsFormat, item: DisplayItem, written: &str) -> Text {
        match (self.module, format.display_key(item)) {
            (Some(module), Some(key)) => Text::Query(ExplainQuery::defined(
                *module,
                key,
                Keyed::first_of(Vec::new()),
            )),
            _ => Text::Raw(written.to_owned()),
        }
    }

    /// The text of the label `item`, whose metadata wrote `written`, read through
    /// [`DisplayText`](crate::text::DisplayText); `None` for white space alone.
    pub(crate) fn label(
        self,
        format: &impl ClaimsFormat,
        item: DisplayItem,
        written: &str,
    ) -> Result<Option<Text>, TextError> {
        Ok(label_text(written)?.map(|_| self.text(format, item, written)))
    }
}

/// A query's refusals in rule order: the first, the `vp_formats_supported` one when it follows,
/// then the claims'.
fn in_order(
    first: Refusal,
    algorithms: Option<Refusal>,
    claims: Option<AllOf<Refusal>>,
) -> AllOf<Refusal> {
    let refused = AllOf::one(first);
    let refused = match algorithms {
        Some(rule) => refused.and(AllOf::one(rule)),
        None => refused,
    };
    match claims {
        Some(claims) => refused.and(claims),
        None => refused,
    }
}

/// One `vp_formats_supported` member constraining a presentation, with the identifiers the
/// presentation can match.
#[derive(Debug, Clone)]
pub struct Constraint<'n> {
    /// The member.
    pub member: VpFormatsMember,
    /// The identifiers, each a JSON value as `vp_formats_supported` writes it.
    pub matched: Vec<Node<'n>>,
}

/// A Credential Query of a claims format. Only [`ClaimsQuery::parse`] makes one.
#[derive(Debug, Clone)]
pub struct ClaimsQuery<'q> {
    id: QueryId<'q>,
    meta: Node<'q>,
    claims: Claims<'q>,
    supported: Option<Node<'q>>,
}

impl<'q> ClaimsQuery<'q> {
    /// The query's id.
    #[must_use]
    pub const fn id(&self) -> &QueryId<'q> {
        &self.id
    }

    /// The query's `meta`.
    #[must_use]
    pub const fn meta(&self) -> &Node<'q> {
        &self.meta
    }

    /// The query's claims and options.
    #[must_use]
    pub const fn claims(&self) -> &Claims<'q> {
        &self.claims
    }

    /// The Verifier's `vp_formats_supported` value for the format.
    #[must_use]
    pub const fn supported(&self) -> Option<&Node<'q>> {
        self.supported.as_ref()
    }

    /// Parses the query, or gives the rules it breaks: a `meta` the format accepts, a
    /// `vp_formats_supported` value of the format's algorithms, well-formed claims.
    pub fn parse(
        format: &impl ClaimsFormat,
        query: &Query<'q>,
        supported: Option<Node<'q>>,
    ) -> Result<Self, AllOf<Refusal>> {
        let refuse = |rule: KitRule| {
            Refusal::new(QueryRule {
                format: format.id(),
                query: query.id().clone().into_owned(),
                rule,
            })
        };
        let object =
            Node::from_raw(query.object()).map_err(|e| AllOf::one(refuse(KitRule::Json(e))))?;
        let meta = format
            .read_meta(object.get("meta"))
            .cloned()
            .map_err(|rule| refuse(KitRule::Meta(rule)));
        let algorithms = vp_formats_refusal(format, query.id(), supported.as_ref());
        let claims = Claims::parse(&object)
            .map_err(|why| AllOf::one(refuse(KitRule::Claims(why))))
            .and_then(|claims| {
                let pointers: Vec<Refusal> = claims
                    .claims()
                    .iter()
                    .enumerate()
                    .filter_map(|(claim, query)| {
                        format
                            .pointer_refusal(&query.path)
                            .map(|rule| refuse(KitRule::Pointer { claim, rule }))
                    })
                    .collect();
                AllOf::new(pointers).map_or(Ok(claims), Err)
            });
        match (meta, algorithms, claims) {
            (Ok(meta), None, Ok(claims)) => Ok(Self {
                id: query.id().clone(),
                meta,
                claims,
                supported,
            }),
            (Err(first), algorithms, claims) => Err(in_order(first, algorithms, claims.err())),
            (Ok(_), Some(first), claims) => Err(in_order(first, None, claims.err())),
            (Ok(_), None, Err(claims)) => Err(claims),
        }
    }

    /// Each member the Verifier states lists an identifier the presentation can match; a member
    /// it leaves out constrains nothing.
    pub fn admits(
        &self,
        format: &impl ClaimsFormat,
        constraints: &[Constraint<'_>],
    ) -> Result<(), Exclude> {
        let Some(supported) = &self.supported else {
            return Ok(());
        };
        for constraint in constraints {
            let Some(listed) = supported
                .get(constraint.member.as_str())
                .and_then(Node::as_array)
            else {
                continue;
            };
            if !constraint
                .matched
                .iter()
                .any(|id| listed.iter().any(|value| value == id))
            {
                return Err(Exclude::new(NoAlgorithm {
                    member: constraint.member,
                    listed: ReprList::json(listed),
                    matched: ReprList::names(&constraint.matched),
                    clause: format.vp_formats_clause(),
                }));
            }
        }
        Ok(())
    }

    /// The options the credential answers: when its types match `meta`, those whose every
    /// claim is found in its values or names a member the transaction writes.
    ///
    /// # Errors
    ///
    /// The format cannot read the view's types.
    pub fn answerable(
        &self,
        format: &impl ClaimsFormat,
        view: &Node<'_>,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        if !format.meta_matches(&self.meta, &format.types(view)?) {
            return Ok(Vec::new());
        }
        let values = view.get("values").unwrap_or(&NULL);
        let found: Vec<bool> = self
            .claims
            .claims()
            .iter()
            .map(|claim| {
                claim.found(values, |element| format.withheld(element))
                    || format.written(claim, provided)
            })
            .collect();
        Ok(self
            .claims
            .options()
            .indexed()
            .filter(|(_, option)| {
                option
                    .items()
                    .iter()
                    .all(|item| found.get(item.get()) == Some(&true))
            })
            .map(|(option, _)| option)
            .collect())
    }

    /// Reads what the End-User could be shown of a credential answering `options` through
    /// [`DisplayText`](crate::text::DisplayText): every metadata text, the `issuer`, and the
    /// labels of the options' rows, which a member name may stand in for.
    ///
    /// # Errors
    ///
    /// [`CardError`]: a text that breaks the rule of display text, or a pointer that selects
    /// nothing.
    pub fn displayable(
        &self,
        format: &impl ClaimsFormat,
        view: &Node<'_>,
        options: &[OptionIndex],
        env: &Env,
    ) -> Result<(), CardError> {
        view.get("metadata")
            .map_or(Ok(()), |metadata| metadata_texts(format, metadata))
            .map_err(CardError::Text)?;
        issuer_display(view)
            .iter()
            .try_for_each(|entry| metadata_texts(format, entry))
            .map_err(CardError::Text)?;
        drop(
            view.get("issuer")
                .and_then(Node::as_str)
                .map_or(Ok(None), label_text)
                .map_err(CardError::Text)?,
        );
        let display = Display {
            locales: env.priority(),
            module: None,
            byte_strings: byte_strings(view),
        };
        for option in options {
            let items = self
                .claims
                .options()
                .get(*option)
                .map_or(&[][..], |option| option.items());
            drop(self.claim_rows(format, items, view, display)?);
        }
        Ok(())
    }

    /// The credential's card: the display entry's name, else the crate module's
    /// `WalletText::Credential` message; as subtitle the name of the Credential Issuer's display
    /// entry, else the `issuer`, white space alone showing none;
    /// the logo resolved at issuance, else the wallet's default icon; the rows of the items shown.
    ///
    /// # Errors
    ///
    /// [`CardError`]: a pointer that selects nothing, or a text that breaks the rule of display
    /// text.
    pub fn card(
        &self,
        format: &impl ClaimsFormat,
        view: &Node<'_>,
        shown: Shown<'_>,
        env: &Env,
        module: Option<&DefinedModule>,
    ) -> Result<Card, CardError> {
        let locales = env.priority();
        let display = Display {
            locales,
            module,
            byte_strings: byte_strings(view),
        };
        let entry = format_entry(metadata(view, "display"), locales);
        let title = entry
            .and_then(|entry| entry.get("name"))
            .and_then(Node::as_str)
            .map_or(Ok(None), |name| {
                display.label(format, DisplayItem::Name, name)
            })
            .map_err(CardError::Text)?
            .unwrap_or_else(|| Text::of(&WalletText::Credential));
        let named = format_entry(issuer_display(view), locales)
            .and_then(|entry| entry.get("name"))
            .and_then(Node::as_str)
            .map_or(Ok(None), label_text)
            .map_err(CardError::Text)?;
        let subtitle = match named {
            Some(name) => Some(name),
            None => view
                .get("issuer")
                .and_then(Node::as_str)
                .map_or(Ok(None), label_text)
                .map_err(CardError::Text)?,
        };
        let icon = env.icon(entry.and_then(|entry| format.logo(entry))).clone();
        let mut rows = self.claim_rows(format, shown.everyone, view, display)?;
        rows.extend(self.claim_rows(format, shown.chosen, view, display)?);
        Ok(Card {
            icon,
            title,
            subtitle,
            rows,
        })
    }

    /// Rows for the requested claims: the metadata's `claims` order (OpenID4VCI B.2), then
    /// claims without metadata in request order.
    fn claim_rows(
        &self,
        format: &impl ClaimsFormat,
        items: &[Item],
        view: &Node<'_>,
        display: Display<'_>,
    ) -> Result<Vec<Row>, CardError> {
        let described: Vec<Described<'_, '_>> = metadata(view, "claims")
            .iter()
            .enumerate()
            .filter_map(|(position, claim)| {
                claim
                    .get("path")
                    .and_then(ClaimPath::parse)
                    .map(|path| Described {
                        path,
                        claim,
                        position,
                    })
            })
            .collect();
        let rank = |item: Item| {
            self.claims
                .claim(item)
                .and_then(|claim| described.iter().position(|known| known.path == claim.path))
                .unwrap_or(described.len())
        };
        let first = |item: Item| items.iter().position(|i| *i == item).unwrap_or(items.len());
        let mut ordered: Vec<Item> = items.to_vec();
        ordered.sort_by_key(|item| (rank(*item), first(*item)));
        let values = view.get("values").unwrap_or(&NULL);
        let mut rows = Vec::new();
        for claim in ordered.iter().filter_map(|item| self.claims.claim(*item)) {
            let selected = claim
                .path
                .select_held(values, |element| format.withheld(element))
                .map_err(CardError::Path)?;
            for (path, value) in selected {
                rows.extend(
                    value_rows(format, &path, value, &described, display, None)
                        .map_err(CardError::Text)?,
                );
            }
        }
        Ok(rows)
    }

    /// The elements the option discloses, each once, in claim order; a claim naming a member the
    /// transaction writes is answered by the proof instead.
    pub fn disclosed<'v>(
        &self,
        format: &impl ClaimsFormat,
        option: OptionIndex,
        view: &'v Node<'v>,
        provided: &[Member],
    ) -> Result<Vec<(ConcretePath<'v>, &'v Node<'v>)>, PathError> {
        let values = view.get("values").unwrap_or(&NULL);
        let items = self
            .claims
            .options()
            .get(option)
            .map_or(&[][..], |option| option.items());
        let mut out: Vec<(ConcretePath<'v>, &'v Node<'v>)> = Vec::new();
        for claim in items.iter().filter_map(|item| self.claims.claim(*item)) {
            if format.written(claim, provided) {
                continue;
            }
            let selected = claim
                .path
                .select_held(values, |element| format.withheld(element))?;
            for (path, value) in selected {
                if !out.iter().any(|(seen, _)| *seen == path) {
                    out.push((path, value));
                }
            }
        }
        Ok(out)
    }
}

static NULL: Node<'static> = Node::Null;

/// The format's rule on the Verifier's `vp_formats_supported` value: an object whose
/// `*_alg_values` members are non-empty arrays of the format's algorithm identifiers.
#[must_use]
pub fn vp_formats_refusal(
    format: &impl ClaimsFormat,
    query: &QueryId<'_>,
    supported: Option<&Node<'_>>,
) -> Option<Refusal> {
    let well_formed = |supported: &Node<'_>| {
        supported.as_object().is_some_and(|object| {
            object
                .members()
                .iter()
                .filter(|member| member.name.ends_with("_alg_values"))
                .all(|member| {
                    member.value.as_array().is_some_and(|values| {
                        !values.is_empty() && values.iter().all(|v| format.is_algorithm(v))
                    })
                })
        })
    };
    supported
        .filter(|supported| !well_formed(supported))
        .map(|_| {
            Refusal::new(QueryRule {
                format: format.id(),
                query: query.clone().into_owned(),
                rule: KitRule::VpFormats,
            })
        })
}

/// A credential with its view as a claims format reads it: a JSON object with a string `type`,
/// a `metadata` object whose `display` and `claims`, when present, are arrays, the credential's
/// `values`, an `issuer` that is absent, null or a string, an `issuer_display`, when present, an
/// array, and `byte_strings`, when present, an array of objects with a `path` array and a natural
/// number `length`.
#[derive(Debug, Clone)]
pub struct ClaimsView<'v> {
    credential: &'v Credential<'v>,
    json: Node<'v>,
}

impl<'v> ClaimsView<'v> {
    /// Reads the credential's view; a view of another shape is a fault of the wallet's data.
    pub fn read(credential: &'v Credential<'v>) -> Result<Self, Fault> {
        let what = || detail!("{id}: view", id = credential.id.to_string());
        let text =
            std::str::from_utf8(credential.view).map_err(|e| Fault::caused(FAULT, what(), e))?;
        let json = Node::parse(text).map_err(|e| Fault::caused(FAULT, what(), e))?;
        let metadata = json.get("metadata").and_then(Node::as_object);
        let listed = |name: &str| {
            metadata
                .and_then(|metadata| metadata.get(name))
                .is_none_or(|value| value.as_array().is_some())
        };
        let shaped = json.get("type").and_then(Node::as_str).is_some()
            && metadata.is_some()
            && listed("display")
            && listed("claims")
            && json.get("values").is_some()
            && json
                .get("issuer")
                .is_none_or(|issuer| matches!(issuer, Node::Null | Node::String(_)))
            && json
                .get(merge::ISSUER_DISPLAY)
                .is_none_or(|display| display.as_array().is_some())
            && json.get("byte_strings").is_none_or(|strings| {
                strings.as_array().is_some_and(|strings| {
                    strings.iter().all(|string| {
                        string.get("path").and_then(Node::as_array).is_some()
                            && matches!(
                                string.get("length"),
                                Some(Node::Number(length))
                                    if Count::parse(length.text()).is_some()
                            )
                    })
                })
            });
        if !shaped {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "{id}: a view without a string type, a metadata object or values",
                    id = credential.id.to_string()
                ),
            ));
        }
        Ok(Self { credential, json })
    }

    /// The credential.
    #[must_use]
    pub fn credential(&self) -> &'v Credential<'v> {
        self.credential
    }

    /// The view.
    #[must_use]
    pub fn json(&self) -> &Node<'v> {
        &self.json
    }
}
