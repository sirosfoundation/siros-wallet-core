//! A transaction data profile that binds by first match over the types a credential supports,
//! or every such entry.
//!
//! A credential's `test` document: `{"supports": [types], "nonconforming": [entries], "stale"?:
//! [entries phase 2 finds no longer hold]}`.

use siros_explain::{RequestText, Text};
use siros_openid4vp::consent::{Header, Overlay, TransactionHeader};
use siros_openid4vp::detail;
use siros_openid4vp::hash;
use siros_openid4vp::host::{Authentication, AuthenticationNeed, ProfileHost};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Answered, Attested, Binding, Bound, BoundEntries, Carriage, Exclude, Fault, FetchedRecord,
    Member, MemberValue, Members, NoCandidate, Profile,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::rows::{Env, HttpsUrl, Image, ImageRef, Row, Value};
use siros_openid4vp::wallet::Credential;

use crate::FAULT;
use crate::rules::{EntryRule, Excluded};

/// Which compatible entries the profile binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binds {
    /// The first, answered with the entries the record attests (`binding`).
    First,
    /// Every one, answered with OpenID4VP B.3.3.1's hashes.
    Every,
}

/// The entries phase 2 found no longer hold: (credential id, entry) pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stale(pub Vec<(String, usize)>);

static BINDING: [Member; 1] = [Member::claim("binding")];

/// The test profile.
#[derive(Debug, Clone)]
pub struct TestProfile {
    binds: Binds,
    stale: Vec<(String, usize)>,
}

impl TestProfile {
    /// A profile that knows of no stale entry.
    #[must_use]
    pub const fn new(binds: Binds) -> Self {
        Self {
            binds,
            stale: Vec::new(),
        }
    }

    /// Which entries it binds.
    #[must_use]
    pub const fn binds(&self) -> Binds {
        self.binds
    }
}

/// The credential's `test` document.
fn document<'c>(credential: &'c Credential<'_>) -> Result<Node<'c>, Fault> {
    let bytes = credential.document("test").ok_or_else(|| {
        Fault::new(
            FAULT,
            detail!("{id}: no test document", id = credential.id.to_string()),
        )
    })?;
    let what = || detail!("{id}: test document", id = credential.id.to_string());
    let text = std::str::from_utf8(bytes).map_err(|e| Fault::caused(FAULT, what(), e))?;
    Node::parse(text).map_err(|e| Fault::caused(FAULT, what(), e))
}

/// The array member of the document, which a test document holds.
fn array<'d>(
    document: &'d Node<'d>,
    member: &str,
    credential: &Credential<'_>,
) -> Result<&'d [Node<'d>], Fault> {
    document
        .get(member)
        .and_then(Node::as_array)
        .ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!(
                    "{id}: test document without {member}",
                    id = credential.id.to_string(),
                    member = member.to_owned()
                ),
            )
        })
}

/// Whether an array lists the entry's index.
fn lists(items: &[Node<'_>], entry: EntryIndex) -> bool {
    items
        .iter()
        .any(|item| matches!(item, Node::Number(n) if n.as_u64() == Some(entry.get() as u64)))
}

impl Profile for TestProfile {
    type Finding = Stale;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        entries
            .iter()
            .filter_map(|index| request.entry(*index).map(|entry| (index, entry)))
            .flat_map(|(index, entry)| {
                hash::rule(entry, request.envelope().hashes()).map(|rule| {
                    Refusal::new(EntryRule {
                        entry: index.get(),
                        rule,
                    })
                })
            })
            .collect()
    }

    fn members(
        &self,
        _placement: siros_openid4vp::wallet_metadata::Placement,
    ) -> Option<&[Member]> {
        Some(match self.binds {
            Binds::Every => &hash::MEMBERS,
            Binds::First => &BINDING,
        })
    }

    fn bind(&self, binding: Binding<'_>, _env: &Env) -> Result<Bound, NoCandidate> {
        let document = document(binding.credential)?;
        let supported = array(&document, "supports", binding.credential)?;
        let nonconforming = array(&document, "nonconforming", binding.credential)?;
        let fit: Vec<EntryIndex> = binding
            .entries
            .iter()
            .copied()
            .filter(|index| {
                binding.request.entry(*index).is_some_and(|entry| {
                    supported
                        .iter()
                        .any(|kind| kind.as_str() == Some(entry.kind().as_str()))
                }) && !lists(nonconforming, *index)
                    && !self.stale.iter().any(|(credential, e)| {
                        *credential == binding.credential.id.as_str() && *e == index.get()
                    })
            })
            .collect();
        if binding.carriage == Carriage::Uncarried || fit.is_empty() {
            return Err(Exclude::new(Excluded::NoEntry).into());
        }
        let chosen = match self.binds {
            Binds::Every => fit,
            Binds::First => fit.into_iter().take(1).collect(),
        };
        if self.binds == Binds::Every {
            let entries: Vec<_> = chosen
                .iter()
                .filter_map(|index| binding.request.entry(*index))
                .collect();
            if hash::algorithm(&entries, binding.request.envelope().hashes()).is_none() {
                return Err(Exclude::new(Excluded::NoAlgorithm).into());
            }
        }
        let reference: Vec<String> = chosen.iter().map(|index| index.get().to_string()).collect();
        let reference = reference.join(",");
        let first = chosen
            .first()
            .and_then(|index| binding.request.entry(*index))
            .map(|entry| entry.kind().as_str() == "t2");
        let entries = BoundEntries::select(binding.entries, chosen)
            .map_err(|e| Fault::caused(FAULT, detail!("bound entries"), e))?;
        let rows = vec![
            Row::new(
                RequestText::raw("Reference".to_owned()),
                Value::Text(RequestText::raw(reference.clone())),
            )
            .in_section(RequestText::raw("Section".to_owned())),
            Row::new(
                RequestText::raw("Logo".to_owned()),
                Value::Image(Image::Embedded(ImageRef {
                    source: siros_openid4vp::rows::ImageSource::Data,
                    media: siros_openid4vp::rows::ImageMedia::PNG,
                    width: 1,
                    height: 1,
                })),
            )
            .in_section(RequestText::raw("Section".to_owned())),
        ];
        let transaction = (first == Some(true)).then(|| TransactionHeader {
            counterparty: RequestText::raw("Merchant".to_owned()),
            amount: RequestText::raw("1.00 EUR".to_owned()),
            rows: Vec::new(),
        });
        Ok(Bound {
            entries,
            header: Header {
                title: Text::Raw(format!("entries {reference}")),
                confirm: Text::Raw("Confirm".to_owned()),
                cancel: Text::Raw("Cancel".to_owned()),
            },
            attested: Attested::new(vec![("entries".to_owned(), reference.clone())])
                .map_err(|e| Fault::caused(FAULT, detail!("attested"), e))?,
            overlay: Overlay {
                rows,
                header: transaction,
                hint: Some(RequestText::raw(format!("hint {reference}"))),
            },
            selected: None,
        })
    }
}

/// Needs no module.
impl<H> ProfileHost<H> for TestProfile {
    /// No resource.
    fn wanted(&self, _record: Answered<'_>, _host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        Ok(Vec::new())
    }

    fn informed(&self, findings: &[&Stale]) -> Self {
        let mut stale = self.stale.clone();
        for Stale(pairs) in findings {
            for pair in pairs {
                if !stale.contains(pair) {
                    stale.push(pair.clone());
                }
            }
        }
        Self {
            binds: self.binds,
            stale,
        }
    }

    /// Presence.
    fn authentication(&self, _record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }

    fn revalidate(&self, record: FetchedRecord<'_>, _host: &H) -> Result<Option<Stale>, Fault> {
        let record = record.record();
        let document = document(record.credential())?;
        let listed = document
            .get("stale")
            .and_then(Node::as_array)
            .unwrap_or(&[]);
        let stale: Vec<(String, usize)> = record
            .entries()
            .entries()
            .iter()
            .filter(|index| lists(listed, **index))
            .map(|index| (record.credential().id.to_string(), index.get()))
            .collect();
        Ok((!stale.is_empty()).then_some(Stale(stale)))
    }

    fn respond(
        &self,
        record: Answered<'_>,
        _host: &H,
        _authentication: &Authentication,
    ) -> Result<Members, Fault> {
        match self.binds {
            Binds::Every => {
                let entries: Vec<_> = record
                    .entries()
                    .entries()
                    .iter()
                    .filter_map(|index| record.request().entry(*index))
                    .collect();
                hash::members(&entries, record.request().envelope().hashes())
                    .map_err(|e| Fault::caused(FAULT, detail!("B.3.3.1 hashes"), e))
            }
            Binds::First => {
                let entries = record
                    .attested()
                    .get("entries")
                    .ok_or_else(|| Fault::new(FAULT, detail!("the record attests no entries")))?;
                let [binding] = BINDING.clone();
                Members::new(vec![(binding, MemberValue::Text(entries.to_owned()))])
                    .map_err(|e| Fault::caused(FAULT, detail!("binding"), e))
            }
        }
    }
}
