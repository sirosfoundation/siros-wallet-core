//! The properties check_props.py states, each with its oracle computed here from the
//! specification's rule: View §2-4 on each rendering (`outcome`), Core §7.4.2's binding rule and
//! the box the overlay composes over a card (`case`), phase 2's findings and the fallback they
//! cause (`phase2`), Core §6.1 and Risk Signals §4-7 on the response members (`members`,
//! `signals`).

use std::borrow::Cow;
use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_openid4vp::boxes::{Card as CardBox, EntryBox};
use siros_openid4vp::claims::Concrete;
use siros_openid4vp::plugins::{Binding, Carriage, NoCandidate, Profile};
use siros_openid4vp::rows::{Amounts, Icon, IconMedia, Label, Row};
use siros_paso::outcome::Outcome;
use siros_paso::{PasoProfile, Source};
use siros_testkit::verifier::ISSUER;

use crate::common::{Card, env, one_query, parameters, section, tables};
use crate::generate::Case;

mod members;
mod outcome;
mod phase2;

use members::members;
use outcome::outcome;
use phase2::{Answer, phase2};

/// How often each outcome and each checked path was reached, by name in order of first reach.
#[derive(Default)]
pub struct Tally(pub Vec<(&'static str, usize)>);

impl Tally {
    fn add(&mut self, name: &'static str) {
        match self.0.iter_mut().find(|(known, _)| *known == name) {
            Some((_, count)) => *count += 1,
            None => self.0.push((name, 1)),
        }
    }

    /// How often a name was reached.
    pub fn count(&self, name: &str) -> usize {
        self.0
            .iter()
            .find(|(known, _)| *known == name)
            .map_or(0, |(_, count)| *count)
    }
}

/// The metadata that renders an entry for the card: the ad-hoc JWT's when the entry carries one,
/// else the card's for the type; `None` when the card lists no metadata for it.
fn given(entry: &Value, types: &Value) -> Option<Value> {
    match entry.get("metadata").and_then(Value::as_str) {
        Some(jwt) => {
            let payload = jwt.split('.').nth(1).expect("a JWS payload");
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
                    .expect("the JWT's claims");
            Some(claims["metadata"].clone())
        }
        None => types.get(entry["type"].as_str().expect("type")).cloned(),
    }
}

/// RFC 4647 §3.4's Lookup truncations of a tag without single-character subtags, lower-cased.
fn chain(tag: &str) -> Vec<String> {
    let subtags: Vec<&str> = tag.split('-').collect();
    (1..=subtags.len())
        .rev()
        .map(|kept| subtags[..kept].join("-").to_lowercase())
        .collect()
}

/// A claim a rulebook's table states: its path, its value type (`None` for text), whether a
/// wallet displays it.
struct TableClaim {
    path: Vec<String>,
    value_type: Option<String>,
    displayed: bool,
}

/// The claims table of a rulebook section, `prefix` prepended to each path.
fn table(file: &str, heading: &str, prefix: &[&str]) -> Vec<TableClaim> {
    let rows = tables(&section(file, heading))
        .into_iter()
        .next()
        .expect("the claims table");
    rows.iter()
        .skip(1)
        .map(|row| {
            let path: Vec<String> = serde_json::from_str(&row[0]).expect("a path");
            TableClaim {
                path: prefix.iter().map(|p| (*p).to_owned()).chain(path).collect(),
                value_type: (!row[2].starts_with('_')).then(|| row[2].clone()),
                displayed: row[3] == "yes",
            }
        })
        .collect()
}

/// Mandate §2's claims, then the embedded payment's (§2.2: the Payment rulebook's display
/// semantics, Payment §1).
fn mandate_claims() -> Vec<TableClaim> {
    let mut claims = table("Mandate.md", "## 2 Transaction Data Claims", &[]);
    claims.retain(|claim| claim.path != ["payment_payload"]);
    claims.extend(table(
        "Payment.md",
        "## 1 Transaction Data Claims",
        &["payment_payload"],
    ));
    claims
}

/// The display arrays of a type's metadata as View §4 reads them: its displayed claims' and its
/// UI labels'. The Mandate rulebook's own arrays each hold an English and a German entry.
fn arrays(mandate: bool, meta: &Value) -> Vec<Vec<Value>> {
    let ui = meta.get("ui_labels");
    let ui_array = |key: &str| {
        ui.and_then(|u| u.get(key))
            .and_then(Value::as_array)
            .cloned()
    };
    let mut out: Vec<Vec<Value>> = if mandate {
        vec![vec![json!({"locale": "en"}), json!({"locale": "de"})]]
    } else {
        let claims = meta["claims"].as_array().expect("claims");
        let mut out: Vec<Vec<Value>> = claims
            .iter()
            .filter_map(|claim| claim.get("display").and_then(Value::as_array).cloned())
            .collect();
        out.extend(
            [
                "transaction_title",
                "affirmative_action_label",
                "denial_action_label",
            ]
            .into_iter()
            .filter_map(ui_array),
        );
        out
    };
    out.extend(ui_array("security_hint"));
    out
}

/// View §4 for one locale as a predicate: every array has an entry whose tag is one of the
/// locale's truncations, or an entry without a locale.
fn complete(locale: &str, arrays: &[Vec<Value>]) -> bool {
    let chain = chain(locale);
    arrays.iter().all(|array| {
        array
            .iter()
            .any(|entry| match entry.get("locale").and_then(Value::as_str) {
                None => true,
                Some(tag) => chain.contains(&tag.to_lowercase()),
            })
    })
}

/// The entry View §4 matches in an array: the one tagged with the earliest truncation, else the
/// default; `None` with a template entry, which a rendering may discard.
fn preferred<'a>(array: &'a [Value], locale: &str, typed_by: &str) -> Option<&'a Value> {
    if array
        .iter()
        .any(|e| e.get(typed_by).and_then(Value::as_str) == Some("template:mini_markdown"))
    {
        return None;
    }
    chain(locale)
        .iter()
        .find_map(|truncation| {
            array.iter().find(|e| {
                e.get("locale")
                    .and_then(Value::as_str)
                    .is_some_and(|tag| tag.to_lowercase() == *truncation)
            })
        })
        .or_else(|| array.iter().find(|e| e.get("locale").is_none()))
}

/// The value kind a value type shows (View §3), a template's being its inner type's.
fn kind_of(value_type: Option<&str>) -> &str {
    match value_type.map(|vt| vt.strip_prefix("template:").unwrap_or(vt)) {
        None => "text",
        Some("iso_date") => "date",
        Some("iso_time") => "time",
        Some("iso_date_time") => "date_time",
        Some("iso_currency") => "currency",
        Some("iso_currency_amount") => "currency_amount",
        Some(other) => other,
    }
}

fn concrete(path: &[Concrete<'_>]) -> Vec<Value> {
    path.iter()
        .map(|part| match part {
            Concrete::Key(key) => json!(key),
            Concrete::Index(index) => json!(index),
        })
        .collect()
}

/// OpenID4VP §7.1 over the payload: the concrete paths a claims path pointer selects. The cases
/// hold no pointer the payload refuses.
fn select(payload: &Value, pointer: &[Value]) -> Vec<Vec<Value>> {
    let mut current: Vec<(Vec<Value>, &Value)> = vec![(Vec::new(), payload)];
    for step in pointer {
        let mut next = Vec::new();
        for (at, node) in current {
            let extended = |part: Value| {
                let mut path = at.clone();
                path.push(part);
                path
            };
            match (step, node) {
                (Value::String(key), Value::Object(members)) => {
                    if let Some(value) = members.get(key) {
                        next.push((extended(json!(key)), value));
                    }
                }
                (Value::Null, Value::Array(items)) => {
                    next.extend(
                        items
                            .iter()
                            .enumerate()
                            .map(|(k, item)| (extended(json!(k)), item)),
                    );
                }
                (step, node) => panic!("the pointer step {step} meets {node}"),
            }
        }
        current = next;
    }
    current.into_iter().map(|(at, _)| at).collect()
}

/// The payload element at a concrete path.
fn at<'v>(payload: &'v Value, path: &[Value]) -> &'v Value {
    path.iter().fold(payload, |node, part| match part {
        Value::String(key) => &node[key.as_str()],
        Value::Number(index) => {
            &node[usize::try_from(index.as_u64().expect("an index")).expect("an index")]
        }
        other => panic!("a concrete path holds {other}"),
    })
}

/// The card a format plug-in draws, which the overlay composes over.
fn drawn() -> CardBox {
    CardBox {
        icon: Icon {
            reference: Cow::Borrowed("asset:card"),
            media: IconMedia::Png,
            size: NonZeroU32::MIN,
        },
        title: "Card".to_owned(),
        subtitle: Some("Bank".to_owned()),
        rows: vec![Row {
            label: Label::text("Holder"),
            value: None,
            section: None,
        }],
    }
}

/// One case: each entry rendered for the card, the binding rule (Core §7.4.2: the first entry
/// that renders binds, a locale failure excludes, no entry excludes), the box the bound entry's
/// overlay composes, phase 2's findings, and the response members.
pub fn case(case: &Case, tally: &mut Tally) {
    let card = Card::new(case.format, &case.types, case.keys.as_deref(), ISSUER);
    let credential = card.credential();
    let amounts = if case.formatted {
        Amounts::Formatted
    } else {
        Amounts::Raw
    };
    let env = env(&case.locales, amounts);
    let profile = PasoProfile::default();
    let texts: Vec<&str> = case.entries.iter().map(String::as_str).collect();
    let parameters = parameters(&one_query(case.format), &texts, "");
    siros_testkit::signed_request!(let request = &parameters);
    let types: Value = serde_json::from_str(&case.types).expect("types");
    let mut first = None;
    for ((index, entry), text) in request.indexed_entries().zip(&case.entries) {
        let json: Value = serde_json::from_str(text).expect("entry");
        let rendered = profile.render(entry, &credential, &env).expect("no fault");
        outcome(case.kind, &json, &types, &rendered, &case.locales, tally);
        if first.is_none() && matches!(rendered, Ok(_) | Err(Outcome::Excluded(_))) {
            first = Some((index, json, rendered));
        }
    }
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let binding = Binding {
        request: &request,
        query: &request.queries()[0],
        credential: &credential,
        entries: &offered,
        carriage: Carriage::Carried,
    };
    let (bound, entry, rendered) = match (profile.bind(binding, &env), first) {
        (Ok(bound), Some((index, entry, Ok(rendered)))) => {
            assert_eq!(bound.entries.entries(), [index], "P-first match");
            (bound, entry, rendered)
        }
        (Err(NoCandidate::Excluded(exclude)), Some((_, _, Err(Outcome::Excluded(_))))) => {
            assert_eq!(exclude.clause(), "View §4", "P-excluded");
            return tally.add("excluded View §4");
        }
        (Err(NoCandidate::Excluded(exclude)), None) => {
            assert_eq!(exclude.clause(), "Core §7.4.2 step 2", "P-excluded");
            return tally.add("excluded no compatible entry");
        }
        (got, first) => panic!("P-first match: {got:?} against {first:?}"),
    };
    tally.add("bound");
    let view = &rendered.view;
    assert_eq!(
        (
            &bound.header.title,
            &bound.header.confirm,
            &bound.header.cancel
        ),
        (&view.title, &view.actions.confirm, &view.actions.deny),
        "P-header"
    );
    let card_box = drawn();
    let rows: Vec<Row> = view.rows.iter().map(|row| row.row.clone()).collect();
    match EntryBox::compose(card_box.clone(), Some(&bound.overlay)) {
        EntryBox::Payment(entry_box) => {
            // Merchant and amount show once, in the payment entry; every other row stays a row,
            // then the card's; the hint is the additional information.
            let heads = view.payment.expect("P-payment rows");
            let texts = view.payment_texts().expect("P-payment rows");
            let rest: Vec<Row> = rows
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != heads.merchant() && *k != heads.amount())
                .map(|(_, row)| row.clone())
                .collect();
            assert_eq!(rest.len() + 2, rows.len(), "P-proxy rows");
            let mut want = rest;
            want.extend(card_box.rows.iter().cloned());
            assert_eq!(entry_box.rows, want, "P-proxy rows");
            assert_eq!(
                (entry_box.merchant.as_str(), entry_box.amount.as_str()),
                texts,
                "P-payment box"
            );
            assert_eq!(
                (
                    &entry_box.method_name,
                    &entry_box.method_subtitle,
                    &entry_box.method_icon
                ),
                (&card_box.title, &card_box.subtitle, &card_box.icon),
                "P-payment method"
            );
            assert_eq!(
                entry_box.additional_info, view.actions.hint,
                "P-hint on the entry"
            );
            tally.add("payment boxes");
        }
        EntryBox::Standard(entry_box) => {
            assert!(view.payment_texts().is_none(), "P-standard box");
            let mut want = rows;
            want.extend(card_box.rows.iter().cloned());
            assert_eq!(entry_box.rows, want, "P-proxy rows");
            assert_eq!(
                (&entry_box.icon, &entry_box.title, &entry_box.subtitle),
                (&card_box.icon, &card_box.title, &card_box.subtitle),
                "P-card is the identity"
            );
            assert_eq!(entry_box.warning, view.actions.hint, "P-hint on the entry");
            tally.add("standard boxes");
        }
    }
    // What the response attests: the locale shown (Core §7.2), the stored metadata's integrity.
    let mut attested = vec![("display_locale".to_owned(), view.locale.tag.to_string())];
    if let Source::Stored { integrity } = &rendered.source {
        attested.push(("metadata_integrity".to_owned(), integrity.clone()));
    }
    assert_eq!(bound.attested.pairs(), attested.as_slice(), "P-attested");
    let meta = given(&entry, &types).expect("the metadata that rendered");
    let answered = Answer {
        request: &request,
        request_object: request.request_object().expect("signed"),
        card: &card,
        bound: &bound,
        entry: &entry,
    };
    phase2(case, &answered, &meta, &env, tally);
    members(case, &answered, &meta, tally);
}
