//! The properties check_props.py states, each with its oracle computed here from the
//! specification's rule: View §2-4 on each rendering (`outcome`), Core §7.4.2's binding rule and
//! the box the overlay composes over a card (`case`), phase 2's findings and the fallback they
//! cause (`phase2`), Core §6.1 and Risk Signals §4-7 on the response members (`members`,
//! `signals`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_explain::RequestText;
use siros_openid4vp::claims::Concrete;
use siros_openid4vp::plugins::{
    AttestedName, AttestedText, Binding, Carriage, NoCandidate, Profile,
};
use siros_openid4vp::rows::{Amounts, Row};
use siros_paso::outcome::Outcome;
use siros_paso::{PasoProfile, Source};
use siros_testkit::verifier::ISSUER;

use crate::common::{Card, env, one_query, parameters, section, tables};
use crate::generate::Case;

mod members;
mod outcome;
mod phase2;
mod replay;

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

/// The metadata that renders an entry for the card, its members in the order its card or its
/// ad-hoc JWT writes them: the text the profile's converted module is named by.
fn given_text(entry: &Value, types: &str) -> Option<String> {
    use siros_openid4vp::json::Node;
    let (text, member) = match entry.get("metadata").and_then(Value::as_str) {
        Some(jwt) => {
            let payload = jwt.split('.').nth(1).expect("a JWS payload");
            let claims = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
            (
                String::from_utf8(claims).expect("utf-8"),
                "metadata".to_owned(),
            )
        }
        None => (
            types.to_owned(),
            entry["type"].as_str().expect("type").to_owned(),
        ),
    };
    let node = Node::parse(&text).expect("JSON");
    node.get(&member)
        .map(|given| given.python_compact().to_string())
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
            Concrete::Index(index) => json!(index.position()),
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

/// One case: each entry rendered for the card, the binding rule (Core §7.4.2: the first entry
/// that renders binds, a locale failure excludes, no entry excludes), the box the bound entry's
/// overlay composes, phase 2's findings, and the response members.
pub fn case(case: &Case, tally: &mut Tally) {
    let card = Card::new(case.format, &case.types, case.keys.as_deref(), ISSUER);
    let credential = card.credential();
    let amounts = if case.formatted {
        Amounts::Formatted
    } else {
        Amounts::Written
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
        let rendered = profile
            .render(
                entry,
                request.envelope().channel().kind(),
                &credential,
                crate::common::placement(&credential.format),
                &env,
            )
            .expect("no fault");
        let given = given_text(&json, &case.types);
        outcome(
            case.kind,
            &json,
            (&types, given.as_deref()),
            &rendered,
            &case.locales,
            tally,
        );
        if first.is_none() && matches!(rendered, Ok(_) | Err(Outcome::Excluded(_))) {
            first = Some((index, json, rendered));
        }
    }
    let offered: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let additions = crate::common::additions(&credential);
    let binding = Binding {
        request: &request,
        query: &request.queries()[0],
        credential: &credential,
        entries: &offered,
        placement: crate::common::placement(&credential.format),
        additions: &*additions,
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
    let rows: Vec<Row<RequestText>> = view.rows.iter().map(|row| row.row.clone()).collect();
    match &bound.overlay.header {
        Some(header) => {
            // Merchant and amount show once, in the transaction header; every other row stays
            // an overlay row.
            let heads = view.payment.expect("P-payment rows");
            let texts = view.payment_texts().expect("P-payment rows");
            let rest: Vec<Row<RequestText>> = rows
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != heads.merchant() && *k != heads.amount())
                .map(|(_, row)| row.clone())
                .collect();
            assert_eq!(rest.len() + 2, rows.len(), "P-proxy rows");
            assert_eq!(bound.overlay.rows, rest, "P-proxy rows");
            assert_eq!(
                (&header.counterparty, &header.amount),
                texts,
                "P-payment header"
            );
            assert_eq!(
                header.rows,
                [rows[heads.merchant()].clone(), rows[heads.amount()].clone()],
                "P-payment header rows"
            );
            tally.add("payment boxes");
        }
        None => {
            assert!(view.payment_texts().is_none(), "P-standard box");
            assert_eq!(bound.overlay.rows, rows, "P-proxy rows");
            tally.add("standard boxes");
        }
    }
    assert_eq!(bound.overlay.hint, view.actions.hint, "P-hint on the entry");
    // What the response attests: the locale shown (Core §7.2), the stored metadata's integrity.
    let mut attested = vec![(
        AttestedName::new("display_locale"),
        AttestedText::new(view.locale.to_string()),
    )];
    if let Source::Stored { integrity } = &rendered.source {
        attested.push((
            AttestedName::new("metadata_integrity"),
            AttestedText::new(integrity.clone()),
        ));
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
