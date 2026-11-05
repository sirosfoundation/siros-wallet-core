//! The specifications' rules the checks state, written here from the specifications: PaSO's
//! tables (the Mandate and Payment rulebooks' claims, the Default risk signal profile), View §4's
//! locale matching, View §3's value kinds, and OpenID4VP §7.1's claims path pointers.

use serde_json::{Value, json};

/// A section of a PaSO specification file, from its heading to the next heading.
fn section(file: &str, heading: &str) -> String {
    let path = format!(
        "{}/../siros-paso/tests/data/paso-d2/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).expect("the specification file");
    let start = text.find(&format!("{heading}\n")).expect("the heading");
    let rest = &text[start + heading.len() + 1..];
    let end = rest
        .match_indices('\n')
        .find(|(k, _)| rest[k + 1..].starts_with('#'))
        .map_or(rest.len(), |(k, _)| k);
    rest[..end].to_owned()
}

/// The first markdown table of a text as rows of cells, the header first, code ticks dropped.
fn table(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|cells| {
            !cells
                .iter()
                .all(|c| c.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
        })
        .collect()
}

/// A claim a rulebook's table states: its path, its value type (`None` for text), whether a
/// wallet displays it.
pub struct TableClaim {
    /// The path.
    pub path: Vec<String>,
    /// The value type.
    pub value_type: Option<String>,
    /// Whether a wallet displays it.
    pub displayed: bool,
}

fn claims_table(file: &str, heading: &str, prefix: &[&str]) -> Vec<TableClaim> {
    table(&section(file, heading))
        .iter()
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

/// The PaSO tables the checks read.
pub struct Spec {
    /// Mandate §2's claims, then the embedded payment's.
    pub mandate: Vec<TableClaim>,
    /// Default.md §2: each signal of the Default profile with its `max_age`.
    pub default: Vec<(String, u64)>,
}

impl Spec {
    /// The tables of the PaSO specification files.
    pub fn read() -> Self {
        Self {
            mandate: mandate_claims(),
            default: default_profile(),
        }
    }
}

/// Mandate §2's claims, then the embedded payment's (§2.2: the Payment rulebook's display
/// semantics, Payment §1).
fn mandate_claims() -> Vec<TableClaim> {
    let mut claims = claims_table("Mandate.md", "## 2 Transaction Data Claims", &[]);
    claims.retain(|claim| claim.path != ["payment_payload"]);
    claims.extend(claims_table(
        "Payment.md",
        "## 1 Transaction Data Claims",
        &["payment_payload"],
    ));
    claims
}

/// Default.md §2: each signal of the Default profile with its `max_age`; every one required.
fn default_profile() -> Vec<(String, u64)> {
    table(&section("Default.md", "## 2 Signals"))
        .iter()
        .skip(1)
        .map(|row| {
            assert_eq!(row[1], "true", "Default.md: every signal required");
            (row[0].clone(), row[2].parse().expect("a max_age"))
        })
        .collect()
}

/// The entry View §4 matches in an array for a locale: the first tagged entry RFC 4647 §3.4's
/// Lookup finds, compared case-insensitively, else the first entry without a locale.
fn matched<'a>(array: &'a [Value], locale: &str) -> Option<&'a Value> {
    siros_testkit::fixtures::lookup_ranges(locale)
        .iter()
        .find_map(|range| {
            array.iter().find(|e| {
                e.get("locale")
                    .and_then(Value::as_str)
                    .is_some_and(|tag| tag.eq_ignore_ascii_case(range))
            })
        })
        .or_else(|| array.iter().find(|e| e.get("locale").is_none()))
}

/// View §4 for one locale as a predicate: every array matches.
pub fn complete(locale: &str, arrays: &[Vec<Value>]) -> bool {
    arrays.iter().all(|array| matched(array, locale).is_some())
}

/// The entry View §4 matches in an array; `None` with a template entry, which a rendering may
/// discard.
pub fn preferred<'a>(array: &'a [Value], locale: &str, typed_by: &str) -> Option<&'a Value> {
    if array
        .iter()
        .any(|e| e.get(typed_by).and_then(Value::as_str) == Some("template:mini_markdown"))
    {
        return None;
    }
    matched(array, locale)
}

/// The value kind a value type shows (View §3), a template's being its inner type's.
pub fn kind_of(value_type: Option<&str>) -> &str {
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

/// OpenID4VP §7.1 over a payload: the concrete paths a claims path pointer selects. The cases
/// hold no pointer the payload refuses.
pub fn select(payload: &Value, pointer: &[Value]) -> Vec<Vec<Value>> {
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
                (Value::Null, Value::Array(items)) => next.extend(
                    items
                        .iter()
                        .enumerate()
                        .map(|(k, item)| (extended(json!(k)), item)),
                ),
                (step, node) => panic!("the pointer step {step} meets {node}"),
            }
        }
        current = next;
    }
    current.into_iter().map(|(at, _)| at).collect()
}

/// The payload element at a concrete path.
pub fn at<'v>(payload: &'v Value, path: &[Value]) -> &'v Value {
    path.iter().fold(payload, |node, part| match part {
        Value::String(key) => &node[key.as_str()],
        Value::Number(index) => {
            &node[usize::try_from(index.as_u64().expect("an index")).expect("an index")]
        }
        other => panic!("a concrete path holds {other}"),
    })
}
