//! View §4's step 1 replayed over a type's metadata and an entry's payload, as a verifier replays
//! `display_locale` (Core §6.1, §7.2): per display array, RFC 4647 §3.4's Lookup with the tag as
//! the range over the array's tagged entries, else its first entry without a locale; the entries
//! a template with an absent claim discards (View §3) take no part.

use serde_json::Value;

use super::{at, select};

/// What a display array labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Array {
    /// Claim n's `display`.
    Claim(usize),
    /// A UI label's entries.
    Ui(&'static str),
}

/// The UI labels, in View §2's order.
const UI: [&str; 4] = [
    "transaction_title",
    "affirmative_action_label",
    "denial_action_label",
    "security_hint",
];

/// A type's display arrays, each entry with whether an absent claim discards it.
pub(super) struct Replay {
    arrays: Vec<(Array, Vec<(Value, bool)>)>,
}

/// The claims a template's `{n}` placeholders name: those whose index is within the claims.
fn references(template: &str, claims: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after.as_bytes().get(digits) == Some(&b'}') {
            if let Some(n) = after[..digits].parse().ok().filter(|n| *n < claims) {
                out.push(n);
            }
            rest = &after[digits + 1..];
        } else {
            rest = after;
        }
    }
    out
}

/// Whether a claim's path resolves in the payload, each `null` of the path taking the next of
/// the referencing instance's indices.
fn present(payload: &Value, path: &[Value], indices: &[u64]) -> bool {
    let mut indices = indices.iter();
    let mut node = payload;
    for step in path {
        let next = match step {
            Value::String(key) => node.get(key.as_str()),
            Value::Null => indices
                .next()
                .and_then(|k| usize::try_from(*k).ok())
                .and_then(|k| node.get(k)),
            _ => None,
        };
        match next {
            Some(next) => node = next,
            None => return false,
        }
    }
    true
}

/// The indices an instance's concrete path takes at its pointer's `null` steps.
fn indices(pointer: &[Value], path: &[Value]) -> Vec<u64> {
    pointer
        .iter()
        .zip(path)
        .filter(|(step, _)| step.is_null())
        .filter_map(|(_, part)| part.as_u64())
        .collect()
}

/// The template's text when the entry is a template label: its `display_type`'s or
/// `value_type`'s `template:` prefix.
fn template<'e>(entry: &'e Value, typed_by: &str, text_at: &str) -> Option<&'e str> {
    entry
        .get(typed_by)
        .and_then(Value::as_str)
        .filter(|kind| kind.starts_with("template:"))
        .and_then(|_| entry.get(text_at).and_then(Value::as_str))
}

impl Replay {
    /// The display arrays of a type's metadata over a payload: every claim's `display` and the
    /// UI labels; the Mandate rulebook's own labels one entry without a locale, the wallet's.
    pub(super) fn of(mandate: bool, meta: &Value, payload: &Value) -> Self {
        let claims: Vec<Value> = if mandate {
            Vec::new()
        } else {
            meta["claims"].as_array().cloned().unwrap_or_default()
        };
        let mut arrays: Vec<(Array, Vec<(Value, bool)>)> = Vec::new();
        if mandate {
            arrays.push((Array::Ui("own"), vec![(serde_json::json!({}), false)]));
        }
        for (k, claim) in claims.iter().enumerate() {
            let Some(display) = claim.get("display").and_then(Value::as_array) else {
                continue;
            };
            let pointer = claim["path"].as_array().cloned().unwrap_or_default();
            let instances: Vec<Vec<u64>> = select(payload, &pointer)
                .iter()
                .map(|path| indices(&pointer, path))
                .collect();
            let incomplete = |text: &str, indices: &[u64]| {
                references(text, claims.len()).into_iter().any(|n| {
                    let path = claims[n]["path"].as_array().cloned().unwrap_or_default();
                    !present(payload, &path, indices)
                })
            };
            // A template value incomplete for an instance discards every entry of the claim.
            let value_template = claim
                .get("value_type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.starts_with("template:"));
            let value_incomplete = value_template
                && select(payload, &pointer).iter().any(|path| {
                    at(payload, path)
                        .as_str()
                        .is_some_and(|text| incomplete(text, &indices(&pointer, path)))
                });
            let entries = display
                .iter()
                .map(|entry| {
                    let label = template(entry, "display_type", "name").is_some_and(|text| {
                        instances.iter().any(|indices| incomplete(text, indices))
                    });
                    (entry.clone(), value_incomplete || label)
                })
                .collect();
            arrays.push((Array::Claim(k), entries));
        }
        let ui = meta.get("ui_labels");
        for key in UI {
            if mandate && key != "security_hint" {
                continue;
            }
            let Some(entries) = ui.and_then(|u| u.get(key)).and_then(Value::as_array) else {
                continue;
            };
            let entries = entries
                .iter()
                .map(|entry| {
                    let discarded = template(entry, "value_type", "value").is_some_and(|text| {
                        references(text, claims.len()).into_iter().any(|n| {
                            let path = claims[n]["path"].as_array().cloned().unwrap_or_default();
                            !present(payload, &path, &[])
                        })
                    });
                    (entry.clone(), discarded)
                })
                .collect();
            arrays.push((Array::Ui(key), entries));
        }
        Self { arrays }
    }

    /// The entry an array's entries match for `tag`, the discarded ones left out when
    /// `discards` holds: the first tagged entry Lookup finds, else the first entry without a
    /// locale.
    fn matched<'e>(entries: &'e [(Value, bool)], tag: &str, discards: bool) -> Option<&'e Value> {
        let live = || {
            entries
                .iter()
                .filter(move |(_, discarded)| !(discards && *discarded))
                .map(|(entry, _)| entry)
        };
        siros_testkit::fixtures::lookup_ranges(tag)
            .iter()
            .find_map(|range| {
                live().find(|entry| {
                    entry
                        .get("locale")
                        .and_then(Value::as_str)
                        .is_some_and(|written| written.eq_ignore_ascii_case(range))
                })
            })
            .or_else(|| live().find(|entry| entry.get("locale").is_none()))
    }

    /// View §4: the first tag of the priority list for which every array matches, the entries
    /// absent claims discard left out when `discards` holds.
    pub(super) fn select(&self, priority: &[&str], discards: bool) -> Option<String> {
        priority
            .iter()
            .find(|tag| {
                self.arrays
                    .iter()
                    .all(|(_, entries)| Self::matched(entries, tag, discards).is_some())
            })
            .map(|tag| (*tag).to_owned())
    }

    /// The entry an array matches for the selected tag, the discarded entries left out.
    pub(super) fn entry(&self, array: Array, tag: &str) -> Option<&Value> {
        self.arrays
            .iter()
            .find(|(known, _)| *known == array)
            .and_then(|(_, entries)| Self::matched(entries, tag, true))
    }
}

/// Whether a rendered template label shows the template's text around its claims' values: each
/// literal run between placeholders naming a claim, in order, its `mini_markdown` styles
/// dropped by `written`.
pub(super) fn shows_template(
    rendered: &str,
    template: &str,
    claims: usize,
    written: impl Fn(&str) -> String,
) -> bool {
    let mut runs: Vec<String> = Vec::new();
    let mut rest = template;
    for n in references(template, claims) {
        let marker = format!("{{{n}}}");
        let Some(at) = rest.find(&marker) else {
            return false;
        };
        runs.push(written(&rest[..at]));
        rest = &rest[at + marker.len()..];
    }
    runs.push(written(rest));
    let Some((first, others)) = runs.split_first() else {
        return false;
    };
    let Some(mut left) = rendered.strip_prefix(first.as_str()) else {
        return false;
    };
    let Some((last, middle)) = others.split_last() else {
        return left.is_empty();
    };
    for run in middle {
        match left.find(run.as_str()) {
            Some(at) => left = &left[at + run.len()..],
            None => return false,
        }
    }
    left.ends_with(last.as_str())
}
