//! View §2-4 on each rendering: check_props.py's `check_outcome`.

use serde_json::{Value, json};
use siros_explain::{Key, Text};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::Amounts;
use siros_paso::Rendered;
use siros_paso::markdown::spans;
use siros_paso::outcome::Outcome;

use crate::common::{Screen, env};

use super::replay::{Array, Replay, shows_template};
use super::{Tally, at, concrete, given, kind_of, mandate_claims, select};

/// View §2-4 on one entry rendered for the card: `display_locale` and each display array's text
/// against View §4's step 1 replayed over the metadata and the payload (the credential excluded
/// when no tag of the list matches every array), label and value kinds, full-text rows,
/// coverage, the hint, the payment.
pub(super) fn outcome(
    kind: &str,
    entry: &Value,
    (types, given_text): (&Value, Option<&str>),
    rendered: &Result<Rendered, Outcome>,
    locales: &[&str],
    tally: &mut Tally,
) {
    let view = match rendered {
        Err(Outcome::Unsupported(_)) => return tally.add("unsupported"),
        Err(Outcome::NotCompatible(_)) => return tally.add("not compatible"),
        Err(Outcome::Excluded(_)) => None,
        Ok(rendered) => Some(&rendered.view),
    };
    let mandate = kind.contains(":mandate:");
    let meta = given(entry, types).expect("the metadata that rendered");
    let replay = Replay::of(mandate, &meta, &entry["payload"]);
    let Some(view) = view else {
        tally.add("excluded");
        assert_eq!(
            replay.select(locales, false),
            None,
            "P-locale excluded: {meta}"
        );
        return;
    };
    tally.add("rendered");
    let locale = view.locale.as_str();
    assert_eq!(
        replay.select(locales, true).as_deref(),
        Some(locale),
        "P-display_locale replayed: {meta}"
    );
    if locales.first() != Some(&locale) {
        tally.add("display_locale after the first tag");
    }
    if !locales.contains(&locale) || !["en", "de"].contains(&locale) {
        tally.add("display_locale a regional tag");
    }
    // The test app's screen: the converted module in the selected locale.
    let entry_type = entry["type"].as_str().expect("type");
    let screen = Screen::of(
        entry_type,
        given_text.expect("the metadata's text"),
        &env(locales, Amounts::Formatted),
        &LocaleTag::parse(locale).expect("a tag"),
    );
    // A label's text as written: a mini_markdown label's spans without their styles.
    let written = |label: &Value, text: &str, typed_by: &str| match label
        .get(typed_by)
        .and_then(Value::as_str)
    {
        Some("mini_markdown" | "template:mini_markdown") => {
            spans(text).into_iter().map(|span| span.text).collect()
        }
        _ => text.to_owned(),
    };
    let claim_count = meta["claims"].as_array().map_or(0, Vec::len);
    // The text the replayed entry gives: as written, or a template's text around its values.
    let matches = |shown: &str, want: &Value, text_at: &str, typed_by: &str| {
        let text = want[text_at].as_str().expect("a label's text");
        let template = want
            .get(typed_by)
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.starts_with("template:"));
        if template {
            let shows =
                shows_template(shown, text, claim_count, |run| written(want, run, typed_by));
            (shows, true)
        } else {
            (shown == written(want, text, typed_by), false)
        }
    };
    let payload = &entry["payload"];
    let spec = mandate_claims();
    let claims = if mandate {
        Vec::new()
    } else {
        meta["claims"].as_array().expect("claims").clone()
    };
    for row in &view.rows {
        let path = concrete(&row.path);
        let value_type = if mandate {
            let claim = spec
                .iter()
                .find(|claim| claim.displayed && json!(claim.path) == json!(path))
                .expect("a displayed Mandate claim");
            assert!(
                matches!(&row.row.label, Text::Query(query) if matches!(query.key(), Key::Message(_))),
                "P-label own {row:?}"
            );
            claim.value_type.clone()
        } else {
            let claim = &claims[row.claim.0];
            let want = replay
                .entry(Array::Claim(row.claim.0), locale)
                .expect("P-replay: the claim's array matches");
            let shown = screen.plain(&row.row.label);
            let (shows, template) = matches(&shown, want, "name", "display_type");
            assert!(shows, "P-replayed label {shown:?} against {want}");
            if template {
                tally.add("template labels replayed");
            }
            claim
                .get("value_type")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        match &row.row.value {
            Some(_) => assert_eq!(
                row.kind.map_or("<none>", |kind| kind.as_str()),
                kind_of(value_type.as_deref()),
                "P-kind {row:?}"
            ),
            None => {
                tally.add("full-text rows");
                assert!(
                    value_type.as_deref() == Some("label_only") || at(payload, &path).is_null(),
                    "P-full {row:?}"
                );
            }
        }
    }
    // View §2: the rows show every displayed claim instance the payload holds, each once.
    let mut want: Vec<Value> = if mandate {
        spec.iter()
            .filter(|claim| claim.displayed)
            .flat_map(|claim| {
                let pointer: Vec<Value> = claim.path.iter().map(|p| json!(p)).collect();
                select(payload, &pointer)
            })
            .map(|path| json!(path))
            .collect()
    } else {
        claims
            .iter()
            .enumerate()
            .filter(|(_, claim)| claim.get("display").is_some())
            .flat_map(|(k, claim)| {
                select(payload, claim["path"].as_array().expect("a path"))
                    .into_iter()
                    .map(move |path| json!([k, path]))
            })
            .collect()
    };
    let mut got: Vec<Value> = view
        .rows
        .iter()
        .map(|row| {
            if mandate {
                json!(concrete(&row.path))
            } else {
                json!([row.claim.0, concrete(&row.path)])
            }
        })
        .collect();
    want.sort_by_key(Value::to_string);
    got.sort_by_key(Value::to_string);
    assert_eq!(got, want, "P-coverage");
    let ui = meta.get("ui_labels");
    let ui_array = |key: &str| ui.and_then(|u| u.get(key)).and_then(Value::as_array);
    let shown = |text: &Text| screen.plain(text);
    let mut labels = vec![("security_hint", view.actions.hint.as_ref().map(shown))];
    if !mandate {
        labels.extend([
            ("transaction_title", Some(shown(&view.title))),
            (
                "affirmative_action_label",
                Some(shown(&view.actions.confirm)),
            ),
            ("denial_action_label", Some(shown(&view.actions.deny))),
        ]);
    }
    for (key, got) in labels {
        if ui_array(key).is_none() {
            continue;
        }
        let want = replay
            .entry(Array::Ui(key), locale)
            .expect("P-replay: the UI label's array matches");
        let shown = got.expect("P-a UI label the metadata gives shows");
        let (shows, template) = matches(&shown, want, "value", "value_type");
        assert!(shows, "P-replayed ui label {key}: {shown:?} against {want}");
        if template {
            tally.add("template labels replayed");
        }
    }
    assert_eq!(
        view.actions.hint.is_some(),
        ui_array("security_hint").is_some(),
        "P-hint"
    );
    if view.payment.is_some() {
        let (merchant, amount) = view.payment_texts().expect("a payment's texts");
        assert!(
            kind == "urn:paso:sca:global:payment:1"
                && !shown(merchant).trim().is_empty()
                && !shown(amount).trim().is_empty(),
            "P-payment {view:?}"
        );
    }
}
