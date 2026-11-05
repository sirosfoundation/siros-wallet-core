//! View §2-4 on each rendering: check_props.py's `check_outcome`.

use serde_json::{Value, json};
use siros_explain::{Key, Text};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::Amounts;
use siros_openid4vp::text::spans;
use siros_paso::Rendered;
use siros_paso::outcome::Outcome;
use siros_testkit::fixtures::with_generic_forms;

use crate::common::{Screen, env};

use super::{
    Tally, arrays, at, complete, concrete, given, kind_of, mandate_claims, preferred, select,
};

/// View §2-4 on one entry rendered for the card: one locale completing every array, each label
/// the entry it matches, label and value kinds, full-text rows, coverage, the hint, the payment.
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
    let arrays = arrays(mandate, &meta);
    let Some(view) = view else {
        tally.add("excluded");
        assert!(
            !locales.iter().any(|locale| complete(locale, &arrays)),
            "P-locale excluded: {meta}"
        );
        return;
    };
    tally.add("rendered");
    // The test app renders in the language the documented practice's list gives every module.
    let tags: Vec<LocaleTag> = locales
        .iter()
        .map(|tag| LocaleTag::parse(tag).expect("a tag"))
        .collect();
    let practice: Vec<String> = with_generic_forms(&tags)
        .iter()
        .map(ToString::to_string)
        .collect();
    let practice: Vec<&str> = practice.iter().map(String::as_str).collect();
    let entry_type = entry["type"].as_str().expect("type");
    let screen = Screen::of(
        entry_type,
        given_text.expect("the metadata's text"),
        &env(&practice, Amounts::Formatted),
    );
    // A label's text as written: a mini_markdown label's spans without their styles.
    let written = |label: &Value, text: &str, typed_by: &str| match label
        .get(typed_by)
        .and_then(Value::as_str)
    {
        Some("mini_markdown") => spans(text).into_iter().map(|span| span.text).collect(),
        _ => text.to_owned(),
    };
    let locale = view.locale.as_str();
    assert!(
        locales.contains(&locale) && complete(locale, &arrays),
        "P-locale {locale}: {meta}"
    );
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
            let display = claim["display"].as_array().expect("a displayed claim");
            if let Some(want) = preferred(display, locale, "display_type") {
                assert_eq!(
                    screen.plain(&row.row.label),
                    written(want, want["name"].as_str().expect("name"), "display_type"),
                    "P-locale label"
                );
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
        if let Some(want) = ui_array(key).and_then(|array| preferred(array, locale, "value_type")) {
            let text = want["value"].as_str().expect("value");
            assert_eq!(
                got,
                Some(written(want, text, "value_type")),
                "P-locale ui label {key}"
            );
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
