//! View §2-4 on each rendering: check_props.py's `check_outcome`.

use serde_json::{Value, json};
use siros_openid4vp::rows::LabelKind;
use siros_paso::Rendered;
use siros_paso::outcome::Outcome;

use super::{
    Tally, arrays, at, complete, concrete, given, kind_of, mandate_claims, preferred, select,
};

/// View §2-4 on one entry rendered for the card: one locale completing every array, each label
/// the entry it matches, label and value kinds, full-text rows, coverage, the hint, the payment.
pub(super) fn outcome(
    kind: &str,
    entry: &Value,
    types: &Value,
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
    let locale = view.locale.tag.as_str();
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
            assert_eq!(row.row.label.kind, LabelKind::Text, "P-label kind");
            claim.value_type.clone()
        } else {
            let claim = &claims[row.claim.0];
            let display = claim["display"].as_array().expect("a displayed claim");
            if let Some(want) = preferred(display, locale, "display_type") {
                assert_eq!(
                    row.row.label.text,
                    want["name"].as_str().expect("name"),
                    "P-locale label"
                );
            }
            let mut kinds: Vec<Option<&str>> = display
                .iter()
                .map(|d| d.get("display_type").and_then(Value::as_str))
                .collect();
            kinds.sort_unstable();
            kinds.dedup();
            let expected = if kinds == [None] {
                LabelKind::Text
            } else {
                LabelKind::MiniMarkdown
            };
            assert!(
                row.row.label.kind == expected || kinds.len() > 1,
                "P-label kind {row:?}"
            );
            claim
                .get("value_type")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        match &row.row.value {
            Some(value) => assert_eq!(
                value.kind().as_str(),
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
    let mut labels = vec![("security_hint", view.actions.hint.as_deref())];
    if !mandate {
        labels.extend([
            ("transaction_title", Some(view.title.text.as_str())),
            (
                "affirmative_action_label",
                Some(view.actions.confirm.text.as_str()),
            ),
            ("denial_action_label", Some(view.actions.deny.text.as_str())),
        ]);
    }
    for (key, got) in labels {
        if let Some(want) = ui_array(key).and_then(|array| preferred(array, locale, "value_type")) {
            assert_eq!(got, want["value"].as_str(), "P-locale ui label {key}");
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
                && !merchant.trim().is_empty()
                && !amount.trim().is_empty(),
            "P-payment {view:?}"
        );
    }
}
