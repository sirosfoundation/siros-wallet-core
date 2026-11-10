//! PaSO View §2-4 on each entry rendered for each credential (check_props.py `check_outcome`):
//! one display locale completing every array, each label the entry it matches, label and value
//! kinds, full-text rows, coverage, the hint, the payment.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_i18n::{Context, Text};
use siros_openid4vp::claims::Concrete;
use siros_openid4vp::rows::Env;
use siros_paso::Rendered;
use siros_paso::mandate::MandateLabel;
use siros_paso::markdown::spans;
use siros_paso::outcome::Outcome;

use crate::spec::{Spec, TableClaim, at, complete, kind_of, preferred, select};
use crate::tally::Tally;

/// The claims of an ad-hoc metadata JWT.
pub fn jwt_claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("a JWS payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
        .expect("the JWT's claims")
}

/// The metadata that renders an entry for a credential: the ad-hoc JWT's when the entry carries
/// one, else the credential's for the type (Proof Metadata §5.4; Core §7.4.2 step 2).
pub fn given(entry: &Value, document: &Value) -> Option<Value> {
    match entry.get("metadata").and_then(Value::as_str) {
        Some(jwt) => Some(jwt_claims(jwt)["metadata"].clone()),
        None => document["transaction_data_types"]
            .get(entry["type"].as_str().expect("type"))
            .cloned(),
    }
}

/// A label's text as written: a mini_markdown label's spans without their styles.
fn written(label: &Value, text: &str, typed_by: &str) -> String {
    match label.get(typed_by).and_then(Value::as_str) {
        Some("mini_markdown") => spans(text).into_iter().map(|span| span.text).collect(),
        _ => text.to_owned(),
    }
}

/// The display arrays of a type's metadata as View §4 reads them: its displayed claims' and its
/// UI labels'. The Mandate rulebook's own arrays each hold a default entry, as the wallet's
/// modules cover every language of the wallet; the credential's metadata gives its security_hint
/// alone.
fn arrays(mandate: bool, meta: &Value) -> Vec<Vec<Value>> {
    let ui_array = |key: &str| {
        meta.get("ui_labels")
            .and_then(|u| u.get(key))
            .and_then(Value::as_array)
            .cloned()
    };
    let mut out: Vec<Vec<Value>> = if mandate {
        vec![vec![json!({})]]
    } else {
        let mut out: Vec<Vec<Value>> = meta["claims"]
            .as_array()
            .expect("claims")
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

fn concrete(path: &[Concrete<'_>]) -> Vec<Value> {
    path.iter()
        .map(|part| match part {
            Concrete::Key(key) => json!(key),
            Concrete::Index(index) => json!(index.position()),
        })
        .collect()
}

fn tag(outcome: &Result<Rendered, Outcome>) -> String {
    match outcome {
        Ok(_) => "outcome TransactionView".to_owned(),
        Err(Outcome::Unsupported(rule)) => format!("outcome Unsupported [{}]", rule.clause()),
        Err(Outcome::NotCompatible(rule)) => format!("outcome NotCompatible [{}]", rule.clause()),
        Err(Outcome::Excluded(rule)) => format!("outcome Excluded [{}]", rule.clause()),
    }
}

/// View §2-4 on one entry rendered for a credential whose PaSO document is `document`, in the
/// wallet's configuration `env` and its context `context`.
pub fn check(
    entry: &Value,
    document: &Value,
    rendered: &Result<Rendered, Outcome>,
    env: &Env,
    context: &Context,
    spec: &Spec,
    tally: &mut Tally,
) {
    tally.add(tag(rendered));
    let view = match rendered {
        Err(Outcome::Unsupported(_) | Outcome::NotCompatible(_)) => return,
        Err(Outcome::Excluded(_)) => None,
        Ok(rendered) => Some(&rendered.view),
    };
    let kind = entry["type"].as_str().expect("type");
    let mandate = kind.contains(":mandate:");
    let meta = given(entry, document).expect("the metadata that rendered");
    let arrays = arrays(mandate, &meta);
    let locales: Vec<&str> = env.priority().iter().map(|tag| tag.as_str()).collect();
    let Some(view) = view else {
        // View §4: no tag of the list matches every array.
        assert!(
            !locales.iter().any(|locale| complete(locale, &arrays)),
            "P-locale excluded: {meta}"
        );
        return;
    };
    let shown = |text: &Text| text.to_string();
    // The wallet's own texts: the Mandate rulebook's labels.
    let mut own: Vec<String> = Vec::new();
    if mandate {
        tally.add("renderings by the Mandate rulebook");
        own = MandateLabel::ALL
            .iter()
            .map(|label| {
                context
                    .resolve(label)
                    .expect("the test app words the Mandate labels")
                    .to_string()
            })
            .collect();
    }
    // View §4: the display locale is a tag of the list that matches every array.
    let locale = view.locale.as_str();
    assert!(
        locales.contains(&locale) && complete(locale, &arrays),
        "P-locale {locale}: {meta}"
    );
    let payload = &entry["payload"];
    let spec = &spec.mandate;
    let claims = if mandate {
        Vec::new()
    } else {
        meta["claims"].as_array().expect("claims").clone()
    };
    for row in &view.rows {
        let path = concrete(&row.path);
        let value_type = if mandate {
            let claim: &TableClaim = spec
                .iter()
                .find(|claim| claim.displayed && json!(claim.path) == json!(path))
                .expect("a displayed Mandate claim");
            // The Mandate rulebook's labels are the wallet's own texts.
            assert!(own.contains(&shown(&row.row.label)), "P-label own {row:?}");
            claim.value_type.clone()
        } else {
            let claim = &claims[row.claim.get()];
            let display = claim["display"].as_array().expect("a displayed claim");
            // View §4: each label is the entry the display locale matches.
            // Proof Metadata §3.3: a mini_markdown label shows its text without its markers.
            if let Some(want) = preferred(display, locale, "display_type") {
                assert_eq!(
                    shown(&row.row.label),
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
            Some(_) => {
                // View §3: a value shows its value type's kind.
                assert_eq!(
                    row.kind.map_or("<none>", |kind| kind.as_str()),
                    kind_of(value_type.as_deref()),
                    "P-kind {row:?}"
                );
                tally.add("rows checked for kind");
            }
            None => {
                // View §2-3: a full-text row is a label_only claim or a null value.
                assert!(
                    value_type.as_deref() == Some("label_only") || at(payload, &path).is_null(),
                    "P-full {row:?}"
                );
                tally.add("full-text rows");
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
                json!([row.claim.get(), concrete(&row.path)])
            }
        })
        .collect();
    want.sort_by_key(Value::to_string);
    got.sort_by_key(Value::to_string);
    assert_eq!(got, want, "P-coverage");
    // View §4: each UI label is the entry the display locale matches; the Mandate rulebook's
    // title and actions are the wallet's own.
    let ui_array = |key: &str| {
        meta.get("ui_labels")
            .and_then(|u| u.get(key))
            .and_then(Value::as_array)
    };
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
            tally.add("ui labels checked for locale");
        }
    }
    // View §2: the security_hint shows exactly when the metadata populates it.
    assert_eq!(
        view.actions.hint.is_some(),
        ui_array("security_hint").is_some(),
        "P-hint"
    );
    // The Payment rulebook alone presents as a payment, its merchant and amount shown.
    if view.payment.is_some() {
        let (merchant, amount) = view
            .payment_texts()
            .expect("P-payment: the rows show texts");
        assert!(
            kind == "urn:paso:sca:global:payment:1"
                && !shown(merchant).trim().is_empty()
                && !shown(amount).trim().is_empty(),
            "P-payment {view:?}"
        );
    }
}
