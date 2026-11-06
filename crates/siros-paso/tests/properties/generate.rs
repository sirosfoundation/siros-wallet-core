//! Random cases shaped as check_props.py dresses the PaSO types: a type's metadata with
//! occasional defects, its payload, ad-hoc metadata JWTs, the wallet's locales and amounts, the
//! card's format and risk signal keys.

use rand::Rng;
use rand::seq::{IndexedRandom, SliceRandom};
use rand_chacha::ChaCha8Rng;
use serde_json::{Value, json};
use siros_testkit::verifier;

use crate::common::{data_png, png, sri};

/// The types the dressing draws from (check_props.py TYPE_POOL, QES left out).
pub const TYPES: [&str; 4] = [
    "urn:paso:sca:global:payment:1",
    "urn:paso:sca:com.example:custom:1",
    "urn:paso:sca:global:generic:x:1",
    "urn:paso:sca:global:mandate:agentic:1",
];
/// The default risk signal profile.
pub const DEFAULT: &str = "urn:paso:risk-profile:global:default:1";
/// The instant phase 2 answers at.
pub const NOW: u64 = 1_785_000_000;
/// The remote logos, the first of which is published as it is.
pub const REMOTE: [&str; 3] = [
    "https://cdn.example/logo0.png",
    "https://cdn.example/logo1.png",
    "https://cdn.example/logo2.png",
];
/// Risk Signals A.6's issuer key.
pub const ENC_KEY: &str = r#"{"kty": "EC", "crv": "P-256", "kid": "issuer-enc-1", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "use": "enc", "alg": "ECDH-ES"}"#;

/// One case: an entry's type, payload and metadata (stored or ad hoc), the card, the wallet.
#[derive(Debug, Clone)]
pub struct Case {
    /// The type.
    pub kind: &'static str,
    /// The entries' JSON texts, in array order; all name the query `q`.
    pub entries: Vec<String>,
    /// The card's `transaction_data_types` JSON text.
    pub types: String,
    /// The card's risk signal keys JSON text.
    pub keys: Option<String>,
    /// The card's format.
    pub format: &'static str,
    /// The wallet's locales.
    pub locales: Vec<&'static str>,
    /// Whether amounts are formatted.
    pub formatted: bool,
}

fn entries_for(rng: &mut ChaCha8Rng, locs: &[&str], make: impl Fn(Option<&str>) -> Value) -> Value {
    let mut out: Vec<Value> = locs
        .iter()
        .map(|loc| {
            let mut entry = make(Some(loc));
            entry["locale"] = json!(loc);
            entry
        })
        .collect();
    if out.is_empty() || rng.random_bool(0.25) {
        out.push(make(None));
    }
    json!(out)
}

fn ui(rng: &mut ChaCha8Rng, locs: &[&str], title: &str, confirm: &str) -> Value {
    let mut out = serde_json::Map::new();
    let named = |prefix: &str, l: Option<&str>| json!({"value": format!("{prefix} {}", l.unwrap_or("None"))});
    if rng.random_bool(0.7) {
        out.extend([(
            "transaction_title".to_owned(),
            entries_for(rng, locs, |l| named(title, l)),
        )]);
    }
    if rng.random_bool(0.7) {
        out.extend([(
            "affirmative_action_label".to_owned(),
            entries_for(rng, locs, |l| named(confirm, l)),
        )]);
    }
    if rng.random_bool(0.3) {
        out.extend([(
            "denial_action_label".to_owned(),
            entries_for(rng, locs, |l| named("No", l)),
        )]);
    }
    if rng.random_bool(0.4) {
        out.extend([(
            "security_hint".to_owned(),
            entries_for(rng, locs, |l| named("Check the payee", l)),
        )]);
    }
    Value::Object(out)
}

/// A type's metadata with occasional defects, as check_props.py's `tx_metadata`.
pub fn metadata(rng: &mut ChaCha8Rng, kind: &str) -> Option<Value> {
    let mut locs = vec!["en", "de"];
    locs.shuffle(rng);
    locs.truncate(rng.random_range(1..=2));
    let disp = |rng: &mut ChaCha8Rng, name: &str| {
        entries_for(
            rng,
            &locs,
            |l| json!({"name": format!("{name} {}", l.unwrap_or("None"))}),
        )
    };
    let mut meta = if kind.ends_with("payment:1") {
        json!({"claims": [
            {"path": ["transaction_id"]},
            {"path": ["amount"], "mandatory": true, "value_type": "iso_currency_amount", "display": disp(rng, "Amount")},
            {"path": ["payee", "name"], "mandatory": true, "display": disp(rng, "Payee")},
            {"path": ["payee", "id"], "mandatory": true},
            {"path": ["payee", "logo"], "value_type": "image", "display": disp(rng, "Logo")},
            {"path": ["payee", "logo#integrity"]}
        ], "ui_labels": ui(rng, &locs, "Pay", "Pay")})
    } else if kind.ends_with("custom:1") {
        let mut claims = vec![json!({"path": ["transaction_id"]})];
        for (k, vt) in [
            ("amount", "iso_currency_amount"),
            ("when", "iso_date"),
            ("at", "iso_time"),
            ("stamp", "iso_date_time"),
            ("every", "frequency"),
            ("flag", "boolean"),
            ("cur", "iso_currency"),
            ("note", "mini_markdown"),
            ("link", "url"),
        ] {
            claims.push(json!({"path": [k], "value_type": vt, "display": disp(rng, k)}));
        }
        claims.push(json!({"path": ["items", null, "name"], "display": disp(rng, "Item")}));
        claims.push(json!({"path": ["items", null, "qty"], "display": locs.iter().map(|l| json!({"locale": l, "name": "Quantity of {10}", "display_type": "template:mini_markdown"})).collect::<Vec<_>>()}));
        claims.push(json!({"path": ["info"], "value_type": "label_only", "display": disp(rng, "This is recurring")}));
        claims.push(json!({"path": ["summary"], "value_type": "template:mini_markdown", "display": disp(rng, "Summary")}));
        claims.push(json!({"path": ["logo"], "value_type": "image", "display": disp(rng, "Logo")}));
        claims.push(json!({"path": ["maybe"], "display": disp(rng, "Maybe")}));
        let mut u = ui(rng, &locs, "Confirm", "OK");
        if rng.random_bool(0.3) {
            let mut titles: Vec<Value> = locs.iter().map(|l| json!({"locale": l, "value": "Pay {1} ({15})", "value_type": "template:mini_markdown"})).collect();
            titles.push(json!({"value": "Pay"}));
            u["transaction_title"] = json!(titles);
        }
        json!({"claims": claims, "ui_labels": u})
    } else if kind.contains(":generic:") {
        let mut claims = vec![json!({"path": ["transaction_id"], "mandatory": true})];
        for k in 0..3 {
            claims.push(json!({"path": [format!("g{k}")], "display": disp(rng, &format!("G{k}"))}));
        }
        claims
            .push(json!({"path": ["g3"], "value_type": "iso_date", "display": disp(rng, "Date")}));
        claims.push(json!({"path": ["payment_payload", "transaction_id"]}));
        claims.push(json!({"path": ["payment_payload", "amount"], "value_type": "iso_currency_amount", "display": disp(rng, "Amount")}));
        claims.push(
            json!({"path": ["payment_payload", "payee", "name"], "display": disp(rng, "Payee")}),
        );
        claims.push(json!({"path": ["payment_payload", "payee", "id"]}));
        json!({"claims": claims, "ui_labels": ui(rng, &locs, "Authorize", "Allow")})
    } else if rng.random_bool(0.5) {
        json!({"claims": [], "ui_labels": ui(rng, &locs, "x", "x")})
    } else {
        return None;
    };
    let r: f64 = rng.random();
    if r < 0.25 {
        meta["risk_signal_profiles"] = json!([DEFAULT]);
    } else if r < 0.3 {
        meta["risk_signal_profiles"] = json!(["urn:paso:risk-profile:com.example:unknown:1"]);
    }
    if rng.random_bool(0.3) {
        meta["risk_signals"] = json!([
            {"type": "urn:paso:risk:global:amr:1", "required": rng.random_bool(0.7)},
            {"type": "urn:paso:risk:global:geolocation:1", "max_age": 60},
            {"type": "urn:paso:risk:global:screen_capture:1", "required": false},
            {"type": "urn:paso:risk:global:device_motion:1", "max_age": 900}
        ]);
    }
    if rng.random_bool(0.15) {
        meta["encrypted"] = json!(true);
    }
    let defect: f64 = rng.random();
    let claims_len = meta["claims"].as_array().map_or(0, Vec::len);
    if defect < 0.05 && claims_len > 0 {
        let k = rng.random_range(0..claims_len);
        let claim = &mut meta["claims"][k];
        if claim.get("display").is_none() {
            claim["display"] = disp(rng, "x");
        }
        claim["display"][0]["name"] = json!("L".repeat(61));
    } else if defect < 0.10 && claims_len > 0 {
        let k = rng.random_range(0..claims_len);
        if let Some(claims) = meta["claims"].as_array_mut() {
            drop(claims.remove(k));
        }
    } else if defect < 0.15 {
        meta["ui_labels"]["security_hint"] =
            json!([{"locale": locs[0], "value": "Typed", "value_type": "mini_markdown"}]);
    }
    Some(meta)
}

/// A type's payload, as check_props.py's `payload`. Object members keep the order written.
pub fn payload(rng: &mut ChaCha8Rng, kind: &str) -> String {
    let member = |name: &str, value: &str| format!("\"{name}\": {value}");
    if kind.ends_with("payment:1") {
        let amount = [
            "\"49.99 EUR\"",
            "\"1000.00 EUR\"",
            "\"5 JPY\"",
            "\"12.50 USD\"",
        ]
        .choose(rng)
        .copied()
        .unwrap_or_default();
        let name = ["\"Acme\"", "\"Shop Inc.\""]
            .choose(rng)
            .copied()
            .unwrap_or_default();
        let r: f64 = rng.random();
        let logo = if r < 0.3 {
            format!(", \"logo\": \"{}\"", data_png(12, 12))
        } else if r < 0.6 {
            format!(
                ", \"logo\": \"{}\", \"logo#integrity\": \"{}\"",
                REMOTE.choose(rng).copied().unwrap_or_default(),
                sri(&png(16, 16))
            )
        } else {
            String::new()
        };
        return format!(
            r#"{{"transaction_id": "t", "amount": {amount}, "payee": {{"name": {name}, "id": "DE1"{logo}}}}}"#
        );
    }
    if kind.ends_with("custom:1") {
        let mut members = vec![member("transaction_id", "\"t\"")];
        let pool = [
            ("amount", "\"2500.00 EUR\""),
            ("when", "\"2026-09-02\""),
            ("at", "\"10:15:30Z\""),
            ("stamp", "\"2026-06-02T10:15:30+02:00\""),
            ("every", "\"MNTH\""),
            ("flag", "false"),
            ("cur", "\"EUR\""),
            ("note", "\"- a **b**\\n- c\""),
            ("link", "\"https://bücher.example/x\""),
        ];
        let mut present = Vec::new();
        for (name, value) in pool {
            if rng.random_bool(0.5) {
                present.push(name);
                members.push(member(name, value));
            }
        }
        let n = rng.random_range(0..=3);
        let items: Vec<String> = (0..n)
            .map(|k| format!(r#"{{"name": "n{k}", "qty": "{k}"}}"#))
            .collect();
        members.push(member("items", &format!("[{}]", items.join(", "))));
        if rng.random_bool(0.4) {
            members.push(member("info", "null"));
        }
        let summary = if present.contains(&"amount") && present.contains(&"when") {
            "\"Total {1} on {2}\""
        } else {
            "\"Total\""
        };
        members.push(member("summary", summary));
        if rng.random_bool(0.3) {
            members.push(member("logo", &format!("\"{}\"", data_png(12, 12))));
        }
        if rng.random_bool(0.5) {
            members.push(member("maybe", "\"here\""));
        }
        if rng.random_bool(0.03) {
            let at = members.iter().position(|m| m.starts_with("\"note\""));
            match at {
                Some(at) => members[at] = member("note", "\"x\\u202ey\""),
                None => members.push(member("note", "\"x\\u202ey\"")),
            }
        }
        return format!("{{{}}}", members.join(", "));
    }
    if kind.contains(":generic:") {
        let mut keys = ["g0", "g1", "g2", "g3"];
        keys.shuffle(rng);
        let mut members = vec![member("transaction_id", "\"t\"")];
        for k in keys {
            if rng.random_bool(0.7) {
                let value = if k == "g3" {
                    "\"2026-01-31\""
                } else {
                    ["\"text\"", "null"]
                        .choose(rng)
                        .copied()
                        .unwrap_or_default()
                };
                members.push(member(k, value));
            }
        }
        if rng.random_bool(0.4) {
            members.push(member("payment_payload", r#"{"transaction_id": "f", "amount": "19.99 EUR", "payee": {"name": "S", "id": "D"}}"#));
        }
        return format!("{{{}}}", members.join(", "));
    }
    let mut members = vec![
        member("mandate_id", "\"M-1\""),
        member("mandatee", r#"{"name": "Agent"}"#),
        member("action", "\"Buy\""),
        member("valid_until", "\"2026-06-09\""),
    ];
    for (k, v) in [
        ("conditions", "\"- only **one**\""),
        ("max_amount", "\"200.00 EUR\""),
        ("max_count", "\"1\""),
        ("period", "\"per month\""),
        ("valid_from", "\"2026-06-01\""),
        ("transaction_id", "\"t\""),
    ] {
        if rng.random_bool(0.5) {
            members.push(member(k, v));
        }
    }
    if rng.random_bool(0.3) {
        members.push(member(
            "payment_payload",
            r#"{"amount": "19.99 EUR", "payee": {"name": "S", "id": "D"}}"#,
        ));
    }
    format!("{{{}}}", members.join(", "))
}

/// An ad-hoc metadata JWT for the type bound to the SD-JWT card, sometimes broken: another key,
/// another credential type, a bad signature; sometimes expired at phase 2.
pub fn adhoc(rng: &mut ChaCha8Rng, kind: &str) -> String {
    let meta = metadata(rng, kind).unwrap_or_else(|| json!({"claims": []}));
    let exp = if rng.random_bool(0.85) {
        NOW + 3600
    } else {
        NOW - 1
    };
    let payload = |sub: &str| {
        json!({"iss": "https://issuer.bank.example", "sub": sub, "format": "dc+sd-jwt", "iat": NOW - 100, "exp": exp,
               "transaction_data_type": kind, "metadata": meta}).to_string()
    };
    let card = "https://bank.example/sca/card";
    let defect: f64 = rng.random();
    let (body, key, kid) = if defect < 0.1 {
        (
            payload(card),
            &verifier::secret_key("issuer-secret-1"),
            "unknown-key",
        )
    } else if defect < 0.2 {
        (
            payload("org.example.card"),
            &verifier::secret_key("issuer-secret-1"),
            "issuer-key-1",
        )
    } else if defect < 0.3 {
        (
            payload(card),
            &verifier::secret_key("another-secret"),
            "issuer-key-1",
        )
    } else {
        (
            payload(card),
            &verifier::secret_key("issuer-secret-1"),
            "issuer-key-1",
        )
    };
    verifier::adhoc_jwt(&body, key, Some(kid), None).expect("jwt")
}

impl Case {
    /// A case: one to three entries of one PaSO type, the card's metadata for it, the wallet.
    pub fn new(rng: &mut ChaCha8Rng) -> Self {
        let kind = TYPES.choose(rng).copied().unwrap_or(TYPES[0]);
        let mut types = serde_json::Map::new();
        if let Some(meta) = metadata(rng, kind) {
            types.extend([(kind.to_owned(), meta)]);
        } else if kind.contains(":mandate:") {
            types.extend([(kind.to_owned(), json!({}))]);
        }
        let entries = (0..rng.random_range(1..=2))
            .map(|_| {
                let adhoc_metadata = rng.random_bool(0.15).then(|| adhoc(rng, kind));
                let metadata = adhoc_metadata
                    .map_or_else(String::new, |jwt| format!(r#", "metadata": "{jwt}""#));
                format!(
                    r#"{{"type": "{kind}", "credential_ids": ["q"], "payload": {}{metadata}}}"#,
                    payload(rng, kind)
                )
            })
            .collect();
        let mut locales = vec!["en", "de", "en-US", "de-CH"];
        locales.shuffle(rng);
        locales.truncate(rng.random_range(1..=2));
        Self {
            kind,
            entries,
            types: Value::Object(types).to_string(),
            keys: rng
                .random_bool(0.6)
                .then(|| format!(r#"{{"keys": [{ENC_KEY}]}}"#)),
            format: if rng.random_bool(0.5) {
                "dc+sd-jwt"
            } else {
                "mso_mdoc"
            },
            locales,
            formatted: rng.random_bool(0.5),
        }
    }
}
