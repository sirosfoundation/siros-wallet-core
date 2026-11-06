//! The transaction data of each real type: its metadata, its payload and its ad-hoc metadata.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::Rng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use serde_json::{Value, json};
use siros_testkit::verifier::{self};

use crate::common::sri;

use super::dress::{entries_for, shown, ui};
use super::{
    DEFAULT_PROFILE, DOC, DOCS, MDOC_TYPE, NOW, Obj, QUALIFIERS, REMOTE, SD_JWT_TYPE, logo_png,
    pick, png, sample, string,
};

/// A credential's `transaction_data_types` entry for a type, with occasional defects
/// (`tx_metadata`); `None` for no entry.
pub fn tx_metadata(rng: &mut ChaCha8Rng, kind: &str) -> Option<Value> {
    let count = rng.random_range(1..=2);
    let locales = sample(rng, &["en", "de"], count);
    let disp = |rng: &mut ChaCha8Rng, name: &str| {
        entries_for(
            rng,
            &locales,
            |_, locale| json!({"name": format!("{name} {}", shown(locale))}),
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
        ], "ui_labels": ui(rng, &locales, "Pay", "Pay")})
    } else if kind.ends_with("custom:1") {
        let mut claims = vec![json!({"path": ["transaction_id"]})];
        for (name, value_type) in [
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
            claims.push(
                json!({"path": [name], "value_type": value_type, "display": disp(rng, name)}),
            );
        }
        claims.push(json!({"path": ["items", null, "name"], "display": disp(rng, "Item")}));
        claims.push(json!({"path": ["items", null, "qty"], "display": locales.iter().map(|l| json!({"locale": l, "name": "Quantity of {10}", "display_type": "template:mini_markdown"})).collect::<Vec<_>>()}));
        claims.push(json!({"path": ["info"], "value_type": "label_only", "display": disp(rng, "This is recurring")}));
        claims.push(json!({"path": ["summary"], "value_type": "template:mini_markdown", "display": disp(rng, "Summary")}));
        claims.push(json!({"path": ["logo"], "value_type": "image", "display": disp(rng, "Logo")}));
        claims.push(json!({"path": ["maybe"], "display": disp(rng, "Maybe")}));
        let mut labels = ui(rng, &locales, "Confirm", "OK");
        if rng.random_bool(0.3) {
            let mut titles: Vec<Value> = locales.iter().map(|l| json!({"locale": l, "value": "Pay {1} ({15})", "value_type": "template:mini_markdown"})).collect();
            titles.push(json!({"value": "Pay"}));
            labels["transaction_title"] = json!(titles);
        }
        json!({"claims": claims, "ui_labels": labels})
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
        json!({"claims": claims, "ui_labels": ui(rng, &locales, "Authorize", "Allow")})
    } else if rng.random_bool(0.5) {
        json!({"claims": [], "ui_labels": ui(rng, &locales, "x", "x")})
    } else {
        return None;
    };
    // Risk Signals §4.1, §7.2: the Default profile, one the wallet does not hold, enumerations,
    // encryption.
    let r: f64 = rng.random();
    if r < 0.25 {
        meta["risk_signal_profiles"] = json!([DEFAULT_PROFILE]);
    } else if r < 0.3 {
        meta["risk_signal_profiles"] = json!(["urn:paso:risk-profile:com.example:unknown:1"]);
    }
    if rng.random_bool(0.3) {
        // Tightening works; demoting a required signal or raising a bound has no effect.
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
    let claims = meta["claims"].as_array_mut().expect("claims");
    if defect < 0.05 && !claims.is_empty() {
        // Proof Metadata §3.3: a label over 60 characters.
        let displayed: Vec<usize> = (0..claims.len())
            .filter(|k| claims[*k].get("display").is_some())
            .collect();
        let k = if displayed.is_empty() {
            rng.random_range(0..claims.len())
        } else {
            pick(rng, &displayed)
        };
        if claims[k].get("display").is_none() {
            claims[k]["display"] = disp(rng, "x");
        }
        claims[k]["display"][0]["name"] = json!("L".repeat(61));
    } else if defect < 0.10 && !claims.is_empty() {
        // A claim the payload holds, missing from the metadata.
        let k = rng.random_range(0..claims.len());
        drop(claims.remove(k));
    } else if defect < 0.15 {
        meta["ui_labels"]["security_hint"] =
            json!([{"locale": locales[0], "value": "Typed", "value_type": "mini_markdown"}]);
    }
    Some(meta)
}

/// A Data URL of a PNG.
pub fn data_png() -> String {
    format!("data:image/png;base64,{}", STANDARD.encode(png(12, 12)))
}

/// A type's payload, its members in the order the model writes them (`payload`).
pub(super) fn payload(rng: &mut ChaCha8Rng, kind: &str) -> String {
    let mut p = Obj::default();
    if kind.ends_with("payment:1") {
        let mut payee = Obj::default()
            .with("name", string(pick(rng, &["Acme", "Shop Inc."])))
            .with("id", string("DE1"));
        let r: f64 = rng.random();
        if r < 0.3 {
            payee.put("logo", string(&data_png()));
        } else if r < 0.6 {
            payee.put("logo", string(pick(rng, &REMOTE)));
            payee.put("logo#integrity", string(&sri(&logo_png())));
        }
        let amount = pick(rng, &["49.99 EUR", "1000.00 EUR", "5 JPY", "12.50 USD"]);
        p.put("transaction_id", string("t"));
        p.put("amount", string(amount));
        p.put("payee", payee.text());
        return p.text();
    }
    if kind.ends_with("custom:1") {
        p.put("transaction_id", string("t"));
        for (name, value) in [
            ("amount", string("2500.00 EUR")),
            ("when", string("2026-09-02")),
            ("at", string("10:15:30Z")),
            ("stamp", string("2026-06-02T10:15:30+02:00")),
            ("every", string("MNTH")),
            ("flag", "false".to_owned()),
            ("cur", string("EUR")),
            ("note", string("- a **b**\n- c")),
            ("link", string("https://bücher.example/x")),
        ] {
            if rng.random_bool(0.5) {
                p.put(name, value);
            }
        }
        let items: Vec<String> = (0..rng.random_range(0..=3))
            .map(|i| format!(r#"{{"name": "n{i}", "qty": "{i}"}}"#))
            .collect();
        p.put("items", format!("[{}]", items.join(", ")));
        if rng.random_bool(0.4) {
            p.put("info", "null");
        }
        let has = |name: &str| p.0.iter().any(|(known, _)| known == name);
        let summary = if has("amount") && has("when") {
            "Total {1} on {2}"
        } else {
            "Total"
        };
        p.put("summary", string(summary));
        if rng.random_bool(0.3) {
            p.put("logo", string(&data_png()));
        }
        if rng.random_bool(0.5) {
            p.put("maybe", string("here"));
        }
        if rng.random_bool(0.03) {
            // Proof Metadata §3.3: a payload string with a directional control.
            let note = string("x\u{202e}y");
            match p.0.iter_mut().find(|(known, _)| known == "note") {
                Some((_, value)) => *value = note,
                None => {
                    p.put("note", note);
                }
            }
        }
        return p.text();
    }
    if kind.contains(":generic:") {
        let mut keys = ["g0", "g1", "g2", "g3"];
        keys.shuffle(rng);
        p.put("transaction_id", string("t"));
        for key in keys {
            if rng.random_bool(0.7) {
                let value = if key == "g3" {
                    string("2026-01-31")
                } else if rng.random_bool(0.5) {
                    string("text")
                } else {
                    "null".to_owned()
                };
                p.put(key, value);
            }
        }
        if rng.random_bool(0.4) {
            p.put(
                "payment_payload",
                r#"{"transaction_id": "f", "amount": "19.99 EUR", "payee": {"name": "S", "id": "D"}}"#,
            );
        }
        return p.text();
    }
    p.put("mandate_id", string("M-1"));
    p.put("mandatee", r#"{"name": "Agent"}"#);
    p.put("action", string("Buy"));
    p.put("valid_until", string("2026-06-09"));
    for (name, value) in [
        ("conditions", "- only **one**"),
        ("max_amount", "200.00 EUR"),
        ("max_count", "1"),
        ("period", "per month"),
        ("valid_from", "2026-06-01"),
        ("transaction_id", "t"),
    ] {
        if rng.random_bool(0.5) {
            p.put(name, string(value));
        }
    }
    if rng.random_bool(0.3) {
        p.put(
            "payment_payload",
            r#"{"amount": "19.99 EUR", "payee": {"name": "S", "id": "D"}}"#,
        );
    }
    p.text()
}

/// A QES entry's members, as `qes_body` writes them.
pub(super) fn qes_body(rng: &mut ChaCha8Rng, entry: &mut Obj) {
    let count = rng.random_range(1..=3);
    let mut docs: Vec<Obj> = (0..count)
        .map(|k| {
            let mut doc = Obj::default()
                .with("label", string(&format!("Document {k}")))
                .with("hash", string("aGFzaA=="))
                .with("hashType", string("sodr"))
                .with("access", r#"{"type": "public"}"#)
                .with("href", string(pick(rng, &DOCS)));
            if rng.random_bool(0.4) {
                doc.put("checksum", string(&sri(DOC)));
            }
            doc
        })
        .collect();
    if rng.random_bool(0.5) {
        let first = docs.first_mut().expect("a document");
        if let Some((_, access)) = first.0.iter_mut().find(|(name, _)| name == "access") {
            *access = r#"{"type": "OTP", "oneTimePassword": "51623"}"#.to_owned();
        }
    }
    if rng.random_bool(0.3) {
        docs.last_mut().expect("a document").remove("label");
    }
    let documents: Vec<String> = docs.iter().map(Obj::text).collect();
    let oid = pick(
        rng,
        &[
            "2.16.840.1.101.3.4.2.1",
            "2.16.840.1.101.3.4.2.2",
            "2.16.840.1.101.3.4.2.8",
        ],
    );
    entry.put("numSignatures", count.to_string());
    entry.put("signatureQualifier", string(pick(rng, &QUALIFIERS)));
    entry.put("documentInfos", format!("[{}]", documents.join(", ")));
    entry.put("hashAlgorithmOID", string(oid));
    if rng.random_bool(0.05) {
        // A member the type does not define.
        entry.put("signAlgo", string("1.2.840.113549.1.1.1"));
    }
}

/// An ad-hoc metadata JWT for the type bound to the SD-JWT card, sometimes broken: another key,
/// another credential type, a bad signature; sometimes expired at phase 2 (`adhoc`).
pub(super) fn adhoc(rng: &mut ChaCha8Rng, kind: &str) -> String {
    let meta = tx_metadata(rng, kind).unwrap_or_else(|| json!({"claims": []}));
    let exp = if rng.random_bool(0.85) {
        NOW + 3600
    } else {
        NOW - 1
    };
    let payload = |sub: &str| {
        json!({"iss": "https://issuer.bank.example", "sub": sub, "format": "dc+sd-jwt", "iat": NOW - 100,
               "exp": exp, "transaction_data_type": kind, "metadata": meta})
        .to_string()
    };
    let defect: f64 = rng.random();
    let (body, key, kid) = if defect < 0.1 {
        (
            payload(SD_JWT_TYPE),
            &verifier::secret_key("issuer-secret-1"),
            "unknown-key",
        )
    } else if defect < 0.2 {
        (
            payload(MDOC_TYPE),
            &verifier::secret_key("issuer-secret-1"),
            "issuer-key-1",
        )
    } else if defect < 0.3 {
        (
            payload(SD_JWT_TYPE),
            &verifier::secret_key("another-secret"),
            "issuer-key-1",
        )
    } else {
        (
            payload(SD_JWT_TYPE),
            &verifier::secret_key("issuer-secret-1"),
            "issuer-key-1",
        )
    };
    verifier::adhoc_jwt(&body, key, Some(kid), None).expect("an ad-hoc metadata JWT")
}
