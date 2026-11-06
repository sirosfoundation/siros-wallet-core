//! Core §6.1 and Risk Signals §4-7 on the response members.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_openid4vp::cbor::decode;
use siros_openid4vp::host::{ProfileHost, Timestamp};
use siros_openid4vp::ids::FormatId;
use siros_openid4vp::plugins::{Answered, Member, MemberValue};
use siros_paso::risk::SignalType;
use siros_paso::{Measured, PasoProfile, Reading, Signal};
use siros_testkit::pin_and_device;
use siros_testkit::reading::model_value;

use crate::paso_host::PasoHost;

use crate::common::{section, sri, tables};
use crate::generate::{Case, DEFAULT, NOW};

use super::Tally;
use super::phase2::{Answer, readings, refused_step};

/// Core §6.1 on the bound entry's response members: the locale shown, SHA-256 over the entry as
/// received, the integrity values, the wallet's version, a fresh `jti`, the risk signals.
pub(super) fn members(case: &Case, answer: &Answer<'_>, meta: &Value, tally: &mut Tally) {
    let credential = answer.card.credential();
    let format = FormatId::parse(case.format).expect("format");
    let mut host = PasoHost::at(Timestamp(NOW));
    host.paso.signals = readings()
        .into_iter()
        .map(|(kind, age, reading, retakes)| Measured {
            signal: SignalType::parse(kind.to_owned()).expect("signal"),
            last: Signal {
                collected_at: Timestamp(NOW - age),
                reading,
                retakes,
            },
        })
        .collect();
    let authentication = pin_and_device(Timestamp(NOW));
    let record = Answered::new(
        answer.request,
        &credential,
        &answer.bound.entries,
        &answer.bound.attested,
        crate::common::placement(&format),
        siros_testkit::fixtures::mode_of(answer.request).expect("a mode"),
    );
    let responded = PasoProfile::default().respond(record, &host, &authentication);
    // A record whose ad-hoc metadata JWT fails a step of §5.3 gets no members: phase 2 falls
    // back before it responds.
    if let Some(jwt) = answer.adhoc()
        && refused_step(jwt, case.format).is_some()
    {
        assert!(responded.is_err(), "R-members: none over a refused JWT");
        tally.add("responses refused over a refused JWT");
        return;
    }
    let members = responded.expect("the members");
    tally.add("responses");
    let mdoc = case.format == "mso_mdoc";
    let get = |name: &str| {
        members
            .iter()
            .find(|(member, _)| match member {
                Member::Claim(claim) => !mdoc && claim == name,
                Member::Element { namespace, element } => {
                    mdoc && namespace == "urn:paso:sca:1" && element == name
                }
            })
            .map(|(_, value)| value.clone())
    };
    let text = |name: &str| match get(name) {
        Some(MemberValue::Text(text)) => text,
        other => panic!("{name} is no text: {other:?}"),
    };
    let raw = answer
        .request
        .entry(answer.bound.entries.entries()[0])
        .expect("the entry")
        .raw();
    let digest = Sha256::digest(raw.as_bytes()).to_vec();
    let hash = if mdoc {
        MemberValue::Bytes(digest)
    } else {
        MemberValue::Text(URL_SAFE_NO_PAD.encode(&digest))
    };
    assert_eq!(get("transaction_data_hash"), Some(hash), "R-PaSO hash");
    assert_eq!(text("transaction_data_hash_alg"), "sha-256");
    assert_eq!(
        Some(text("display_locale").as_str()),
        answer
            .bound
            .attested
            .get("display_locale")
            .map(|text| text.as_str()),
        "R-locale shown"
    );
    assert_eq!(
        text("request_integrity"),
        sri(answer.request_object.as_bytes()),
        "R-request_integrity"
    );
    assert_eq!(text("wallet_instance_version"), host.paso.version);
    let jti = text("jti");
    let shaped = jti.len() == 36
        && jti.chars().enumerate().all(|(k, c)| match k {
            8 | 13 | 18 | 23 => c == '-',
            14 => c == '4',
            19 => c == '8',
            _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
        });
    assert!(shaped, "R-jti {jti}");
    match get("metadata_integrity") {
        None => assert!(
            answer.adhoc().is_some(),
            "R-metadata_integrity present iff stored metadata rendered"
        ),
        Some(value) => {
            assert!(
                answer.adhoc().is_none(),
                "R-metadata_integrity present iff stored metadata rendered"
            );
            assert_eq!(
                value,
                MemberValue::Text(answer.card.integrity()),
                "R-metadata_integrity"
            );
        }
    }
    signals(meta, get("risk_signals"), mdoc, tally);
}

/// Seconds since the epoch of a `YYYY-MM-DDTHH:MM:SSZ` stamp, the days counted from the civil
/// date in March-based years.
pub(super) fn epoch(stamp: &str) -> u64 {
    let shaped = stamp.len() == 20
        && stamp
            .chars()
            .zip("dddd-dd-ddTdd:dd:ddZ".chars())
            .all(|(c, want)| {
                if want == 'd' {
                    c.is_ascii_digit()
                } else {
                    c == want
                }
            });
    assert!(shaped, "R-collected_at {stamp}");
    let n = |from: usize, to: usize| stamp[from..to].parse::<u64>().expect("digits");
    let (year, month, day) = (n(0, 4), n(5, 7), n(8, 10));
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + day - 1 - 719_468;
    days * 86_400 + n(11, 13) * 3600 + n(14, 16) * 60 + n(17, 19)
}

/// A JSON value with every integer a float, as an mdoc's measured values are (Risk Signals §5.2).
pub(super) fn floats(value: Value) -> Value {
    match value {
        Value::Number(n) if n.is_u64() || n.is_i64() => json!(n.as_f64().expect("a number")),
        Value::Array(items) => Value::Array(items.into_iter().map(floats).collect()),
        Value::Object(members) => {
            Value::Object(members.into_iter().map(|(k, v)| (k, floats(v))).collect())
        }
        other => other,
    }
}

/// The envelopes of an encrypted `risk_signals` member: the stand-in JWE's or COSE_Encrypt's
/// plaintext, its protected header checked (Risk Signals §7.5-7.6).
pub(super) fn opened(value: MemberValue, mdoc: bool) -> Value {
    let (protected, plaintext) = match value {
        MemberValue::Text(jwe) if !mdoc => {
            let parts: Vec<&str> = jwe.split('.').collect();
            assert_eq!(parts.len(), 5, "a JWE has five parts");
            let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).expect("base64url");
            (
                serde_json::from_slice::<Value>(&decode(parts[0])).expect("the header"),
                decode(parts[3]),
            )
        }
        MemberValue::Cbor(structure) if mdoc => {
            let item = decode(structure.as_bytes()).expect("a data item");
            let shape = model_value(&item).expect("the COSE_Encrypt stand-in");
            let sealed: Value =
                serde_json::from_str(&shape.python_compact().to_string()).expect("JSON");
            let hex = sealed["COSE_Encrypt"]["ciphertext"]["bstr"]
                .as_str()
                .expect("hex");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|k| u8::from_str_radix(&hex[k..k + 2], 16).expect("hex"))
                .collect();
            (sealed["COSE_Encrypt"]["protected"].clone(), bytes)
        }
        other => panic!("R-encrypted: {other:?}"),
    };
    assert_eq!(
        protected,
        json!({"alg": "ECDH-ES", "enc": "A256GCM", "kid": "issuer-enc-1"}),
        "R-encrypted"
    );
    serde_json::from_slice(&plaintext).expect("the envelopes")
}

/// Risk Signals §4-7 with the Default profile as Default.md tabulates it and the metadata's
/// enumeration: an envelope per required signal; a measurement older than its bound measured
/// again or unavailable; one the wallet lacks unavailable; the response mode the request's;
/// encrypted to the published key when the Default profile or the metadata says so; absent with
/// no required signal.
pub(super) fn signals(meta: &Value, value: Option<MemberValue>, mdoc: bool, tally: &mut Tally) {
    let profile = tables(&section("Default.md", "## 2 Signals"))
        .into_iter()
        .next()
        .expect("Default.md's signal table");
    let default = meta
        .get("risk_signal_profiles")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id == DEFAULT));
    let mut bound: Vec<(String, u64)> = if default {
        profile
            .iter()
            .skip(1)
            .map(|row| (row[0].clone(), row[2].parse().expect("max_age")))
            .collect()
    } else {
        Vec::new()
    };
    let mut required: Vec<String> = bound.iter().map(|(kind, _)| kind.clone()).collect();
    for listed in meta
        .get("risk_signals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = listed["type"].as_str().expect("type").to_owned();
        if listed.get("required") == Some(&json!(true)) && !required.contains(&kind) {
            required.push(kind.clone());
        }
        if let (Some(age), Some(slot)) = (
            listed.get("max_age").and_then(Value::as_u64),
            bound.iter_mut().find(|(known, _)| *known == kind),
        ) {
            slot.1 = slot.1.min(age);
        }
    }
    let Some(value) = value else {
        assert!(required.is_empty(), "R-risk_signals present");
        return;
    };
    assert!(!required.is_empty(), "R-risk_signals absent");
    let envelopes = if default || meta.get("encrypted") == Some(&json!(true)) {
        tally.add("risk signals encrypted");
        opened(value, mdoc)
    } else {
        tally.add("risk signals plain");
        match value {
            MemberValue::Json(text) => serde_json::from_str(text.as_str()).expect("the envelopes"),
            other => panic!("R-plain: {other:?}"),
        }
    };
    let envelopes = envelopes.as_array().expect("an array");
    let mut kinds: Vec<&str> = envelopes
        .iter()
        .map(|e| e["type"].as_str().expect("type"))
        .collect();
    kinds.sort_unstable();
    required.sort();
    assert_eq!(kinds, required, "R-required signals");
    let readings = readings();
    for envelope in envelopes {
        let kind = envelope["type"].as_str().expect("type");
        let limit = bound
            .iter()
            .find(|(known, _)| known == kind)
            .map(|(_, age)| *age);
        let (status, value) = if kind == "urn:paso:risk:global:response_mode:1" {
            ("ok", json!("dc_api"))
        } else if kind == "urn:paso:risk:global:amr:1" {
            // Registry §2.8 over `pin_and_device`: RFC 8176's `pin` and `hwk`.
            ("ok", json!(["pin", "hwk"]))
        } else {
            match readings.iter().find(|(known, ..)| *known == kind) {
                None => ("unavailable", Value::Null),
                Some((_, age, _, false)) if limit.is_some_and(|limit| *age > limit) => {
                    ("unavailable", Value::Null)
                }
                Some((_, _, Reading::Ok(raw), _)) => {
                    ("ok", serde_json::from_str(raw.get()).expect("json"))
                }
                Some((_, _, Reading::Denied, _)) => ("denied", Value::Null),
                Some((_, _, Reading::Unavailable, _)) => ("unavailable", Value::Null),
            }
        };
        let value = if mdoc { floats(value) } else { value };
        assert_eq!(
            (
                envelope["status"].as_str(),
                envelope.get("value").cloned().unwrap_or(Value::Null)
            ),
            (Some(status), value),
            "R-envelope {kind}"
        );
        let collected = epoch(envelope["collected_at"].as_str().expect("collected_at"));
        let age = NOW
            .checked_sub(collected)
            .expect("R-fresh: collected in the future");
        assert!(
            limit.is_none_or(|limit| age <= limit),
            "R-fresh at signing (§4.3): {kind} {age} s"
        );
    }
}
