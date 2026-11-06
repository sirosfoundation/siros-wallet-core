//! `check_members` and `check_signals`: each profile's response members.

use crate::common::HaipHost;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::Sha3_256;
use siros_openid4vp::matching::EntryView;
use siros_qes::NAMESPACE;

use crate::common::sri;
use crate::dressed::{Case, document};
use crate::generate::{DEFAULT_PROFILE, ENC_KEY, NOW, SIGNALS};
use crate::outcome::given;
use crate::tally::Tally;

use super::session::{mode, opened_jwe};
use super::{b64url, credential, hex};

/// The digest by the hash algorithm an object identifier names (NIST CSOR hashAlgs).
pub(super) fn nist(oid: &str, data: &[u8]) -> Vec<u8> {
    match oid {
        "2.16.840.1.101.3.4.2.1" => Sha256::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.2" => Sha384::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.3" => Sha512::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.8" => Sha3_256::digest(data).to_vec(),
        other => panic!("no hash for {other}"),
    }
}

/// Each profile's members, stated here from its specification.
pub(super) fn members(
    case: &Case<'_>,
    view: &EntryView<'_>,
    format: &str,
    got: &[(Value, Value)],
    host: &HaipHost,
    tally: &mut Tally,
) {
    let [first] = view.record.entries() else {
        panic!("a record authorizes one entry of PaSO or QES");
    };
    let entry = case.request.entry(*first).expect("the entry");
    let json = case.entry_json(*first);
    let kind = json["type"].as_str().expect("type");
    let mdoc = format == "mso_mdoc";
    let held = credential(case, view.record.credential().as_str());
    if kind.starts_with("urn:paso:sca:") {
        // PaSO Core §6.1-6.3: the locale shown, the hash of the entry as received, the integrity
        // values, the wallet's version and a fresh jti; the record attests what the display
        // showed.
        let key = |name: &str| {
            if mdoc {
                json!(["urn:paso:sca:1", name])
            } else {
                json!(name)
            }
        };
        let get = |name: &str| {
            got.iter()
                .find(|(member, _)| *member == key(name))
                .map(|(_, value)| value.clone())
        };
        let shown = case
            .rendered(*first, view.record.credential().as_str())
            .as_ref()
            .expect("the bound entry renders")
            .view
            .locale
            .to_string();
        let attested = view
            .record
            .attested()
            .and_then(|attested| attested.get("display_locale"));
        assert!(
            get("display_locale") == Some(json!(shown)) && attested == Some(shown.as_str()),
            "R-locale shown"
        );
        let digest = Sha256::digest(entry.raw().as_bytes());
        let hash = if mdoc {
            json!({"bstr": hex(&digest)})
        } else {
            json!(b64url(&digest))
        };
        assert_eq!(get("transaction_data_hash"), Some(hash), "R-PaSO hash");
        assert_eq!(get("transaction_data_hash_alg"), Some(json!("sha-256")));
        assert_eq!(
            get("wallet_instance_version"),
            Some(json!(host.paso.version))
        );
        let request_object = case.request.request_object().expect("a signed request");
        assert_eq!(
            get("request_integrity"),
            Some(json!(sri(request_object.as_bytes()))),
            "R-request_integrity"
        );
        let jti = get("jti").expect("R-jti");
        let jti = jti.as_str().expect("R-jti");
        let shaped = jti.len() == 36
            && jti.chars().enumerate().all(|(k, c)| match k {
                8 | 13 | 18 | 23 => c == '-',
                14 => c == '4',
                19 => c == '8',
                _ => c.is_ascii_digit() || ('a'..='f').contains(&c),
            });
        assert!(shaped, "R-jti {jti}");
        let document = document(held, "paso").expect("a PaSO document");
        let adhoc = json.get("metadata").is_some();
        assert_eq!(
            get("metadata_integrity"),
            (!adhoc).then(|| document["integrity"].clone()),
            "R-metadata_integrity present iff stored metadata rendered"
        );
        let meta = given(&json, &document).expect("the metadata that rendered");
        signals(case, &meta, get("risk_signals"), mdoc, tally);
        tally.add(format!("PaSO responses {format}"));
    } else if kind == siros_qes::TYPE {
        // CSC §7.2: by hashAlgorithmOID, over the decoded bytes in DeviceSigned data; over the
        // string as received, base64-encoded, in a Key Binding JWT.
        let oid = json["hashAlgorithmOID"].as_str().expect("hashAlgorithmOID");
        let want = if mdoc {
            let decoded = URL_SAFE_NO_PAD.decode(entry.raw()).expect("base64url");
            vec![(
                json!([NAMESPACE, "qesApproval"]),
                json!({"bstr": hex(&nist(oid, &decoded))}),
            )]
        } else {
            vec![(
                json!(format!("{NAMESPACE}.qesApproval")),
                json!(STANDARD.encode(nist(oid, entry.raw().as_bytes()))),
            )]
        };
        assert_eq!(got, want, "R-qesApproval");
        tally.add(format!("QES responses {format}"));
    } else {
        panic!("a transaction of no profile the dressed run registers: {kind}");
    }
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

/// Risk Signals §4-7 with the Default profile as Default.md tabulates it and the metadata's
/// enumeration: an envelope per required signal; a measurement older than its bound measured
/// again or unavailable, one the wallet lacks unavailable, the response mode the request's;
/// encrypted to the published key when the Default profile or the metadata requires it; absent
/// with no required signal.
pub(super) fn signals(
    case: &Case<'_>,
    meta: &Value,
    value: Option<Value>,
    mdoc: bool,
    tally: &mut Tally,
) {
    let default = meta
        .get("risk_signal_profiles")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id == DEFAULT_PROFILE));
    let mut bound: Vec<(String, u64)> = if default {
        case.spec.default.clone()
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
        assert!(required.is_empty(), "R-risk_signals absent: {required:?}");
        tally.add("responses without risk signals");
        return;
    };
    assert!(!required.is_empty(), "R-risk_signals present: {value}");
    let envelopes: Value = if default || meta.get("encrypted") == Some(&json!(true)) {
        // §7.5-7.6: encrypted to the issuer's published key, ECDH-ES and A256GCM.
        let key: Value = serde_json::from_str(ENC_KEY).expect("the key");
        let (protected, plaintext) = if mdoc {
            let sealed = &value["COSE_Encrypt"];
            let hex = sealed["ciphertext"]["bstr"].as_str().expect("hex");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|k| u8::from_str_radix(&hex[k..k + 2], 16).expect("hex"))
                .collect();
            (sealed["protected"].clone(), bytes)
        } else {
            opened_jwe(value.as_str().expect("R-encrypted: a JWE"))
        };
        assert_eq!(
            protected,
            json!({"alg": "ECDH-ES", "enc": "A256GCM", "kid": key["kid"]}),
            "R-encrypted"
        );
        tally.add("risk signals encrypted");
        serde_json::from_slice(&plaintext).expect("the envelopes")
    } else {
        tally.add("risk signals plain");
        value
    };
    let envelopes = envelopes.as_array().expect("an array of envelopes");
    let mut kinds: Vec<&str> = envelopes
        .iter()
        .map(|e| e["type"].as_str().expect("type"))
        .collect();
    kinds.sort_unstable();
    required.sort();
    assert_eq!(kinds, required, "R-required signals");
    for envelope in envelopes {
        let kind = envelope["type"].as_str().expect("type");
        let limit = bound
            .iter()
            .find(|(known, _)| known == kind)
            .map(|(_, age)| *age);
        let measured = SIGNALS.iter().find(|signal| signal.kind == kind);
        let (status, want) = if kind == "urn:paso:risk:global:response_mode:1" {
            ("ok", json!(mode(case)))
        } else if kind == "urn:paso:risk:global:amr:1" {
            // Registry §2.8 over the platform's `pin_and_device`: RFC 8176's `pin` and `hwk`.
            ("ok", json!(["pin", "hwk"]))
        } else {
            match measured {
                None => ("unavailable", Value::Null),
                Some(signal)
                    if !signal.retakes && limit.is_some_and(|limit| signal.age > limit) =>
                {
                    ("unavailable", Value::Null)
                }
                Some(signal) => (
                    signal.status,
                    signal.value.map_or(Value::Null, |text| {
                        serde_json::from_str(text).expect("a value")
                    }),
                ),
            }
        };
        let want = if mdoc { floats(want) } else { want };
        assert_eq!(
            (
                envelope["status"].as_str(),
                envelope.get("value").cloned().unwrap_or(Value::Null)
            ),
            (Some(status), want),
            "R-envelope {kind}"
        );
        // §4.3: fresh at signing.
        let collected = epoch(envelope["collected_at"].as_str().expect("collected_at"));
        let age = NOW
            .checked_sub(collected)
            .expect("R-fresh: collected in the future");
        assert!(
            limit.is_none_or(|limit| age <= limit),
            "R-fresh at signing (§4.3): {kind} {age} s"
        );
        tally.add(format!("risk envelopes {status}"));
    }
}
