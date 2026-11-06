//! `check_session`: what binds each presentation to the request, with the readers it needs.

use crate::common::HaipHost;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siros_openid4vp::json::Node;
use siros_openid4vp::matching::EntryView;
use siros_openid4vp::request::HolderBinding;
use siros_openid4vp::wallet::{Credential, Holder};
use siros_testkit::fixtures::{NONCE, ORIGIN};
use siros_testkit::reading::model_shape;

use crate::dressed::Case;
use crate::tally::Tally;

use super::b64url;

/// An mdoc presentation as a Verifier reads it, in the reference model's JSON shape.
pub(super) fn read_mdoc(presentation: &Value) -> Value {
    let text = presentation.to_string();
    let written = Node::parse(&text).expect("JSON");
    let read = model_shape(&written, None).expect("R-mdoc: a DeviceResponse");
    serde_json::from_str(&read.python_compact().to_string()).expect("JSON")
}

pub(super) fn mode(case: &Case<'_>) -> String {
    match siros_testkit::fixtures::mode_of(case.request) {
        Some(mode) => mode.as_str().to_owned(),
        None => panic!("R-mode: an accepted request answers in a mode"),
    }
}

/// A JWK the key rule accepts (§8.3, HAIP §5; reading 25): `kty` EC, `crv` P-256, `alg`
/// ECDH-ES, `use` enc or absent, a `kid`, and 32-octet coordinates (RFC 7518 §6.2.1.2).
pub(super) fn response_key(key: &Value) -> bool {
    let octets = |name: &str| {
        key.get(name)
            .and_then(Value::as_str)
            .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
            .is_some_and(|bytes| bytes.len() == 32)
    };
    key.get("kty") == Some(&json!("EC"))
        && key.get("crv") == Some(&json!("P-256"))
        && key.get("alg") == Some(&json!("ECDH-ES"))
        && key.get("use").is_none_or(|usage| usage == "enc")
        && key.get("kid").is_some()
        && octets("x")
        && octets("y")
}

/// A JWK on a curve the wallet implements (RFC 7518 §6.2, RFC 8037).
pub(super) fn agreeable_curve(key: &Value) -> bool {
    matches!(
        (
            key.get("kty").and_then(Value::as_str),
            key.get("crv").and_then(Value::as_str)
        ),
        (Some("EC"), Some("P-256" | "P-384" | "P-521")) | (Some("OKP"), Some("X25519" | "X448"))
    )
}

/// The protected header and the plaintext of the host's stand-in JWE: five parts, the
/// plaintext where the ciphertext goes.
pub(super) fn opened_jwe(jwe: &str) -> (Value, Vec<u8>) {
    let parts: Vec<&str> = jwe.split('.').collect();
    assert_eq!(parts.len(), 5, "a JWE has five parts");
    let header = URL_SAFE_NO_PAD.decode(parts[0]).expect("base64url");
    (
        serde_json::from_slice(&header).expect("a protected header"),
        URL_SAFE_NO_PAD.decode(parts[3]).expect("base64url"),
    )
}

/// The transaction members a presentation's proof holds, read in its format's layout: a Key
/// Binding JWT's claims beside its own, an mdoc's device-signed data elements, none for
/// `zkp_req`.
pub(super) fn members_of(format: &str, presentation: &Value) -> Vec<(Value, Value)> {
    match format {
        "dc+sd-jwt" => presentation
            .get("kb_jwt")
            .and_then(|kb| kb["payload"].as_object())
            .map(|payload| {
                payload
                    .iter()
                    .filter(|(name, _)| {
                        !["iat", "aud", "nonce", "sd_hash"].contains(&name.as_str())
                    })
                    .map(|(name, value)| (json!(name), value.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        "mso_mdoc" => presentation["documents"][0]["deviceSigned"]["nameSpaces"]
            .as_object()
            .expect("nameSpaces")
            .iter()
            .flat_map(|(namespace, elements)| {
                elements
                    .as_object()
                    .expect("elements")
                    .iter()
                    .map(move |(element, value)| (json!([namespace, element]), value.clone()))
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// OpenID4VP Annex A and B.3.6: the audience is the Origin prefixed with `origin:`, the nonce
/// the request's. An SD-JWT ends in a Key Binding JWT exactly when the credential has a key,
/// whose sd_hash covers the SD-JWT before it. An mdoc authenticates its device with a MAC, agreed
/// with the first Verifier key on the device key's curve, exactly when the Verifier lists the MAC
/// for that curve and either lists no signature the device key makes or the presentation carries
/// no transaction; with a signature otherwise (B.2, ISO/IEC 18013-5 §9.1.3).
pub(super) fn session(
    case: &Case<'_>,
    view: &EntryView<'_>,
    held: &Credential<'_>,
    format: &str,
    presentation: &Value,
    host: &HaipHost,
    tally: &mut Tally,
) {
    let aud = format!("origin:{ORIGIN}");
    let transaction = !view.record.entries().is_empty();
    match format {
        "dc+sd-jwt" => {
            let sd_jwt = presentation["sd_jwt"].as_str().expect("sd_jwt");
            assert!(sd_jwt.ends_with('~'), "R-SD-JWT");
            if held.facts.holder == Holder::Bound {
                let kb = presentation
                    .get("kb_jwt")
                    .expect("R-a Key Binding JWT whenever the credential has a key");
                assert!(
                    kb["header"]["typ"] == "kb+jwt"
                        && (
                            &kb["payload"]["aud"],
                            &kb["payload"]["nonce"],
                            &kb["payload"]["iat"]
                        ) == (&json!(aud), &json!(NONCE), &json!(host.platform.now.0)),
                    "R-KB-JWT session {kb}"
                );
                assert_eq!(
                    kb["payload"]["sd_hash"],
                    json!(b64url(&Sha256::digest(sd_jwt.as_bytes()))),
                    "R-sd_hash"
                );
                let waived = case.query(view.pick.query).holder_binding() == HolderBinding::Waived;
                tally.add(if waived {
                    "KB-JWTs with holder binding waived"
                } else {
                    "KB-JWTs"
                });
            } else {
                assert_eq!(
                    presentation
                        .as_object()
                        .map(|p| p.keys().collect::<Vec<_>>()),
                    Some(vec![&"sd_jwt".to_owned()]),
                    "R-no KB-JWT without a key"
                );
                tally.add("SD-JWTs without a key");
            }
        }
        "mso_mdoc" => {
            let view: Value = serde_json::from_slice(held.view).expect("a view");
            let metadata: Value = serde_json::from_str(
                case.request
                    .client_metadata()
                    .expect("client_metadata")
                    .get(),
            )
            .expect("client_metadata");
            let curve = view["device_curve"].as_str().expect("device_curve");
            let device_alg = view["device_alg"].as_i64().expect("device_alg");
            let allowed: Option<Vec<i64>> = metadata
                .get("vp_formats_supported")
                .and_then(|v| v.get("mso_mdoc"))
                .and_then(|v| v.get("deviceauth_alg_values"))
                .map(|values| {
                    values
                        .as_array()
                        .expect("values")
                        .iter()
                        .map(|v| v.as_i64().expect("an identifier"))
                        .collect()
                });
            let keys: Vec<&Value> = metadata
                .get("jwks")
                .and_then(|jwks| jwks["keys"].as_array())
                .map(|keys| {
                    keys.iter()
                        .filter(|k| {
                            k.get("crv").and_then(Value::as_str) == Some(curve)
                                && agreeable_curve(k)
                                && k.get("kid").is_some()
                        })
                        .collect()
                })
                .unwrap_or_default();
            // B.2: the deviceMac identifier by the device key's curve (HMAC 256/256).
            let mac_id = match curve {
                "P-256" => -65537,
                "P-384" => -65538,
                "P-521" => -65539,
                "X25519" => -65540,
                "X448" => -65541,
                other => panic!("no MAC identifier for {other}"),
            };
            let mac = allowed
                .as_ref()
                .is_some_and(|allowed| !keys.is_empty() && allowed.contains(&mac_id));
            // ECDSA with SHA-256 on P-256 is also the fully specified -9.
            let mut signs = vec![device_alg];
            if (device_alg, curve) == (-7, "P-256") {
                signs.push(-9);
            }
            let signature = allowed
                .as_ref()
                .is_none_or(|allowed| signs.iter().any(|alg| allowed.contains(alg)));
            let auth = &presentation["documents"][0]["deviceSigned"]["deviceAuth"];
            let modes: Vec<&String> = auth.as_object().expect("deviceAuth").keys().collect();
            if mac && (!signature || !transaction) {
                let kid = auth["deviceMac"]
                    .as_str()
                    .and_then(|mac| mac.split(':').nth(2));
                assert!(
                    modes == ["deviceMac"] && kid == keys[0]["kid"].as_str(),
                    "R-deviceMac {auth}"
                );
                tally.add("mdoc deviceMac");
            } else {
                assert_eq!(modes, ["deviceSignature"], "R-deviceSignature {auth}");
                tally.add("mdoc deviceSignature");
            }
        }
        other => panic!("a presentation of {other}"),
    }
}
