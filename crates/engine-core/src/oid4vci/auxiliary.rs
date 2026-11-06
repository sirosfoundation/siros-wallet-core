//! Credential Auxiliary Data v0.1 (nym_auth_rulebook PR #12) — the
//! advertisement the engine reads, the usability verdict it takes from
//! one configuration, and the refusals it answers with.
//!
//! **The engine never handles a secret value** (v0.1 §8.4): an issuer
//! delivers a Secret Value in an encrypted response the client decrypts.
//! `auxiliary_data` is the one `credential_metadata` member that carries
//! Secret Values; the engine decides from the advertisement alone whether
//! the response MUST be encrypted (§7.1).
//!
//! The members of `credential_metadata` the engine does not know are
//! ordinary unknown members, ignored.

use serde_json::Value;

/// The one `credential_metadata` member that carries Credential Auxiliary
/// Data in a response. It MUST NOT appear in issuer metadata (§7).
pub const AUXILIARY_DATA_MEMBER: &str = "auxiliary_data";

/// The one Auxiliary Data Type the engine knows. Its response entries
/// carry a Secret Value (an opening).
const AUX_TYPE_HASH_COMMITMENT: &str = "hash_commitment";

/// The hash functions a `hash_commitment` entry may declare (§4.1).
const SUPPORTED_ALGS: &[&str] = &["sha-256"];

/// The encodings a `hash_commitment` entry's claim at `path` may use
/// (§4.1): absent, `base64url`, `base64`, or `hex`.
const SUPPORTED_ENCODINGS: &[&str] = &["base64url", "base64", "hex"];

/// What the engine takes from one credential configuration's secret
/// delivery advertisement: parsed once, consulted at the selection (the
/// refusal), the proof ask, and the response check.
#[derive(Debug, Clone, Default)]
pub struct SecretDelivery {
    /// The issuer delivers Secret Values to the wallet (any `to_wallet`
    /// `hash_commitment`), so the credential response MUST be encrypted
    /// (§7.1).
    pub require_encryption: bool,
    /// The advertised `to_issuer` entries the wallet can send, verbatim,
    /// for the host to place in its key proofs. A `hash_commitment`
    /// entry the wallet cannot send (an unsupported `alg` or
    /// `encoding`) is not here — and made the whole configuration
    /// unusable when it was `required`.
    pub to_issuer: Vec<Value>,
    /// At least one `to_issuer` entry is of a type the engine knows, so
    /// the wallet needs the credential type to derive a commitment from.
    pub to_issuer_recognised: bool,
    /// The advertised `to_wallet` entries, verbatim, so the client can
    /// check what it receives and refuse a response that lacks one
    /// (§7.2).
    pub to_wallet: Vec<Value>,
    /// Why the wallet must not request the credential, when it must not:
    /// a `to_wallet` `hash_commitment` entry with an unrecognised `alg`
    /// or `encoding`, or a `required` `to_issuer` entry it cannot send
    /// (§§4.1, 5). The reason never carries the content.
    pub unusable: Option<String>,
    /// A `to_issuer` entry is `required`, so a key proof that can carry
    /// auxiliary data is needed.
    pub required_to_issuer: bool,
}

/// Why a credential configuration's secret delivery could not be read.
/// The text never carries the offending content.
#[derive(Debug, thiserror::Error)]
pub enum SecretDeliveryError {
    /// The `auxiliary_data_supported` advertisement is malformed (§5):
    /// not an object, neither `to_wallet` nor `to_issuer`, a non-empty
    /// array rule broken, a duplicate (type, path), a `hash_commitment`
    /// entry without a string `alg` or a valid claims path, a value
    /// where metadata belongs, or a `required` in the wrong place or
    /// shape.
    #[error("oid4vci: the issuer metadata secret delivery advertisement is malformed: {0}")]
    MalformedAdvertisement(String),
    /// `auxiliary_data` MUST NOT appear in issuer metadata (§7).
    #[error("oid4vci: the issuer metadata secret delivery advertisement is malformed: {0}")]
    AuxiliaryDataInIssuerMetadata(String),
}

impl SecretDeliveryError {
    /// The stable reason, without content.
    #[must_use]
    pub fn reason(&self) -> String {
        self.to_string()
    }
}

/// Reads one credential configuration's secret delivery advertisement
/// (`secretDeliveryOf`): the `auxiliary_data_supported` member, and the
/// §7 rule that `auxiliary_data` MUST NOT appear in the issuer's
/// `credential_metadata`. An absent advertisement is the zero value; a
/// malformed one fails closed.
pub fn secret_delivery_of(configuration: &Value) -> Result<SecretDelivery, SecretDeliveryError> {
    let mut delivery = SecretDelivery::default();

    // §7: auxiliary_data MUST NOT appear in the issuer's
    // credential_metadata (it carries Secret Values; the issuer metadata
    // is an advertisement, not a delivery).
    let credential_metadata = configuration.get("credential_metadata");
    if let Some(metadata) = credential_metadata.filter(|v| v.is_object()) {
        if metadata.get(AUXILIARY_DATA_MEMBER).is_some() {
            return Err(SecretDeliveryError::AuxiliaryDataInIssuerMetadata(
                "auxiliary_data in credential_metadata".to_owned(),
            ));
        }
    }

    let advertisement = match configuration.get("auxiliary_data_supported") {
        Some(value) if !value.is_null() => value,
        _ => return Ok(delivery),
    };

    // §5: an object with at least one of to_wallet and to_issuer.
    let Some(advertisement) = advertisement.as_object() else {
        return Err(SecretDeliveryError::MalformedAdvertisement(
            "auxiliary_data_supported is not an object".to_owned(),
        ));
    };
    let to_wallet = advertisement.get("to_wallet");
    let to_issuer = advertisement.get("to_issuer");
    if to_wallet.is_none() && to_issuer.is_none() {
        return Err(SecretDeliveryError::MalformedAdvertisement(
            "auxiliary_data_supported has neither to_wallet nor to_issuer".to_owned(),
        ));
    }

    if let Some(to_wallet) = to_wallet {
        let entries = parse_aux_entries(to_wallet, "to_wallet")?;
        // §7.1: a to_wallet hash_commitment entry carries a Secret Value,
        // so the response must be encrypted.
        delivery.require_encryption = entries
            .iter()
            .any(|entry| entry.typ == AUX_TYPE_HASH_COMMITMENT);
        // §4.1: every to_wallet entry of a type the wallet knows must be
        // one it can check — MUST NOT request the credential otherwise.
        for entry in &entries {
            if entry.typ == AUX_TYPE_HASH_COMMITMENT && !entry.sendable {
                delivery.unusable = Some(
                    "a to_wallet entry has an alg or encoding this wallet does not recognise"
                        .to_owned(),
                );
            }
        }
        delivery.to_wallet = entry_values(to_wallet);
    }

    if let Some(to_issuer) = to_issuer {
        let entries = parse_aux_entries(to_issuer, "to_issuer")?;
        let values = entry_values(to_issuer);
        for (entry, value) in entries.iter().zip(&values) {
            match entry {
                // MUST NOT be sent; required, the credential must not be
                // requested either (§5).
                AuxEntry {
                    typ,
                    sendable: false,
                    required: true,
                } if typ.as_str() == AUX_TYPE_HASH_COMMITMENT => {
                    delivery.unusable = Some(
                        "a required to_issuer entry has an alg or encoding this wallet does not recognise"
                            .to_owned(),
                    );
                }
                // A required entry of an unrecognised type cannot be sent
                // either (§3: the recipient ignores it).
                AuxEntry {
                    typ,
                    required: true,
                    sendable: false,
                } if typ.as_str() != AUX_TYPE_HASH_COMMITMENT => {
                    delivery.unusable = Some(
                        "a required to_issuer entry is of a type this wallet does not recognise"
                            .to_owned(),
                    );
                }
                _ => {
                    // The credential type is needed only for an entry the
                    // wallet will send, not for one dropped above.
                    delivery.to_issuer_recognised =
                        delivery.to_issuer_recognised || entry.typ == AUX_TYPE_HASH_COMMITMENT;
                    delivery.required_to_issuer = delivery.required_to_issuer || entry.required;
                    delivery.to_issuer.push(value.clone());
                }
            }
        }
    }

    Ok(delivery)
}

/// Whether the wallet may request the credential (the `usable` verdict,
/// §§4.1, 5): every `to_wallet` `hash_commitment` entry and every
/// `required` `to_issuer` entry is one it recognises, and a `required`
/// `to_issuer` entry has a key proof type to ride (the configuration
/// must declare a `jwt` or `attestation` proof — the two the engine can
/// inspect for auxiliary data).
pub fn usable(delivery: &SecretDelivery, configuration: &Value) -> Result<(), AuxUnsupported> {
    if let Some(reason) = &delivery.unusable {
        return Err(AuxUnsupported {
            reason: reason.clone(),
        });
    }
    if delivery.required_to_issuer && !carries_auxiliary_data(configuration) {
        return Err(AuxUnsupported {
            reason: "a required to_issuer entry needs a jwt or attestation key proof".to_owned(),
        });
    }
    Ok(())
}

/// Why the wallet must not request the credential: the
/// `AUXILIARY_DATA_UNSUPPORTED` refusal (the Go
/// `errAuxiliaryDataUnsupported`), answered at the selection — before
/// any authorization or request.
#[derive(Debug, thiserror::Error)]
#[error("the credential configuration needs auxiliary data this wallet cannot handle: {reason}")]
pub struct AuxUnsupported {
    /// The reason, without content.
    pub reason: String,
}

/// The configuration declares a key proof type in which the wallet can
/// place auxiliary_data and the engine can inspect it (the `jwt` or
/// `attestation` of `proof_types_supported`).
pub fn carries_auxiliary_data(configuration: &Value) -> bool {
    configuration
        .get("proof_types_supported")
        .and_then(Value::as_object)
        .is_some_and(|proofs| proofs.contains_key("jwt") || proofs.contains_key("attestation"))
}

/// Whether a response-level `credential_metadata` object carries the
/// `auxiliary_data` member (§7.1's check: a PLAIN response carrying it
/// travelled a Secret Value unencrypted — the flow refuses, nothing
/// logged).
pub fn has_auxiliary_data_member(credential_metadata: &Value) -> bool {
    credential_metadata
        .as_object()
        .is_some_and(|object| object.contains_key(AUXILIARY_DATA_MEMBER))
}

// ─── The entry parse (§5) ───────────────────────────────────────────────────

/// One parsed entry: the type, whether it is required, and whether the
/// wallet can send it (a `hash_commitment` entry whose `alg` and
/// `encoding` it recognises).
#[derive(Debug)]
struct AuxEntry {
    typ: String,
    required: bool,
    sendable: bool,
}

/// The values of a parsed entries array, verbatim (the host places these
/// in its proofs; the client checks these against its response).
fn entry_values(raw: &Value) -> Vec<Value> {
    raw.as_array().cloned().unwrap_or_default()
}

/// Parses one entries list (§5): a non-empty array of entry objects, no
/// two `hash_commitment` entries of the same (type, path).
fn parse_aux_entries(raw: &Value, list: &str) -> Result<Vec<AuxEntry>, SecretDeliveryError> {
    let malformed =
        |why: &str| SecretDeliveryError::MalformedAdvertisement(format!("{list} {why}"));
    let Some(entries) = raw.as_array().filter(|entries| !entries.is_empty()) else {
        return Err(malformed("is not a non-empty array"));
    };

    let mut seen: Vec<String> = Vec::new();
    let mut parsed: Vec<AuxEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        let parsed_entry = parse_aux_entry(entry, list)?;
        if parsed_entry.typ == AUX_TYPE_HASH_COMMITMENT {
            // The duplicate key: (type, path) — the entry's path as the
            // compacted normal form.
            if let Some(key) = &parsed_entry.path_key {
                if seen.contains(key) {
                    return Err(malformed("has two entries of the same type and path"));
                }
                seen.push(key.clone());
            }
        }
        parsed.push(AuxEntry {
            typ: parsed_entry.typ,
            required: parsed_entry.required,
            sendable: parsed_entry.sendable,
        });
    }
    Ok(parsed)
}

/// One parsed entry, with its duplicate-detection path key.
#[derive(Debug)]
struct AuxEntryParsed {
    typ: String,
    required: bool,
    sendable: bool,
    path_key: Option<String>,
}

/// Parses one entry (§5): an object with a string `type`; a
/// `hash_commitment` entry needs a string `alg` and a valid claims path,
/// carries no `opening` or `commitment` at any depth (values, never
/// metadata), and its `alg`/`encoding` decide whether the wallet can send
/// it; a `to_issuer` entry may carry a boolean `required`.
fn parse_aux_entry(entry: &Value, list: &str) -> Result<AuxEntryParsed, SecretDeliveryError> {
    let malformed =
        |why: &str| SecretDeliveryError::MalformedAdvertisement(format!("{list} {why}"));
    let Some(object) = entry.as_object() else {
        return Err(malformed("has an entry that is not an object"));
    };
    let Some(typ) = object.get("type").and_then(Value::as_str) else {
        return Err(malformed(
            "has an entry that is not an object with a string type",
        ));
    };

    // required: only to_issuer entries may carry it, and it is a boolean.
    let required = match object.get("required") {
        Some(value) => {
            if list != "to_issuer" {
                return Err(malformed("has a required member"));
            }
            if !value.is_boolean() {
                return Err(malformed("has a required member that is not a boolean"));
            }
            value.as_bool().unwrap_or(false)
        }
        None => false,
    };

    if typ != AUX_TYPE_HASH_COMMITMENT {
        // §3: a recipient ignores an entry of an unrecognised type — its
        // own parameters are its own. Only required was read.
        return Ok(AuxEntryParsed {
            typ: typ.to_owned(),
            required,
            sendable: false,
            path_key: None,
        });
    }

    // Values, never metadata: no opening or commitment member at any
    // depth (§4.1 — the engine must never even hold one).
    if contains_member(entry, "opening") || contains_member(entry, "commitment") {
        return Err(malformed(
            "has an entry carrying an opening or a commitment",
        ));
    }

    // A hash_commitment entry needs a string alg (§4.1).
    let alg = object
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if alg.is_empty() {
        return Err(malformed(
            "has a hash_commitment entry without a string alg",
        ));
    }
    // ... and a valid claims path (OpenID4VCI App. C).
    let path_key = claims_path_key(object.get("path").unwrap_or(&Value::Null))
        .ok_or_else(|| malformed("has a hash_commitment entry without a valid claims path"))?;

    // The encoding: absent, or one the spec defines.
    let encoding_ok = match object.get("encoding") {
        None => true,
        Some(value) => value
            .as_str()
            .is_some_and(|encoding| SUPPORTED_ENCODINGS.contains(&encoding)),
    };
    let sendable = SUPPORTED_ALGS.contains(&alg.as_str()) && encoding_ok;

    Ok(AuxEntryParsed {
        typ: typ.to_owned(),
        required,
        sendable,
        path_key: Some(path_key),
    })
}

/// Whether any member of the JSON object tree carries `name`.
fn contains_member(value: &Value, name: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(name) || object.values().any(|v| contains_member(v, name))
        }
        Value::Array(items) => items.iter().any(|item| contains_member(item, name)),
        _ => false,
    }
}

/// The normal form of a claims path (OpenID4VCI App. C: a non-empty array
/// of strings, nulls, and non-negative integers), for the duplicate
/// detection: `[\"p\", 1]` and `[\"p\", 1.0]` must detect as the same
/// path.
fn claims_path_key(raw: &Value) -> Option<String> {
    let items = raw.as_array()?;
    if items.is_empty() {
        return None;
    }
    let mut normal = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Null => normal.push(Value::Null),
            Value::String(text) => normal.push(Value::String(text.clone())),
            Value::Number(number) => {
                // A non-negative integer only. A whole float (1.0) is its
                // integer (the JSON spelling must not change the path).
                let unsigned = number
                    .as_u64()
                    .or_else(|| number.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))?;
                normal.push(serde_json::Value::from(unsigned));
            }
            _ => return None,
        }
    }
    serde_json::to_string(&normal).ok()
}
