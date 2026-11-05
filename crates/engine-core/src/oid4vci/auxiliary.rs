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

use crate::claims_path::{ClaimsPath, ClaimsPathError};
use crate::oid4vci::types::CredentialFormat;

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
    /// The advertised `to_issuer` entries the wallet sends, verbatim, for
    /// the host to place in its key proofs: each `hash_commitment` entry
    /// it recognises, and each optional entry of another type.
    pub to_issuer: Vec<Value>,
    /// Why the wallet does not recognise each optional `to_issuer`
    /// `hash_commitment` entry it leaves out of `to_issuer`: it MUST NOT
    /// send them (§4.1).
    pub to_issuer_left_out: Vec<Unrecognised>,
    /// At least one `to_issuer` entry is of a type the engine knows, so
    /// the wallet needs the credential type to derive a commitment from.
    pub to_issuer_recognised: bool,
    /// The advertised `to_wallet` entries, verbatim, so the client can
    /// check what it receives and refuse a response that lacks one
    /// (§7.2).
    pub to_wallet: Vec<Value>,
    /// Why the wallet must not request the credential, when it must not
    /// (§§4.1, 5): the reason of the first entry that forbids it.
    pub unusable: Option<UnsupportedReason>,
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
    /// entry without a string `alg` or without a `path`, a value where
    /// metadata belongs, or a `required` in the wrong place or shape.
    #[error("oid4vci: the issuer metadata secret delivery advertisement is malformed: {0}")]
    MalformedAdvertisement(String),
    /// A `hash_commitment` entry's `path` is no claims path pointer into
    /// a Credential of the configuration's format (§4.1, OpenID4VCI 1.0
    /// Appendix C).
    #[error(
        "oid4vci: the issuer metadata secret delivery advertisement is malformed: \
         {list} has a hash_commitment entry whose path is no claims path pointer: {error}"
    )]
    MalformedClaimsPath {
        /// The entries list: `to_wallet` or `to_issuer`.
        list: &'static str,
        /// Why the path is no claims path pointer.
        error: ClaimsPathError,
    },
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
    // The format decides how an entry's claims path pointer reads
    // (OpenID4VCI 1.0 Appendix C).
    let format = configuration
        .get("format")
        .and_then(Value::as_str)
        .and_then(CredentialFormat::from_identifier);

    if let Some(to_wallet) = to_wallet {
        let entries = parse_aux_entries(to_wallet, "to_wallet", format)?;
        // §7.1: a to_wallet hash_commitment entry carries a Secret Value,
        // so the response must be encrypted.
        delivery.require_encryption = entries
            .iter()
            .any(|entry| matches!(entry.kind, EntryKind::HashCommitment { .. }));
        // §4.1: every to_wallet entry of a type the wallet knows must be
        // one it can check — MUST NOT request the credential otherwise.
        delivery.unusable = entries.iter().find_map(|entry| match entry.kind {
            EntryKind::HashCommitment {
                recognition: Recognition::Unrecognised(why),
                ..
            } => Some(UnsupportedReason::ToWallet(why)),
            EntryKind::HashCommitment {
                recognition: Recognition::Recognised,
                ..
            }
            | EntryKind::OtherType => None,
        });
        delivery.to_wallet = entries.iter().map(|entry| entry.value.clone()).collect();
    }

    if let Some(to_issuer) = to_issuer {
        for entry in parse_aux_entries(to_issuer, "to_issuer", format)? {
            let refusal = match (entry.kind, entry.required) {
                // The wallet sends it, and needs the credential type to
                // derive its commitment.
                (
                    EntryKind::HashCommitment {
                        recognition: Recognition::Recognised,
                        ..
                    },
                    required,
                ) => {
                    delivery.to_issuer_recognised = true;
                    delivery.required_to_issuer = delivery.required_to_issuer || required;
                    delivery.to_issuer.push(entry.value.clone());
                    None
                }
                // §4.1: MUST NOT be sent; required, the credential MUST NOT
                // be requested either.
                (
                    EntryKind::HashCommitment {
                        recognition: Recognition::Unrecognised(why),
                        ..
                    },
                    true,
                ) => Some(UnsupportedReason::RequiredToIssuer(why)),
                (
                    EntryKind::HashCommitment {
                        recognition: Recognition::Unrecognised(why),
                        ..
                    },
                    false,
                ) => {
                    delivery.to_issuer_left_out.push(why);
                    None
                }
                // §5: the wallet MUST recognise a required entry's type
                // before it requests the credential.
                (EntryKind::OtherType, true) => {
                    Some(UnsupportedReason::RequiredToIssuerOfOtherType)
                }
                // §3: the wallet ignores it; it rides verbatim, for the
                // host.
                (EntryKind::OtherType, false) => {
                    delivery.to_issuer.push(entry.value.clone());
                    None
                }
            };
            delivery.unusable = delivery.unusable.or(refusal);
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
    if let Some(reason) = delivery.unusable {
        return Err(AuxUnsupported { reason });
    }
    if delivery.required_to_issuer && !carries_auxiliary_data(configuration) {
        return Err(AuxUnsupported {
            reason: UnsupportedReason::NoCarrierProof,
        });
    }
    Ok(())
}

/// Why the wallet must not request the credential: the
/// `AUXILIARY_DATA_UNSUPPORTED` refusal (the Go
/// `errAuxiliaryDataUnsupported`), answered at the selection — before
/// any authorization or request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the credential configuration needs auxiliary data this wallet cannot handle: {reason}")]
pub struct AuxUnsupported {
    /// The reason, without content.
    pub reason: UnsupportedReason,
}

/// Why the wallet must not request the credential (§§4.1, 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnsupportedReason {
    /// A `to_wallet` `hash_commitment` entry the wallet does not
    /// recognise, so it cannot check the entry it receives (§4.1).
    #[error("a to_wallet entry has {0}")]
    ToWallet(Unrecognised),
    /// A required `to_issuer` `hash_commitment` entry the wallet does not
    /// recognise (§§4.1, 5).
    #[error("a required to_issuer entry has {0}")]
    RequiredToIssuer(Unrecognised),
    /// A required `to_issuer` entry of a type the wallet does not
    /// recognise (§5).
    #[error("a required to_issuer entry is of a type this wallet does not recognise")]
    RequiredToIssuerOfOtherType,
    /// A required `to_issuer` entry, and no `jwt` or `attestation` key
    /// proof to carry it.
    #[error("a required to_issuer entry needs a jwt or attestation key proof")]
    NoCarrierProof,
}

/// Why the wallet does not recognise a `hash_commitment` entry (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unrecognised {
    /// The configuration's `format` is absent or outside OpenID4VCI 1.0
    /// Appendix A, so Appendix C gives the entry's `path` no semantics.
    #[error("a path in a credential format this wallet does not recognise")]
    Format,
    /// An `alg` the wallet does not support (§4.1 defines `sha-256`).
    #[error("an alg this wallet does not recognise")]
    Alg,
    /// An `encoding` the wallet does not support (§4.1 defines
    /// `base64url`, `base64` and `hex`).
    #[error("an encoding this wallet does not recognise")]
    Encoding,
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

/// One advertised entry, parsed.
#[derive(Debug)]
struct AuxEntry<'a> {
    /// The entry as advertised, for the host and the client.
    value: &'a Value,
    /// The entry's `required` (`to_issuer` only, §5).
    required: bool,
    /// What the entry is to the wallet.
    kind: EntryKind,
}

/// What an advertised entry is to the wallet (§§3, 4.1).
#[derive(Debug)]
enum EntryKind {
    /// A `hash_commitment` entry (§4.1).
    HashCommitment {
        /// Its claims path pointer: with its type, the duplicate key.
        path: ClaimsPath,
        /// Whether the wallet can check and send it.
        recognition: Recognition,
    },
    /// An entry of a type the wallet does not recognise (§3).
    OtherType,
}

/// Whether the wallet recognises a `hash_commitment` entry (§4.1).
#[derive(Debug, Clone, Copy)]
enum Recognition {
    /// It recognises the entry's credential format, `alg` and `encoding`:
    /// it can check the entry and send it.
    Recognised,
    /// It does not, for this reason.
    Unrecognised(Unrecognised),
}

/// Parses one entries list (§5): a non-empty array of entry objects, no
/// two `hash_commitment` entries of the same (type, path). `format` is the
/// configuration's credential format, when Appendix A of OpenID4VCI 1.0
/// defines it.
fn parse_aux_entries<'a>(
    raw: &'a Value,
    list: &'static str,
    format: Option<CredentialFormat>,
) -> Result<Vec<AuxEntry<'a>>, SecretDeliveryError> {
    let malformed =
        |why: &str| SecretDeliveryError::MalformedAdvertisement(format!("{list} {why}"));
    let Some(entries) = raw.as_array().filter(|entries| !entries.is_empty()) else {
        return Err(malformed("is not a non-empty array"));
    };
    let parsed = entries
        .iter()
        .map(|entry| parse_aux_entry(entry, list, format))
        .collect::<Result<Vec<_>, _>>()?;

    // The duplicate key: (type, path), the path as its parsed pointer.
    let paths: Vec<&ClaimsPath> = parsed
        .iter()
        .filter_map(|entry| match &entry.kind {
            EntryKind::HashCommitment { path, .. } => Some(path),
            EntryKind::OtherType => None,
        })
        .collect();
    let duplicate = paths
        .iter()
        .enumerate()
        .any(|(at, path)| paths.iter().take(at).any(|earlier| earlier == path));
    if duplicate {
        return Err(malformed("has two entries of the same type and path"));
    }
    Ok(parsed)
}

/// Parses one entry (§5): an object with a string `type`; a
/// `hash_commitment` entry needs a string `alg` and a claims path pointer,
/// carries no `opening` or `commitment` at any depth (values, never
/// metadata), and its credential format, `alg` and `encoding` decide
/// whether the wallet recognises it; a `to_issuer` entry may carry a
/// boolean `required`.
fn parse_aux_entry<'a>(
    entry: &'a Value,
    list: &'static str,
    format: Option<CredentialFormat>,
) -> Result<AuxEntry<'a>, SecretDeliveryError> {
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
        return Ok(AuxEntry {
            value: entry,
            required,
            kind: EntryKind::OtherType,
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
    // ... and a claims path pointer (§4.1), parsed here, where it enters,
    // by the semantics of the credential's format, or by Appendix C's
    // grammar alone for a format Appendix A does not define (OpenID4VCI
    // 1.0 Appendices A and C).
    let Some(path) = object.get("path") else {
        return Err(malformed("has a hash_commitment entry without a path"));
    };
    let path = ClaimsPath::parse(path, format)
        .map_err(|error| SecretDeliveryError::MalformedClaimsPath { list, error })?;

    // The encoding: absent, or one the spec defines.
    let encoding_ok = match object.get("encoding") {
        None => true,
        Some(value) => value
            .as_str()
            .is_some_and(|encoding| SUPPORTED_ENCODINGS.contains(&encoding)),
    };
    let recognition = if format.is_none() {
        Recognition::Unrecognised(Unrecognised::Format)
    } else if !SUPPORTED_ALGS.contains(&alg.as_str()) {
        Recognition::Unrecognised(Unrecognised::Alg)
    } else if !encoding_ok {
        Recognition::Unrecognised(Unrecognised::Encoding)
    } else {
        Recognition::Recognised
    };

    Ok(AuxEntry {
        value: entry,
        required,
        kind: EntryKind::HashCommitment { path, recognition },
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
