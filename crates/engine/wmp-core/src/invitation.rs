//! Invitations: self-contained, signed objects that bootstrap a WMP session
//! — the mirror of go-wmp's `invitation.go` (wmp-invitation.md §2).

use std::sync::Mutex;

use rustc_hash::FxHashMap;

use crate::error::{RpcError, ERR_NOT_AUTHORIZED};
use crate::handler::HandlerError;
use crate::token::base64url_unpadded;
use crate::types::Capabilities;
use serde::{Deserialize, Serialize};

/// The invitation purpose: bootstrap a session.
pub const INVITATION_PURPOSE_SESSION: &str = "session";
/// The invitation purpose: OID4VCI issuance.
pub const INVITATION_PURPOSE_OID4VCI: &str = "oid4vci";
/// The invitation purpose: OID4VP presentation.
pub const INVITATION_PURPOSE_OID4VP: &str = "oid4vp";
/// The invitation purpose: join a group.
pub const INVITATION_PURPOSE_JOIN: &str = "join";

/// Verifies the signature on an [`Invitation`]. Implementations must check
/// that the invitation was signed by the sender (or a delegate authorized by
/// the sender) and that the key material is bound to the provider/sender
/// identifier.
pub trait InvitationVerifier: Send + Sync {
    /// Verifies the invitation's signature.
    fn verify_invitation(&self, inv: &Invitation) -> Result<(), HandlerError>;
}

/// A self-contained, signed object that bootstraps a WMP session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Invitation {
    /// The provider whose session this invitation bootstraps.
    pub provider: String,
    /// The sender of the invitation.
    pub sender: String,
    /// The unguessable nonce.
    pub nonce: String,
    /// The relay to reach the sender through.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay: String,
    /// The invitation's purpose.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    /// The session the invitation is for, when it names one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    /// A human-readable label.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// The capabilities the sender offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// When the invitation expires, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// The invitation's signature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// Why an invitation could not be read or validated.
#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    /// The URI is not an invitation URI.
    #[error("wmp: unrecognised invitation URI scheme: {0:?}")]
    UnrecognisedUri(String),
    /// The URI carries no data.
    #[error("wmp: invitation URI missing 'data' parameter")]
    MissingData,
    /// The URI carries a `ref` parameter instead of data: fetch the URL to
    /// get the full invitation.
    #[error("wmp: invitation uses ref={0:?}: fetch the URL to get the full invitation")]
    RefNotResolved(String),
    /// The HTTPS fallback URI carries no fragment.
    #[error("wmp: HTTPS invitation URI missing fragment")]
    MissingFragment,
    /// The encoded data is not base64url.
    #[error("wmp: decode invitation data: {0}")]
    Decode(String),
    /// The decoded bytes are not an invitation.
    #[error("wmp: unmarshal invitation: {0}")]
    Unmarshal(String),
    /// The signature verification failed.
    #[error("wmp: invitation signature verification failed")]
    Signature,
    /// The nonce is missing, unknown or expired.
    #[error("wmp: {0}")]
    Nonce(String),
    /// The provider names no domain for the HTTPS fallback.
    #[error("wmp: cannot extract domain from provider {0:?}")]
    NoDomain(String),
    /// The entropy source is missing.
    #[error("wmp: no entropy source for the invitation nonce")]
    NoEntropy,
}

impl Invitation {
    /// Whether the invitation has expired at `now` (RFC 3339, unix
    /// seconds). An invitation that names no expiry has not expired; one
    /// whose expiry cannot be read is treated as expired, refusing rather
    /// than guessing.
    pub fn is_expired(&self, now: i64) -> bool {
        match &self.expires_at {
            None => false,
            Some(expires) => match rfc3339_to_unix(expires) {
                Some(expires) => now > expires,
                None => true,
            },
        }
    }

    /// The JCS-ready JSON object for signing: every field except the
    /// signature. The caller is responsible for JCS canonicalization and
    /// JWS construction — this only produces the JSON to be signed.
    pub fn signing_payload(&self) -> Result<Vec<u8>, InvitationError> {
        let mut copy = self.clone();
        copy.signature = String::new();
        serde_json::to_vec(&copy).map_err(|err| InvitationError::Unmarshal(err.to_string()))
    }

    /// The invitation as a `wmp://invite?data=<base64url>` URI.
    pub fn uri(&self) -> Result<String, InvitationError> {
        let data =
            serde_json::to_vec(self).map_err(|err| InvitationError::Unmarshal(err.to_string()))?;
        Ok(format!("wmp://invite?data={}", base64url_unpadded(&data)))
    }

    /// The invitation as an HTTPS fallback URI on the provider's domain:
    /// `https://<domain>/wmp/invite#<base64url>`.
    pub fn https_uri(&self) -> Result<String, InvitationError> {
        let domain = crate::discovery::extract_domain(&self.provider);
        if domain.is_empty() {
            return Err(InvitationError::NoDomain(self.provider.clone()));
        }
        let data =
            serde_json::to_vec(self).map_err(|err| InvitationError::Unmarshal(err.to_string()))?;
        Ok(format!(
            "https://{domain}/wmp/invite#{}",
            base64url_unpadded(&data)
        ))
    }
}

/// Creates a fresh unguessable nonce: `inv-` plus 128 entropy bits,
/// base64url unpadded. go-wmp samples `crypto/rand`; the mirror takes its
/// entropy from the caller.
pub fn generate_nonce(
    entropy: &crate::sessionservice::EntropyFn,
) -> Result<String, InvitationError> {
    let mut bytes = [0u8; 16];
    if !entropy(&mut bytes) {
        return Err(InvitationError::NoEntropy);
    }
    Ok(format!("inv-{}", base64url_unpadded(&bytes)))
}

/// Creates a new unsigned invitation for `provider` and `sender`, expiring
/// `ttl_secs` after `now` (unix seconds). The caller must set the signature
/// after signing the payload with the sender's key.
pub fn new_invitation(
    provider: &str,
    sender: &str,
    ttl_secs: i64,
    now: i64,
    entropy: &crate::sessionservice::EntropyFn,
) -> Result<Invitation, InvitationError> {
    Ok(Invitation {
        provider: provider.to_owned(),
        sender: sender.to_owned(),
        nonce: generate_nonce(entropy)?,
        purpose: INVITATION_PURPOSE_SESSION.to_owned(),
        expires_at: Some(unix_to_rfc3339(now + ttl_secs)),
        ..Invitation::default()
    })
}

/// Parses an invitation from a `wmp://invite?data=...` URI or an
/// `https://...#...` fallback URI. Does **not** verify the signature.
pub fn parse_invitation_uri(uri: &str) -> Result<Invitation, InvitationError> {
    let encoded = if uri.starts_with("wmp://invite") {
        let query = uri.split_once('?').map_or("", |(_, q)| q);
        let data = query_param(query, "data");
        if data.is_empty() {
            let r#ref = query_param(query, "ref");
            if !r#ref.is_empty() {
                return Err(InvitationError::RefNotResolved(r#ref));
            }
            return Err(InvitationError::MissingData);
        }
        data
    } else if uri.contains("/wmp/invite#") {
        let fragment = uri.rsplit_once('#');
        match fragment {
            Some((_, encoded)) if !encoded.is_empty() => encoded.to_owned(),
            _ => return Err(InvitationError::MissingFragment),
        }
    } else {
        return Err(InvitationError::UnrecognisedUri(uri.to_owned()));
    };
    let decoded = decode_base64url(&encoded)?;
    parse_invitation_json(&decoded)
}

/// Parses an invitation from raw JSON bytes. Does **not** verify the
/// signature.
pub fn parse_invitation_json(data: &[u8]) -> Result<Invitation, InvitationError> {
    serde_json::from_slice(data).map_err(|err| InvitationError::Unmarshal(err.to_string()))
}

/// The `data` member of a `wmp://invite` query string.
fn query_param(query: &str, name: &str) -> String {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return value.to_owned();
        }
    }
    String::new()
}

/// Unpadded base64url decoding.
fn decode_base64url(encoded: &str) -> Result<Vec<u8>, InvitationError> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(InvitationError::Decode("odd length".to_owned()));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let Some(v) = value(b) else {
            return Err(InvitationError::Decode("invalid character".to_owned()));
        };
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Tracks issued invitation nonces.
pub trait InvitationStore: Send + Sync {
    /// Stores a nonce with its invitation, refusing one that already exists.
    fn put(&self, nonce: &str, inv: &Invitation) -> Result<(), InvitationError>;

    /// Atomically removes a nonce and answers its invitation, at `now`:
    /// `None` when the nonce is unknown or expired.
    fn consume(&self, now: i64, nonce: &str) -> Option<Invitation>;

    /// Removes expired nonces and answers how many.
    fn cleanup(&self, now: i64) -> Result<usize, InvitationError>;
}

/// A thread-safe in-memory [`InvitationStore`].
#[derive(Default)]
pub struct MemoryInvitationStore {
    nonces: Mutex<FxHashMap<String, Invitation>>,
}

impl MemoryInvitationStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl InvitationStore for MemoryInvitationStore {
    fn put(&self, nonce: &str, inv: &Invitation) -> Result<(), InvitationError> {
        let Ok(mut nonces) = self.nonces.lock() else {
            return Err(InvitationError::Nonce("store unavailable".to_owned()));
        };
        if nonces.contains_key(nonce) {
            return Err(InvitationError::Nonce(format!(
                "nonce {nonce:?} already exists"
            )));
        }
        nonces.insert(nonce.to_owned(), inv.clone());
        Ok(())
    }

    fn consume(&self, now: i64, nonce: &str) -> Option<Invitation> {
        let Ok(mut nonces) = self.nonces.lock() else {
            return None;
        };
        let inv = nonces.remove(nonce)?;
        if inv.is_expired(now) {
            return None;
        }
        Some(inv)
    }

    fn cleanup(&self, now: i64) -> Result<usize, InvitationError> {
        let Ok(mut nonces) = self.nonces.lock() else {
            return Err(InvitationError::Nonce("store unavailable".to_owned()));
        };
        let expired: Vec<String> = nonces
            .iter()
            .filter(|(_, inv)| inv.is_expired(now))
            .map(|(nonce, _)| nonce.clone())
            .collect();
        let count = expired.len();
        for nonce in expired {
            nonces.remove(&nonce);
        }
        Ok(count)
    }
}

/// Checks the `invitation_nonce` of a `wmp.session.create` request: the
/// nonce must exist, the invitation must not have expired, and its signature
/// — when a verifier is given — must verify. A failed verification is
/// treated the same as an invalid nonce: `-31002`.
pub fn validate_invitation_nonce(
    store: &dyn InvitationStore,
    now: i64,
    nonce: &str,
    verifier: Option<&dyn InvitationVerifier>,
) -> Result<Invitation, HandlerError> {
    if nonce.is_empty() {
        return Err(RpcError::new(
            ERR_NOT_AUTHORIZED,
            Some(serde_json::json!({ "reason": "missing invitation_nonce" })),
        )
        .into());
    }
    let Some(inv) = store.consume(now, nonce) else {
        return Err(RpcError::new(
            ERR_NOT_AUTHORIZED,
            Some(serde_json::json!({ "reason": "invalid_invitation_nonce" })),
        )
        .into());
    };
    if inv.is_expired(now) {
        return Err(RpcError::new(
            ERR_NOT_AUTHORIZED,
            Some(serde_json::json!({ "reason": "invitation expired" })),
        )
        .into());
    }
    if let Some(verifier) = verifier {
        verifier.verify_invitation(&inv).map_err(|_| {
            RpcError::new(
                ERR_NOT_AUTHORIZED,
                Some(serde_json::json!({ "reason": "invitation signature verification failed" })),
            )
        })?;
    }
    Ok(inv)
}

/// Minimal RFC 3339 (`YYYY-MM-DDTHH:MM:SS(.fff)?Z`) to unix seconds, for
/// expiry comparisons; `None` for anything the format does not cover.
fn rfc3339_to_unix(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    // The separators of the canonical form, by position.
    const SHAPE: &[(usize, u8)] = &[(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if bytes.len() < 20 || !bytes.ends_with(b"Z") {
        return None;
    }
    for &(position, expected) in SHAPE {
        if bytes.get(position).copied() != Some(expected) {
            return None;
        }
    }
    let two = |a: usize| -> Option<i64> {
        let first = bytes.get(a).copied()?;
        let second = bytes.get(a + 1).copied()?;
        if !first.is_ascii_digit() || !second.is_ascii_digit() {
            return None;
        }
        Some(((first - b'0') as i64) * 10 + (second - b'0') as i64)
    };
    let four = |start: usize| -> Option<i64> { Some(two(start)? * 100 + two(start + 2)?) };
    let year = four(0)?;
    let month = two(5)?;
    let day = two(8)?;
    let hour = two(11)?;
    let minute = two(14)?;
    let second = two(17)?;
    // Fractional seconds, when present, are ignored: expiry works at second
    // granularity.
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days from the civil date to 1970-01-01 — Howard Hinnant's algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Unix seconds to canonical RFC 3339 — the inverse of [`rfc3339_to_unix`].
fn unix_to_rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs / 60) % 60;
    let second = secs % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// The civil date of days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
