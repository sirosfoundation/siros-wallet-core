//! The `secret_seed` an issuer delivered with a nym_auth credential: the `opening` of its
//! `hash_commitment` Auxiliary Data Entry for `ssc` (privatedata 3.1, Section 5A; Credential
//! Auxiliary Data, Section 4.1; nym_auth rulebook, "Issuance of the seeds").

use itertools::Itertools;
use siros_codec::base64url;
use siros_codec::json::{Json, JsonFault};
use siros_codec::Base64Error;
use siros_credential::Credential;
use siros_zkp_req_nym_auth::attestation::SecretSeed;
use siros_zkp_req_nym_auth::catalogue::MDOC_DOCTYPE;
use zeroize::Zeroizing;

/// The claim the seed commits to.
const SSC: [&str; 2] = [MDOC_DOCTYPE, "ssc"];

/// Why a credential gives no `secret_seed`. A credential without one answers no nym_auth query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum NoSeed {
    /// The strict reader refuses an `auxiliary_data` value.
    Entries(#[source] JsonFault),
    /// An `auxiliary_data` value is no JSON array.
    EntriesNotArray,
    /// No `hash_commitment` entry names `ssc`.
    Missing,
    /// Several do (Credential Auxiliary Data, Section 3).
    Repeated,
    /// The entry's `alg` is not `sha-256`.
    Algorithm,
    /// The entry has an `encoding`, which a seed's `hash_commitment` leaves out.
    Encoding,
    /// The entry has no `opening`.
    OpeningAbsent,
    /// The entry's `opening` is not a string.
    OpeningNotString,
    /// The entry's `opening` is not unpadded base64url.
    OpeningNotBase64url(#[source] Base64Error),
    /// The entry's `opening` decodes to this many bytes, where a seed has 16.
    OpeningLength(usize),
}

impl NoSeed {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Entries(_) | Self::EntriesNotArray => "seed_entries",
            Self::Missing => "seed_missing",
            Self::Repeated => "seed_repeated",
            Self::Algorithm => "seed_algorithm",
            Self::Encoding => "seed_encoding",
            Self::OpeningAbsent
            | Self::OpeningNotString
            | Self::OpeningNotBase64url(_)
            | Self::OpeningLength(_) => "seed_opening",
        }
    }
}

/// The `secret_seed` delivered with `credential`: the opening of its one `hash_commitment`
/// entry for `ssc`.
pub(crate) fn delivered(credential: &Credential) -> Result<SecretSeed, NoSeed> {
    let entries: Vec<Json> = credential
        .auxiliary_data()
        .iter()
        .map(|value| match Json::parse_unique(value.json().as_bytes()) {
            Ok(Json::Array(entries)) => Ok(entries),
            Ok(_) => Err(NoSeed::EntriesNotArray),
            Err(fault) => Err(NoSeed::Entries(fault)),
        })
        .flatten_ok()
        .try_collect()?;
    let entry = entries
        .iter()
        .filter(|entry| commits_to_ssc(entry))
        .at_most_one()
        .map_err(|_| NoSeed::Repeated)?
        .ok_or(NoSeed::Missing)?;
    opening(entry)
}

/// The string member `name` of `entry`.
fn text<'e>(entry: &'e Json, name: &str) -> Option<&'e str> {
    match entry.member(name) {
        Some(Json::String(text)) => Some(text),
        _ => None,
    }
}

/// Whether `entry` is a `hash_commitment` of the claim `ssc`.
fn commits_to_ssc(entry: &Json) -> bool {
    let path = match entry.member("path") {
        Some(Json::Array(path)) => path,
        _ => return false,
    };
    text(entry, "type") == Some("hash_commitment")
        && path
            .iter()
            .map(|component| match component {
                Json::String(component) => Some(component.as_str()),
                _ => None,
            })
            .eq(SSC.map(Some))
}

/// The seed `entry` opens with: `sha-256`, no `encoding`, and a 16-byte `opening`.
fn opening(entry: &Json) -> Result<SecretSeed, NoSeed> {
    if text(entry, "alg") != Some("sha-256") {
        return Err(NoSeed::Algorithm);
    }
    if entry.member("encoding").is_some() {
        return Err(NoSeed::Encoding);
    }
    let opening = match entry.member("opening") {
        None => return Err(NoSeed::OpeningAbsent),
        Some(Json::String(opening)) => opening,
        Some(_) => return Err(NoSeed::OpeningNotString),
    };
    let decoded = Zeroizing::new(base64url::decode(opening).map_err(NoSeed::OpeningNotBase64url)?);
    let mut seed = Zeroizing::new([0u8; 16]);
    if decoded.len() != seed.len() {
        return Err(NoSeed::OpeningLength(decoded.len()));
    }
    for (slot, byte) in seed.iter_mut().zip(decoded.iter()) {
        *slot = *byte;
    }
    Ok(SecretSeed::new(seed))
}
