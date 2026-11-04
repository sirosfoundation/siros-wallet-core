//! OpenID4VP 1.0 B.3.3.1, a profile a transaction data type can include: the entry's
//! `transaction_data_hashes_alg` and the response's `transaction_data_hashes`, one hash per entry
//! the presentation authorizes, with the algorithm used.

#[cfg(feature = "resolve")]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "resolve")]
use blake2::{Blake2b, Blake2b512, Blake2s256, digest::consts::U32};
#[cfg(feature = "resolve")]
use k12::{ExtendableOutput, Kt128, Kt256};
#[cfg(feature = "resolve")]
use sha2::{Digest, Sha256, Sha384, Sha512};
#[cfg(feature = "resolve")]
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use siros_explain::Explain;

use crate::json::Node;
use crate::plugins::Member;
#[cfg(feature = "resolve")]
use crate::plugins::{JsonText, MemberTwice, MemberValue, Members};
use crate::refusal::{ErrorCode, ReprList, RequestRule};
use crate::request::Entry;

/// The response members B.3.3.1 defines.
pub static MEMBERS: [Member; 2] = [
    Member::claim("transaction_data_hashes"),
    Member::claim("transaction_data_hashes_alg"),
];

/// Every algorithm of the IANA "Named Information Hash Algorithm" registry B.3.3.1 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// `sha-256`.
    Sha256,
    /// `sha-256-128`: the leftmost 128 bits of SHA-256 (RFC 6920 §2).
    Sha256_128,
    /// `sha-256-120`: the leftmost 120 bits of SHA-256.
    Sha256_120,
    /// `sha-256-96`: the leftmost 96 bits of SHA-256.
    Sha256_96,
    /// `sha-256-64`: the leftmost 64 bits of SHA-256.
    Sha256_64,
    /// `sha-256-32`: the leftmost 32 bits of SHA-256.
    Sha256_32,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
    /// `sha3-224`.
    Sha3_224,
    /// `sha3-256`.
    Sha3_256,
    /// `sha3-384`.
    Sha3_384,
    /// `sha3-512`.
    Sha3_512,
    /// `blake2s-256`.
    Blake2s256,
    /// `blake2b-256`.
    Blake2b256,
    /// `blake2b-512`.
    Blake2b512,
    /// `k12-256`: KT128 with 32 bytes of output (RFC 9861 §6).
    K12_256,
    /// `k12-512`: KT256 with 64 bytes of output (RFC 9861 §6).
    K12_512,
}

impl HashAlgorithm {
    const ALL: [Self; 17] = [
        Self::Sha256,
        Self::Sha256_128,
        Self::Sha256_120,
        Self::Sha256_96,
        Self::Sha256_64,
        Self::Sha256_32,
        Self::Sha384,
        Self::Sha512,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Blake2s256,
        Self::Blake2b256,
        Self::Blake2b512,
        Self::K12_256,
        Self::K12_512,
    ];

    /// The algorithm of a Hash Name String.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == name)
    }

    /// The Hash Name String.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha256_128 => "sha-256-128",
            Self::Sha256_120 => "sha-256-120",
            Self::Sha256_96 => "sha-256-96",
            Self::Sha256_64 => "sha-256-64",
            Self::Sha256_32 => "sha-256-32",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Blake2s256 => "blake2s-256",
            Self::Blake2b256 => "blake2b-256",
            Self::Blake2b512 => "blake2b-512",
            Self::K12_256 => "k12-256",
            Self::K12_512 => "k12-512",
        }
    }

    /// The digest of data.
    #[cfg(feature = "resolve")]
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha256_128 => leftmost(data, 16),
            Self::Sha256_120 => leftmost(data, 15),
            Self::Sha256_96 => leftmost(data, 12),
            Self::Sha256_64 => leftmost(data, 8),
            Self::Sha256_32 => leftmost(data, 4),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
            Self::Sha3_224 => Sha3_224::digest(data).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(data).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(data).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(data).to_vec(),
            Self::Blake2s256 => Blake2s256::digest(data).to_vec(),
            Self::Blake2b256 => Blake2b::<U32>::digest(data).to_vec(),
            Self::Blake2b512 => Blake2b512::digest(data).to_vec(),
            Self::K12_256 => {
                let mut out = [0u8; 32];
                Kt128::digest_xof(data, &mut out);
                out.to_vec()
            }
            Self::K12_512 => {
                let mut out = [0u8; 64];
                Kt256::digest_xof(data, &mut out);
                out.to_vec()
            }
        }
    }
}

/// The leftmost `bytes` bytes of the data's SHA-256 (RFC 6920 §2).
#[cfg(feature = "resolve")]
fn leftmost(data: &[u8], bytes: usize) -> Vec<u8> {
    Sha256::digest(data).iter().copied().take(bytes).collect()
}

/// The entry's `transaction_data_hashes_alg`, when present.
fn listed<'e>(entry: &'e Entry<'_>) -> Option<&'e Node<'static>> {
    entry.members().get("transaction_data_hashes_alg")
}

/// B.3.3.1's rules on an entry's `transaction_data_hashes_alg`: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.hashes_alg")]
pub enum HashesAlgRule {
    /// No non-empty array of strings.
    #[error("transaction_data_hashes_alg is not a non-empty array of strings (B.3.3.1)")]
    NotArray,
    /// No hash the wallet computes.
    #[error("transaction_data_hashes_alg {names} names no hash this wallet computes (B.3.3.1)")]
    Unknown {
        /// The names.
        names: ReprList,
    },
}

impl RequestRule for HashesAlgRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::InvalidTransactionData
    }
}

/// The entry's rule a `transaction_data_hashes_alg` breaks: when present, it is a non-empty
/// array of strings naming a hash the wallet computes.
#[must_use]
pub fn rule(entry: &Entry<'_>) -> Option<HashesAlgRule> {
    let value = listed(entry)?;
    let names: Option<Vec<&str>> = value
        .as_array()
        .filter(|items| !items.is_empty())
        .and_then(|items| items.iter().map(Node::as_str).collect());
    match names {
        None => Some(HashesAlgRule::NotArray),
        Some(names)
            if names
                .iter()
                .all(|name| HashAlgorithm::parse(name).is_none()) =>
        {
            Some(HashesAlgRule::Unknown {
                names: ReprList::strings(&names),
            })
        }
        Some(_) => None,
    }
}

/// One algorithm every entry allows, an entry without a list allowing sha-256 alone: the first
/// of the first entry's that the others allow and the wallet computes.
#[must_use]
pub fn algorithm(entries: &[&Entry<'_>]) -> Option<HashAlgorithm> {
    let allowed = |entry: &Entry<'_>| -> Vec<String> {
        match listed(entry)
            .and_then(Node::as_array)
            .filter(|items| !items.is_empty())
        {
            Some(items) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
            None => vec!["sha-256".to_owned()],
        }
    };
    let (first, others) = entries.split_first()?;
    let others: Vec<Vec<String>> = others.iter().map(|entry| allowed(entry)).collect();
    allowed(first).iter().find_map(|name| {
        HashAlgorithm::parse(name).filter(|_| others.iter().all(|other| other.contains(name)))
    })
}

/// Why the B.3.3.1 members cannot be written.
#[cfg(feature = "resolve")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.hashes")]
pub enum HashesError {
    /// No algorithm every entry allows.
    #[error("no hash algorithm every entry allows (B.3.3.1)")]
    NoCommonAlgorithm,
    /// A member written twice.
    #[error(transparent)]
    MemberTwice(#[from] MemberTwice),
}

/// The hashes of the entries as received, in array order (no base64url decoding first), and
/// the algorithm when an entry listed algorithms.
#[cfg(feature = "resolve")]
pub fn members(entries: &[&Entry<'_>]) -> Result<Members, HashesError> {
    let algorithm = algorithm(entries).ok_or(HashesError::NoCommonAlgorithm)?;
    let hashes = entries
        .iter()
        .map(|entry| {
            Node::String(
                URL_SAFE_NO_PAD
                    .encode(algorithm.digest(entry.raw().as_bytes()))
                    .into(),
            )
        })
        .collect();
    let [hashes_member, alg_member] = MEMBERS.clone();
    let mut out = vec![(
        hashes_member,
        MemberValue::Json(JsonText::from(&Node::Array(hashes))),
    )];
    if entries.iter().any(|entry| listed(entry).is_some()) {
        out.push((alg_member, MemberValue::Text(algorithm.name().to_owned())));
    }
    Ok(Members::new(out)?)
}
