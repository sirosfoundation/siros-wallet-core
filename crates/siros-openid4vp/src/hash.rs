//! Transaction data hashes (OpenID4VP B.3.3.1; feature `transaction-data`): the entry's
//! `transaction_data_hashes_alg` and the response's `transaction_data_hashes`, one hash per entry
//! the presentation authorizes, with the algorithm used. The IANA "Named Information Hash
//! Algorithm Registry" B.3.3.1 names is open, so an algorithm is a plug-in the registry takes
//! ([`HashAlgorithm`]): phase 1 reads its name, phase 2 its digest. The core's SHA-2
//! algorithms (`Sha2`) are peers of any extension's, beside SHA-3, BLAKE2 and KangarooTwelve,
//! each behind the feature that links its crate (`sha3`, `blake2`, `k12`). [`HashName`] compiles
//! in every build: the registry's refusals carry it.

use std::fmt;
#[cfg(feature = "transaction-data")]
use std::num::NonZeroUsize;

#[cfg(all(feature = "transaction-data", feature = "resolve"))]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "blake2")]
use blake2::{Blake2b, Blake2b512, Blake2s256, digest::consts::U32};
#[cfg(feature = "transaction-data")]
use dyn_clone::DynClone;
#[cfg(feature = "k12")]
use k12::{ExtendableOutput, Kt128, Kt256};
#[cfg(feature = "transaction-data")]
use sha2::{Digest, Sha256, Sha384, Sha512};
#[cfg(feature = "sha3")]
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
#[cfg(feature = "transaction-data")]
use siros_explain::Explain;

#[cfg(feature = "transaction-data")]
use crate::json::Node;
#[cfg(feature = "transaction-data")]
use crate::plugins::Member;
#[cfg(all(feature = "transaction-data", feature = "resolve"))]
use crate::plugins::{JsonText, MemberTwice, MemberValue, Members};
#[cfg(feature = "transaction-data")]
use crate::refusal::{ErrorCode, ReprList, RequestRule};
#[cfg(feature = "transaction-data")]
use crate::request::Entry;

#[cfg(feature = "transaction-data")]
/// The response members B.3.3.1 defines.
pub static MEMBERS: [Member; 2] = [
    Member::claim("transaction_data_hashes"),
    Member::claim("transaction_data_hashes_alg"),
];

/// A Hash Name String (RFC 6920 §9.4's registry): one or more of lowercase ASCII letters, digits
/// and `-`. An algorithm makes its own with `siros_syntax::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashName(&'static str);

impl HashName {
    /// The name; `None` for an empty text or another character.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        if rest.is_empty() {
            return None;
        }
        while let [byte, tail @ ..] = rest {
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-') {
                return None;
            }
            rest = tail;
        }
        Some(Self(name))
    }

    /// The name as `transaction_data_hashes_alg` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for HashName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "transaction-data")]
/// A transaction data hash algorithm: its name, which B.3.3.1's rule matches against each entry's
/// `transaction_data_hashes_alg` in phase 1, its digest's length, and the digest phase 2 writes.
///
/// # Implementing
///
/// `name` and `octets` are constants; the registry refuses a name registered twice
/// (`RegistryError::HashTwice`), and a build that registers a transaction data profile without
/// `sha-256`, B.3.3.1's default (`Sha256Absent`). The matcher's and the wallet's registries come
/// from one registration function generic over the host, so both name the same algorithms.
/// `digest` hashes the bytes as given; the core refuses a digest of another length than `octets`
/// with a `HashesError::Digest`.
pub trait HashAlgorithm: DynClone + Send + Sync {
    /// The Hash Name String.
    fn name(&self) -> HashName;
    /// The digest's length in octets.
    fn octets(&self) -> NonZeroUsize;
    /// The digest of the entry's bytes as received.
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}

#[cfg(feature = "transaction-data")]
dyn_clone::clone_trait_object!(HashAlgorithm);

#[cfg(feature = "transaction-data")]
pub use crate::plugins::Hashes;

#[cfg(feature = "transaction-data")]
/// The digest lengths of the hash families, one or more octets each.
macro_rules! octets {
    ($n:literal) => {
        const {
            match NonZeroUsize::new($n) {
                Some(n) => n,
                #[allow(clippy::panic, reason = "a panic in a constant fails the build")]
                None => panic!("a digest holds one octet or more"),
            }
        }
    };
}

#[cfg(feature = "transaction-data")]
/// The SHA-2 algorithms of the registry, over the sha2 crate the core links already.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sha2 {
    /// `sha-256`.
    Sha256,
    /// `sha-256-128`, `sha-256-120`, `sha-256-96`, `sha-256-64`, `sha-256-32`: SHA-256's
    /// leftmost octets (RFC 6920 §2).
    Sha256Truncated(Truncation),
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

#[cfg(feature = "transaction-data")]
/// The truncations of SHA-256 the registry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Truncation {
    /// 128 bits.
    To128,
    /// 120 bits.
    To120,
    /// 96 bits.
    To96,
    /// 64 bits.
    To64,
    /// 32 bits.
    To32,
}

#[cfg(feature = "transaction-data")]
impl Sha2 {
    /// The eight SHA-2 algorithms the registry names.
    pub const ALL: [Self; 8] = [
        Self::Sha256,
        Self::Sha256Truncated(Truncation::To128),
        Self::Sha256Truncated(Truncation::To120),
        Self::Sha256Truncated(Truncation::To96),
        Self::Sha256Truncated(Truncation::To64),
        Self::Sha256Truncated(Truncation::To32),
        Self::Sha384,
        Self::Sha512,
    ];
}

#[cfg(feature = "transaction-data")]
impl HashAlgorithm for Sha2 {
    fn name(&self) -> HashName {
        match self {
            Self::Sha256 => siros_syntax::checked!(HashName, "sha-256"),
            Self::Sha256Truncated(Truncation::To128) => {
                siros_syntax::checked!(HashName, "sha-256-128")
            }
            Self::Sha256Truncated(Truncation::To120) => {
                siros_syntax::checked!(HashName, "sha-256-120")
            }
            Self::Sha256Truncated(Truncation::To96) => {
                siros_syntax::checked!(HashName, "sha-256-96")
            }
            Self::Sha256Truncated(Truncation::To64) => {
                siros_syntax::checked!(HashName, "sha-256-64")
            }
            Self::Sha256Truncated(Truncation::To32) => {
                siros_syntax::checked!(HashName, "sha-256-32")
            }
            Self::Sha384 => siros_syntax::checked!(HashName, "sha-384"),
            Self::Sha512 => siros_syntax::checked!(HashName, "sha-512"),
        }
    }

    fn octets(&self) -> NonZeroUsize {
        match self {
            Self::Sha256 => octets!(32),
            Self::Sha256Truncated(Truncation::To128) => octets!(16),
            Self::Sha256Truncated(Truncation::To120) => octets!(15),
            Self::Sha256Truncated(Truncation::To96) => octets!(12),
            Self::Sha256Truncated(Truncation::To64) => octets!(8),
            Self::Sha256Truncated(Truncation::To32) => octets!(4),
            Self::Sha384 => octets!(48),
            Self::Sha512 => octets!(64),
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha256Truncated(_) => Sha256::digest(data)
                .iter()
                .copied()
                .take(self.octets().get())
                .collect(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

#[cfg(feature = "sha3")]
/// The SHA-3 algorithms: `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sha3 {
    /// `sha3-224`.
    Sha3_224,
    /// `sha3-256`.
    Sha3_256,
    /// `sha3-384`.
    Sha3_384,
    /// `sha3-512`.
    Sha3_512,
}

#[cfg(feature = "sha3")]
impl Sha3 {
    /// The four SHA-3 algorithms the registry names.
    pub const ALL: [Self; 4] = [
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
    ];
}

#[cfg(feature = "sha3")]
impl HashAlgorithm for Sha3 {
    fn name(&self) -> HashName {
        match self {
            Self::Sha3_224 => siros_syntax::checked!(HashName, "sha3-224"),
            Self::Sha3_256 => siros_syntax::checked!(HashName, "sha3-256"),
            Self::Sha3_384 => siros_syntax::checked!(HashName, "sha3-384"),
            Self::Sha3_512 => siros_syntax::checked!(HashName, "sha3-512"),
        }
    }

    fn octets(&self) -> NonZeroUsize {
        match self {
            Self::Sha3_224 => octets!(28),
            Self::Sha3_256 => octets!(32),
            Self::Sha3_384 => octets!(48),
            Self::Sha3_512 => octets!(64),
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha3_224 => Sha3_224::digest(data).to_vec(),
            Self::Sha3_256 => Sha3_256::digest(data).to_vec(),
            Self::Sha3_384 => Sha3_384::digest(data).to_vec(),
            Self::Sha3_512 => Sha3_512::digest(data).to_vec(),
        }
    }
}

#[cfg(feature = "blake2")]
/// The BLAKE2 algorithms: `blake2s-256`, `blake2b-256`, `blake2b-512`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Blake2 {
    /// `blake2s-256`.
    Blake2s256,
    /// `blake2b-256`.
    Blake2b256,
    /// `blake2b-512`.
    Blake2b512,
}

#[cfg(feature = "blake2")]
impl Blake2 {
    /// The three BLAKE2 algorithms the registry names.
    pub const ALL: [Self; 3] = [Self::Blake2s256, Self::Blake2b256, Self::Blake2b512];
}

#[cfg(feature = "blake2")]
impl HashAlgorithm for Blake2 {
    fn name(&self) -> HashName {
        match self {
            Self::Blake2s256 => siros_syntax::checked!(HashName, "blake2s-256"),
            Self::Blake2b256 => siros_syntax::checked!(HashName, "blake2b-256"),
            Self::Blake2b512 => siros_syntax::checked!(HashName, "blake2b-512"),
        }
    }

    fn octets(&self) -> NonZeroUsize {
        match self {
            Self::Blake2s256 | Self::Blake2b256 => octets!(32),
            Self::Blake2b512 => octets!(64),
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Blake2s256 => Blake2s256::digest(data).to_vec(),
            Self::Blake2b256 => Blake2b::<U32>::digest(data).to_vec(),
            Self::Blake2b512 => Blake2b512::digest(data).to_vec(),
        }
    }
}

#[cfg(feature = "k12")]
/// The KangarooTwelve algorithms (RFC 9861 §6): `k12-256` (KT128 with 32 bytes of output) and
/// `k12-512` (KT256 with 64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum K12 {
    /// `k12-256`.
    K12_256,
    /// `k12-512`.
    K12_512,
}

#[cfg(feature = "k12")]
impl K12 {
    /// The two KangarooTwelve algorithms the registry names.
    pub const ALL: [Self; 2] = [Self::K12_256, Self::K12_512];
}

#[cfg(feature = "k12")]
impl HashAlgorithm for K12 {
    fn name(&self) -> HashName {
        match self {
            Self::K12_256 => siros_syntax::checked!(HashName, "k12-256"),
            Self::K12_512 => siros_syntax::checked!(HashName, "k12-512"),
        }
    }

    fn octets(&self) -> NonZeroUsize {
        match self {
            Self::K12_256 => octets!(32),
            Self::K12_512 => octets!(64),
        }
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
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

#[cfg(feature = "transaction-data")]
/// The entry's `transaction_data_hashes_alg`, when present.
fn listed<'e>(entry: &'e Entry<'_>) -> Option<&'e Node<'static>> {
    entry.members().get("transaction_data_hashes_alg")
}

#[cfg(feature = "transaction-data")]
/// B.3.3.1's rules on an entry's `transaction_data_hashes_alg`: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum HashesAlgRule {
    /// No non-empty array of strings.
    #[error("transaction_data_hashes_alg is not a non-empty array of strings (B.3.3.1)")]
    #[explain(id = "hashes_alg.not_array")]
    NotArray,
    /// No hash the wallet computes.
    #[error("transaction_data_hashes_alg {} names no hash this wallet computes (B.3.3.1)", .names.repr_text())]
    #[explain(id = "hashes_alg.unknown")]
    Unknown {
        /// The names.
        names: ReprList,
    },
}

#[cfg(feature = "transaction-data")]
impl RequestRule for HashesAlgRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

#[cfg(feature = "transaction-data")]
/// The entry's rule a `transaction_data_hashes_alg` breaks: when present, it is a non-empty
/// array of strings naming a registered algorithm.
#[must_use]
pub fn rule(entry: &Entry<'_>, hashes: Hashes<'_>) -> Option<HashesAlgRule> {
    let value = listed(entry)?;
    let names: Option<Vec<&str>> = value
        .as_array()
        .filter(|items| !items.is_empty())
        .and_then(|items| items.iter().map(Node::as_str).collect());
    match names {
        None => Some(HashesAlgRule::NotArray),
        Some(names) if names.iter().all(|name| hashes.named(name).is_none()) => {
            Some(HashesAlgRule::Unknown {
                names: ReprList::strings(&names),
            })
        }
        Some(_) => None,
    }
}

#[cfg(feature = "transaction-data")]
/// One registered algorithm every entry allows, an entry without a list allowing sha-256 alone:
/// the first of the first entry's that the others allow and the registry holds.
#[must_use]
pub fn algorithm<'h>(entries: &[&Entry<'_>], hashes: Hashes<'h>) -> Option<&'h dyn HashAlgorithm> {
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
        hashes
            .named(name)
            .filter(|_| others.iter().all(|other| other.contains(name)))
    })
}

/// Why the B.3.3.1 members cannot be written.
#[cfg(all(feature = "transaction-data", feature = "resolve"))]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum HashesError {
    /// No algorithm every entry allows.
    #[error("no hash algorithm every entry allows (B.3.3.1)")]
    #[explain(id = "hashes.no_common_algorithm")]
    NoCommonAlgorithm,
    /// A member written twice.
    #[error(transparent)]
    MemberTwice(#[from] MemberTwice),
    /// A registered algorithm's digest of another length than it states: its plug-in's bug.
    #[error("{name}'s digest holds {octets} octets, and it states {stated}")]
    #[explain(id = "hashes.digest")]
    Digest {
        /// The algorithm.
        name: HashName,
        /// The digest's length.
        octets: usize,
        /// The length it states.
        stated: usize,
    },
}

/// The hashes of the entries as received, in array order (no base64url decoding first), and
/// the algorithm when an entry listed algorithms.
#[cfg(all(feature = "transaction-data", feature = "resolve"))]
pub fn members(entries: &[&Entry<'_>], hashes: Hashes<'_>) -> Result<Members, HashesError> {
    let algorithm = algorithm(entries, hashes).ok_or(HashesError::NoCommonAlgorithm)?;
    let hashes = entries
        .iter()
        .map(|entry| {
            let digest = algorithm.digest(entry.raw().as_bytes());
            let stated = algorithm.octets().get();
            if digest.len() == stated {
                Ok(Node::String(URL_SAFE_NO_PAD.encode(digest).into()))
            } else {
                Err(HashesError::Digest {
                    name: algorithm.name(),
                    octets: digest.len(),
                    stated,
                })
            }
        })
        .collect::<Result<_, _>>()?;
    let [hashes_member, alg_member] = MEMBERS.clone();
    let mut out = vec![(
        hashes_member,
        MemberValue::Json(JsonText::from(&Node::Array(hashes))),
    )];
    if entries.iter().any(|entry| listed(entry).is_some()) {
        out.push((
            alg_member,
            MemberValue::Text(algorithm.name().as_str().to_owned()),
        ));
    }
    Ok(Members::new(out)?)
}
