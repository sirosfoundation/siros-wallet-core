//! The transaction data profile of OpenID4VP 1.0, B.3.3.1: the request member
//! `transaction_data_hashes_alg` and the KB-JWT claims `transaction_data_hashes` and
//! `transaction_data_hashes_alg`.

use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::base64url::{self, Base64Url};
use siros_codec::json::Json;
use siros_codec::member::ArrayIndex;
use siros_oid4vp::TransactionDataItem;

/// A hash algorithm of the IANA Named Information Hash Algorithm Registry that this wallet
/// computes, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    /// `sha-256`, which every implementation supports (B.3.3.1).
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl HashAlg {
    const ALL: [Self; 3] = [Self::Sha256, Self::Sha384, Self::Sha512];

    /// The Hash Name String of the registry.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }

    /// The element of `transaction_data_hashes` for `entry`, the string the request carried:
    /// base64url of the hash over its bytes. The string is hashed as received, without
    /// base64url decoding (B.3.3.1).
    #[must_use]
    pub fn hash(self, entry: &TransactionDataItem) -> Base64Url {
        base64url::encode(&self.digest(entry.as_str().as_bytes()))
    }

    /// The digest of `bytes`.
    pub(crate) fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }

    /// The length of a digest, in bytes.
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The algorithm the Hash Name String `name` names.
    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.identifier() == name)
    }

    /// The algorithm the W3C Subresource Integrity token `token` names (SRI, Section 3.2),
    /// compared without regard to ASCII case.
    pub(crate) fn sri_named(token: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|alg| alg.sri_token().eq_ignore_ascii_case(token))
    }

    /// The token of the algorithm in SRI.
    fn sri_token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

/// The algorithms an entry accepts for its hash (B.3.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Accepted {
    /// The entry carries no `transaction_data_hashes_alg`: `sha-256`.
    Default,
    /// The entry carries `transaction_data_hashes_alg`: its first algorithm this wallet
    /// computes.
    Listed(HashAlg),
}

/// Why an entry's `transaction_data_hashes_alg` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum HashesAlgFault {
    /// The member is neither an array nor a string.
    WrongType,
    /// The array is empty.
    Empty,
    /// The element at this position is no string.
    Element(ArrayIndex),
    /// No name is of an algorithm this wallet computes.
    Unsupported,
}

impl HashesAlgFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::WrongType | Self::Empty | Self::Element(_) => {
                "transaction_data_hash_alg_malformed"
            }
            Self::Unsupported => "transaction_data_hash_alg_unsupported",
        }
    }
}

/// Whether a KB-JWT carries `transaction_data_hashes_alg` (B.3.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgClaim {
    /// The entry carried `transaction_data_hashes_alg`: the KB-JWT names the algorithm.
    Repeated,
    /// It did not.
    Omitted,
}

impl Accepted {
    /// The algorithms `value`, the entry's `transaction_data_hashes_alg`, accepts: a non-empty
    /// array of Hash Name Strings (B.3.3.1), or one string as CS-12, Section 8.1 sends it,
    /// which reads as a list of one. A name this wallet does not compute is passed over.
    pub(crate) fn parse(value: Option<Json>) -> Result<Self, HashesAlgFault> {
        let names = match value {
            None => return Ok(Self::Default),
            Some(Json::String(name)) => vec![name],
            Some(Json::Array(items)) if items.is_empty() => return Err(HashesAlgFault::Empty),
            Some(Json::Array(items)) => items
                .into_iter()
                .enumerate()
                .map(|(at, item)| match item {
                    Json::String(name) => Ok(name),
                    _ => Err(HashesAlgFault::Element(ArrayIndex::new(at))),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(HashesAlgFault::WrongType),
        };
        names
            .iter()
            .find_map(|name| HashAlg::named(name))
            .map(Self::Listed)
            .ok_or(HashesAlgFault::Unsupported)
    }

    /// The algorithm of the hash: the first the verifier lists that this wallet computes, else
    /// `sha-256` (B.3.3.1).
    pub(crate) fn alg(&self) -> HashAlg {
        match self {
            Self::Default => HashAlg::Sha256,
            Self::Listed(alg) => *alg,
        }
    }

    /// Whether the KB-JWT names the algorithm.
    pub(crate) fn claim(&self) -> AlgClaim {
        match self {
            Self::Default => AlgClaim::Omitted,
            Self::Listed(_) => AlgClaim::Repeated,
        }
    }
}
