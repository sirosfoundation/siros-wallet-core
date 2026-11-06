//! The `x509_hash` and `x509_san_dns` Client Identifier Prefixes (OpenID4VP 1.0 §5.9.3) for the
//! SIROS wallet core: HAIP §5 requires `x509_hash`, and nym_auth's `x509_san_dns` form of
//! `verifier_id` needs `x509_san_dns`. Each reads the signed request's `x5c` header (RFC 7515
//! §4.1.6), the leaf's key (RFC 5480) and, for `x509_san_dns`, its dNSName entries (RFC 5280
//! §4.2.1.6); asks the caller's trust service one evaluation in AuthZEN's shape, with
//! `verifier_info` and the DCQL query in its context; and binds the leaf's key and the endpoints
//! the decision lists. The trust service validates the chain (RFC 5280 path validation and
//! revocation); the crate parses it.
//!
//! ```
//! use siros_openid4vp::plugins::Registry;
//! use siros_testkit::TestHost;
//! use siros_x509::{X509Hash, X509SanDns};
//!
//! let mut builder = Registry::<TestHost>::builder();
//! builder.client_prefix(X509Hash);
//! builder.client_prefix(X509SanDns);
//! let registry = builder.build().expect("a registry");
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

mod chain;
mod claim;
mod names;
#[cfg(feature = "test-util")]
pub mod test_util;

use siros_explain::{Explain, Explained, Message, Messages};
use siros_openid4vp::authenticate::{
    ClientClaim, ClientPrefix, PrefixClaim, PrefixHost, PrefixName,
};

pub use chain::{ChainCertificate, SpkiKey, X5c, X5cItem};
pub use der::Error as DerError;
pub use names::{HashText, LeafHash, SanDnsName};

use claim::{Rule, X509Claim};

const X509_HASH: PrefixName = siros_explain::checked!(PrefixName, "x509_hash");
const X509_SAN_DNS: PrefixName = siros_explain::checked!(PrefixName, "x509_san_dns");

/// Why a claim breaks an X.509 prefix's rule (A5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "x509")]
pub enum X509Refusal {
    /// The protected header holds no `x5c`.
    #[error("x5c is absent")]
    X5cAbsent,
    /// `x5c` is no array of strings.
    #[error("x5c is no array of strings")]
    X5cNotArray,
    /// `x5c` is empty.
    #[error("x5c is empty")]
    X5cEmpty,
    /// An item is no base64 (RFC 7515 §4.1.6: base64, not base64url).
    #[error("x5c item {0} is no base64")]
    Base64(#[explain(name = "item")] X5cItem),
    /// An item is no DER certificate: x509-cert refuses it, a trailing byte or a non-minimal
    /// length included.
    #[error("x5c item {item} is no DER certificate: {cause}")]
    Certificate {
        /// The item.
        item: X5cItem,
        /// der's reason, for the log.
        #[explain(skip)]
        cause: der::Error,
    },
    /// The leaf's key is none [`SpkiKey::key`] reads: an uncompressed point under
    /// id-ecPublicKey and secp256r1, secp384r1 or secp521r1 (RFC 5480 §2.1.1, §2.2), or an
    /// id-Ed25519 or id-Ed448 key (RFC 8410 §3).
    #[error("the leaf's key is no EC or EdDSA public key the wallet reads")]
    Key,
    /// The original Client Identifier is no base64url without padding of 32 octets.
    #[error("x509_hash {0:?} is no base64url SHA-256 hash")]
    HashSyntax(#[explain(name = "original")] String),
    /// The leaf's SHA-256 is another hash than the identifier.
    #[error("x509_hash {:?} is not the leaf certificate's hash", .0.as_str())]
    Hash(#[explain(name = "original")] HashText),
    /// The original Client Identifier is no DNS name in preferred name syntax (RFC 1034 §3.5).
    #[error("x509_san_dns {0:?} is no DNS name")]
    SanSyntax(#[explain(name = "original")] String),
    /// No dNSName entry of the leaf's subjectAltName names the DNS name (RFC 5280 §4.2.1.6,
    /// §7.2).
    #[error("x509_san_dns {:?} is named by no dNSName of the leaf", .0.as_str())]
    San(#[explain(name = "original")] SanDnsName),
    /// The leaf's subjectAltName extension is no DER SubjectAltName, or appears twice (RFC 5280
    /// §4.2).
    #[error("the leaf's subjectAltName is unreadable: {0}")]
    SubjectAltName(#[explain(skip)] der::Error),
}

/// The crate's messages: its refusals'.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        X509Refusal::messages()
    }
}

/// The `x509_hash` prefix: the original Client Identifier is the base64url SHA-256 of the leaf
/// certificate's DER. Without `endpoints` in the decision, the request's `response_uri` stands
/// once authenticated (`EndpointBasis::Request`).
#[derive(Debug, Clone, Copy, Default)]
pub struct X509Hash;

/// The `x509_san_dns` prefix: the original Client Identifier is a DNS name a dNSName of the leaf
/// names. Without `endpoints` in the decision, the `response_uri` must be on that host
/// (`EndpointBasis::Framework`, since the certificate names the host).
#[derive(Debug, Clone, Copy, Default)]
pub struct X509SanDns;

fn refused(rule: X509Refusal) -> Box<dyn Explained> {
    Box::new(rule)
}

impl ClientPrefix for X509Hash {
    fn name(&self) -> PrefixName {
        X509_HASH
    }
}

impl<H> PrefixHost<H> for X509Hash {
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        _host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explained>> {
        let chain = X5c::of(claim.signed().header()).map_err(refused)?;
        let hash = LeafHash::parse(claim.original()).map_err(refused)?;
        if hash != chain.leaf().hash() {
            return Err(refused(X509Refusal::Hash(hash.text())));
        }
        let key = chain.leaf().key().map_err(refused)?;
        Ok(Box::new(X509Claim::new(claim, chain, key, Rule::Hash)))
    }
}

impl ClientPrefix for X509SanDns {
    fn name(&self) -> PrefixName {
        X509_SAN_DNS
    }
}

impl<H> PrefixHost<H> for X509SanDns {
    fn claim<'c>(
        &'c self,
        claim: ClientClaim<'c>,
        _host: &H,
    ) -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explained>> {
        let chain = X5c::of(claim.signed().header()).map_err(refused)?;
        let name = SanDnsName::parse(claim.original()).map_err(refused)?;
        if !name.names(chain.leaf()).map_err(refused)? {
            return Err(refused(X509Refusal::San(name)));
        }
        let key = chain.leaf().key().map_err(refused)?;
        Ok(Box::new(X509Claim::new(claim, chain, key, Rule::San(name))))
    }
}
