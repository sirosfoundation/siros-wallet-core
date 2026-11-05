//! The doubles of the core's response types, response modes and hash algorithms: each states what
//! a test gives it, an output the core must refuse included.

use std::num::NonZeroUsize;

use sha2::{Digest, Sha256};
use siros_openid4vp::hash::{HashAlgorithm, HashName};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Agreements, ContentEncryption, Request};
use siros_openid4vp::routing::{
    ChannelKind, Encrypting, Mode, ModeHost, ModeName, ResponseType, ResponseTypeName,
    VerifierMetadata,
};
use siros_openid4vp::wallet_metadata::{MetadataMember, ParameterName};

use crate::rules::TestRule;

/// A response type of the name given (RFC 6749 §3.1.1).
#[derive(Debug, Clone, Copy)]
pub struct TestResponseType(pub ResponseTypeName);

impl ResponseType for TestResponseType {
    fn name(&self) -> ResponseTypeName {
        self.0
    }
}

/// The encryption a [`TestMode`] chooses, which the core checks: a choice the sealing statement
/// does not admit, an `enc` the Verifier does not list, or a key on a route in the clear, is a
/// `Fault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestChoice {
    /// In the clear.
    Plain,
    /// The Verifier's key at this place among its agreeable keys, and this `enc`, whatever the
    /// statement admits; the mode's rule refuses (C7 under the mode's name) when the Verifier
    /// has no key at the place.
    Key {
        /// The key's place.
        place: usize,
        /// The content encryption.
        enc: ContentEncryption<'static>,
    },
}

/// A response mode a test configures: its name and channel, its request rule, the
/// `wallet_metadata` names it declares and the members it writes, which may name what it did not
/// declare, and its encryption choice.
#[derive(Debug, Clone)]
pub struct TestMode {
    /// The `response_mode` value.
    pub name: ModeName,
    /// The channel it answers on.
    pub channel: ChannelKind,
    /// The rule it refuses every request with, when given.
    pub refuses: Option<TestRule>,
    /// The `wallet_metadata` names it declares.
    pub declares: &'static [ParameterName],
    /// The members it writes.
    pub writes: Vec<MetadataMember>,
    /// Its encryption.
    pub choice: TestChoice,
}

impl TestMode {
    /// A mode in the clear of the name and channel, without a rule, declaring and writing nothing.
    #[must_use]
    pub const fn new(name: ModeName, channel: ChannelKind) -> Self {
        Self {
            name,
            channel,
            refuses: None,
            declares: &[],
            writes: Vec::new(),
            choice: TestChoice::Plain,
        }
    }
}

impl Mode for TestMode {
    fn name(&self) -> ModeName {
        self.name
    }

    fn channel(&self) -> ChannelKind {
        self.channel
    }

    fn rules(&self, _request: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        self.refuses.iter().cloned().map(Refusal::new).collect()
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        self.declares
    }
}

/// Needs no module.
impl<H> ModeHost<H> for TestMode {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        match self.choice {
            TestChoice::Plain => Ok(Encrypting::Plain),
            TestChoice::Key { place, enc } => metadata
                .keys()
                .iter()
                .nth(place)
                .map(|key| Encrypting::Jwe { key, enc })
                .ok_or_else(|| {
                    Refusal::new(TestRule::invalid_request(format!(
                        "C7 {}: no key at place {place}",
                        self.name
                    )))
                }),
        }
    }

    fn wallet_metadata(
        &self,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        Ok(self.writes.clone())
    }
}

/// A hash algorithm of the name and digest length given, whose digest is SHA-256's octets, cycled
/// or cut to `writes`: a `writes` other than `octets` breaks the contract the core checks.
#[derive(Debug, Clone, Copy)]
pub struct TestHash {
    /// The Hash Name String.
    pub name: HashName,
    /// The digest length it states.
    pub octets: NonZeroUsize,
    /// The digest length it writes.
    pub writes: usize,
}

impl HashAlgorithm for TestHash {
    fn name(&self) -> HashName {
        self.name
    }

    fn octets(&self) -> NonZeroUsize {
        self.octets
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data)
            .iter()
            .copied()
            .cycle()
            .take(self.writes)
            .collect()
    }
}
