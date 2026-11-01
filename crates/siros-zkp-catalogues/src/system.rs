//! The nym_auth systems of the rulebook and the requests each supports (system rulebooks,
//! Sections 1 to 3).
//!
//! `urn:mms:bbs-cd:nym_auth:v1` is not listed: no Wallet proves it yet.

use siros_codec::date::Date;
use siros_zkp_req::{CredentialType, PairRefusal, ProofBackend, SystemId, ZkProof};

use crate::age::Bounds;
use crate::catalogue::{Config, Form, Item, Prf, MDOC_DOCTYPE};
use crate::verifier_id::sha256;

/// The largest `zk_proof` the proof backends read (`longfellow-libzk-v1`, `vega-v1`).
pub const MAX_ZK_PROOF: usize = 1 << 20;

const LONGFELLOW_ID: SystemId = SystemId::from_static("urn:circuits:longfellow:nym_auth:v1");
const VEGA_ID: SystemId = SystemId::from_static("urn:circuits:vega:nym_auth:v1");
const LONGFELLOW_BACKENDS: &[ProofBackend] = &[ProofBackend::from_static("longfellow-libzk-v1")];
const VEGA_BACKENDS: &[ProofBackend] = &[ProofBackend::from_static("vega-v1")];

/// A nym_auth system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NymAuthSystem {
    /// `urn:circuits:longfellow:nym_auth:v1` on `longfellow-libzk-v1`.
    LongfellowV1,
    /// `urn:circuits:vega:nym_auth:v1` on `vega-v1`.
    VegaV1,
}

/// Why a system answers `unsupported` for an option (system rulebooks, Section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unsupported {
    /// The option has no `pseudonym` item.
    NoPseudonym,
    /// `pseudonym.config` is another configuration than `known-offender-matching-ssc`.
    Config,
    /// `pseudonym.prf` is another PRF than `sha-256`.
    Prf,
    /// E or C lies outside the dates the system encodes.
    AgeBounds,
}

impl Unsupported {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::NoPseudonym => "no_pseudonym",
            Self::Config => "config",
            Self::Prf => "prf",
            Self::AgeBounds => "age_bounds",
        }
    }
}

/// The stable identifier of a pair refusal (`zkp_req`, Section 1.3) for a nym_auth system.
pub fn pair_code(refusal: &PairRefusal<Unsupported>) -> &'static str {
    match refusal {
        PairRefusal::SystemNotListed => "system_not_listed",
        PairRefusal::NoListedBackend => "no_listed_backend",
        PairRefusal::CredentialType => "credential_type",
        PairRefusal::Unsupported(u) => u.code(),
    }
}

/// A file a system rulebook pins in its Section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactPin {
    /// The file name the rulebook gives.
    pub name: &'static str,
    /// Its length in bytes.
    pub len: usize,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

impl ArtifactPin {
    /// Whether `bytes` are this file.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.len && sha256(bytes) == self.sha256
    }
}

/// The circuit artifact of a system (Section 8): the file as distributed, one zstd frame, and
/// its decompressed content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitArtifact {
    /// `circuits.zst` or `shapes.zst`.
    pub compressed: ArtifactPin,
    /// The decompressed content.
    pub content: ArtifactPin,
}

const LONGFELLOW_ARTIFACT: CircuitArtifact = CircuitArtifact {
    compressed: ArtifactPin {
        name: "circuits.zst",
        len: 395_608,
        sha256: [
            0x6c, 0x4b, 0x96, 0xed, 0x43, 0x1e, 0xe5, 0x47, 0xa3, 0xa2, 0xe5, 0xb6, 0x26, 0x21,
            0x94, 0x3a, 0x9a, 0x0a, 0x44, 0x64, 0x62, 0x67, 0x65, 0x3b, 0xf2, 0xdb, 0x0f, 0xcc,
            0x26, 0x9b, 0x5c, 0x3b,
        ],
    },
    content: ArtifactPin {
        name: "circuits.zst, decompressed",
        len: 1_062_842,
        sha256: [
            0x92, 0xdd, 0x42, 0xfd, 0xf9, 0x96, 0x73, 0x24, 0x9e, 0xec, 0x33, 0xc7, 0xd0, 0x78,
            0x50, 0xbd, 0x9d, 0xa6, 0x6f, 0xbd, 0xab, 0x01, 0xef, 0x26, 0x39, 0x1e, 0x04, 0xc8,
            0x34, 0x1c, 0x1b, 0x7f,
        ],
    },
};

const VEGA_ARTIFACT: CircuitArtifact = CircuitArtifact {
    compressed: ArtifactPin {
        name: "shapes.zst",
        len: 361_395,
        sha256: [
            0xb4, 0x57, 0xba, 0x53, 0x82, 0xeb, 0x76, 0x04, 0xef, 0x03, 0x5e, 0x79, 0x0f, 0x2c,
            0xb2, 0x4f, 0x0c, 0xd5, 0xfd, 0xcd, 0x06, 0x5f, 0x38, 0x3f, 0xf1, 0xc2, 0xc4, 0x9f,
            0xab, 0x1b, 0xb4, 0xdf,
        ],
    },
    content: ArtifactPin {
        name: "shapes.zst, decompressed",
        len: 12_205_144,
        sha256: [
            0x4d, 0xa5, 0xe7, 0x3a, 0xfb, 0x9b, 0xe2, 0x68, 0x2e, 0x70, 0xbe, 0x79, 0x3c, 0x99,
            0x56, 0xa7, 0x33, 0x04, 0xe2, 0x1f, 0x31, 0x24, 0x6a, 0xa1, 0x0d, 0xa0, 0xd3, 0xe9,
            0x5c, 0x92, 0x64, 0x25,
        ],
    },
};

impl NymAuthSystem {
    /// Every system of this crate.
    pub const ALL: [Self; 2] = [Self::LongfellowV1, Self::VegaV1];

    /// The system identifier.
    #[must_use]
    pub fn id(self) -> SystemId {
        match self {
            Self::LongfellowV1 => LONGFELLOW_ID,
            Self::VegaV1 => VEGA_ID,
        }
    }

    /// The system with identifier `id`.
    #[must_use]
    pub fn from_id(id: &SystemId) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == *id)
    }

    /// The proof backends the system runs on (Section 1).
    #[must_use]
    pub fn backends(self) -> &'static [ProofBackend] {
        match self {
            Self::LongfellowV1 => LONGFELLOW_BACKENDS,
            Self::VegaV1 => VEGA_BACKENDS,
        }
    }

    /// Whether the system runs on `backend` (Section 1).
    #[must_use]
    pub fn runs_on(self, backend: &ProofBackend) -> bool {
        self.backends().contains(backend)
    }

    /// The attestation form it proves over.
    pub fn form(self) -> Form {
        Form::Mdoc
    }

    /// The dates E and C may take (Section 2): 0000-01-01 to 9999-12-31 for both systems.
    pub fn bound_window(self) -> (Date, Date) {
        match self {
            Self::LongfellowV1 | Self::VegaV1 => (Date::FIRST, Date::LAST),
        }
    }

    /// The circuit artifact the system rulebook pins (Section 8).
    pub fn circuit_artifact(self) -> CircuitArtifact {
        match self {
            Self::LongfellowV1 => LONGFELLOW_ARTIFACT,
            Self::VegaV1 => VEGA_ARTIFACT,
        }
    }

    /// The exact length of `zk_proof` the system rulebook states, if it states one.
    #[must_use]
    pub fn zk_proof_len(self) -> Option<usize> {
        match self {
            Self::LongfellowV1 => None,
            Self::VegaV1 => Some(96_079),
        }
    }

    /// Whether `zk_proof` has a length the system's proof backend reads: at most
    /// [`MAX_ZK_PROOF`], and the rulebook's exact length where it states one.
    #[must_use]
    pub fn admits_zk_proof(self, zk_proof: &ZkProof) -> bool {
        let length = zk_proof.as_bytes().len();
        length <= MAX_ZK_PROOF && self.zk_proof_len().is_none_or(|n| n == length)
    }

    /// Whether the system supports an option: its items, and E and C at the proof date
    /// (Section 2).
    ///
    /// # Errors
    ///
    /// [`Unsupported`]: the first rule of Section 2 the option breaks.
    pub fn supports<'a>(
        self,
        items: impl IntoIterator<Item = &'a Item>,
        bounds: &Bounds,
    ) -> Result<(), Unsupported> {
        let pseudonym = items
            .into_iter()
            .find_map(Item::pseudonym)
            .ok_or(Unsupported::NoPseudonym)?;
        if *pseudonym.config() != Config::KnownOffenderMatchingSsc {
            return Err(Unsupported::Config);
        }
        if pseudonym.prf() != Prf::Sha256 {
            return Err(Unsupported::Prf);
        }
        let (min, max) = self.bound_window();
        if !bounds.within(min, max) {
            return Err(Unsupported::AgeBounds);
        }
        Ok(())
    }
}

impl siros_zkp_req::System for NymAuthSystem {
    fn id(&self) -> SystemId {
        NymAuthSystem::id(*self)
    }

    fn runs_on(&self, backend: &ProofBackend) -> bool {
        NymAuthSystem::runs_on(*self, backend)
    }

    fn proves_over(&self, credential_type: &CredentialType) -> bool {
        matches!(
            credential_type,
            CredentialType::MsoMdoc { doctype } if doctype.as_str() == MDOC_DOCTYPE
        )
    }
}
