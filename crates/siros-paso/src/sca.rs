//! Core §6: the SCA response claims (§6.1) and where each format carries them: Key Binding JWT
//! claims of an SD-JWT VC (§6.2), device-signed elements of `urn:paso:sca:1` in an mdoc (§6.3).

use siros_openid4vp::ids::FormatId;
use siros_openid4vp::plugins::Member;

/// The SCA response claims (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Sca {
    Jti,
    DisplayLocale,
    TransactionDataHash,
    TransactionDataHashAlg,
    MetadataIntegrity,
    RequestIntegrity,
    WalletInstanceVersion,
    RiskSignals,
}

impl Sca {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Jti => "jti",
            Self::DisplayLocale => "display_locale",
            Self::TransactionDataHash => "transaction_data_hash",
            Self::TransactionDataHashAlg => "transaction_data_hash_alg",
            Self::MetadataIntegrity => "metadata_integrity",
            Self::RequestIntegrity => "request_integrity",
            Self::WalletInstanceVersion => "wallet_instance_version",
            Self::RiskSignals => "risk_signals",
        }
    }
}

/// The namespace of the device-signed elements (§6.3).
pub const NAMESPACE: &str = "urn:paso:sca:1";

/// The SCA response claims as Key Binding JWT claims (§6.2).
pub static KEY_BINDING: [Member; 8] = [
    Member::claim(Sca::Jti.name()),
    Member::claim(Sca::DisplayLocale.name()),
    Member::claim(Sca::TransactionDataHash.name()),
    Member::claim(Sca::TransactionDataHashAlg.name()),
    Member::claim(Sca::MetadataIntegrity.name()),
    Member::claim(Sca::RequestIntegrity.name()),
    Member::claim(Sca::WalletInstanceVersion.name()),
    Member::claim(Sca::RiskSignals.name()),
];

/// The SCA response claims as device-signed elements of `urn:paso:sca:1` (§6.3).
pub static DEVICE_SIGNED: [Member; 8] = [
    Member::element(NAMESPACE, Sca::Jti.name()),
    Member::element(NAMESPACE, Sca::DisplayLocale.name()),
    Member::element(NAMESPACE, Sca::TransactionDataHash.name()),
    Member::element(NAMESPACE, Sca::TransactionDataHashAlg.name()),
    Member::element(NAMESPACE, Sca::MetadataIntegrity.name()),
    Member::element(NAMESPACE, Sca::RequestIntegrity.name()),
    Member::element(NAMESPACE, Sca::WalletInstanceVersion.name()),
    Member::element(NAMESPACE, Sca::RiskSignals.name()),
];

/// Where a presentation carries the SCA response claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proof {
    /// An SD-JWT VC's Key Binding JWT (`dc+sd-jwt`).
    KeyBinding,
    /// An mdoc's device-signed data elements (`mso_mdoc`).
    DeviceSigned,
}

impl Proof {
    /// The proof of a format PaSO defines a binding for.
    #[must_use]
    pub fn of(format: &FormatId<'_>) -> Option<Self> {
        match format.as_str() {
            "dc+sd-jwt" => Some(Self::KeyBinding),
            "mso_mdoc" => Some(Self::DeviceSigned),
            _ => None,
        }
    }

    /// The SCA response claims as members of this proof.
    #[must_use]
    pub fn members(self) -> &'static [Member] {
        match self {
            Self::KeyBinding => &KEY_BINDING,
            Self::DeviceSigned => &DEVICE_SIGNED,
        }
    }

    siros_openid4vp::with_resolve! {
        /// A claim as a member of this proof.
        pub(crate) const fn member(self, claim: Sca) -> Member {
            match self {
                Self::KeyBinding => Member::claim(claim.name()),
                Self::DeviceSigned => Member::element(NAMESPACE, claim.name()),
            }
        }
    }
}
