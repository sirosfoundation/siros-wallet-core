//! Core §6: the SCA response claims (§6.1) and where a proof carries them, by its format's
//! placement: Key Binding JWT claims (§6.2), or device-signed elements of `urn:paso:sca:1` (§6.3).

use siros_openid4vp::plugins::Member;
use siros_openid4vp::wallet_metadata::Placement;

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

/// The SCA response claims as members of a proof that places them so: Key Binding JWT claims
/// (§6.2), or elements of [`NAMESPACE`] (§6.3).
#[must_use]
pub const fn members(placement: Placement) -> &'static [Member] {
    match placement {
        Placement::Claims => &KEY_BINDING,
        Placement::NameSpaces => &DEVICE_SIGNED,
    }
}

#[cfg(feature = "resolve")]
/// A claim as a member of a proof that places members so.
pub(crate) const fn member(placement: Placement, claim: Sca) -> Member {
    match placement {
        Placement::Claims => Member::claim(claim.name()),
        Placement::NameSpaces => Member::element(NAMESPACE, claim.name()),
    }
}
