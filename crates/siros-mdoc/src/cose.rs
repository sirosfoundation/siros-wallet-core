//! COSE signers and the identifiers of `vp_formats_supported` they match (B.2.4), the curves of
//! ISO/IEC 18013-5 Table 22, and B.2.4's identifiers of the device MAC per curve. Phase 2 builds
//! DeviceSignature and DeviceMac over coset.

use siros_openid4vp::request::Curve as Agreed;

/// An elliptic curve a device or issuer key is on (ISO/IEC 18013-5 Table 22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Curve {
    /// P-256.
    P256,
    /// P-384.
    P384,
    /// P-521.
    P521,
    /// X25519.
    X25519,
    /// X448.
    X448,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// brainpoolP256r1.
    BrainpoolP256r1,
    /// brainpoolP320r1.
    BrainpoolP320r1,
    /// brainpoolP384r1.
    BrainpoolP384r1,
    /// brainpoolP512r1.
    BrainpoolP512r1,
}

impl Curve {
    const ALL: [Self; 11] = [
        Self::P256,
        Self::P384,
        Self::P521,
        Self::X25519,
        Self::X448,
        Self::Ed25519,
        Self::Ed448,
        Self::BrainpoolP256r1,
        Self::BrainpoolP320r1,
        Self::BrainpoolP384r1,
        Self::BrainpoolP512r1,
    ];

    /// The curve of a name.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|curve| curve.name() == name)
    }

    /// The curve's name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::BrainpoolP256r1 => "brainpoolP256r1",
            Self::BrainpoolP320r1 => "brainpoolP320r1",
            Self::BrainpoolP384r1 => "brainpoolP384r1",
            Self::BrainpoolP512r1 => "brainpoolP512r1",
        }
    }
}

/// B.2.4: the identifier of HMAC 256/256 with its key agreed by ECDH (ISO/IEC 18013-5 §9.1.3.5)
/// on the reader key's curve; `None` for a curve B.2.4's table does not name.
pub(crate) fn mac(curve: Agreed<'_>) -> Option<i64> {
    match curve.as_str() {
        "P-256" => Some(-65537),
        "P-384" => Some(-65538),
        "P-521" => Some(-65539),
        "X25519" => Some(-65540),
        "X448" => Some(-65541),
        _ => None,
    }
}

/// A COSE signer: the `alg` of its COSE header and its key's curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signer {
    /// The COSE algorithm identifier.
    pub(crate) alg: i64,
    /// The key's curve.
    pub(crate) curve: Curve,
}

/// RFC 9864 §2: the fully-specified algorithm each polymorphic COSE algorithm becomes on a curve:
/// ES256 (-7), ES384 (-35), ES512 (-36) and EdDSA (-8).
const FULLY_SPECIFIED: [(i64, Curve, i64); 9] = [
    (-7, Curve::P256, -9),
    (-35, Curve::P384, -51),
    (-36, Curve::P521, -52),
    (-7, Curve::BrainpoolP256r1, -265),
    (-35, Curve::BrainpoolP320r1, -266),
    (-35, Curve::BrainpoolP384r1, -267),
    (-36, Curve::BrainpoolP512r1, -268),
    (-8, Curve::Ed25519, -19),
    (-8, Curve::Ed448, -53),
];

impl Signer {
    /// B.2.4: the identifiers a signature matches, its `alg` and the fully-specified algorithm
    /// of its `alg` on its key's curve.
    pub(crate) fn identifiers(self) -> Vec<i64> {
        std::iter::once(self.alg)
            .chain(
                FULLY_SPECIFIED
                    .iter()
                    .filter(|(alg, curve, _)| *alg == self.alg && *curve == self.curve)
                    .map(|(_, _, specified)| *specified),
            )
            .collect()
    }
}

#[cfg(feature = "resolve")]
use siros_openid4vp::cbor::cose::coset::{
    CoseMac0, CoseMac0Builder, CoseSign1, CoseSign1Builder, HeaderBuilder, MacContext,
    ProtectedHeader, iana, mac_structure_data,
};
#[cfg(feature = "resolve")]
use siros_openid4vp::plugins::Fault;

#[cfg(feature = "resolve")]
/// DeviceSignature (ISO/IEC 18013-5 §9.1.3.6): a COSE_Sign1 with the device key's `alg`
/// protected, nothing unprotected and the payload detached (nil); the signature over RFC 9052
/// §4.4's Sig_structure of DeviceAuthenticationBytes with an empty external_aad.
pub(crate) fn device_signature<E>(
    alg: iana::Algorithm,
    detached: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
) -> Result<CoseSign1, E> {
    CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(alg).build())
        .try_create_detached_signature(detached, b"", sign)
        .map(CoseSign1Builder::build)
}

#[cfg(feature = "resolve")]
/// DeviceMac (ISO/IEC 18013-5 §9.1.3.5): a COSE_Mac0 with HMAC 256/256 (5) protected, nothing
/// unprotected and the payload detached; the tag over RFC 9052 §6.3's MAC_structure of
/// DeviceAuthenticationBytes. coset's builder MACs a set payload alone, so the MAC_structure
/// comes from its `mac_structure_data`.
pub(crate) fn device_mac(
    detached: &[u8],
    mac: impl FnOnce(&[u8]) -> Result<Vec<u8>, Fault>,
) -> Result<CoseMac0, Fault> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::HMAC_256_256)
        .build();
    let to_be_maced = mac_structure_data(
        MacContext::CoseMac0,
        ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        },
        b"",
        detached,
    );
    Ok(CoseMac0Builder::new()
        .protected(protected)
        .tag(mac(&to_be_maced)?)
        .build())
}
