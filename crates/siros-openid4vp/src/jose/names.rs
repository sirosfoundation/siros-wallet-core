//! The algorithms the host's modules state: the JWS algorithms the verifying module verifies
//! (`Haip::verifies`, A7) and the curves and JWE algorithms the decrypting module decrypts
//! (`RequestDecryption::decrypts`, U11). Each list has one owner, the module that implements it.

use crate::request::{ContentEncryption, Curve, KeyAgreement, jose_name};

/// A JWS `alg` (IANA "JSON Web Signature and Encryption Algorithms"): one or more printable ASCII
/// characters other than space and `"`. A module names its own with `checked!(JwsAlgorithm,
/// "...")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwsAlgorithm(&'static str);

impl JwsAlgorithm {
    /// `ES256` (RFC 7518 §3.4).
    pub const ES256: Self = Self("ES256");

    /// The name; `None` for an empty text, a character outside printable ASCII, space and `"`,
    /// and `none`, which RFC 8725 §3.2 refuses.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        if jose_name(name) && !matches!(name.as_bytes(), b"none") {
            Some(Self(name))
        } else {
            None
        }
    }

    /// The name as `alg` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// What a verifying module states (`Haip::verifies`), in its order. [`JwsAlgorithms::NONE`] is a
/// module that verifies nothing, under which A7 refuses every signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwsAlgorithms(&'static [JwsAlgorithm]);

impl JwsAlgorithms {
    /// No algorithm.
    pub const NONE: Self = Self(&[]);

    /// The statement.
    #[must_use]
    pub const fn new(algorithms: &'static [JwsAlgorithm]) -> Self {
        Self(algorithms)
    }

    /// Whether it states the `alg` a header names.
    #[must_use]
    pub fn states(&self, alg: &str) -> bool {
        self.0.iter().any(|stated| stated.as_str() == alg)
    }

    /// The algorithms.
    #[must_use]
    pub const fn algorithms(&self) -> &'static [JwsAlgorithm] {
        self.0
    }
}

/// What a decrypting module states (`RequestDecryption::decrypts`): the curves of the keys it
/// draws, and the `alg` and `enc` values it decrypts, each list one or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JweAlgorithms {
    curves: &'static [Curve<'static>],
    agreements: &'static [KeyAgreement<'static>],
    encryptions: &'static [ContentEncryption<'static>],
}

impl JweAlgorithms {
    /// The statement; `None` when a list is empty: a module that decrypts nothing is no
    /// `RequestDecryption`.
    #[must_use]
    pub const fn new(
        curves: &'static [Curve<'static>],
        agreements: &'static [KeyAgreement<'static>],
        encryptions: &'static [ContentEncryption<'static>],
    ) -> Option<Self> {
        if curves.is_empty() || agreements.is_empty() || encryptions.is_empty() {
            None
        } else {
            Some(Self {
                curves,
                agreements,
                encryptions,
            })
        }
    }

    /// Whether it states the curve.
    #[must_use]
    pub fn curve(&self, curve: Curve<'_>) -> bool {
        self.curves.iter().any(|c| c.as_str() == curve.as_str())
    }

    /// Whether it states the key agreement.
    #[must_use]
    pub fn agreement(&self, alg: KeyAgreement<'_>) -> bool {
        self.agreements.iter().any(|a| a.as_str() == alg.as_str())
    }

    /// Whether it states the content encryption.
    #[must_use]
    pub fn encryption(&self, enc: ContentEncryption<'_>) -> bool {
        self.encryptions.iter().any(|e| e.as_str() == enc.as_str())
    }

    /// The curves.
    #[must_use]
    pub const fn curves(&self) -> &'static [Curve<'static>] {
        self.curves
    }

    /// The key agreements.
    #[must_use]
    pub const fn agreements(&self) -> &'static [KeyAgreement<'static>] {
        self.agreements
    }

    /// The content encryptions.
    #[must_use]
    pub const fn encryptions(&self) -> &'static [ContentEncryption<'static>] {
        self.encryptions
    }
}
