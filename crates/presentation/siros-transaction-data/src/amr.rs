//! The authentication factors a KB-JWT reports in `amr` (EC TS12 v1.0.1, Section 3.6).

use serde_json::{Map, Value};

/// An authentication factor the wallet applied to authorize a presentation: its category and
/// method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Factor {
    /// `knowledge`.
    Knowledge(Knowledge),
    /// `possession`.
    Possession(Possession),
    /// `inherence`.
    Inherence(Inherence),
}

/// A `knowledge` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Knowledge {
    /// `pin_less_than_6_digits`.
    PinLessThan6Digits,
    /// `pin_6_or_more_digits`.
    Pin6OrMoreDigits,
    /// `passphrase_less_than_8_chars`.
    PassphraseLessThan8Chars,
    /// `passphrase_8_to_11_chars`.
    Passphrase8To11Chars,
    /// `passphrase_12_or_more_chars`.
    Passphrase12OrMoreChars,
    /// `pattern`.
    Pattern,
    /// `other`.
    Other,
}

/// A `possession` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Possession {
    /// `key_in_remote_wscd`.
    KeyInRemoteWscd,
    /// `key_in_local_external_wscd`.
    KeyInLocalExternalWscd,
    /// `key_in_local_internal_wscd`.
    KeyInLocalInternalWscd,
    /// `key_in_local_native_wscd`.
    KeyInLocalNativeWscd,
    /// `other`.
    Other,
}

/// An `inherence` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Inherence {
    /// `fingerprint_device`.
    FingerprintDevice,
    /// `fingerprint_external`.
    FingerprintExternal,
    /// `face_device`.
    FaceDevice,
    /// `face_external`.
    FaceExternal,
    /// `other`.
    Other,
}

impl Factor {
    /// The category key.
    #[must_use]
    pub fn category(self) -> &'static str {
        match self {
            Self::Knowledge(_) => "knowledge",
            Self::Possession(_) => "possession",
            Self::Inherence(_) => "inherence",
        }
    }

    /// The method value.
    #[must_use]
    pub fn method(self) -> &'static str {
        match self {
            Self::Knowledge(method) => match method {
                Knowledge::PinLessThan6Digits => "pin_less_than_6_digits",
                Knowledge::Pin6OrMoreDigits => "pin_6_or_more_digits",
                Knowledge::PassphraseLessThan8Chars => "passphrase_less_than_8_chars",
                Knowledge::Passphrase8To11Chars => "passphrase_8_to_11_chars",
                Knowledge::Passphrase12OrMoreChars => "passphrase_12_or_more_chars",
                Knowledge::Pattern => "pattern",
                Knowledge::Other => "other",
            },
            Self::Possession(method) => match method {
                Possession::KeyInRemoteWscd => "key_in_remote_wscd",
                Possession::KeyInLocalExternalWscd => "key_in_local_external_wscd",
                Possession::KeyInLocalInternalWscd => "key_in_local_internal_wscd",
                Possession::KeyInLocalNativeWscd => "key_in_local_native_wscd",
                Possession::Other => "other",
            },
            Self::Inherence(method) => match method {
                Inherence::FingerprintDevice => "fingerprint_device",
                Inherence::FingerprintExternal => "fingerprint_external",
                Inherence::FaceDevice => "face_device",
                Inherence::FaceExternal => "face_external",
                Inherence::Other => "other",
            },
        }
    }
}

/// The authentication factors cover fewer than two categories (EC TS12 v1.0.1, Section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub struct AmrCategories;

impl AmrCategories {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        "transaction_data_amr_categories"
    }
}

/// The factors of a signing key, at least two categories among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amr(Vec<Factor>);

impl Amr {
    /// The factors `factors`, which the host reports for the signing key (H3).
    ///
    /// # Errors
    ///
    /// [`AmrCategories`]: the factors cover fewer than two categories.
    pub fn new(factors: Vec<Factor>) -> Result<Self, AmrCategories> {
        let first = factors.first().map(|f| f.category());
        if factors.iter().any(|f| Some(f.category()) != first) {
            Ok(Self(factors))
        } else {
            Err(AmrCategories)
        }
    }

    /// The factors, in the order the host reported them.
    #[must_use]
    pub fn factors(&self) -> &[Factor] {
        &self.0
    }

    /// The `amr` claim: one object `{category: method}` per factor.
    pub(crate) fn claim(&self) -> Value {
        Value::Array(
            self.0
                .iter()
                .map(|f| {
                    let factor: Map<String, Value> =
                        std::iter::once((f.category().to_owned(), f.method().into())).collect();
                    Value::Object(factor)
                })
                .collect(),
        )
    }
}
