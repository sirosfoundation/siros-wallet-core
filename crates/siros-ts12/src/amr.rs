//! TS12 §3.6: the `amr` object of an authentication factor.

use siros_openid4vp::host::{Factor, Knowledge, Modality, Possession, Sensor};

/// An `amr` category (TS12 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmrCategory {
    /// `knowledge`.
    Knowledge,
    /// `possession`.
    Possession,
    /// `inherence`.
    Inherence,
}

impl AmrCategory {
    /// The member name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Knowledge => "knowledge",
            Self::Possession => "possession",
            Self::Inherence => "inherence",
        }
    }
}

/// The method TS12 §3.6 keeps for a factor outside its list.
const OTHER: &str = "other";

/// The `amr` object of a factor: its category and method.
#[must_use]
pub fn amr(factor: &Factor) -> (AmrCategory, &'static str) {
    match factor {
        Factor::Knowledge(knowledge) => (AmrCategory::Knowledge, knowledge_method(*knowledge)),
        Factor::Possession(possession) => (
            AmrCategory::Possession,
            match possession {
                Possession::RemoteWscd => "key_in_remote_wscd",
                Possession::LocalExternalWscd => "key_in_local_external_wscd",
                Possession::LocalInternalWscd => "key_in_local_internal_wscd",
                Possession::LocalNativeWscd => "key_in_local_native_wscd",
                Possession::Software => OTHER,
            },
        ),
        Factor::Inherence(inherence) => (
            AmrCategory::Inherence,
            match (inherence.modality, inherence.sensor) {
                (Modality::Fingerprint, Sensor::Device) => "fingerprint_device",
                (Modality::Fingerprint, Sensor::External) => "fingerprint_external",
                (Modality::Face, Sensor::Device) => "face_device",
                (Modality::Face, Sensor::External) => "face_external",
                (Modality::Iris | Modality::Unknown, _) => OTHER,
            },
        ),
    }
}

fn knowledge_method(knowledge: Knowledge) -> &'static str {
    match knowledge {
        Knowledge::Pin(Some(digits)) if digits.get() < 6 => "pin_less_than_6_digits",
        Knowledge::Pin(Some(_)) => "pin_6_or_more_digits",
        Knowledge::Passphrase(Some(chars)) if chars.get() < 8 => "passphrase_less_than_8_chars",
        Knowledge::Passphrase(Some(chars)) if chars.get() < 12 => "passphrase_8_to_11_chars",
        Knowledge::Passphrase(Some(_)) => "passphrase_12_or_more_chars",
        Knowledge::Pattern => "pattern",
        Knowledge::Pin(None) | Knowledge::Passphrase(None) | Knowledge::Unknown => OTHER,
    }
}
