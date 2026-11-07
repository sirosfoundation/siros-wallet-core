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

/// A method TS12 §3.6 lists, with the category it falls under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmrMethod {
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
    /// `other` under `knowledge`.
    OtherKnowledge,
    /// `key_in_remote_wscd`.
    KeyInRemoteWscd,
    /// `key_in_local_external_wscd`.
    KeyInLocalExternalWscd,
    /// `key_in_local_internal_wscd`.
    KeyInLocalInternalWscd,
    /// `key_in_local_native_wscd`.
    KeyInLocalNativeWscd,
    /// `other` under `possession`.
    OtherPossession,
    /// `fingerprint_device`.
    FingerprintDevice,
    /// `fingerprint_external`.
    FingerprintExternal,
    /// `face_device`.
    FaceDevice,
    /// `face_external`.
    FaceExternal,
    /// `other` under `inherence`.
    OtherInherence,
}

impl AmrMethod {
    /// The category holding the method.
    #[must_use]
    pub const fn category(self) -> AmrCategory {
        match self {
            Self::PinLessThan6Digits
            | Self::Pin6OrMoreDigits
            | Self::PassphraseLessThan8Chars
            | Self::Passphrase8To11Chars
            | Self::Passphrase12OrMoreChars
            | Self::Pattern
            | Self::OtherKnowledge => AmrCategory::Knowledge,
            Self::KeyInRemoteWscd
            | Self::KeyInLocalExternalWscd
            | Self::KeyInLocalInternalWscd
            | Self::KeyInLocalNativeWscd
            | Self::OtherPossession => AmrCategory::Possession,
            Self::FingerprintDevice
            | Self::FingerprintExternal
            | Self::FaceDevice
            | Self::FaceExternal
            | Self::OtherInherence => AmrCategory::Inherence,
        }
    }

    /// The member's value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PinLessThan6Digits => "pin_less_than_6_digits",
            Self::Pin6OrMoreDigits => "pin_6_or_more_digits",
            Self::PassphraseLessThan8Chars => "passphrase_less_than_8_chars",
            Self::Passphrase8To11Chars => "passphrase_8_to_11_chars",
            Self::Passphrase12OrMoreChars => "passphrase_12_or_more_chars",
            Self::Pattern => "pattern",
            Self::KeyInRemoteWscd => "key_in_remote_wscd",
            Self::KeyInLocalExternalWscd => "key_in_local_external_wscd",
            Self::KeyInLocalInternalWscd => "key_in_local_internal_wscd",
            Self::KeyInLocalNativeWscd => "key_in_local_native_wscd",
            Self::FingerprintDevice => "fingerprint_device",
            Self::FingerprintExternal => "fingerprint_external",
            Self::FaceDevice => "face_device",
            Self::FaceExternal => "face_external",
            Self::OtherKnowledge | Self::OtherPossession | Self::OtherInherence => "other",
        }
    }
}

/// The `amr` method of a factor.
#[must_use]
pub const fn amr(factor: &Factor) -> AmrMethod {
    match factor {
        Factor::Knowledge(knowledge) => knowledge_method(*knowledge),
        Factor::Possession(possession) => match possession {
            Possession::RemoteWscd => AmrMethod::KeyInRemoteWscd,
            Possession::LocalExternalWscd => AmrMethod::KeyInLocalExternalWscd,
            Possession::LocalInternalWscd => AmrMethod::KeyInLocalInternalWscd,
            Possession::LocalNativeWscd => AmrMethod::KeyInLocalNativeWscd,
            Possession::Software => AmrMethod::OtherPossession,
        },
        Factor::Inherence(inherence) => match (inherence.modality, inherence.sensor) {
            (Modality::Fingerprint, Sensor::Device) => AmrMethod::FingerprintDevice,
            (Modality::Fingerprint, Sensor::External) => AmrMethod::FingerprintExternal,
            (Modality::Face, Sensor::Device) => AmrMethod::FaceDevice,
            (Modality::Face, Sensor::External) => AmrMethod::FaceExternal,
            (Modality::Iris | Modality::Unknown, _) => AmrMethod::OtherInherence,
        },
    }
}

const fn knowledge_method(knowledge: Knowledge) -> AmrMethod {
    match knowledge {
        Knowledge::Pin(Some(digits)) if digits.get() < 6 => AmrMethod::PinLessThan6Digits,
        Knowledge::Pin(Some(_)) => AmrMethod::Pin6OrMoreDigits,
        Knowledge::Passphrase(Some(chars)) if chars.get() < 8 => {
            AmrMethod::PassphraseLessThan8Chars
        }
        Knowledge::Passphrase(Some(chars)) if chars.get() < 12 => AmrMethod::Passphrase8To11Chars,
        Knowledge::Passphrase(Some(_)) => AmrMethod::Passphrase12OrMoreChars,
        Knowledge::Pattern => AmrMethod::Pattern,
        Knowledge::Pin(None) | Knowledge::Passphrase(None) | Knowledge::Unknown => {
            AmrMethod::OtherKnowledge
        }
    }
}
