//! Risk Signal Registry §2.8: the `amr` signal's value, the End-User's authentication as RFC 8176
//! method values and the registry's biometric classes.

use std::borrow::Cow;

use siros_openid4vp::host::{
    AttackDetection, Authentication, Factor, Inherence, Isolation, Knowledge, Modality, Possession,
};
use siros_openid4vp::json::Node;

/// The false accept rate `bio_strong` admits at most: one in 50,000 (Registry §2.8).
const STRONG_ATTEMPTS: u32 = 50_000;

/// The false accept rate `bio_weak` admits at most: one in 10,000 (Registry §2.8).
const WEAK_ATTEMPTS: u32 = 10_000;

/// An inherence factor's `amr` class (Registry §2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BiometricClass {
    /// `bio_weak`: a false accept rate of one in 10,000 or less, short of `bio_strong`.
    Weak,
    /// `bio_strong`: matching in a hardware-isolated environment, a false accept rate of one in
    /// 50,000 or less, and presentation attack detection.
    Strong,
}

impl BiometricClass {
    /// The class of the facts the platform reported. `None` for a factor that meets neither
    /// class: a false accept rate above one in 10,000, or none reported.
    #[must_use]
    pub fn of(inherence: &Inherence) -> Option<Self> {
        let attempts = inherence.false_accepts?.attempts().get();
        let strong = inherence.isolation == Isolation::Hardware
            && attempts >= STRONG_ATTEMPTS
            && inherence.attack_detection == AttackDetection::Present;
        if strong {
            Some(Self::Strong)
        } else if attempts >= WEAK_ATTEMPTS {
            Some(Self::Weak)
        } else {
            None
        }
    }

    /// The method value.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Strong => "bio_strong",
            Self::Weak => "bio_weak",
        }
    }
}

/// The knowledge and possession factors' methods in the order applied (RFC 8176 §2): `pin` for a
/// PIN or a pattern, `pwd` for a passphrase, `kba` for a knowledge factor the platform does not
/// name, `hwk` for a key in a WSCD, `swk` for a software key. Then, with a biometric factor,
/// exactly one of `bio_strong` and `bio_weak`, the best class a factor meets
/// ([`BiometricClass::of`]), and each modality the platform names (`fpt`, `face`, `iris`). Each
/// method once.
///
/// `None` when every biometric factor meets neither class: §2.8 then admits no value, and the
/// signal is unavailable (Risk Signals §2.3).
#[must_use]
pub fn methods(authentication: &Authentication) -> Option<Node<'static>> {
    let factors = authentication.factors().items();
    let inherence = factors
        .iter()
        .filter_map(|factor| match factor {
            Factor::Inherence(inherence) => Some(inherence),
            Factor::Knowledge(_) | Factor::Possession(_) => None,
        })
        .collect::<Vec<_>>();
    let class = if inherence.is_empty() {
        None
    } else {
        let best = inherence
            .iter()
            .filter_map(|inherence| BiometricClass::of(inherence))
            .max()?;
        Some(best.method())
    };
    let modalities = inherence
        .iter()
        .filter_map(|inherence| match inherence.modality {
            Modality::Fingerprint => Some("fpt"),
            Modality::Face => Some("face"),
            Modality::Iris => Some("iris"),
            Modality::Unknown => None,
        });
    let others = factors.iter().filter_map(|factor| match factor {
        Factor::Knowledge(Knowledge::Pin(_) | Knowledge::Pattern) => Some("pin"),
        Factor::Knowledge(Knowledge::Passphrase(_)) => Some("pwd"),
        Factor::Knowledge(Knowledge::Unknown) => Some("kba"),
        Factor::Possession(Possession::Software) => Some("swk"),
        Factor::Possession(
            Possession::RemoteWscd
            | Possession::LocalExternalWscd
            | Possession::LocalInternalWscd
            | Possession::LocalNativeWscd,
        ) => Some("hwk"),
        Factor::Inherence(_) => None,
    });
    let mut written: Vec<&'static str> = Vec::new();
    for method in others.chain(class).chain(modalities) {
        if !written.contains(&method) {
            written.push(method);
        }
    }
    Some(Node::Array(
        written
            .into_iter()
            .map(|method| Node::String(Cow::Borrowed(method)))
            .collect(),
    ))
}
