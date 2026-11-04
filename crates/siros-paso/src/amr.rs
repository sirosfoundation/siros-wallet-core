//! Risk Signal Registry §2.8: the `amr` signal's value, the End-User's authentication as RFC 8176
//! method values and the registry's biometric strengths.

use std::borrow::Cow;

use siros_openid4vp::host::{Authentication, Factor, Knowledge, Modality, Possession, Strength};
use siros_openid4vp::json::Node;

/// The knowledge and possession factors' methods in the order applied (RFC 8176 §2): `pin` for a
/// PIN or a pattern, `pwd` for a passphrase, `kba` for a knowledge factor the platform does not
/// name, `hwk` for a key in a WSCD, `swk` for a software key. Then, with a biometric factor,
/// exactly one of `bio_strong` and `bio_weak`, strong when one factor meets the criteria, and each
/// modality the platform names (`fpt`, `face`, `iris`). Each method once.
#[must_use]
pub fn methods(authentication: &Authentication) -> Node<'static> {
    let factors = authentication.factors().items();
    let inherence = factors
        .iter()
        .filter_map(|factor| match factor {
            Factor::Inherence(inherence) => Some(inherence),
            Factor::Knowledge(_) | Factor::Possession(_) => None,
        })
        .collect::<Vec<_>>();
    let strength = (!inherence.is_empty()).then(|| {
        if inherence
            .iter()
            .any(|inherence| inherence.strength == Strength::Strong)
        {
            "bio_strong"
        } else {
            "bio_weak"
        }
    });
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
    for method in others.chain(strength).chain(modalities) {
        if !written.contains(&method) {
            written.push(method);
        }
    }
    Node::Array(
        written
            .into_iter()
            .map(|method| Node::String(Cow::Borrowed(method)))
            .collect(),
    )
}
