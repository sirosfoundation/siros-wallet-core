//! Risk Signals §3-4 and §7.2: the risk signal profiles the wallet transcribed, the effective
//! signal set a type's metadata resolves (§4.1), and whether its signals must be encrypted.
//! Neither the PaSO rulebooks nor Core reference a profile or enumerate a signal: the metadata
//! that renders the entry is the one source.

use std::borrow::Cow;
use std::fmt;

use siros_openid4vp::ids::InvalidId;
use siros_openid4vp::json::Node;
use siros_openid4vp::refusal::ReprItem;

use crate::outcome::NotCompatible;

/// The prefix of every risk signal type (§2.1).
const SIGNAL_PREFIX: &str = "urn:paso:risk:";
/// The prefix of every risk signal profile identifier (§3.2).
const PROFILE_PREFIX: &str = "urn:paso:risk-profile:";

/// The profile PaSO publishes (Default.md).
pub const DEFAULT_PROFILE: &str = "urn:paso:risk-profile:global:default:1";

/// A signal type the wallet measures: a URN (RFC 8141), `urn:`, a non-empty namespace
/// identifier, `:` and a non-empty namespace-specific string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalType<'a>(Cow<'a, str>);

impl<'a> SignalType<'a> {
    /// Parses the type.
    ///
    /// # Errors
    ///
    /// The text is no such URN.
    pub fn parse(text: impl Into<Cow<'a, str>>) -> Result<Self, InvalidId> {
        let text = text.into();
        let urn = text
            .strip_prefix("urn:")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(nid, nss)| !nid.is_empty() && !nss.is_empty());
        if urn {
            Ok(Self(text))
        } else {
            Err(InvalidId {
                what: "signal type URN",
                value: text.into_owned(),
            })
        }
    }

    /// The type's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignalType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A risk signal type (§2.1): a URN under `urn:paso:risk:`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RiskSignal(SignalType<'static>);

impl RiskSignal {
    /// The response mode signal, which the request itself gives (Risk Signal Registry §2.7).
    pub const RESPONSE_MODE: Self = Self(SignalType(Cow::Borrowed(
        "urn:paso:risk:global:response_mode:1",
    )));
    /// The authentication methods signal, which strong customer authentication requires (Risk
    /// Signal Registry §2.8).
    pub const AMR: Self = Self(SignalType(Cow::Borrowed("urn:paso:risk:global:amr:1")));

    /// The signal type a text names.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        text.starts_with(SIGNAL_PREFIX)
            .then(|| SignalType::parse(text.to_owned()).ok().map(Self))
            .flatten()
    }

    /// The type as the PaSO module measures it.
    #[must_use]
    pub const fn signal(&self) -> &SignalType<'static> {
        &self.0
    }

    /// The type identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A risk signal profile identifier (§3.2): a URN under `urn:paso:risk-profile:`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    /// The identifier a text names.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        text.starts_with(PROFILE_PREFIX)
            .then(|| Self(text.to_owned()))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether the wallet must include a signal's envelope (§3.4 `required`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Need {
    /// Required: an envelope with its status, measured or not.
    Required,
    /// Optional: the wallet may leave it out (§4.2).
    Optional,
}

impl Need {
    /// The logical OR of two requirements: the strictest wins (§4.1 steps 2-3).
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Optional, Self::Optional) => Self::Optional,
            _ => Self::Required,
        }
    }
}

/// A signal's freshness bound in seconds (§3.4 `max_age`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MaxAge(pub u64);

/// The tighter of two optional bounds: the minimum of those present.
#[must_use]
pub fn tighter(a: Option<MaxAge>, b: Option<MaxAge>) -> Option<MaxAge> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Whether a type's risk signals must be encrypted (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sealing {
    /// Encrypted to the issuer's key.
    Encrypted,
    /// Sent as the plaintext array.
    Plain,
}

/// One signal of a profile or of the effective set: its type, its requirement and its bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalSpec {
    /// The signal type.
    pub signal: RiskSignal,
    /// Whether it is required.
    pub need: Need,
    /// Its freshness bound.
    pub max_age: Option<MaxAge>,
}

/// A risk signal profile the wallet transcribed (§3.3): whether it mandates encryption, and its
/// signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskProfile {
    /// Whether it mandates encryption.
    pub sealing: Sealing,
    /// Its signals.
    pub signals: Vec<SignalSpec>,
}

/// The risk signal profiles the wallet holds, by identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue(Vec<(ProfileId, RiskProfile)>);

impl Catalogue {
    /// The profiles, each identifier once (a later one replaces an earlier one).
    #[must_use]
    pub fn new(profiles: Vec<(ProfileId, RiskProfile)>) -> Self {
        let mut held: Vec<(ProfileId, RiskProfile)> = Vec::with_capacity(profiles.len());
        for (id, profile) in profiles {
            match held.iter_mut().find(|(known, _)| *known == id) {
                Some((_, slot)) => *slot = profile,
                None => held.push((id, profile)),
            }
        }
        Self(held)
    }

    /// The profile PaSO publishes, as Default.md tabulates it: seven required signals, each
    /// bound to 600 seconds, encrypted.
    #[must_use]
    pub fn paso() -> Self {
        let signals = [
            "response_mode",
            "geolocation",
            "call_activity",
            "device_motion",
            "screen_capture",
            "device_basics",
            "app_vendor_id",
        ]
        .into_iter()
        .filter_map(|name| RiskSignal::parse(&format!("urn:paso:risk:global:{name}:1")))
        .map(|signal| SignalSpec {
            signal,
            need: Need::Required,
            max_age: Some(MaxAge(600)),
        })
        .collect();
        Self::new(
            ProfileId::parse(DEFAULT_PROFILE)
                .map(|id| {
                    (
                        id,
                        RiskProfile {
                            sealing: Sealing::Encrypted,
                            signals,
                        },
                    )
                })
                .into_iter()
                .collect(),
        )
    }

    /// The profile of an identifier.
    #[must_use]
    pub fn get(&self, id: &ProfileId) -> Option<&RiskProfile> {
        self.0
            .iter()
            .find(|(known, _)| known == id)
            .map(|(_, profile)| profile)
    }
}

/// The effective signal set (§4.1) in resolution order, and whether it is encrypted (§7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The signals.
    pub signals: Vec<SignalSpec>,
    /// Whether they are encrypted.
    pub sealing: Sealing,
}

impl Effective {
    /// §4.1 over a type's metadata: the referenced profiles' signals united (`required` ORed,
    /// the least `max_age`), then the `risk_signals` enumeration applied as a ratchet; §7.2:
    /// encrypted when the metadata's `encrypted` or a referenced profile says so. Not
    /// compatible when a profile is one the wallet does not hold, or a member is malformed.
    pub fn resolve(metadata: &Node<'_>, catalogue: &Catalogue) -> Result<Self, NotCompatible> {
        let references = match metadata.get("risk_signal_profiles") {
            None => Vec::new(),
            Some(references) => references
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().and_then(ProfileId::parse))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or(NotCompatible::RiskProfiles)?,
        };
        let profiles = references
            .iter()
            .map(|id| {
                catalogue
                    .get(id)
                    .ok_or_else(|| NotCompatible::UnknownRiskProfile(id.as_str().to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut signals: Vec<SignalSpec> = Vec::new();
        for spec in profiles.iter().flat_map(|profile| &profile.signals) {
            merge(&mut signals, spec.clone());
        }
        let listed = match metadata.get("risk_signals") {
            None => &[][..],
            Some(listed) => listed
                .as_array()
                .ok_or(NotCompatible::RiskSignalsNotArray)?,
        };
        for entry in listed {
            let spec = enumerated(entry)
                .ok_or_else(|| NotCompatible::RiskSignalMalformed(ReprItem::repr(entry)))?;
            merge(&mut signals, spec);
        }
        let encrypted = match metadata.get("encrypted") {
            None | Some(Node::Bool(false)) => false,
            Some(Node::Bool(true)) => true,
            Some(_) => return Err(NotCompatible::EncryptedNotBoolean),
        };
        let sealing = if encrypted
            || profiles
                .iter()
                .any(|profile| profile.sealing == Sealing::Encrypted)
        {
            Sealing::Encrypted
        } else {
            Sealing::Plain
        };
        Ok(Self { signals, sealing })
    }

    /// The required signals, in resolution order (§4.2).
    pub fn required(&self) -> impl Iterator<Item = &SignalSpec> {
        self.signals
            .iter()
            .filter(|spec| spec.need == Need::Required)
    }
}

/// A signal joined to the set: a new one appended, a known one made stricter in place.
fn merge(signals: &mut Vec<SignalSpec>, spec: SignalSpec) {
    match signals.iter_mut().find(|known| known.signal == spec.signal) {
        Some(known) => {
            known.need = known.need.or(spec.need);
            known.max_age = tighter(known.max_age, spec.max_age);
        }
        None => signals.push(spec),
    }
}

/// A `risk_signals` entry (§3.4): an object with a signal `type`, `required` a boolean when
/// present, `max_age` a non-negative integer or `null` when present.
fn enumerated(entry: &Node<'_>) -> Option<SignalSpec> {
    let signal = RiskSignal::parse(entry.get("type")?.as_str()?)?;
    let need = match entry.get("required") {
        None | Some(Node::Bool(false)) => Need::Optional,
        Some(Node::Bool(true)) => Need::Required,
        Some(_) => return None,
    };
    let max_age = match entry.get("max_age") {
        None | Some(Node::Null) => None,
        Some(Node::Number(number)) if number.is_integer() => match number.as_u64() {
            Some(seconds) => Some(MaxAge(seconds)),
            None if number.text().starts_with('-') => return None,
            // Beyond 2^64 seconds no measurement ages out.
            None => Some(MaxAge(u64::MAX)),
        },
        Some(_) => return None,
    };
    Some(SignalSpec {
        signal,
        need,
        max_age,
    })
}
