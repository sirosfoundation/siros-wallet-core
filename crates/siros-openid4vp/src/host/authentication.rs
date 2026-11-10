//! How the wallet authenticated the End-User, and the authentication a profile needs (PSD2 Art.
//! 4(30); TS12 §3.6).

use std::fmt;
use std::num::NonZeroU32;

use siros_syntax::AllOf;

use super::Timestamp;

/// A knowledge factor's method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Knowledge {
    /// A PIN, with its digits when the platform reports them.
    Pin(Option<NonZeroU32>),
    /// A passphrase, with its characters when the platform reports them.
    Passphrase(Option<NonZeroU32>),
    /// A pattern.
    Pattern,
    /// A method the platform does not name.
    Unknown,
}

/// A possession factor's method: where the key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Possession {
    /// A remote WSCD.
    RemoteWscd,
    /// A local external WSCD.
    LocalExternalWscd,
    /// A local internal WSCD.
    LocalInternalWscd,
    /// A local native WSCD.
    LocalNativeWscd,
    /// Software.
    Software,
}

/// An inherence factor's modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modality {
    /// A fingerprint.
    Fingerprint,
    /// A face.
    Face,
    /// An iris.
    Iris,
    /// A modality the platform does not name.
    Unknown,
}

/// Where an inherence sensor sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensor {
    /// In the device.
    Device,
    /// Outside the device.
    External,
}

/// Where an inherence factor's comparison ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Isolation {
    /// In an environment the operating system cannot read: a TEE or a secure element.
    Hardware,
    /// Alongside the operating system.
    None,
    /// The platform does not report it.
    Unreported,
}

/// A matcher's false accept rate: at most one false accept in `n` attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FalseAcceptRate(NonZeroU32);

impl FalseAcceptRate {
    /// At most one in `n`.
    #[must_use]
    pub const fn one_in(n: NonZeroU32) -> Self {
        Self(n)
    }

    /// `n`.
    #[must_use]
    pub const fn attempts(self) -> NonZeroU32 {
        self.0
    }
}

/// Whether the matching detects presentation attacks (ISO/IEC 30107-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackDetection {
    /// It does.
    Present,
    /// It does not.
    Absent,
    /// The platform does not report it.
    Unreported,
}

/// An inherence factor as the platform reports it: the modality, the sensor, and the facts of its
/// matching, which a profile classifies by its own criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inherence {
    /// The modality.
    pub modality: Modality,
    /// Where the sensor sits.
    pub sensor: Sensor,
    /// Where the comparison ran.
    pub isolation: Isolation,
    /// The false accept rate, when the platform reports it.
    pub false_accepts: Option<FalseAcceptRate>,
    /// Presentation attack detection.
    pub attack_detection: AttackDetection,
}

/// One factor the wallet applied, by PSD2 Art. 4(30) category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Factor {
    /// Something only the user knows.
    Knowledge(Knowledge),
    /// Something only the user possesses.
    Possession(Possession),
    /// Something the user is.
    Inherence(Inherence),
}

/// How the wallet authenticated the End-User for one response: when the user completed it, and
/// each factor in the order applied, one or more. Each profile writes its own encoding of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    completed_at: Timestamp,
    factors: AllOf<Factor>,
}

impl Authentication {
    /// The authentication the platform reports.
    #[must_use]
    pub const fn new(completed_at: Timestamp, factors: AllOf<Factor>) -> Self {
        Self {
            completed_at,
            factors,
        }
    }

    /// When the user completed it.
    #[must_use]
    pub const fn completed_at(&self) -> Timestamp {
        self.completed_at
    }

    /// The factors, in the order applied.
    #[must_use]
    pub const fn factors(&self) -> &AllOf<Factor> {
        &self.factors
    }
}

/// The End-User authentication a profile needs; the stronger need is the greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthenticationNeed {
    /// Whatever the wallet's unlock asks.
    Presence,
    /// Factors of two PSD2 categories among knowledge, possession and inherence (PSD2 Art.
    /// 4(30); TS12 §3.6).
    Strong,
}

impl AuthenticationNeed {
    /// Whether factors covering these categories meet the need.
    #[must_use]
    pub const fn met_by(self, covered: Categories) -> bool {
        match self {
            Self::Presence => true,
            Self::Strong => covered.count() >= 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Presence => "presence",
            Self::Strong => "strong",
        }
    }
}

impl fmt::Display for AuthenticationNeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The PSD2 categories (Art. 4(30)) an authentication's factors cover: a set of knowledge,
/// possession and inherence. Only [`Categories::of`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Categories {
    knowledge: bool,
    possession: bool,
    inherence: bool,
}

impl Categories {
    /// The categories of the factors applied.
    #[must_use]
    pub fn of(authentication: &Authentication) -> Self {
        let covers =
            |category: fn(&Factor) -> bool| authentication.factors.items().iter().any(category);
        Self {
            knowledge: covers(|factor| matches!(factor, Factor::Knowledge(_))),
            possession: covers(|factor| matches!(factor, Factor::Possession(_))),
            inherence: covers(|factor| matches!(factor, Factor::Inherence(_))),
        }
    }

    /// How many: 1 to 3.
    #[must_use]
    pub const fn count(self) -> usize {
        self.knowledge as usize + self.possession as usize + self.inherence as usize
    }
}

impl fmt::Display for Categories {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.count())
    }
}
