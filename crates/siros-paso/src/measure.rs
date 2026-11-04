//! The PaSO module, which siros-paso requires: the wallet's version (Core §6.1) and its risk
//! signals' measurements (Risk Signals §2.3), which the app keeps.

use serde_json::value::RawValue;
use siros_openid4vp::host::{Seconds, Timestamp};

use crate::risk::SignalType;

/// A risk signal measurement (Risk Signals §2.3).
#[derive(Debug, Clone)]
pub struct Measurement {
    /// When it was measured.
    pub collected_at: Timestamp,
    /// What it found.
    pub reading: Reading,
}

/// A measurement's status and value.
#[derive(Debug, Clone)]
pub enum Reading {
    /// Measured: the value.
    Ok(Box<RawValue>),
    /// No measurement was obtainable, or the wallet does not implement the signal.
    Unavailable,
    /// The permission was refused.
    Denied,
}

/// The wallet's version and its risk signals; the app keeps the last measurement of each.
pub trait Paso {
    /// The wallet's version (Core §6.1 `wallet_instance_version`).
    fn version(&self) -> &str;
    /// A signal's last measurement when no older than `max_age`, else a new one when the wallet
    /// can measure again, else an unavailable one; `None` when the wallet does not implement the
    /// signal.
    fn measure(&self, signal: &SignalType<'_>, max_age: Option<Seconds>) -> Option<Measurement>;
}

/// The PaSO module's stand-in for the tests (feature `test-util`).
#[cfg(feature = "test-util")]
mod test_util {
    use siros_openid4vp::host::{Seconds, Timestamp};

    use super::{Measurement, Paso, Reading, SignalType};

    /// A risk signal's last measurement.
    #[derive(Debug, Clone)]
    pub struct Signal {
        /// When it was measured.
        pub collected_at: Timestamp,
        /// What it found.
        pub reading: Reading,
        /// Whether the wallet can measure it again.
        pub retakes: bool,
    }

    /// A signal type with its last measurement.
    #[derive(Debug, Clone)]
    pub struct Measured {
        /// The signal type.
        pub signal: SignalType<'static>,
        /// Its last measurement.
        pub last: Signal,
    }

    /// The PaSO module's stand-in: its clock, the wallet's version, and the last measurement of
    /// each signal it implements.
    #[derive(Debug, Clone)]
    pub struct TestPaso {
        /// The clock measurements age by.
        pub now: Timestamp,
        /// The wallet's version.
        pub version: String,
        /// The signals the wallet implements.
        pub signals: Vec<Measured>,
    }

    impl Default for TestPaso {
        /// At 1 785 000 000, nothing measured.
        fn default() -> Self {
            Self::at(Timestamp(1_785_000_000))
        }
    }

    impl TestPaso {
        /// The default module at another time.
        #[must_use]
        pub fn at(now: Timestamp) -> Self {
            Self {
                now,
                version: "android:org.siros.wallet:1.0.0".to_owned(),
                signals: Vec::new(),
            }
        }
    }

    impl Paso for TestPaso {
        fn version(&self) -> &str {
            &self.version
        }

        fn measure(&self, signal: &SignalType<'_>, max_age: Option<Seconds>) -> Option<Measurement> {
            let Measured { last, .. } = self
                .signals
                .iter()
                .find(|measured| measured.signal.as_str() == signal.as_str())?;
            let fresh = max_age
                .is_none_or(|Seconds(bound)| self.now.0.saturating_sub(last.collected_at.0) <= bound);
            Some(match (fresh, last.retakes) {
                (true, _) => Measurement {
                    collected_at: last.collected_at,
                    reading: last.reading.clone(),
                },
                (false, true) => Measurement {
                    collected_at: self.now,
                    reading: last.reading.clone(),
                },
                (false, false) => Measurement {
                    collected_at: self.now,
                    reading: Reading::Unavailable,
                },
            })
        }
    }
}

#[cfg(feature = "test-util")]
pub use test_util::{Measured, Signal, TestPaso};
