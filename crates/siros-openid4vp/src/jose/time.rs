//! The JWT claims a recipient checks against its clock (RFC 7519 §4.1.4, §4.1.5): `exp` and
//! `nbf` as NumericDates, within a clock skew.

use siros_explain::Explain;

use crate::host::{Seconds, Timestamp};
use crate::json::{Node, Object};

/// A NumericDate (RFC 7519 §2): seconds since the epoch, a fraction allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NumericDate {
    seconds: i64,
    nanos: u32,
}

impl NumericDate {
    /// The date a JSON number states; `None` for another value, or one outside an `i64` of
    /// seconds.
    #[must_use]
    pub fn of(value: &Node<'_>) -> Option<Self> {
        let Node::Number(number) = value else {
            return None;
        };
        if let Ok(seconds) = number.text().parse::<i64>() {
            return Some(Self { seconds, nanos: 0 });
        }
        let value = number.to_double()?;
        let whole = value.floor();
        // `as` saturates; the range check keeps the seconds exact.
        (whole.abs() < 9.2e18).then_some(Self {
            seconds: whole as i64,
            nanos: ((value - whole) * 1e9) as u32,
        })
    }

    /// The seconds since the epoch, the fraction left out.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }
}

/// A clock skew of at most 300 seconds (RFC 7519 §4.1.4: "usually no more than a few minutes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skew(Seconds);

/// A skew past 300 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.time")]
#[error("a clock skew of {0} s is past 300 s")]
pub struct SkewTooLarge(#[explain(name = "seconds")] pub u64);

impl Skew {
    /// The longest skew the wallet allows.
    pub const MAX: u64 = 300;

    /// The skew; refused past 300 seconds.
    ///
    /// # Errors
    ///
    /// The skew is past 300 seconds.
    pub const fn new(seconds: Seconds) -> Result<Self, SkewTooLarge> {
        if seconds.0 > Self::MAX {
            Err(SkewTooLarge(seconds.0))
        } else {
            Ok(Self(seconds))
        }
    }

    /// The skew in seconds.
    #[must_use]
    pub const fn seconds(self) -> Seconds {
        self.0
    }
}

/// A JWT used outside its validity, or a time claim that is no NumericDate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.time")]
pub enum TimeError {
    /// `exp` or `nbf` is no number.
    #[error("{0} is no NumericDate")]
    NotNumericDate(#[explain(name = "claim")] &'static str),
    /// `exp` has passed.
    #[error("expired")]
    Expired,
    /// `nbf` is still ahead.
    #[error("not yet valid")]
    NotYetValid,
}

/// The validity a JWT states: its `exp` and `nbf` (RFC 7519 §4.1.4, §4.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    exp: Option<NumericDate>,
    nbf: Option<NumericDate>,
}

impl Validity {
    /// The validity the claims state.
    ///
    /// # Errors
    ///
    /// `exp` or `nbf` is no NumericDate.
    pub fn of(claims: &Object<'_>) -> Result<Self, TimeError> {
        Self::read(claims.get("exp"), claims.get("nbf"))
    }

    /// The validity of an `exp` and an `nbf` as received.
    ///
    /// # Errors
    ///
    /// `exp` or `nbf` is no NumericDate.
    pub fn read(exp: Option<&Node<'_>>, nbf: Option<&Node<'_>>) -> Result<Self, TimeError> {
        let date = |value: Option<&Node<'_>>, claim: &'static str| {
            value
                .map(|value| NumericDate::of(value).ok_or(TimeError::NotNumericDate(claim)))
                .transpose()
        };
        Ok(Self {
            exp: date(exp, "exp")?,
            nbf: date(nbf, "nbf")?,
        })
    }

    /// `exp`.
    #[must_use]
    pub const fn exp(&self) -> Option<NumericDate> {
        self.exp
    }

    /// Whether the JWT is processed at `now` before `exp` and at or after `nbf`, each within the
    /// skew.
    ///
    /// # Errors
    ///
    /// `exp` has passed, or `nbf` is still ahead.
    pub fn check(&self, now: Timestamp, skew: Skew) -> Result<(), TimeError> {
        let now = i128::from(now.0);
        let skew = i128::from(skew.0.0);
        let at =
            |date: NumericDate| i128::from(date.seconds) * 1_000_000_000 + i128::from(date.nanos);
        let now = now * 1_000_000_000;
        let skew = skew * 1_000_000_000;
        if self.exp.is_some_and(|exp| now >= at(exp) + skew) {
            return Err(TimeError::Expired);
        }
        if self.nbf.is_some_and(|nbf| now + skew < at(nbf)) {
            return Err(TimeError::NotYetValid);
        }
        Ok(())
    }
}
