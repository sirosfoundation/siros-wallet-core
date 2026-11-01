//! Validity, and the witness of validity at a given time (C4).

use siros_codec::date::DateTime;

use crate::credential::Credential;
use crate::error::ValidityError;

/// The times between which a credential is valid: from `not_before`, before `not_after`. An
/// absent bound leaves its side open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Validity {
    not_before: Option<DateTime>,
    not_after: Option<DateTime>,
}

impl Validity {
    pub(crate) fn new(not_before: Option<DateTime>, not_after: Option<DateTime>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// The first second of validity: the MSO's `validFrom`, or `nbf`.
    pub fn not_before(&self) -> Option<DateTime> {
        self.not_before
    }

    /// The first second after validity: the MSO's `validUntil`, or `exp`.
    pub fn not_after(&self) -> Option<DateTime> {
        self.not_after
    }
}

/// A credential valid at a given time: `not_before ≤ now < not_after`.
#[derive(Clone, Copy)]
pub struct UsableCredential<'c> {
    credential: &'c Credential,
    time: DateTime,
}

impl<'c> UsableCredential<'c> {
    /// `credential`, which is valid at `now`.
    ///
    /// # Errors
    ///
    /// [`ValidityError::NotYetValid`] before `not_before`; [`ValidityError::Expired`] from
    /// `not_after` on.
    pub fn at(credential: &'c Credential, now: DateTime) -> Result<Self, ValidityError> {
        let validity = credential.validity();
        if validity.not_before.is_some_and(|t| now < t) {
            return Err(ValidityError::NotYetValid);
        }
        if validity.not_after.is_some_and(|t| now >= t) {
            return Err(ValidityError::Expired);
        }
        Ok(Self {
            credential,
            time: now,
        })
    }

    /// The credential.
    pub fn credential(&self) -> &'c Credential {
        self.credential
    }

    /// The time the credential is valid at.
    pub fn time(&self) -> DateTime {
        self.time
    }
}

impl AsRef<Credential> for UsableCredential<'_> {
    fn as_ref(&self) -> &Credential {
        self.credential
    }
}
