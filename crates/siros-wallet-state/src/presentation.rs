//! A presentation record: an entry of `S.presentations`, and the record the core returns for
//! the host to append as a `new_presentation` event (privatedata 3.1, Section 6; H5).

use crate::entry::{object, Members};
use crate::error::{JsonTextError, PresentationsFault, WalletStateError};
use crate::ids::{CredentialId, PresentationId, TransactionId};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

/// `data`: the presentation as sent, the `vp_token` of an OpenID4VP response.
#[derive(Serialize)]
#[serde(transparent)]
pub struct PresentationData(String);

impl PresentationData {
    /// The presentation `text`.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }
}

/// `audience`: whom the presentation was sent to.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Audience(String);

impl Audience {
    /// The audience `text`.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text)
    }
}

/// The members of `new_presentation`. It serialises to them, with
/// `presentationTimestampSeconds` in seconds since 1970-01-01T00:00:00Z.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRecord {
    presentation_id: PresentationId,
    transaction_id: TransactionId,
    data: PresentationData,
    used_credential_ids: Vec<CredentialId>,
    #[serde(
        rename = "presentationTimestampSeconds",
        serialize_with = "unix_seconds"
    )]
    timestamp: Timestamp,
    audience: Audience,
}

impl PresentationRecord {
    /// The record of the presentation `data`, sent to `audience` at `timestamp`, which used the
    /// credential entries `used_credential_ids`.
    pub fn new(
        presentation_id: PresentationId,
        transaction_id: TransactionId,
        data: PresentationData,
        used_credential_ids: Vec<CredentialId>,
        timestamp: Timestamp,
        audience: Audience,
    ) -> Self {
        Self {
            presentation_id,
            transaction_id,
            data,
            used_credential_ids,
            timestamp,
            audience,
        }
    }

    /// `usedCredentialIds`: the credential entries the presentation used.
    pub fn used_credential_ids(&self) -> &[CredentialId] {
        &self.used_credential_ids
    }

    /// The entry of `S.presentations` that `raw` holds.
    pub(crate) fn parse(raw: &RawValue) -> Result<Self, WalletStateError> {
        let members = object(raw).map_err(record)?;
        let seconds: i64 = field(&members, "presentationTimestampSeconds")?;
        let used_credential_ids: Vec<u64> = field(&members, "usedCredentialIds")?;
        Ok(Self {
            presentation_id: PresentationId::new(field(&members, "presentationId")?),
            transaction_id: TransactionId::new(field(&members, "transactionId")?),
            data: PresentationData(field(&members, "data")?),
            used_credential_ids: used_credential_ids
                .into_iter()
                .map(CredentialId::new)
                .collect(),
            timestamp: Timestamp::from_unix(seconds).ok_or(WalletStateError::Presentations(
                PresentationsFault::Timestamp,
            ))?,
            audience: Audience(field(&members, "audience")?),
        })
    }
}

/// The refusal of a record's text.
fn record(error: JsonTextError) -> WalletStateError {
    WalletStateError::Presentations(PresentationsFault::Record(error))
}

/// The member `name` of a record, as a `T`.
fn field<T: DeserializeOwned>(
    members: &Members<'_>,
    name: &'static str,
) -> Result<T, WalletStateError> {
    let raw = members
        .get(name)
        .ok_or_else(|| record(JsonTextError::of(&serde_json::Error::missing_field(name))))?;
    serde_json::from_str(raw.get()).map_err(|error| record(JsonTextError::of(&error)))
}

fn unix_seconds<S: Serializer>(time: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_i64(time.unix())
}

/// An instant in whole seconds since 1970-01-01T00:00:00Z, within RFC 3339's years 0000 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The first second of 0000-01-01.
    pub const MIN_UNIX: i64 = -62_167_219_200;
    /// The last second of 9999-12-31.
    pub const MAX_UNIX: i64 = 253_402_300_799;

    /// The instant `unix` seconds after 1970-01-01T00:00:00Z; `None` outside the years 0000 to
    /// 9999.
    #[must_use]
    pub fn from_unix(unix: i64) -> Option<Self> {
        (Self::MIN_UNIX..=Self::MAX_UNIX)
            .contains(&unix)
            .then_some(Self(unix))
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub fn unix(self) -> i64 {
        self.0
    }
}
