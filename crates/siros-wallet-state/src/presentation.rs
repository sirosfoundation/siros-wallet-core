//! A presentation record: an entry of `S.presentations`, and the record the core returns for
//! the host to append as a `new_presentation` event (privatedata 3.1, Section 6; H5).

use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use siros_codec::date::DateTime;
use siros_codec::json::JsonTextError;

use crate::error::{PresentationsFault, WalletStateError};
use crate::ids::{CredentialId, PresentationId, TransactionId};

/// The members of `new_presentation`. It serialises to them, with
/// `presentationTimestampSeconds` in seconds since 1970-01-01T00:00:00Z.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRecord {
    presentation_id: PresentationId,
    transaction_id: TransactionId,
    data: String,
    used_credential_ids: Vec<CredentialId>,
    #[serde(
        rename = "presentationTimestampSeconds",
        serialize_with = "unix_seconds"
    )]
    timestamp: DateTime,
    audience: String,
}

impl PresentationRecord {
    /// The record of the presentation `data`, sent to `audience` at `timestamp`, which used the
    /// credential entries `used_credential_ids`.
    pub fn new(
        presentation_id: PresentationId,
        transaction_id: TransactionId,
        data: String,
        used_credential_ids: Vec<CredentialId>,
        timestamp: DateTime,
        audience: String,
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
        let fault = WalletStateError::Presentations;
        let stored: Stored = serde_json::from_str(raw.get())
            .map_err(|error| fault(PresentationsFault::Record(JsonTextError::of(&error))))?;
        Ok(Self {
            presentation_id: PresentationId::new(stored.presentation_id),
            transaction_id: TransactionId::new(stored.transaction_id),
            data: stored.data,
            used_credential_ids: stored
                .used_credential_ids
                .into_iter()
                .map(CredentialId::new)
                .collect(),
            timestamp: DateTime::from_unix(stored.presentation_timestamp_seconds)
                .ok_or(fault(PresentationsFault::Timestamp))?,
            audience: stored.audience,
        })
    }
}

/// An entry of `S.presentations`, as `wallet-frontend` writes it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    presentation_id: u64,
    transaction_id: u64,
    data: String,
    used_credential_ids: Vec<u64>,
    presentation_timestamp_seconds: i64,
    audience: String,
}

fn unix_seconds<S: Serializer>(time: &DateTime, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_i64(time.unix())
}
