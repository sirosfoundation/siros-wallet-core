//! `S`, the wallet state of a WalletStateContainer (privatedata 3.1, Section 6).

use rustc_hash::FxHashSet;
use serde_json::value::RawValue;
use siros_codec::json::JsonTextError;

use crate::entry::{array, object, CredentialEntry, Members};
use crate::error::{ArrayFault, FoundVersion, PresentationsFault, WalletStateError};
use crate::ids::KeyId;
use crate::presentation::PresentationRecord;

/// The credentials, presentations and key identifiers of a wallet state of version 3 or 4.
pub struct WalletState {
    credentials: Vec<CredentialEntry>,
    presentations: Vec<PresentationRecord>,
    key_ids: Vec<KeyId>,
}

impl WalletState {
    /// The wallet state whose JSON text is `text`.
    ///
    /// Version 3 reads as version 4: a container written before privatedata 3.0 can carry
    /// `metadata` under version 3. The state keeps `credentials`, `keypairs` and
    /// `presentations`.
    ///
    /// # Errors
    ///
    /// [`WalletStateError`]: the first rule the text breaks.
    pub fn parse(text: &str) -> Result<Self, WalletStateError> {
        let members: Members<'_> = serde_json::from_str(text)
            .map_err(|error| WalletStateError::Malformed(JsonTextError::of(&error)))?;
        match schema_version(&members) {
            FoundVersion::Version(3 | 4) => {}
            found => return Err(WalletStateError::UnsupportedSchemaVersion(found)),
        }
        let credentials = elements(&members, "credentials", WalletStateError::Credentials)?
            .into_iter()
            .map(CredentialEntry::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let mut ids = FxHashSet::default();
        if !credentials.iter().all(|c| ids.insert(c.credential_id())) {
            return Err(WalletStateError::RepeatedCredentialId);
        }
        let key_ids = elements(&members, "keypairs", WalletStateError::Keypairs)?
            .into_iter()
            .filter_map(key_id)
            .collect();
        let presentations = elements(&members, "presentations", |fault| {
            WalletStateError::Presentations(PresentationsFault::NotArray(fault))
        })?
        .into_iter()
        .map(PresentationRecord::parse)
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            credentials,
            presentations,
            key_ids,
        })
    }

    /// `credentials`, in their order.
    pub fn credentials(&self) -> &[CredentialEntry] {
        &self.credentials
    }

    /// `presentations`, in their order.
    pub fn presentations(&self) -> &[PresentationRecord] {
        &self.presentations
    }

    /// The `kid` of each entry of `keypairs` that has one, in their order.
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }
}

/// The `schemaVersion` of the state.
fn schema_version(members: &Members<'_>) -> FoundVersion {
    match members.get("schemaVersion") {
        None => FoundVersion::Absent,
        Some(raw) => {
            serde_json::from_str(raw.get()).map_or(FoundVersion::NotAVersion, FoundVersion::Version)
        }
    }
}

/// The elements of the array member `name`; `error` gives the refusal of its fault.
fn elements<'a>(
    members: &Members<'a>,
    name: &str,
    error: fn(ArrayFault) -> WalletStateError,
) -> Result<Vec<&'a RawValue>, WalletStateError> {
    let member = members.get(name).ok_or(error(ArrayFault::Absent))?;
    array(member).map_err(|fault| error(ArrayFault::NotArray(fault)))
}

/// The `kid` of a `keypairs` entry. Privatedata 3.1, Section 6 keeps entries a reader cannot
/// parse; those name no key.
fn key_id(entry: &RawValue) -> Option<KeyId> {
    let Ok(members) = object(entry) else {
        return None;
    };
    let kid = members.get("kid")?;
    let Ok(kid) = serde_json::from_str::<String>(kid.get()) else {
        return None;
    };
    KeyId::known(kid)
}
