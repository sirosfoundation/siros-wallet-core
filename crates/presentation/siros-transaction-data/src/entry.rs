//! An entry of the `transaction_data` request parameter (T1; OpenID4VP 1.0, Section 5.1; PaSO
//! Core, Section 7.1; PaSO Proof Metadata, Section 5.1).

use siros_codec::base64url;
use siros_codec::json::Json;
use siros_codec::member::MemberFault;
use siros_credential::Format;
use siros_dcql::{DcqlQuery, HolderBinding, QueryId};
use siros_oid4vp::TransactionDataItem;

use crate::error::{EntryMember, EntryPosition, EntryRefusal};
use crate::hash::Accepted;
use crate::json::{self, Fields};
use crate::sources::AdHocMetadata;
use crate::type_id::{EmptyTypeId, TypeId};

/// A `transaction_data` entry: the string the request carried and its members, read.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    position: EntryPosition,
    raw: TransactionDataItem,
    type_id: TypeId,
    credential_ids: Vec<QueryId>,
    payload: Json,
    metadata: Option<AdHocMetadata>,
    hashes: Accepted,
}

impl Entry {
    /// The entry `raw` at `position` of the request's `transaction_data`, against the request's
    /// `query`.
    ///
    /// `raw` is base64url of a JSON object that repeats no member name in any object, with a
    /// non-empty string `type`, a non-empty array `credential_ids` of Credential Query ids of
    /// `query`, an object `payload`, an optional string `metadata`, and an optional
    /// `transaction_data_hashes_alg`. No SD-JWT VC query it names sets
    /// `require_cryptographic_holder_binding` to `false` (B.3).
    ///
    /// # Errors
    ///
    /// [`EntryRefusal`]: the first rule `raw` breaks.
    pub fn parse(
        position: EntryPosition,
        raw: &TransactionDataItem,
        query: &DcqlQuery,
    ) -> Result<Self, EntryRefusal> {
        let bytes = base64url::decode(raw.as_str()).map_err(EntryRefusal::NotBase64url)?;
        let text =
            String::from_utf8(bytes).map_err(|error| EntryRefusal::NotUtf8(error.utf8_error()))?;
        let mut fields = match Json::parse_unique(text.as_bytes()).map_err(EntryRefusal::NotJson)? {
            Json::Object(members) => Fields::new(members),
            _ => return Err(EntryRefusal::NotJsonObject),
        };
        let member = |member| move |fault| EntryRefusal::Member(member, fault);
        let type_id = fields
            .require(EntryMember::Type.as_str())
            .and_then(json::text)
            .map_err(member(EntryMember::Type))?;
        let type_id = TypeId::parse(&type_id).map_err(|EmptyTypeId| EntryRefusal::TypeEmpty)?;
        let credential_ids = credential_ids(&mut fields, query)?;
        let payload = fields
            .require(EntryMember::Payload.as_str())
            .and_then(|payload| match payload {
                Json::Object(_) => Ok(payload),
                _ => Err(MemberFault::WrongType),
            })
            .map_err(member(EntryMember::Payload))?;
        let metadata = fields
            .optional(EntryMember::Metadata.as_str(), json::text)
            .map_err(member(EntryMember::Metadata))?
            .map(AdHocMetadata::new);
        let hashes = Accepted::parse(fields.take(EntryMember::HashesAlg.as_str()))
            .map_err(EntryRefusal::HashesAlg)?;
        if let Some(unknown) = fields.first_left() {
            return Err(EntryRefusal::MemberUnknown(unknown.to_owned()));
        }
        Ok(Self {
            position,
            raw: raw.clone(),
            type_id,
            credential_ids,
            payload,
            metadata,
            hashes,
        })
    }

    /// The entry's position in the request's `transaction_data`.
    #[must_use]
    pub fn position(&self) -> EntryPosition {
        self.position
    }

    /// The string the request carried.
    #[must_use]
    pub fn raw(&self) -> &TransactionDataItem {
        &self.raw
    }

    /// The `type` value.
    #[must_use]
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// `credential_ids`: the Credential Query ids, at least one, in the verifier's order.
    #[must_use]
    pub fn credential_ids(&self) -> &[QueryId] {
        &self.credential_ids
    }

    /// Whether `credential_ids` names the Credential Query `id`.
    #[must_use]
    pub fn names(&self, id: &QueryId) -> bool {
        self.credential_ids.contains(id)
    }

    /// The `payload` object.
    pub(crate) fn payload(&self) -> &Json {
        &self.payload
    }

    /// The ad-hoc metadata JWT, which the wallet verifies and the credential picker cannot.
    #[must_use]
    pub fn metadata(&self) -> Option<&AdHocMetadata> {
        self.metadata.as_ref()
    }

    /// The algorithms of the entry's hash.
    pub(crate) fn hashes(&self) -> &Accepted {
        &self.hashes
    }
}

/// `credential_ids`: a non-empty array of Credential Query ids of `query` (Section 5.1); an
/// SD-JWT VC query among them requires holder binding (B.3).
fn credential_ids(fields: &mut Fields, query: &DcqlQuery) -> Result<Vec<QueryId>, EntryRefusal> {
    let member = |fault| EntryRefusal::Member(EntryMember::CredentialIds, fault);
    let ids = fields
        .require(EntryMember::CredentialIds.as_str())
        .and_then(json::array)
        .map_err(member)?
        .into_iter()
        .map(|id| json::text(id).map_err(member))
        .collect::<Result<Vec<_>, _>>()?;
    if ids.is_empty() {
        return Err(EntryRefusal::CredentialIdsEmpty);
    }
    ids.into_iter()
        .map(|id| {
            let credential = query
                .credentials()
                .iter()
                .find(|credential| credential.id().as_str() == id)
                .ok_or(EntryRefusal::CredentialIdUnknown(id))?;
            let sd_jwt = *credential.format() == Format::SdJwtVc.identifier();
            if sd_jwt && credential.holder_binding() == HolderBinding::Optional {
                return Err(EntryRefusal::HolderBindingNotRequired(
                    credential.id().clone(),
                ));
            }
            Ok(credential.id().clone())
        })
        .collect()
}
