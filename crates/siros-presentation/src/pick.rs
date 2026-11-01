//! What a credential picker entry carries for the wallet, and Credential Manager returns when the
//! user picks the entry (K3): the offer, the Credential Query, and the `credentialId` of the
//! credential.

use serde_json::{Map, Value};
use siros_codec::member::MemberFault;
use siros_dcql::{QueryId, QueryIdError};
use siros_wallet_state::CredentialId;

use crate::ids::OfferIndex;

/// A credential picker entry, by the ids its data carries (K3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pick {
    pub(crate) offer: OfferIndex,
    pub(crate) query: QueryId,
    pub(crate) credential: CredentialId,
}

/// A member of a pick's JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickMember {
    /// `offer`: the offer's position, a non-negative integer.
    Offer,
    /// `query`: the Credential Query's `id`.
    Query,
    /// `credential`: the `credentialId`, as a decimal string.
    Credential,
}

/// Why a JSON value is no pick.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PickFault {
    /// The value is no object.
    NotObject,
    /// A member is absent or of the wrong type.
    Member(PickMember, #[source] MemberFault),
    /// `query` is no Credential Query id.
    QueryId(#[source] QueryIdError),
    /// The object has this member, which a pick does not define.
    MemberUnknown(String),
}

impl PickMember {
    /// The member's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Query => "query",
            Self::Credential => "credential",
        }
    }
}

impl PickFault {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject | Self::Member(..) | Self::MemberUnknown(_) => "pick_malformed",
            Self::QueryId(error) => error.code(),
        }
    }
}

impl Pick {
    /// The entry of the credential `credential` answering the Credential Query `query` in the
    /// offer `offer`.
    pub fn new(offer: OfferIndex, query: QueryId, credential: CredentialId) -> Self {
        Self {
            offer,
            query,
            credential,
        }
    }

    /// The offer.
    pub fn offer(&self) -> OfferIndex {
        self.offer
    }

    /// The Credential Query.
    pub fn query(&self) -> &QueryId {
        &self.query
    }

    /// The credential.
    pub fn credential(&self) -> CredentialId {
        self.credential
    }

    /// The JSON value the picker entry carries:
    /// `{"offer": <position>, "query": "<id>", "credential": "<credentialId>"}`.
    pub fn to_json(&self) -> Value {
        let members = [
            (PickMember::Offer, Value::from(self.offer.value())),
            (PickMember::Query, Value::from(self.query.as_str())),
            (
                PickMember::Credential,
                Value::from(self.credential.to_string()),
            ),
        ];
        // Extended member by member: a map collected at once sorts first, which links a slice
        // sort into the picker.
        let mut object = serde_json::Map::new();
        object.extend(
            members
                .into_iter()
                .map(|(member, value)| (member.as_str().to_owned(), value)),
        );
        Value::Object(object)
    }

    /// The pick of the JSON value `value`, as [`Pick::to_json`] writes it.
    ///
    /// # Errors
    ///
    /// [`PickFault`]: the first rule `value` breaks.
    pub fn parse(value: &Value) -> Result<Self, PickFault> {
        let object = value.as_object().ok_or(PickFault::NotObject)?;
        if let Some(unknown) = object.keys().find(|name| {
            ![PickMember::Offer, PickMember::Query, PickMember::Credential]
                .iter()
                .any(|member| member.as_str() == name.as_str())
        }) {
            return Err(PickFault::MemberUnknown(unknown.clone()));
        }
        let offer = member(object, PickMember::Offer)?
            .as_u64()
            .and_then(|offer| usize::try_from(offer).ok())
            .ok_or(PickFault::Member(PickMember::Offer, MemberFault::WrongType))?;
        let query = member(object, PickMember::Query)?
            .as_str()
            .ok_or(PickFault::Member(PickMember::Query, MemberFault::WrongType))?;
        let credential = member(object, PickMember::Credential)?
            .as_str()
            .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u64>().ok())
            .ok_or(PickFault::Member(
                PickMember::Credential,
                MemberFault::WrongType,
            ))?;
        Ok(Self {
            offer: OfferIndex::new(offer),
            query: QueryId::parse(query).map_err(PickFault::QueryId)?,
            credential: CredentialId::new(credential),
        })
    }
}

/// The member `member` of `object`.
fn member(object: &Map<String, Value>, member: PickMember) -> Result<&Value, PickFault> {
    object
        .get(member.as_str())
        .ok_or(PickFault::Member(member, MemberFault::Absent))
}
