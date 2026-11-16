//! The `vp_token` (OpenID4VP 1.0, Section 8.1) and the Authorization Response that carries it,
//! in JSON and in CBOR (`zkp_req.md`, Section 6.1).

use std::fmt;

use rustc_hash::FxHashSet;
use serde_json::{Map, Value};
use siros_codec::base64url;
use siros_codec::cbor::{self, Value as Cbor};
use siros_dcql::{Multiplicity, QueryId};

use super::submission::{Outcome, ResponseParameters};
use super::ResponseError;
use crate::error_code::ErrorCode;
use crate::parameters::State;
use crate::verified::VerifiedRequest;

/// One presentation of a `vp_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation(Form);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Form {
    /// A presentation that is a string, as SD-JWT VC and mdoc presentations are.
    Text(String),
    /// A presentation that is a CBOR map, as a `zkp_req` `ZkpPresentation` is, encoded.
    Cbor(Vec<u8>),
}

impl Presentation {
    /// A presentation that is a string; it is the same string in JSON and in CBOR.
    #[must_use]
    pub fn text(text: String) -> Self {
        Self(Form::Text(text))
    }

    /// A presentation that is a CBOR map: in CBOR the map itself, in JSON the base64url of its
    /// encoding (`zkp_req.md`, Section 6.1).
    ///
    /// # Errors
    ///
    /// [`ResponseError::PresentationNotCborMap`] when `encoded` is not one CBOR map in the
    /// strict encoding of `siros-codec`.
    pub fn cbor_map(encoded: Vec<u8>) -> Result<Self, ResponseError> {
        match cbor::decode(&encoded) {
            Ok(item) if item.as_map().is_some() => Ok(Self(Form::Cbor(encoded))),
            _ => Err(ResponseError::PresentationNotCborMap),
        }
    }

    fn json(&self) -> Value {
        match &self.0 {
            Form::Text(text) => Value::String(text.clone()),
            Form::Cbor(encoded) => Value::String(base64url::encode(encoded).into()),
        }
    }

    fn cbor(&self) -> Cbor {
        match &self.0 {
            Form::Text(text) => Cbor::text(text),
            Form::Cbor(encoded) => Cbor::Encoded(encoded.clone()),
        }
    }
}

/// A `vp_token` for one verified request (Section 8.1).
///
/// Its existence guarantees that each key is the `id` of a Credential Query of the request,
/// once, with at least one presentation, and exactly one unless the query sets `multiple`.
#[derive(Debug, Clone)]
pub struct VpToken<'r> {
    pub(super) request: &'r VerifiedRequest,
    entries: Vec<(QueryId, Vec<Presentation>)>,
}

impl VerifiedRequest {
    /// The `vp_token` of `entries`: the presentations answering each Credential Query, by its
    /// `id`.
    ///
    /// # Errors
    ///
    /// [`ResponseError`]: the first rule of Section 8.1 an entry breaks.
    pub fn vp_token(
        &self,
        entries: Vec<(QueryId, Vec<Presentation>)>,
    ) -> Result<VpToken<'_>, ResponseError> {
        let mut seen = FxHashSet::default();
        entries.iter().try_for_each(|(id, presentations)| {
            self.answers(id, presentations)?;
            if seen.insert(id) {
                Ok(())
            } else {
                Err(ResponseError::DuplicateQueryId)
            }
        })?;
        Ok(VpToken {
            request: self,
            entries,
        })
    }

    /// Refuses `presentations` as the answer to the Credential Query `id` unless the query is
    /// the request's and they are one presentation, or several for a `multiple` query.
    fn answers(&self, id: &QueryId, presentations: &[Presentation]) -> Result<(), ResponseError> {
        let query = self
            .dcql_query
            .credential(id)
            .ok_or(ResponseError::UnknownQueryId)?;
        match presentations.len() {
            0 => Err(ResponseError::NoPresentation),
            1 => Ok(()),
            _ if query.multiplicity() == Multiplicity::One => {
                Err(ResponseError::MultipleNotAllowed)
            }
            _ => Ok(()),
        }
    }
}

impl VpToken<'_> {
    /// The `vp_token` in JSON (Section 8.1).
    #[must_use]
    pub fn json(&self) -> VpTokenJson {
        VpTokenJson(
            self.entries
                .iter()
                .map(|(id, presentations)| {
                    let list = presentations.iter().map(Presentation::json).collect();
                    (id.to_string(), Value::Array(list))
                })
                .collect(),
        )
    }
}

/// A `vp_token` in JSON (Section 8.1): each Credential Query's `id` with its presentations,
/// each a string, a CBOR map as the base64url of its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpTokenJson(Map<String, Value>);

impl VpTokenJson {
    /// The object.
    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// The JSON text of the object.
impl fmt::Display for VpTokenJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Value::Object(self.0.clone()))
    }
}

/// What an Authorization Response answers (Section 8.1, 8.5): a `vp_token` or an error.
pub(super) enum Answer<'a> {
    VpToken(&'a VpToken<'a>),
    Error(ErrorCode),
}

impl Answer<'_> {
    /// The response parameters, with `state` when given.
    pub(super) fn parameters(&self, state: Option<&State>) -> ResponseParameters {
        ResponseParameters::new(self.outcome(), state.cloned())
    }

    /// The outcome, the `vp_token` in JSON.
    pub(super) fn outcome(&self) -> Outcome {
        match self {
            Self::VpToken(token) => Outcome::VpToken(token.json()),
            Self::Error(code) => Outcome::Error(*code),
        }
    }

    /// The Authorization Response in CBOR (`zkp_req.md`, Section 6.1), with `state` when given.
    pub(super) fn cbor(&self, state: Option<&State>) -> Cbor {
        let mut members = vec![match self {
            Self::VpToken(token) => {
                let token = token
                    .entries
                    .iter()
                    .map(|(id, presentations)| {
                        let list = presentations.iter().map(Presentation::cbor).collect();
                        (Cbor::text(id), Cbor::Array(list))
                    })
                    .collect();
                (Cbor::text("vp_token"), Cbor::Map(token))
            }
            Self::Error(code) => (Cbor::text("error"), Cbor::text(code.as_str())),
        }];
        if let Some(state) = state {
            members.push((Cbor::text("state"), Cbor::text(state.as_str())));
        }
        Cbor::Map(members)
    }
}
