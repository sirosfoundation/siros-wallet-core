//! The presentation (`zkp_req`, Section 4), the `Proof` its proof backends share, and the
//! `vp_token` (Section 6.1).

use siros_codec::base64url;
use siros_codec::cbor::{self, CborError, Item, Kind, Value};
use siros_dcql::QueryId;

use crate::ids::{InputName, ProofBackend, ReqSetIndex, ResultKey, SystemId};

/// A member of a CBOR map this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    /// `system_id`.
    SystemId,
    /// `proof_backend`.
    ProofBackend,
    /// `req_set`.
    ReqSet,
    /// `proof`.
    Proof,
    /// `results`.
    Results,
    /// `inputs` of `Proof`.
    Inputs,
    /// `zk_proof` of `Proof`.
    ZkProof,
}

impl Member {
    /// The member's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::SystemId => "system_id",
            Self::ProofBackend => "proof_backend",
            Self::ReqSet => "req_set",
            Self::Proof => "proof",
            Self::Results => "results",
            Self::Inputs => "inputs",
            Self::ZkProof => "zk_proof",
        }
    }
}

/// Why bytes are not a [`ZkpPresentation`] or a [`ProofEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    /// Not one CBOR item the strict reader accepts.
    #[error(transparent)]
    Cbor(#[from] CborError),
    /// The item is not a map.
    #[error("not a CBOR map")]
    NotMap,
    /// A map key is not a text string, or a member this structure does not define.
    #[error("unknown member")]
    UnknownMember,
    /// A required member is absent.
    #[error("{} is missing", .0.name())]
    Missing(Member),
    /// A member has the wrong CBOR type.
    #[error("{} has the wrong type", .0.name())]
    WrongType(Member),
    /// An unsigned member exceeds the indexes this platform holds.
    #[error("{} is out of range", .0.name())]
    OutOfRange(Member),
}

/// Declares bytes whose meaning a specification other than `zkp_req` defines.
macro_rules! opaque_bytes {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// The bytes `bytes`.
            #[must_use]
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// The bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

opaque_bytes!(
    /// The content of a presentation's `proof`, which the proof backend specification defines.
    ProofContent
);

opaque_bytes!(
    /// `zk_proof` of `Proof`: the proof the proof backend verifies.
    ZkProof
);

/// `ZkpPresentation` (Section 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpPresentation {
    /// `system_id`.
    pub system_id: SystemId,
    /// `proof_backend`.
    pub proof_backend: ProofBackend,
    /// `req_set`: present exactly when the query has `_req_sets` (Section 2.1).
    pub req_set: Option<ReqSetIndex>,
    /// `proof`, defined by the proof backend specification.
    pub proof: ProofContent,
    /// `results`: each `return` handle of the answered option and its result (Section 3).
    pub results: Vec<(ResultKey, Value)>,
}

impl ZkpPresentation {
    /// The presentation as a CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut members = vec![
            (
                Value::text("system_id"),
                Value::text(self.system_id.as_str()),
            ),
            (
                Value::text("proof_backend"),
                Value::text(self.proof_backend.as_str()),
            ),
            (Value::text("proof"), Value::Bytes(self.proof.0.clone())),
            (
                Value::text("results"),
                text_map(&self.results, ResultKey::as_str),
            ),
        ];
        if let Some(req_set) = self.req_set {
            members.push((Value::text("req_set"), Value::Unsigned(req_set.as_u64())));
        }
        Value::Map(members)
    }

    /// The deterministic CBOR encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Reads a presentation from untrusted bytes.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: the bytes are not one CBOR map with exactly the members of Section 4,
    /// each of its type.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let item = cbor::decode(bytes)?;
        let entries = item.as_map().ok_or(EncodingError::NotMap)?;
        let mut p = Partial::default();
        for (key, value) in entries {
            p.read(key, value)?;
        }
        p.finish()
    }
}

#[derive(Default)]
struct Partial {
    system_id: Option<SystemId>,
    proof_backend: Option<ProofBackend>,
    req_set: Option<ReqSetIndex>,
    proof: Option<ProofContent>,
    results: Option<Vec<(ResultKey, Value)>>,
}

impl Partial {
    fn read(&mut self, key: &Item<'_>, value: &Item<'_>) -> Result<(), EncodingError> {
        match key.as_text() {
            Some("system_id") => {
                self.system_id = Some(SystemId::new(text(value, Member::SystemId)?));
            }
            Some("proof_backend") => {
                self.proof_backend = Some(ProofBackend::new(text(value, Member::ProofBackend)?));
            }
            Some("req_set") => self.req_set = Some(req_set(value)?),
            Some("proof") => {
                let bytes = value
                    .as_bytes()
                    .ok_or(EncodingError::WrongType(Member::Proof))?;
                self.proof = Some(ProofContent(bytes.to_vec()));
            }
            Some("results") => {
                self.results = Some(read_text_map(value, Member::Results, ResultKey::new)?);
            }
            _ => return Err(EncodingError::UnknownMember),
        }
        Ok(())
    }

    fn finish(self) -> Result<ZkpPresentation, EncodingError> {
        let missing = EncodingError::Missing;
        Ok(ZkpPresentation {
            system_id: self.system_id.ok_or(missing(Member::SystemId))?,
            proof_backend: self.proof_backend.ok_or(missing(Member::ProofBackend))?,
            req_set: self.req_set,
            proof: self.proof.ok_or(missing(Member::Proof))?,
            results: self.results.ok_or(missing(Member::Results))?,
        })
    }
}

fn req_set(item: &Item<'_>) -> Result<ReqSetIndex, EncodingError> {
    let Kind::Unsigned(n) = item.kind() else {
        return Err(EncodingError::WrongType(Member::ReqSet));
    };
    usize::try_from(*n)
        .map(ReqSetIndex::new)
        .map_err(|_| EncodingError::OutOfRange(Member::ReqSet))
}

fn text<'i>(item: &'i Item<'_>, member: Member) -> Result<&'i str, EncodingError> {
    item.as_text().ok_or(EncodingError::WrongType(member))
}

/// A map from text keys, each read by `key`, to any values.
fn read_text_map<K>(
    item: &Item<'_>,
    member: Member,
    key: fn(&str) -> K,
) -> Result<Vec<(K, Value)>, EncodingError> {
    let entries = item.as_map().ok_or(EncodingError::WrongType(member))?;
    entries
        .iter()
        .map(|(k, v)| {
            let text = k.as_text().ok_or(EncodingError::WrongType(member))?;
            Ok((key(text), Value::from_item(v)))
        })
        .collect()
}

fn text_map<K>(entries: &[(K, Value)], text: fn(&K) -> &str) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::text(text(k)), v.clone()))
            .collect(),
    )
}

/// `Proof = { "inputs": { * tstr => any }, "zk_proof": bstr }`, the content of `proof` for the
/// proof backends `longfellow-libzk-v1`, `vega-v1` and `bbs-cd-plugins-v0.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// `inputs`: the prover-supplied values the system rulebook names.
    pub inputs: Vec<(InputName, Value)>,
    /// `zk_proof`.
    pub zk_proof: ZkProof,
}

impl ProofEnvelope {
    /// The deterministic CBOR encoding: the content of `proof`.
    #[must_use]
    pub fn encode(&self) -> ProofContent {
        ProofContent(
            Value::Map(vec![
                (
                    Value::text("inputs"),
                    text_map(&self.inputs, InputName::as_str),
                ),
                (
                    Value::text("zk_proof"),
                    Value::Bytes(self.zk_proof.0.clone()),
                ),
            ])
            .encode(),
        )
    }

    /// Reads `Proof` from the content of `proof`.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: a member of `Proof` is missing, repeated, unknown or of the wrong
    /// type, or bytes follow the map. The system checks the members of `inputs`.
    pub fn decode(proof: &ProofContent) -> Result<Self, EncodingError> {
        let item = cbor::decode(proof.as_bytes())?;
        let entries = item.as_map().ok_or(EncodingError::NotMap)?;
        let (mut inputs, mut zk_proof) = (None, None);
        for (key, value) in entries {
            match key.as_text() {
                Some("inputs") => {
                    inputs = Some(read_text_map(value, Member::Inputs, InputName::new)?);
                }
                Some("zk_proof") => {
                    let bytes = value
                        .as_bytes()
                        .ok_or(EncodingError::WrongType(Member::ZkProof))?;
                    zk_proof = Some(ZkProof(bytes.to_vec()));
                }
                _ => return Err(EncodingError::UnknownMember),
            }
        }
        Ok(Self {
            inputs: inputs.ok_or(EncodingError::Missing(Member::Inputs))?,
            zk_proof: zk_proof.ok_or(EncodingError::Missing(Member::ZkProof))?,
        })
    }
}

/// The `vp_token` of the answered queries, as JSON Response Modes carry it (Section 6.1): each
/// presentation is the base64url, without padding, of its CBOR encoding.
#[must_use]
pub fn vp_token_json(answers: &[(QueryId, Vec<ZkpPresentation>)]) -> serde_json::Value {
    let map = answers
        .iter()
        .map(|(query_id, presentations)| {
            let list = presentations
                .iter()
                .map(|p| serde_json::Value::String(base64url::encode(&p.encode()).into()))
                .collect();
            (query_id.as_str().to_owned(), serde_json::Value::Array(list))
        })
        .collect();
    serde_json::Value::Object(map)
}

/// The `vp_token` as `direct_post.cwt` carries it (Section 6.1): each presentation is the map
/// itself.
#[must_use]
pub fn vp_token_cbor(answers: &[(QueryId, Vec<ZkpPresentation>)]) -> Value {
    Value::Map(
        answers
            .iter()
            .map(|(query_id, presentations)| {
                let list = presentations
                    .iter()
                    .map(ZkpPresentation::to_value)
                    .collect();
                (Value::text(query_id.as_str()), Value::Array(list))
            })
            .collect(),
    )
}
