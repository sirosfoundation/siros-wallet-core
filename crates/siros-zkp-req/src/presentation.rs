//! The presentation (`zkp_req`, Section 4), the `Proof` its proof backends share, and the
//! `vp_token` (Section 6.1).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use siros_openid4vp::cbor::{self, CborError, Value};
use siros_openid4vp::ids::QueryId;

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

/// The deepest nesting a presentation's reader accepts.
pub const MAX_DEPTH: usize = 32;

/// An encoding the presentation's reader refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Unsupported {
    /// Additional information 31: an indefinite length, or the break that ends one.
    #[error("additional information 31: an indefinite length, or the break that ends one")]
    IndefiniteLength,
    /// A head RFC 8949, Section 3 makes not well-formed: additional information 28 to 30
    /// among them.
    #[error("a head that is not well-formed")]
    NotWellFormed,
    /// A floating-point number.
    #[error("a floating-point number")]
    Float,
    /// A simple value other than `false`, `true` and `null`.
    #[error("a simple value other than `false`, `true` and `null`")]
    SimpleValue,
}

/// Why bytes are no CBOR item the presentation's reader accepts: one item with definite lengths
/// and no float, each map key once, nested at most [`MAX_DEPTH`] levels, nothing after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum CborFault {
    /// The input ends inside an item.
    #[error("CBOR item is truncated")]
    Truncated,
    /// Bytes follow the item.
    #[error("bytes follow the CBOR item")]
    TrailingBytes,
    /// An encoding the reader refuses.
    #[error("unsupported CBOR encoding")]
    Unsupported(#[source] Unsupported),
    /// A text string is not UTF-8.
    #[error("CBOR text is not UTF-8")]
    InvalidUtf8,
    /// A map has the same key twice.
    #[error("CBOR map repeats a key")]
    DuplicateKey,
    /// Arrays, maps and tags nest deeper than [`MAX_DEPTH`].
    #[error("CBOR nests too deeply")]
    TooDeep,
}

impl CborFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Truncated => "cbor_truncated",
            Self::TrailingBytes => "cbor_trailing_bytes",
            Self::Unsupported(_) => "cbor_unsupported",
            Self::InvalidUtf8 => "cbor_invalid_utf8",
            Self::DuplicateKey => "cbor_duplicate_key",
            Self::TooDeep => "cbor_too_deep",
        }
    }
}

/// The one CBOR item of `bytes`, as the presentation's reader accepts it.
///
/// # Errors
///
/// [`CborFault`]: what the item breaks.
pub fn read_item(bytes: &[u8]) -> Result<Value, CborFault> {
    let value = cbor::decode_definite(bytes, MAX_DEPTH).map_err(|error| match error {
        CborError::Truncated => CborFault::Truncated,
        CborError::Trailing { .. } => CborFault::TrailingBytes,
        CborError::Utf8 { .. } => CborFault::InvalidUtf8,
        CborError::RepeatedKey(_) => CborFault::DuplicateKey,
        CborError::Depth { .. } => CborFault::TooDeep,
        CborError::Indefinite { .. } => CborFault::Unsupported(Unsupported::IndefiniteLength),
        CborError::Simple { .. } => CborFault::Unsupported(Unsupported::SimpleValue),
        CborError::Malformed { .. }
        | CborError::IntegerRange { .. }
        | CborError::DoubleRange { .. }
        | CborError::Encode(_)
        | CborError::Key(_)
        | CborError::Object(_)
        | CborError::Unknown(_) => CborFault::Unsupported(Unsupported::NotWellFormed),
    })?;
    if holds_float(&value) {
        return Err(CborFault::Unsupported(Unsupported::Float));
    }
    Ok(value)
}

/// Whether the value holds a float at any depth.
fn holds_float(value: &Value) -> bool {
    match value {
        Value::Float(_) => true,
        Value::Array(items) => items.iter().any(holds_float),
        Value::Map(pairs) => pairs.iter().any(|(k, v)| holds_float(k) || holds_float(v)),
        Value::Tag(_, inner) => holds_float(inner),
        _ => false,
    }
}

/// Why bytes are not a [`ZkpPresentation`] or a [`ProofEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    /// Not one CBOR item the presentation's reader accepts.
    #[error(transparent)]
    Cbor(#[from] CborFault),
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
#[derive(Debug, Clone, PartialEq)]
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
            (text_value("system_id"), text_value(self.system_id.as_str())),
            (
                text_value("proof_backend"),
                text_value(self.proof_backend.as_str()),
            ),
            (text_value("proof"), Value::Bytes(self.proof.0.clone())),
            (
                text_value("results"),
                text_map(&self.results, ResultKey::as_str),
            ),
        ];
        if let Some(req_set) = self.req_set {
            members.push((
                text_value("req_set"),
                Value::Integer(req_set.as_u64().into()),
            ));
        }
        Value::Map(members)
    }

    /// The deterministic CBOR encoding (RFC 8949, Section 4.2.1).
    ///
    /// # Errors
    ///
    /// Two `results` keys are equal.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        cbor::encode_deterministic(&self.to_value())
    }

    /// Reads a presentation from untrusted bytes.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: the bytes are not one CBOR map with exactly the members of Section 4,
    /// each of its type.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let item = read_item(bytes)?;
        let Value::Map(entries) = &item else {
            return Err(EncodingError::NotMap);
        };
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
    fn read(&mut self, key: &Value, value: &Value) -> Result<(), EncodingError> {
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

fn req_set(item: &Value) -> Result<ReqSetIndex, EncodingError> {
    let Value::Integer(n) = item else {
        return Err(EncodingError::WrongType(Member::ReqSet));
    };
    let n = u64::try_from(*n).map_err(|_| EncodingError::WrongType(Member::ReqSet))?;
    usize::try_from(n)
        .map(ReqSetIndex::new)
        .map_err(|_| EncodingError::OutOfRange(Member::ReqSet))
}

fn text(item: &Value, member: Member) -> Result<&str, EncodingError> {
    item.as_text().ok_or(EncodingError::WrongType(member))
}

fn text_value(text: &str) -> Value {
    Value::Text(text.to_owned())
}

/// A map from text keys, each read by `key`, to any values.
fn read_text_map<K>(
    item: &Value,
    member: Member,
    key: fn(&str) -> K,
) -> Result<Vec<(K, Value)>, EncodingError> {
    let entries = item.as_map().ok_or(EncodingError::WrongType(member))?;
    entries
        .iter()
        .map(|(k, v)| {
            let text = k.as_text().ok_or(EncodingError::WrongType(member))?;
            Ok((key(text), v.clone()))
        })
        .collect()
}

fn text_map<K>(entries: &[(K, Value)], text: fn(&K) -> &str) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (text_value(text(k)), v.clone()))
            .collect(),
    )
}

/// `Proof = { "inputs": { * tstr => any }, "zk_proof": bstr }`, the content of `proof` for the
/// proof backends `longfellow-libzk-v1`, `vega-v1` and `bbs-cd-plugins-v0.1`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofEnvelope {
    /// `inputs`: the prover-supplied values the system rulebook names.
    pub inputs: Vec<(InputName, Value)>,
    /// `zk_proof`.
    pub zk_proof: ZkProof,
}

impl ProofEnvelope {
    /// The deterministic CBOR encoding (RFC 8949, Section 4.2.1): the content of `proof`.
    ///
    /// # Errors
    ///
    /// Two `inputs` names are equal.
    pub fn encode(&self) -> Result<ProofContent, CborError> {
        cbor::encode_deterministic(&Value::Map(vec![
            (
                text_value("inputs"),
                text_map(&self.inputs, InputName::as_str),
            ),
            (
                text_value("zk_proof"),
                Value::Bytes(self.zk_proof.0.clone()),
            ),
        ]))
        .map(ProofContent)
    }

    /// Reads `Proof` from the content of `proof`.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: a member of `Proof` is missing, repeated, unknown or of the wrong
    /// type, or bytes follow the map. The system checks the members of `inputs`.
    pub fn decode(proof: &ProofContent) -> Result<Self, EncodingError> {
        let item = read_item(proof.as_bytes())?;
        let Value::Map(entries) = &item else {
            return Err(EncodingError::NotMap);
        };
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
///
/// # Errors
///
/// A presentation's `results` repeat a key.
pub fn vp_token_json(
    answers: &[(QueryId<'static>, Vec<ZkpPresentation>)],
) -> Result<serde_json::Value, CborError> {
    let map = answers
        .iter()
        .map(|(query_id, presentations)| {
            let list = presentations
                .iter()
                .map(|p| {
                    Ok(serde_json::Value::String(
                        URL_SAFE_NO_PAD.encode(p.encode()?),
                    ))
                })
                .collect::<Result<_, CborError>>()?;
            Ok((query_id.as_str().to_owned(), serde_json::Value::Array(list)))
        })
        .collect::<Result<_, CborError>>()?;
    Ok(serde_json::Value::Object(map))
}

/// The `vp_token` as `direct_post.cwt` carries it (Section 6.1): each presentation is the map
/// itself.
#[must_use]
pub fn vp_token_cbor(answers: &[(QueryId<'static>, Vec<ZkpPresentation>)]) -> Value {
    Value::Map(
        answers
            .iter()
            .map(|(query_id, presentations)| {
                let list = presentations
                    .iter()
                    .map(ZkpPresentation::to_value)
                    .collect();
                (text_value(query_id.as_str()), Value::Array(list))
            })
            .collect(),
    )
}
