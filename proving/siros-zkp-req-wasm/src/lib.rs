//! The `zkp_req` parts of the browser presenter, with the Longfellow and Vega provers, built
//! with `wasm-pack build --target web` and run in a Web Worker. It proves on one thread.
//!
//! `ZkpProvers` loads the circuit artifacts the host fetched and names the loaded systems; Rust
//! code proves through it as a `NymAuthProver`. `vpTokenJson` writes the `vp_token`. A refusal
//! throws an object `{error_code, kind, code}`: `error_code` is what the wallet sends the
//! verifier (`zkp_req`, Section 5).

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use siros_dcql::QueryId;
use siros_zkp_backend_longfellow::{self as longfellow, LongfellowProver};
use siros_zkp_backend_vega::{self as vega, VegaNymAuth};
use siros_zkp_req::{ErrorCode, ZkpPresentation};
use siros_zkp_req_nym_auth::prover::{NymAuthProver, ProofJob, ProofOutput, ProverFailure};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use wasm_bindgen::prelude::*;

/// A refusal, as thrown to JavaScript.
#[derive(Serialize)]
struct Thrown {
    error_code: &'static str,
    kind: &'static str,
    code: String,
}

fn host(code: &str) -> JsValue {
    let thrown = Thrown {
        error_code: ErrorCode::AccessDenied.as_str(),
        kind: "host",
        code: code.to_owned(),
    };
    thrown
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .unwrap_or_else(|e| JsValue::from_str(&e.to_string()))
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue, what: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|_| host(what))
}

/// The provers of the systems whose artifacts the host loaded.
#[wasm_bindgen]
#[derive(Default)]
pub struct ZkpProvers {
    longfellow: Option<LongfellowProver>,
    vega: Option<VegaNymAuth>,
}

#[wasm_bindgen]
impl ZkpProvers {
    /// No system yet.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads `urn:circuits:longfellow:nym_auth:v1` from `circuits.zst`.
    ///
    /// # Errors
    ///
    /// Throws `{kind: "host"}` with `artifact_pin` for bytes that are not the pinned artifact,
    /// `artifact_decompress`, or `artifact_refused`.
    #[wasm_bindgen(js_name = loadLongfellow)]
    pub fn load_longfellow(&mut self, circuits_zst: &[u8]) -> Result<(), JsValue> {
        let prover = LongfellowProver::load(circuits_zst).map_err(|e| {
            host(match e {
                longfellow::ArtifactError::Pin(_) => "artifact_pin",
                longfellow::ArtifactError::Decompress(_) => "artifact_decompress",
                longfellow::ArtifactError::Circuits(_) => "artifact_refused",
            })
        })?;
        self.longfellow = Some(prover);
        Ok(())
    }

    /// Loads `urn:circuits:vega:nym_auth:v1` from `shapes.zst`.
    ///
    /// # Errors
    ///
    /// Throws `{kind: "host"}` with `artifact_pin` for bytes that are not the pinned artifact,
    /// `artifact_decompress`, or `artifact_refused`.
    #[wasm_bindgen(js_name = loadVega)]
    pub fn load_vega(&mut self, shapes_zst: &[u8]) -> Result<(), JsValue> {
        let keys = VegaNymAuth::load(shapes_zst).map_err(|e| {
            host(match e {
                vega::ArtifactError::Pin(_) => "artifact_pin",
                vega::ArtifactError::Decompress(_) => "artifact_decompress",
                vega::ArtifactError::Shapes(_) => "artifact_refused",
            })
        })?;
        self.vega = Some(keys);
        Ok(())
    }

    /// The identifiers of the loaded systems.
    pub fn systems(&self) -> Vec<String> {
        [
            (NymAuthSystem::LongfellowV1, self.longfellow.is_some()),
            (NymAuthSystem::VegaV1, self.vega.is_some()),
        ]
        .into_iter()
        .filter(|(_, loaded)| *loaded)
        .map(|(system, _)| system.id().as_str().to_owned())
        .collect()
    }
}

impl NymAuthProver for ZkpProvers {
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure> {
        match job.statement().system {
            NymAuthSystem::LongfellowV1 => self.longfellow.as_ref().map(|p| p.prove(job)),
            NymAuthSystem::VegaV1 => self.vega.as_ref().map(|p| p.prove(job)),
        }
        .unwrap_or(Err(ProverFailure::Unavailable))
    }
}

#[derive(Deserialize)]
struct JsVpTokenEntry {
    query_id: String,
    presentations: Vec<ByteBuf>,
}

/// The `vp_token` of JSON Response Modes (`zkp_req`, Section 6.1), from `[{query_id,
/// presentations}]`.
///
/// # Errors
///
/// Throws `{kind: "host"}` for bytes that are no presentation.
#[wasm_bindgen(js_name = vpTokenJson)]
pub fn vp_token_json(entries: JsValue) -> Result<String, JsValue> {
    let entries: Vec<JsVpTokenEntry> = from_js(entries, "vp_token_entries")?;
    let answers = entries
        .into_iter()
        .map(|e| {
            let query_id = QueryId::parse(&e.query_id).map_err(|e| host(e.code()))?;
            let presentations = e
                .presentations
                .iter()
                .map(|p| ZkpPresentation::decode(p).map_err(|_| host("presentation_not_cbor")))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((query_id, presentations))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(siros_zkp_req::vp_token_json(&answers).to_string())
}
