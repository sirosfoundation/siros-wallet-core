//! The presenter chain exposed to JavaScript (the hidden web wallet, #45).
//!
//! [`ZkpPresenter`] is the wasm-bindgen surface over `siros-zkp-catalogues`'s
//! presenter: `prepare → dataToSign → (the host signs — its WSCD, or
//! WebCrypto; the key never crosses the boundary) → job → prove
//! ([`crate::ZkpProvers::prove_job`]) → assemble`. All protocol logic stays
//! in the catalogues crate — this module only translates types at the
//! boundary.
//!
//! The division of labor the architecture fixes (the same split as the
//! Kotlin/Swift twins, transposed to the browser):
//!
//! - The **engine** validates the request (signed, trusted, encrypted
//!   response mode, `expected_origins`) and hands the host the verified
//!   facts through its `vp` ask: the `Handover` inputs and the
//!   `verifier_id` (`VerifierInfo.trust_context`), the query and its
//!   `client_metadata` (`MatchParams`).
//! - The **host** (the page) holds the credential and the device key — the
//!   key in its `WscdManagerJs` (`@sirosfoundation/wscd-manager-wasm`, the
//!   `plugin-softkey-pure` softkey), the same WSCD abstraction the
//!   Kotlin/Swift wallets use — and signs `dataToSign` between the two
//!   presenter steps.
//! - The **presenter** (here) consumes the engine-verified facts as
//!   explicit inputs and the credential's own issuer-chain admission
//!   against the query's `trusted_authorities` (the credential-side
//!   trust check, as the e2e chain runs it). It does NOT re-validate the
//!   verifier's trust — that is the engine's half.
//!
//! Refusals throw the crate's uniform shape (`{error_code, kind, code}`),
//! the §5 codes.

use siros_codec::date::DateTime;
use siros_codec::signature::Es256Signature;
use siros_dcql::CredentialQuery;
use siros_oid4vp::Handover;
use siros_trust::{AdmittedIssuer, IssuerChain, QueryAuthorities, TrustStore};
use siros_zkp_catalogues::attestation::{SecretSeed, TestedAttestation, UsableAttestation};
use siros_zkp_catalogues::catalogue::{Catalogued, NymAuthQuery};
use siros_zkp_catalogues::presenter::Answer;
use siros_zkp_catalogues::presenter::Prepared;
use siros_zkp_catalogues::presenter::Session;
use siros_zkp_catalogues::system::NymAuthSystem;
use siros_zkp_catalogues::verifier_id::Intermediary as VerifierIdIntermediary;
use siros_zkp_catalogues::verifier_id::{VerifierId, VerifierIdForm};
use siros_zkp_req::{SystemId, ZkpFormats, ZkpReqQuery};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{from_js, host, JsProofJob, JsProofOutput};

/// The `prepare` call's input, as the host serializes it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsPrepareInput {
    /// The system to prove with (`urn:circuits:longfellow:nym_auth:v1`).
    system: String,
    /// The verifier's `zkp_req` credential query, as JSON text.
    query: String,
    /// The `client_metadata` the request carried, as JSON text — the
    /// `vp_formats_supported.zkp_req` facts the pair selection reads (the
    /// engine's match ask already delivered them to the host).
    client_metadata: String,
    /// The held `nym_auth` mdoc: the `IssuerSigned` CBOR, base64url (the
    /// string OID4VCI delivered).
    credential: String,
    /// The `secret_seed` that opens the attestation's `ssc` (16 bytes).
    seed: Vec<u8>,
    /// The `Handover` of the channel the request arrived on: its CBOR
    /// encoding (one of OpenID4VP 1.0 B.2.6's two arrays) — the engine's
    /// verified facts.
    handover: Vec<u8>,
    /// The `verifier_id`'s form: `"x509_san_dns"` or `"semantic"`.
    verifier_id_form: String,
    /// The `verifier_id`'s value, in that form.
    verifier_id: String,
}

/// The presenter chain's prepared state, held for the host between calls:
/// the query's selected pair, the attestation the seed opens, the prepared
/// statement. Opaque to JavaScript.
#[wasm_bindgen]
pub struct ZkpPresenter {
    prepared: Prepared,
}

#[wasm_bindgen]
impl ZkpPresenter {
    /// Prepares the credential's answer in the request's session: the
    /// first query option with a usable pair for `system`, the attestation
    /// the `seed` opens, the statement in the session. The next steps:
    /// [`Self::data_to_sign`], the host's ES256 signature,
    /// [`Self::job`], [`crate::ZkpProvers::prove_job`],
    /// [`Self::assemble`].
    ///
    /// # Errors
    ///
    /// Throws the crate's refusal shape (`{error_code, kind, code}`): the
    /// §5 `access_denied` for data-dependent failures — a seed that does
    /// not open `ssc`, an issuer the query's `trusted_authorities` do not
    /// admit, no usable pair for the system — and the host-kind codes for
    /// inputs that do not parse.
    #[wasm_bindgen(js_name = prepare)]
    pub fn prepare(input: JsValue) -> Result<ZkpPresenter, JsValue> {
        let input: JsPrepareInput = from_js(input, "prepare_input")?;
        let system = NymAuthSystem::from_id(&SystemId::new(&input.system))
            .ok_or_else(|| host("unknown_system"))?;
        let query: serde_json::Value =
            serde_json::from_str(&input.query).map_err(|_| host("query_not_json"))?;
        let client_metadata: serde_json::Value = serde_json::from_str(&input.client_metadata)
            .map_err(|_| host("client_metadata_not_json"))?;
        let now = now_unix().ok_or_else(|| host("clock_invalid"))?;

        // The query, as the catalogues read it.
        let credential_query = CredentialQuery::parse(&query).map_err(|e| host(e.code()))?;
        let zkp_query = ZkpReqQuery::parse(&credential_query).map_err(|e| host(e.code()))?;
        let nym = match NymAuthQuery::from_query(zkp_query) {
            Ok(Catalogued::NymAuth(nym)) => nym,
            Ok(Catalogued::OtherType(_)) => return Err(host("not_a_nym_auth_query")),
            Err(e) => return Err(host(e.code())),
        };

        // The pair: the first option with a usable proof backend for the
        // system, over the request's own advertised formats.
        let formats =
            ZkpFormats::from_client_metadata(&client_metadata).map_err(|e| host(e.code()))?;
        let date = now.date();
        let (pairs, _refusals): (Vec<_>, Vec<_>) = nym
            .options()
            .map(|option| option.pair(&formats, system, date))
            .partition(Result::is_ok);
        let pair = pairs
            .into_iter()
            .find_map(Result::ok)
            .ok_or_else(|| host("no_usable_pair"))?;

        // The attestation: the mdoc the seed opens, its issuer chain
        // admitted against the query's own trusted_authorities (the
        // credential-side trust check, as the e2e chain runs it).
        let mdoc = siros_mdoc::Mdoc::parse(&input.credential).map_err(|e| host(e.code()))?;
        let tested = TestedAttestation::of(&mdoc, now).map_err(|e| host(e.code()))?;
        let authorities = QueryAuthorities::of(&credential_query).map_err(|e| host(e.code()))?;
        let chain = IssuerChain::parse(mdoc.issuer_auth().x5chain())
            .map_err(|_| host("issuer_chain_invalid"))?;
        let store = TrustStore::parse("[]").map_err(|_| host("trust_store"))?;
        // Unadmitted carries the per-authority refusals with no stable code;
        // the class is what the wallet reports.
        let issuer = AdmittedIssuer::resolve(&authorities, Some(&chain), &store, now)
            .map_err(|_| host("issuer_unadmitted"))?;
        let usable = UsableAttestation::new(tested, issuer, &nym).map_err(|e| host(e.code()))?;

        // The answer: the attestation in the pair's session, the seed
        // opening the ssc.
        let seed: [u8; 16] = input.seed.try_into().map_err(|_| host("seed_not_16"))?;
        let answer = Answer::new(pair, usable, &SecretSeed::new(Zeroizing::new(seed)))
            .map_err(|e| host(e.code()))?;

        // The session, from the engine-verified facts.
        let handover =
            Handover::from_cbor(&input.handover).map_err(|_| host("handover_invalid"))?;
        let form = match input.verifier_id_form.as_str() {
            "x509_san_dns" => VerifierIdForm::X509SanDns,
            "semantic" => VerifierIdForm::Semantic,
            _ => return Err(host("unknown_verifier_id_form")),
        };
        let verifier_id = match form {
            VerifierIdForm::X509SanDns => {
                let client_id = siros_oid4vp::ClientId::parse(&input.verifier_id)
                    .map_err(|_| host("verifier_id_invalid"))?;
                VerifierId::x509_san_dns(&client_id, VerifierIdIntermediary::Absent)
                    .map_err(|_| host("verifier_id_invalid"))?
            }
            VerifierIdForm::Semantic => {
                let identifier = siros_oid4vp::SemanticIdentifier::parse_stated(&input.verifier_id)
                    .map_err(|_| host("verifier_id_invalid"))?;
                VerifierId::semantic(&identifier)
            }
        };
        let session = Session {
            handover,
            verifier_id,
        };

        let prepared = Prepared::in_session(answer, &session).map_err(|e| host(e.code()))?;
        Ok(Self { prepared })
    }

    /// The bytes the device key signs — ES256 over these, host-side (the
    /// page's `WscdManagerJs.sign`, or WebCrypto directly); the key never
    /// crosses the wasm boundary.
    #[wasm_bindgen(js_name = dataToSign)]
    pub fn data_to_sign(&self) -> Vec<u8> {
        self.prepared.data_to_sign().as_bytes().to_vec()
    }

    /// The proof job the loaded provers take, from the device signature
    /// (raw ES256 bytes, 64).
    ///
    /// # Errors
    ///
    /// Throws the crate's refusal shape for a signature the statement
    /// refuses.
    #[wasm_bindgen(js_name = job)]
    pub fn job(&self, device_signature: Vec<u8>) -> Result<JsProofJob, JsValue> {
        let signature = Es256Signature::parse(&device_signature)
            .map_err(|_| host("device_signature_invalid"))?;
        let job = self.prepared.job(&signature).map_err(|e| host(e.code()))?;
        Ok(JsProofJob(job))
    }

    /// The assembled presentation (CBOR) — the `vp_token`'s value, from
    /// the prover's output. The nym_auth rulebook v0.4's
    /// `ZkpPresentation` (nym_auth_rulebook.md, the Presentation
    /// section's CDDL): `system_id`, `proof` as the proof system's raw
    /// bytes, `issuer_key_set`, `? proof_time`, `results` — the shape
    /// the deployed verifier's parser and the native SDK presenters
    /// speak (found live in the realeyes demo: the draft-0.1 envelope
    /// this crate used to emit carries `proof_backend`, an unknown
    /// member the verifier refuses). The prover still produces the
    /// draft-0.1 `ProofEnvelope` internally; this boundary promotes its
    /// `inputs` to the rulebook's top level. The rest of the draft-0.1
    /// lineage on this side (the typed `ZkpPresentation`,
    /// `vp_token_json`, the catalogues' verifier-side parser) is the
    /// zkp owners' alignment follow-up. Note: `vpTokenJson` decodes the
    /// draft-0.1 shape — a host driving THIS assemble builds the
    /// `vp_token` JSON itself (the mini-wallet seam does).
    #[wasm_bindgen(js_name = assemble)]
    pub fn assemble(&self, output: &JsProofOutput) -> Result<Vec<u8>, JsValue> {
        use siros_codec::cbor::Value as Cbor;
        use siros_zkp_req::presentation::ProofEnvelope;

        let presentation = self
            .prepared
            .assemble(&output.0)
            .map_err(|e| host(e.code()))?;
        // Decode the envelope to promote the verifier's top-level members.
        let envelope =
            ProofEnvelope::decode(&presentation.proof).map_err(|_| host("envelope_decode"))?;
        let mut members: Vec<(Cbor, Cbor)> = vec![
            (
                Cbor::text("system_id"),
                Cbor::text(presentation.system_id.as_str()),
            ),
            // The raw zk_proof (the JsProofOutput's accessor), not the
            // envelope's wrapper.
            (
                Cbor::text("proof"),
                Cbor::Bytes(output.0.zk_proof.as_bytes().to_vec()),
            ),
        ];
        for (name, value) in &envelope.inputs {
            match name.as_str() {
                "issuer_key_set" => members.push((Cbor::text("issuer_key_set"), value.clone())),
                "proof_time" => members.push((Cbor::text("proof_time"), value.clone())),
                _ => {}
            }
        }
        let results: Vec<(Cbor, Cbor)> = presentation
            .results
            .iter()
            .map(|(key, value)| (Cbor::text(key.as_str()), value.clone()))
            .collect();
        members.push((Cbor::text("results"), Cbor::Map(results)));
        Ok(Cbor::Map(members).encode())
    }
}

/// The host's now, as the proof date — the same clock the page's engine
/// instance reads (`js_sys::Date`), so the presenter and the engine agree
/// on "now" within one flow. `None` for a clock outside the codec's range
/// (the epoch fallback would silently mis-date the proof; refusing is the
/// honest answer — a broken clock is a broken flow).
fn now_unix() -> Option<DateTime> {
    DateTime::from_unix((js_sys::Date::now() / 1000.0) as i64)
}
