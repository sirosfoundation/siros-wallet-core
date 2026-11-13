//! The scripted world: the ports the engine runs against during one
//! vector — the HTTP the engine sends asserted and answered by the
//! `http_out` steps, the sub-flows it asks the host for by the
//! `host_ask` steps, the PDP from `setup`, the fixed clock and the
//! seeded entropy, and the in-memory persistence.
//!
//! The steps are consumed in script order: the engine's next HTTP
//! request must match the next expected `http_out` (or the vector
//! fails with the difference), and likewise for the host asks. A
//! `must_refuse` / `no_ask` step fails the vector the moment the engine
//! makes the request it forbids.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::matchers::{match_url, matches, parse_form, Bindings};
use crate::script::{HttpOut, Step};

/// The run state one vector's world carries.
pub struct World {
    /// The script steps, in order, each with its consumed flag.
    steps: Mutex<Vec<(Step, bool)>>,
    /// The wildcard bindings.
    bindings: Mutex<Bindings>,
    /// The first failure, when there is one: the vector id-less
    /// reason text.
    failure: Mutex<Option<String>>,
    /// The setup the vector declared.
    setup: Value,
    /// The fixed time.
    now_unix: i64,
}

impl World {
    /// Builds the world for one script, with the setup's fixed time.
    pub fn new(script: Vec<Step>, setup: Value, now_unix: i64) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(script.into_iter().map(|step| (step, false)).collect()),
            bindings: Mutex::new(Bindings::default()),
            failure: Mutex::new(None),
            setup,
            now_unix,
        })
    }

    /// The fixed time from `setup.time`.
    pub fn now_unix(&self) -> i64 {
        self.now_unix
    }

    /// The setup document.
    pub fn setup(&self) -> &Value {
        &self.setup
    }

    /// Records the first failure; later failures keep the first (a
    /// vector is triaged, never retried into green).
    pub fn fail(&self, reason: String) {
        let mut failure = self.failure.lock().unwrap_or_else(|p| p.into_inner());
        failure.get_or_insert(reason);
    }

    /// The first failure, when there is one.
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The bindings, for the runner's later steps.
    pub fn bindings(&self) -> &Mutex<Bindings> {
        &self.bindings
    }

    /// Marks the step at script index consumed.
    pub fn consume(&self, index: usize) {
        let mut steps = self.steps.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = steps.get_mut(index) {
            state.1 = true;
        }
    }

    /// Whether every `http_out` and `host_ask` step before the given
    /// script index was consumed — the runner's check before it
    /// advances past a `wmp_in`/`wmp_out` step (a step that expects an
    /// event and does not see it before the next `wmp_in` fails).
    pub fn assert_interleaved_consumed(&self, before: usize) -> Result<(), String> {
        let steps = self.steps.lock().unwrap_or_else(|p| p.into_inner());
        for (index, (step, consumed)) in steps.iter().enumerate() {
            if index >= before {
                return Ok(());
            }
            match step {
                Step::HttpOut { http_out } => {
                    // A must_refuse step is satisfied by absence: the
                    // engine never making the forbidden request IS the
                    // expectation (a violation failed the run the
                    // moment it happened).
                    if !consumed && !http_out.expect.must_refuse.unwrap_or(false) {
                        return Err(format!(
                            "step {index} was not satisfied before the next wmp step: the engine \
                                 never made the request it expects"
                        ));
                    }
                }
                Step::HostAsk { host_ask }
                    if !consumed && !host_ask.expect.no_ask.unwrap_or(false) =>
                {
                    return Err(format!(
                        "step {index} was not satisfied before the next wmp step: the engine \
                                 never made the ask it expects"
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Every step consumed at the end of the script. A `no_ask` or
    /// `must_refuse` step counts as satisfied when it was never
    /// violated (a violation failed the run the moment it happened).
    pub fn assert_all_consumed(&self) -> Result<(), String> {
        let steps = self.steps.lock().unwrap_or_else(|p| p.into_inner());
        for (index, (step, consumed)) in steps.iter().enumerate() {
            match step {
                Step::HttpOut { http_out } => {
                    // A must_refuse step is satisfied by absence: the
                    // engine never making the forbidden request IS the
                    // expectation (a violation failed the run the
                    // moment it happened).
                    if !consumed && !http_out.expect.must_refuse.unwrap_or(false) {
                        return Err(format!("step {index} was never satisfied"));
                    }
                }
                Step::HostAsk { host_ask } => {
                    if !consumed && !host_ask.expect.no_ask.unwrap_or(false) {
                        return Err(format!("step {index} was never satisfied"));
                    }
                }
                Step::WmpOut { .. } => {
                    if !consumed {
                        return Err(format!("step {index} was never satisfied"));
                    }
                }
                Step::WmpIn { .. } => {}
            }
        }
        Ok(())
    }

    /// The engine's HTTP request: matched against the next expected
    /// `http_out` step, answered by its reply. `Err` is the refusal an
    /// exhausted or failing world gives the engine.
    pub fn http_request(
        &self,
        request: &engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        let mismatch = self.match_http(request);
        match mismatch {
            Ok(reply) => Ok(reply),
            Err(reason) => {
                self.fail(reason.clone());
                // The refusal carries the reason: the engine's flow
                // error then names what actually mismatched.
                Err(engine_ports::HttpError::Transport(reason))
            }
        }
    }

    fn match_http(
        &self,
        request: &engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, String> {
        let mut steps = self.steps.lock().unwrap_or_else(|p| p.into_inner());
        let mut bindings = self.bindings.lock().unwrap_or_else(|p| p.into_inner());

        // The first unconsumed http_out step, in script order.
        let candidate = steps
            .iter()
            .position(|(step, consumed)| matches!(step, Step::HttpOut { .. }) && !consumed);

        let Some(index) = candidate else {
            return Err(format!(
                "unexpected HTTP request {} {} (no pending http_out step)",
                request.method, request.url
            ));
        };
        let Some(step) = steps.get(index) else {
            return Err("internal: the step index is out of range".to_owned());
        };
        let Step::HttpOut { http_out } = step.0.clone() else {
            return Err("internal: the step index is not an http_out".to_owned());
        };
        let consumed_index = index;

        // must_refuse: the engine made a request the vector forbids.
        if http_out.expect.must_refuse.unwrap_or(false) {
            return Err(format!(
                "the engine made a forbidden request: {} {}",
                request.method, request.url
            ));
        }

        // The expectation.
        if http_out.expect.method != request.method {
            return Err(format!(
                "http_out step {consumed_index}: expected method {}, found {}",
                http_out.expect.method, request.method
            ));
        }
        if let Err(mismatch) = match_url(&http_out.expect.url, &request.url, &mut bindings, "url") {
            return Err(format!("http_out step {consumed_index}: {mismatch}"));
        }
        if http_out.expect.purpose != format!("{:?}", request.purpose) {
            return Err(format!(
                "http_out step {consumed_index}: expected purpose {}, found {:?}",
                http_out.expect.purpose, request.purpose
            ));
        }
        if let Some(expected_bytes) = http_out.expect.max_response_bytes {
            if expected_bytes != request.max_response_bytes as i64 {
                return Err(format!(
                    "http_out step {consumed_index}: expected max_response_bytes \
                     {expected_bytes}, found {}",
                    request.max_response_bytes
                ));
            }
        }
        if let Some(expected_redirects) = &http_out.expect.redirects {
            let actual = format!("{:?}", request.redirects);
            if !actual.contains(expected_redirects.trim_matches('"')) {
                return Err(format!(
                    "http_out step {consumed_index}: expected redirects \
                     {expected_redirects}, found {actual}"
                ));
            }
        }
        if let Some(headers) = &http_out.expect.headers {
            let mut object = serde_json::Map::new();
            if let Some(expected) = headers.as_object() {
                for name in expected.keys() {
                    let actual = request
                        .headers
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(name))
                        .map(|(_, v)| Value::String(v.clone()))
                        .unwrap_or(Value::Null);
                    object.insert(name.clone(), actual);
                }
            }
            let actual_headers = Value::Object(object);
            if let Err(mismatch) = matches(headers, &actual_headers, &mut bindings) {
                return Err(format!("http_out step {consumed_index}: {mismatch}"));
            }
        }
        if let Some(form) = &http_out.expect.form {
            let actual = parse_form(&request.body);
            if let Err(mismatch) = matches(form, &actual, &mut bindings) {
                return Err(format!(
                    "http_out step {consumed_index}: {mismatch} — the body was {:?}",
                    String::from_utf8_lossy(&request.body)
                ));
            }
        }
        if let Some(expected_json) = &http_out.expect.json {
            let actual: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            if let Err(mismatch) = matches(expected_json, &actual, &mut bindings) {
                return Err(format!("http_out step {consumed_index}: {mismatch}"));
            }
        }

        // Consume and answer. The request's JSON body feeds the
        // encrypt-to-offer reply form.
        if let Some(state) = steps.get_mut(consumed_index) {
            state.1 = true;
        }
        let request_json: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let body = reply_body(&http_out, &request_json);
        let mut headers = Vec::new();
        if let Some(content_type) = &http_out.reply.content_type {
            headers.push(("content-type".to_owned(), content_type.clone()));
        }
        // The scripted response headers — e.g. the `DPoP-Nonce` of a
        // use_dpop_nonce demand (RFC 9449 §8): the engine captures
        // them for the retried proof.
        if let Some(scripted) = &http_out.reply.headers {
            for (name, value) in scripted {
                if let Some(text) = value.as_str() {
                    headers.push((name.clone(), text.to_owned()));
                }
            }
        }
        Ok(engine_ports::HttpResponse {
            status: http_out.reply.status as u16,
            headers,
            body,
        })
    }

    /// The engine's host ask: matched against the next expected
    /// `host_ask` step, answered by its answer. With no pending step of
    /// the kind, the host answers the best-effort refusal — the flow
    /// proceeds without, exactly as a host without the capability does
    /// (the Go rule) — unless a pending `no_ask` step forbids the ask,
    /// which fails the vector.
    pub fn host_ask(&self, kind: &str, ask: Value) -> Result<Value, String> {
        let mut steps = self.steps.lock().unwrap_or_else(|p| p.into_inner());
        let mut bindings = self.bindings.lock().unwrap_or_else(|p| p.into_inner());

        let candidate = steps.iter().position(|(step, consumed)| {
            matches!(step, Step::HostAsk { host_ask } if !consumed
                && host_ask.expect.kind == kind)
        });

        let Some(index) = candidate else {
            // A pending no_ask step of this kind: the violation.
            if steps.iter().any(|(step, consumed)| {
                matches!(step, Step::HostAsk { host_ask } if !consumed
                    && host_ask.expect.kind == kind
                    && host_ask.expect.no_ask.unwrap_or(false))
            }) {
                return Err(format!("the engine made a forbidden host ask: {kind}"));
            }
            // No pending step, no prohibition: the best-effort refusal.
            return Ok(Value::Null);
        };
        let Some(step) = steps.get(index) else {
            return Err("internal: the step index is out of range".to_owned());
        };
        let Step::HostAsk { host_ask } = step.0.clone() else {
            return Err("internal: the step index is not a host_ask".to_owned());
        };

        // A kind mismatch: the ask the engine made is not the ask the
        // vector expected next.
        if host_ask.expect.kind != kind {
            return Err(format!(
                "host_ask step {index}: expected kind {}, the engine asked {kind}",
                host_ask.expect.kind
            ));
        }
        // no_ask: the engine asked what the vector forbids.
        if host_ask.expect.no_ask.unwrap_or(false) {
            return Err(format!("the engine made a forbidden host ask: {kind}"));
        }
        // The inputs.
        if let Some(inputs) = &host_ask.expect.inputs {
            if let Err(mismatch) = matches(inputs, &ask, &mut bindings) {
                return Err(format!("host_ask step {index}: {mismatch}"));
            }
        }

        if let Some(state) = steps.get_mut(index) {
            state.1 = true;
        }
        Ok(host_ask
            .answer
            .as_ref()
            .and_then(|answer| answer.value.clone())
            .unwrap_or(Value::Null))
    }
}

/// The reply body: a string is raw bytes, a plain JSON value is its
/// serialization, and the **encrypt-to-offer** form builds a JWE the
/// engine can actually decrypt — the offer's JWK comes from the
/// request the step just matched, so an encrypted answer cannot be
/// pre-baked:
///
/// ```json
/// "body": {"encrypt_to_offer": true, "plaintext": {"credential": "..."}}
/// ```
///
/// The alg and enc are the request's `credential_response_encryption`
/// members; the JWK is its `jwk`.
fn reply_body(http_out: &HttpOut, request_json: &Value) -> Vec<u8> {
    let Some(value) = &http_out.reply.body else {
        return Vec::new();
    };
    if value.get("encrypt_to_offer").and_then(Value::as_bool) == Some(true) {
        let offer = request_json.get("credential_response_encryption");
        let jwk = offer
            .and_then(|offer| offer.get("jwk"))
            .cloned()
            .unwrap_or(Value::Null);
        let alg = offer
            .and_then(|offer| offer.get("alg"))
            .and_then(Value::as_str)
            .unwrap_or("ECDH-ES");
        let enc = offer
            .and_then(|offer| offer.get("enc"))
            .and_then(Value::as_str)
            .unwrap_or("A256GCM");
        let plaintext = value
            .get("plaintext")
            .cloned()
            .unwrap_or(Value::Null)
            .to_string();
        return encrypt_to_offer(&plaintext, &jwk, alg, enc).into_bytes();
    }
    match value {
        Value::String(text) => text.clone().into_bytes(),
        value => value.to_string().into_bytes(),
    }
}

/// The JWE an issuer would send: ECDH-ES key agreement to the wallet's
/// offered public JWK, the declared content encryption, the plaintext
/// as the JWE's payload.
fn encrypt_to_offer(plaintext: &str, jwk: &Value, alg: &str, enc: &str) -> String {
    let Ok(jwk) = serde_json::from_value::<jose_rs::jwk::Jwk>(jwk.clone()) else {
        return String::new();
    };
    let Ok(alg) = jose_rs::algorithm::JweAlgorithm::from_str(alg) else {
        return String::new();
    };
    let Ok(enc) = jose_rs::algorithm::JweEncryption::from_str(enc) else {
        return String::new();
    };
    let mut recipient = jwk.clone();
    recipient.alg = Some(alg.as_str().to_owned());
    let header = jose_rs::header::JoseHeader::for_jwe(alg, enc);
    jose_rs::jwe::compact::encrypt_with_jwk_header(&recipient, header, plaintext.as_bytes(), enc)
        .unwrap_or_default()
}

// ─── The scripted ports ──────────────────────────────────────────────────

/// The scripted HttpClient.
pub struct ScriptedHttp {
    world: Arc<World>,
}

impl ScriptedHttp {
    /// The client over the given world.
    pub fn new(world: Arc<World>) -> Self {
        Self { world }
    }
}

#[async_trait::async_trait]
impl engine_ports::HttpClient for ScriptedHttp {
    async fn send(
        &self,
        request: engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        self.world.http_request(&request)
    }
}

/// The scripted Host.
pub struct ScriptedHost {
    world: Arc<World>,
}

impl ScriptedHost {
    /// The host over the given world.
    pub fn new(world: Arc<World>) -> Self {
        Self { world }
    }

    /// Interprets a host answer per the ask kind.
    fn tx_code_answer(&self, value: &Value) -> Result<String, engine_ports::HostError> {
        Ok(value.as_str().unwrap_or_default().to_owned())
    }
}

#[async_trait::async_trait]
impl engine_ports::Host for ScriptedHost {
    /// The signing-key ask: the vector's `signing_key` step answers
    /// with the public JWK; no scripted step is the best-effort
    /// refusal (the engine falls back to the bare proof header).
    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("signing_key", ask) {
            Ok(value) => {
                // The refusal shape: no jwk, or a Null answer.
                let jwk = value.get("jwk").cloned().unwrap_or(Value::Null);
                if jwk.is_null() {
                    return Err(engine_ports::HostError::Cannot(
                        "the scripted host exposes no signing key".to_owned(),
                    ));
                }
                Ok(engine_ports::SigningKeyResult { jwk })
            }
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_sign(
        &self,
        params: engine_ports::SignParams,
    ) -> Result<engine_ports::SignResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("sign", ask) {
            Ok(value) => {
                // The signature: an array of byte values, else the raw
                // bytes of the string.
                let signature =
                    if let Some(array) = value.get("signature").and_then(Value::as_array) {
                        array
                            .iter()
                            .filter_map(|v| v.as_i64().map(|b| b as u8))
                            .collect()
                    } else {
                        value
                            .get("signature")
                            .and_then(Value::as_str)
                            .map(|text| text.as_bytes().to_vec())
                            .unwrap_or_default()
                    };
                Ok(engine_ports::SignResult { signature })
            }
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_match(
        &self,
        params: engine_ports::MatchParams,
    ) -> Result<engine_ports::MatchResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("match", ask) {
            Ok(value) => {
                let selections = value
                    .get("selections")
                    .and_then(Value::as_array)
                    .map(|entries| {
                        entries
                            .iter()
                            .map(|entry| engine_ports::VpSelection {
                                credential_query_id: entry
                                    .get("credential_query_id")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                credential_id: entry
                                    .get("credential_id")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                disclosed_claims: entry
                                    .get("disclosed_claims")
                                    .and_then(Value::as_array)
                                    .map(|claims| {
                                        claims
                                            .iter()
                                            .filter_map(Value::as_str)
                                            .map(str::to_owned)
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(engine_ports::MatchResult {
                    selections,
                    // The scripted conformance host has no transport
                    // handle: the ask is answered in-process.
                    handle: None,
                })
            }
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_consent(
        &self,
        params: engine_ports::ConsentParams,
    ) -> Result<engine_ports::ConsentResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("consent", ask) {
            Ok(value) => Ok(engine_ports::ConsentResult {
                consented: value
                    .get("consented")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_tx_code(&self, flow_id: &str) -> Result<String, engine_ports::HostError> {
        let ask = json!({ "flow_id": flow_id });
        match self.world.host_ask("tx_code", ask) {
            Ok(value) => self.tx_code_answer(&value),
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn open_authorization(
        &self,
        flow_id: &str,
        url: &str,
    ) -> Result<(), engine_ports::HostError> {
        let ask = json!({ "flow_id": flow_id, "url": url });
        match self.world.host_ask("open_authorization", ask) {
            Ok(_) => Ok(()),
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_vp(
        &self,
        params: engine_ports::VpParams,
    ) -> Result<engine_ports::VpResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("presentation", ask) {
            Ok(value) => {
                // No scripted answer is the refusal: an empty VP token
                // submitted to a verifier would be worse.
                let token = value
                    .get("vp_token")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if token.is_empty() {
                    return Err(engine_ports::HostError::Cannot(
                        "the scripted host refuses to present".to_owned(),
                    ));
                }
                Ok(engine_ports::VpResult {
                    vp_token: token,
                    refusal: None,
                })
            }
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_dpop_proof(
        &self,
        params: engine_ports::DpopProofParams,
    ) -> Result<engine_ports::DpopProofResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("dpop", ask) {
            Ok(value) => {
                let proof = value
                    .get("proof")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                Ok(engine_ports::DpopProofResult { proof })
            }
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    async fn request_attestation(
        &self,
        params: engine_ports::AttestationParams,
    ) -> Result<engine_ports::AttestationResult, engine_ports::HostError> {
        let ask = serde_json::to_value(&params).unwrap_or(Value::Null);
        match self.world.host_ask("attestation", ask) {
            Ok(value) => Ok(engine_ports::AttestationResult {
                wia: value
                    .get("wia")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                pop: value
                    .get("pop")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            }),
            Err(reason) => {
                self.world.fail(reason);
                Err(engine_ports::HostError::Cannot(
                    "the scripted host refused".to_owned(),
                ))
            }
        }
    }

    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}

/// The scripted Pdp: `setup.pdp` decides — `trusted` with an optional
/// `decision`; the default trusts (a vector that tests a trust
/// refusal sets `trusted: false`).
pub struct ScriptedPdp {
    trusted: bool,
    decision: Option<String>,
}

impl ScriptedPdp {
    /// The PDP from the setup document.
    pub fn new(setup: &Value) -> Self {
        let pdp = setup.get("pdp");
        Self {
            trusted: pdp
                .and_then(|p| p.get("trusted"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            decision: pdp
                .and_then(|p| p.get("decision"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }
}

#[async_trait::async_trait]
impl engine_ports::Pdp for ScriptedPdp {
    async fn evaluate(
        &self,
        _request: engine_ports::EvaluationRequest,
    ) -> Result<engine_ports::EvaluationResponse, engine_ports::PdpError> {
        Ok(engine_ports::EvaluationResponse {
            trusted: self.trusted,
            decision: self.decision.clone(),
            context: None,
        })
    }

    async fn resolve(
        &self,
        _request: engine_ports::ResolveRequest,
    ) -> Result<engine_ports::ResolveResponse, engine_ports::PdpError> {
        Err(engine_ports::PdpError::NotImplemented)
    }
}

/// The fixed clock: `setup.time`, no sleeping.
pub struct FixedClock {
    now_unix: i64,
}

impl FixedClock {
    /// The clock at the setup's time.
    pub fn new(now_unix: i64) -> Self {
        Self { now_unix }
    }
}

#[async_trait::async_trait]
impl engine_ports::Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }

    async fn sleep(&self, _duration_ms: u64) {}
}

/// The seeded entropy: deterministic bytes derived from
/// `setup.entropy_seed`, so a scenario is reproducible.
pub struct SeededRng {
    seed: u64,
}

impl SeededRng {
    /// The entropy from the setup's seed.
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }
}

impl engine_ports::Rng for SeededRng {
    fn fill(&self, buf: &mut [u8]) -> bool {
        // SplitMix64: one step per byte, deterministic and cheap.
        let mut state = self.seed.wrapping_add(buf.len() as u64);
        for byte in buf.iter_mut() {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            *byte = (z ^ (z >> 31)) as u8;
        }
        true
    }
}

/// The in-memory persistence.
pub struct MemoryKv {
    entries: Mutex<rustc_hash::FxHashMap<String, Vec<u8>>>,
}

impl MemoryKv {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(rustc_hash::FxHashMap::default()),
        }
    }
}

impl Default for MemoryKv {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl engine_ports::KeyValue for MemoryKv {
    async fn get(&self, key: &str) -> Option<engine_ports::KeyValueEntry> {
        self.entries
            .lock()
            .ok()?
            .get(key)
            .map(|value| engine_ports::KeyValueEntry {
                value: value.clone(),
                ttl_secs: None,
            })
    }

    async fn put(&self, key: &str, entry: engine_ports::KeyValueEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(key.to_owned(), entry.value);
        }
    }

    async fn delete(&self, key: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }
}

/// The no-op telemetry.
pub struct NoTelemetry;

impl engine_ports::Telemetry for NoTelemetry {
    fn event(&self, _event: engine_ports::TelemetryEvent) {}
}

/// Minimal base64url decoding, for the JWE header matcher.
pub fn decode_b64url(encoded: &str) -> Vec<u8> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let Some(v) = value(b) else { continue };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}
