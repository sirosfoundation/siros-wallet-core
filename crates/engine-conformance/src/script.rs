//! The vector-file model: the `engine-vectors` schema as serde types.
//! One JSON object per file; the script is an ordered array of steps
//! (the runner contract, docs/runner-contract.md in the vectors repo).

use serde::Deserialize;

/// One engine test vector, as `vector-schema.json` defines it.
#[derive(Debug, Clone, Deserialize)]
pub struct VectorFile {
    /// The vector's dotted identifier.
    pub id: String,
    /// What the vector tests.
    pub description: String,
    /// What backs the expected behaviour: spec, oidf, policy or
    /// go-observed.
    pub provenance: String,
    /// Where the vector was generated from, at which commit.
    pub generator: Generator,
    /// The latest date a go-observed vector may gate CI.
    #[serde(default)]
    pub review_by: Option<String>,
    /// Why an extended `review_by` is justified.
    #[serde(default)]
    pub review_reason: Option<String>,
    /// The clauses and decisions that demand this behaviour.
    #[serde(default)]
    pub spec_refs: Option<Vec<String>>,
    /// A recorded disagreement between the engines.
    #[serde(default)]
    pub known_divergence: Option<String>,
    /// The engine configuration the scenario runs under.
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// The world the scenario builds: endpoints, keys, wallet state,
    /// time.
    #[serde(default)]
    pub setup: Option<serde_json::Value>,
    /// The script of steps, in order.
    pub script: Vec<Step>,
    /// Free text carried forward with a run's report.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Where a vector was generated from, at which commit.
#[derive(Debug, Clone, Deserialize)]
pub struct Generator {
    /// The repository.
    pub repo: String,
    /// The commit, full hexadecimal.
    pub commit: String,
    /// The generation date.
    pub date: String,
}

/// One script step. The kinds interleave: `http_out` and `host_ask`
/// steps are satisfied between the `wmp_in`/`wmp_out` steps, in
/// arrival order.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Step {
    /// A message from the wallet host into the engine.
    WmpIn {
        /// The step.
        wmp_in: WmpIn,
    },
    /// An outgoing HTTP request the engine makes.
    HttpOut {
        /// The step.
        http_out: HttpOut,
    },
    /// A sub-flow the engine asks the wallet host for.
    HostAsk {
        /// The step.
        host_ask: HostAsk,
    },
    /// A message from the engine to the wallet host.
    WmpOut {
        /// The step.
        wmp_out: WmpOut,
    },
}

/// `wmp_in`: the message the wallet host sends.
#[derive(Debug, Clone, Deserialize)]
pub struct WmpIn {
    /// A WMP method, e.g. `wmp.flow.start`.
    pub method: String,
    /// The method params as the wallet host sends them.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// `http_out`: the engine's request, asserted and answered.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpOut {
    /// What the request must look like.
    pub expect: HttpExpect,
    /// The world's answer.
    pub reply: HttpReply,
}

/// The HTTP request expectation.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpExpect {
    /// The method.
    pub method: String,
    /// The exact URL, with `*` wildcards, or a `re:` regular expression.
    pub url: String,
    /// Selected headers that must match.
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    /// Form members that must be present with these values.
    #[serde(default)]
    pub form: Option<serde_json::Value>,
    /// JSON members that must be present with these values.
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    /// The fetch purpose the engine declared.
    pub purpose: String,
    /// The response size limit the engine declared.
    #[serde(default)]
    pub max_response_bytes: Option<i64>,
    /// The redirect policy the engine declared.
    #[serde(default)]
    pub redirects: Option<String>,
    /// The engine must NOT make this request.
    #[serde(default)]
    pub must_refuse: Option<bool>,
}

/// The world's answer to the engine's request.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpReply {
    /// The status.
    pub status: i64,
    /// The content type, as a response header.
    #[serde(default)]
    pub content_type: Option<String>,
    /// The body: a string is raw bytes, anything else is JSON.
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// The world's answer latency.
    #[serde(default)]
    pub delay_ms: Option<i64>,
}

/// `host_ask`: the sub-flow request, asserted and answered.
#[derive(Debug, Clone, Deserialize)]
pub struct HostAsk {
    /// What the ask must look like (or, with `no_ask`, must not happen).
    pub expect: HostExpect,
    /// The host's answer.
    #[serde(default)]
    pub answer: Option<HostAnswer>,
}

/// The host-ask expectation.
#[derive(Debug, Clone, Deserialize)]
pub struct HostExpect {
    /// The sub-flow kind: sign, match, consent, tx_code,
    /// open_authorization or attestation.
    pub kind: String,
    /// Selected members of the ask that must match.
    #[serde(default)]
    pub inputs: Option<serde_json::Value>,
    /// The engine must not ask at all.
    #[serde(default)]
    pub no_ask: Option<bool>,
}

/// The host's answer.
#[derive(Debug, Clone, Deserialize)]
pub struct HostAnswer {
    /// The answer: the tx_code text, the consent decision, the
    /// selection, the attestation pair.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// `wmp_out`: the engine's message, asserted.
#[derive(Debug, Clone, Deserialize)]
pub struct WmpOut {
    /// What the message must look like.
    pub expect: WmpOutExpect,
    /// The engine must answer with the WMP error named in `error_code`.
    #[serde(default)]
    pub must_refuse: Option<bool>,
    /// The error code the refusal carries.
    #[serde(default)]
    pub error_code: Option<i64>,
}

/// The wmp_out expectation.
#[derive(Debug, Clone, Deserialize)]
pub struct WmpOutExpect {
    /// A WMP method, e.g. `wmp.flow.complete`.
    pub method: String,
    /// Selected members that must match, with `*` wildcards for
    /// engine-generated values.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}
