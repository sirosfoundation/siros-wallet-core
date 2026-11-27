//! The engine server's configuration — a struct passed to the constructor,
//! never read from the environment inside the core. Mirrors the Go
//! engine's `--mode=engine` configuration shape where the names overlap.

use serde::{Deserialize, Serialize};

/// The engine server's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The address the HTTP server listens on (`ENGINE_ADDR`, default
    /// `0.0.0.0:8780`).
    pub listen_addr: String,
    /// The maximum incoming WMP message size in bytes (default 1 MiB, the
    /// transport spec's minimum is 64 KiB).
    pub max_message_size: usize,
    /// The session TTL in seconds when a `wmp.session.create` carries no
    /// `ttl` (default 3600, the core's default).
    pub default_session_ttl_secs: i64,
    /// The AS's external URL, whose JWKS the standalone engine validates
    /// tokens against — the `as.external_url` the Go engine requires.
    /// Drives the derived JWKS URL and issuer (the defaults) when they
    /// are not named.
    pub as_external_url: String,
    /// The AS's JWKS URL, when it is not the derived
    /// `{as_external_url}/.well-known/jwks.json` — the Go backend's own AS
    /// publishes it at `{as_external_url}/auth/.well-known/jwks.json`.
    /// Empty means the derived form.
    pub as_jwks_url: String,
    /// The `iss` claim the tokens carry, when it is not the
    /// `as_external_url` (the Go AS's `iss` is its configured issuer,
    /// `WALLET_AS_ISSUER`, which can differ from its external URL).
    /// Empty means the `as_external_url`.
    pub as_issuer: String,
    /// The accepted `aud` claims. Empty accepts every audience (the
    /// go-tokenauth behaviour the backend's AS relies on); the default
    /// is `wallet-engine` (the engine's own audience).
    pub as_audiences: Vec<String>,
    /// The PDP URL the engine evaluates trust through. Empty means the
    /// backend's proxy (the legacy fallback); a URL means the engine calls
    /// the PDP directly.
    pub pdp_url: String,
    /// The bearer token the backend's proxy routes validate (the
    /// `/v1/evaluate` and `/v1/resolve` TAC gate: an AS-issued token
    /// with `tac` covering `r` and an audience the deployment accepts —
    /// `wallet-backend` or `wallet-registry` on the default rules).
    /// The deployment mints it: the dev stack's
    /// `scripts/mint_engine_pdp_token.py`, Fly's deploy from the AS
    /// signing key. Empty means no token: the proxy's routes 401 and
    /// the engine's trust evaluation fails closed.
    pub pdp_token: String,
    /// Whether plain `http` fetches are allowed (never in production; the
    /// Go engine's `http_client.allow_plaintext`).
    pub allow_plaintext: bool,
    /// The `metadata_type` policy: `prefer-signed` (default),
    /// `require-signed`, `prefer-unsigned`, `require-unsigned`, `any`.
    pub metadata_type: String,
    /// Whether the RFC 9207 `iss` is REQUIRED on every authorization
    /// response (`ENGINE_REQUIRE_AUTHORIZATION_RESPONSE_ISSUER`, the Go
    /// `WALLET_SECURITY_REQUIRE_AUTHORIZATION_RESPONSE_ISSUER`): FAPI
    /// enforcement even when the AS metadata does not advertise
    /// `authorization_response_iss_parameter_supported`. Advertised
    /// support always requires `iss`, regardless of this knob. Default
    /// false preserves non-FAPI issuers without RFC 9207 support
    /// (go-wallet-backend#551's rule).
    pub require_authorization_response_issuer: bool,
    /// The maximum concurrent flows a session may run (the flows
    /// capability the session create advertises, core §10.3; default 16,
    /// the wasm dispatcher's bound).
    pub max_concurrent_flows: i64,
    /// How the deployment keys session ownership
    /// (`ENGINE_PRINCIPAL_MODE`, engine-parity.md §8): `user` — the
    /// historic shape, sessions owned by `tenant/subject` — or
    /// `tenant` — W10's tenant-bound remote principal, where the token's
    /// `sub` is a rotating pseudonym and the tenant owns the session.
    /// Default `user`.
    pub principal_mode: wmp_core::principal::PrincipalMode,
    /// The provider's own public base URL (`ENGINE_PUBLIC_URL`,
    /// issue #77): the invitation's `provider` field — the domain the
    /// counterparty's discovery resolves against. Empty disables the
    /// invitation endpoint (the create route answers `-32601`).
    pub public_url: String,
    /// The participant's own identifier (`ENGINE_PARTICIPANT_ID`,
    /// issue #100): the `x509:san:dns:…` form the well-known document
    /// carries (CS-15 §7.2) — who this endpoint is, beside where it
    /// is. Empty omits the field.
    #[serde(default)]
    pub participant_id: String,
    /// The participant's certificate chain, PEM
    /// (`ENGINE_PARTICIPANT_CERT_PEM`, issue #100): the leaf first,
    /// then the intermediates — the `x5c` the well-known's signed form
    /// carries (CS-15 §7.2: the configuration as attestation,
    /// `application/jwt` on request). Empty serves the plain JSON
    /// only.
    #[serde(default)]
    pub participant_cert_pem: String,
    /// The participant certificate's private key, PEM
    /// (`ENGINE_PARTICIPANT_KEY_PEM`, issue #100) — signs the
    /// well-known's `application/jwt` form, the software home. Empty
    /// disables the signed form (the route answers `406`); when the
    /// PKCS#11 knobs below name a token, the key lives there instead
    /// and this field is ignored.
    #[serde(default)]
    pub participant_key_pem: String,
    /// The PKCS#11 module path (`ENGINE_PKCS11_MODULE`, issue #100):
    /// when set, the participant signing key lives on a PKCS#11 token
    /// — CS-15 §8.4's WSCA/QSCD, the key MUST NOT leave it — and the
    /// PEM key field is ignored. The certificate chain still comes
    /// from `ENGINE_PARTICIPANT_CERT_PEM` (the `x5c` is public
    /// material).
    #[serde(default)]
    pub pkcs11_module: String,
    /// The PKCS#11 slot id (`ENGINE_PKCS11_SLOT`): unset picks the
    /// first slot with a token.
    #[serde(default)]
    pub pkcs11_slot_id: Option<u64>,
    /// The PKCS#11 login PIN (`ENGINE_PKCS11_PIN`).
    #[serde(default)]
    pub pkcs11_pin: String,
    /// The private key object's label on the token
    /// (`ENGINE_PKCS11_KEY_LABEL`).
    #[serde(default)]
    pub pkcs11_key_label: String,
    /// The signing algorithm the token key uses (`ENGINE_PKCS11_ALG`):
    /// `ES256` (the default), `ES384`, `RS256` — the token's key is
    /// found by label, so the deployment names the algorithm.
    #[serde(default)]
    pub pkcs11_alg: String,
    /// The invitation TTL in seconds when a create carries none
    /// (`ENGINE_INVITATION_TTL_SECS`, issue #77). Default 900.
    pub invitation_ttl_secs: i64,
    /// The persistence path (`ENGINE_PERSISTENCE_PATH`): when non-empty,
    /// the session and invitation stores persist as JSON files under this
    /// directory (`sessions.json` and `invitations.json`), surviving
    /// restarts (#109). Empty (the default) keeps the in-memory stores.
    pub persistence_path: String,
    /// Whether the engine answers MCP tools (issue #76):
    /// `tools/list`/`tools/call` behind the `mcp` capability
    /// (`ENGINE_MCP_TOOLS`). Default true — the capability gate (a
    /// session that did not offer `mcp` never negotiates it) is the
    /// deployment's control, not the env.
    pub mcp_tools: bool,
    /// The relay-only deployment (issue #77's wmp-mcp backend): no
    /// issuance flows register — the flow families' `wmp.flow.start`
    /// answers `-31005` (capability not supported, core §10.3: nobody
    /// registered the family). The relay surface stays whole: sessions,
    /// invitations, the mailbox, the SSE outbox, the well-known, MCP
    /// tools. `ENGINE_RELAY_MODE`.
    pub relay_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8780".to_owned(),
            max_message_size: 1 << 20,
            default_session_ttl_secs: 3600,
            as_external_url: String::new(),
            as_jwks_url: String::new(),
            as_issuer: String::new(),
            as_audiences: vec!["wallet-engine".to_owned()],
            pdp_url: String::new(),
            pdp_token: String::new(),
            allow_plaintext: false,
            metadata_type: "prefer-signed".to_owned(),
            require_authorization_response_issuer: false,
            max_concurrent_flows: 16,
            principal_mode: wmp_core::principal::PrincipalMode::User,
            public_url: String::new(),
            participant_id: String::new(),
            participant_cert_pem: String::new(),
            participant_key_pem: String::new(),
            pkcs11_module: String::new(),
            pkcs11_slot_id: None,
            pkcs11_pin: String::new(),
            pkcs11_key_label: String::new(),
            pkcs11_alg: "ES256".to_owned(),
            invitation_ttl_secs: 900,
            persistence_path: String::new(),
            mcp_tools: true,
            relay_mode: false,
        }
    }
}

impl Config {
    /// The configuration from the environment (`ENGINE_*`), over the
    /// defaults — the container's form: `ENGINE_ADDR`,
    /// `ENGINE_MAX_MESSAGE_SIZE`, `ENGINE_DEFAULT_SESSION_TTL_SECS`,
    /// `ENGINE_AS_EXTERNAL_URL`, `ENGINE_PDP_URL`,
    /// `ENGINE_ALLOW_PLAINTEXT`, `ENGINE_METADATA_TYPE`,
    /// `ENGINE_MAX_CONCURRENT_FLOWS`. An unset variable is the
    /// default; an empty `ENGINE_ADDR`-style string is the default
    /// too (the container's `ENV ENGINE_LISTEN_ADDR=` form), and an
    /// unparseable one is the default rather than a refusal — a
    /// misconfigured scaler's pod still starts and serves its
    /// probes, exactly as the Go engine's config treats its
    /// environment.
    ///
    /// A `ENGINE_CONFIG`-named JSON file remains the full-fidelity
    /// form (`main_entry` reads it); the variables are the container
    /// platform's deployment shape.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();
        let text = |name: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        if let Some(value) = text("ENGINE_LISTEN_ADDR").or_else(|| text("ENGINE_ADDR")) {
            config.listen_addr = value;
        }
        if let Some(value) = text("ENGINE_MAX_MESSAGE_SIZE") {
            if let Ok(parsed) = value.trim().parse() {
                config.max_message_size = parsed;
            }
        }
        if let Some(value) = text("ENGINE_DEFAULT_SESSION_TTL_SECS") {
            if let Ok(parsed) = value.trim().parse() {
                config.default_session_ttl_secs = parsed;
            }
        }
        if let Some(value) = text("ENGINE_AS_EXTERNAL_URL") {
            config.as_external_url = value;
        }
        if let Some(value) = text("ENGINE_AS_JWKS_URL") {
            config.as_jwks_url = value;
        }
        if let Some(value) = text("ENGINE_AS_ISSUER") {
            config.as_issuer = value;
        }
        // The audiences, comma-separated: `ENGINE_AS_AUDIENCES=wallet-engine,
        //wallet-backend`. The var is read set-but-empty too (unlike the
        // others): an empty list accepts every audience, the go-tokenauth
        // behaviour the backend's AS relies on, so `ENGINE_AS_AUDIENCES=`
        // is the operator's way to say exactly that.
        if let Ok(value) = std::env::var("ENGINE_AS_AUDIENCES") {
            config.as_audiences = value
                .split(',')
                .map(str::trim)
                .filter(|audience| !audience.is_empty())
                .map(str::to_owned)
                .collect();
        }
        // bool: any of true/yes/on/1 (case-insensitive) is true; the Go
        // viper form's rule.
        if let Some(value) = text("ENGINE_REQUIRE_AUTHORIZATION_RESPONSE_ISSUER") {
            config.require_authorization_response_issuer = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "yes" | "on" | "1"
            );
        }
        if let Some(value) = text("ENGINE_PDP_URL") {
            config.pdp_url = value;
        }
        if let Some(value) = text("ENGINE_PUBLIC_URL") {
            config.public_url = value;
        }
        // The participant identity and the well-known's signing material
        // (issue #100, CS-15 §7.2): the identifier the document
        // carries, and the certificate chain + key that sign its
        // `application/jwt` form. PEM in the environment is the
        // multi-line secret form the container platforms accept; the
        // ENGINE_CONFIG JSON file carries them as string fields.
        if let Some(value) = text("ENGINE_PARTICIPANT_ID") {
            config.participant_id = value;
        }
        if let Some(value) = text("ENGINE_PARTICIPANT_CERT_PEM") {
            config.participant_cert_pem = value;
        }
        if let Some(value) = text("ENGINE_PARTICIPANT_KEY_PEM") {
            config.participant_key_pem = value;
        }
        // The PKCS#11 home (issue #100, CS-15 §8.4): the token the
        // subscriber key lives on — the qualified deployments' shape.
        if let Some(value) = text("ENGINE_PKCS11_MODULE") {
            config.pkcs11_module = value;
        }
        if let Some(value) = text("ENGINE_PKCS11_SLOT") {
            if let Ok(parsed) = value.trim().parse() {
                config.pkcs11_slot_id = Some(parsed);
            }
        }
        if let Some(value) = text("ENGINE_PKCS11_PIN") {
            config.pkcs11_pin = value;
        }
        if let Some(value) = text("ENGINE_PKCS11_KEY_LABEL") {
            config.pkcs11_key_label = value;
        }
        if let Some(value) = text("ENGINE_PKCS11_ALG") {
            config.pkcs11_alg = value;
        }
        if let Some(value) = text("ENGINE_INVITATION_TTL_SECS") {
            if let Ok(parsed) = value.trim().parse() {
                config.invitation_ttl_secs = parsed;
            }
        }
        if let Some(value) = text("ENGINE_PERSISTENCE_PATH") {
            config.persistence_path = value;
        }
        if let Some(value) = text("ENGINE_RELAY_MODE") {
            config.relay_mode = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            );
        }
        if let Some(value) = text("ENGINE_MCP_TOOLS") {
            // The truthy forms a compose file or a chart writes (issue #76).
            config.mcp_tools = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            );
        }
        if let Some(value) = text("ENGINE_PDP_TOKEN") {
            config.pdp_token = value;
        }
        if let Some(value) = text("ENGINE_ALLOW_PLAINTEXT") {
            // The truthy forms a compose file or a chart writes.
            config.allow_plaintext = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Some(value) = text("ENGINE_METADATA_TYPE") {
            config.metadata_type = value;
        }
        if let Some(value) = text("ENGINE_MAX_CONCURRENT_FLOWS") {
            if let Ok(parsed) = value.trim().parse() {
                config.max_concurrent_flows = parsed;
            }
        }
        if let Some(value) = text("ENGINE_PRINCIPAL_MODE") {
            // `user` (the default, the historic shape) or `tenant` (W10's
            // tenant-bound remote principal, engine-parity.md §8). An
            // unrecognised value is the default, like the rest of the
            // container's variables: a misconfigured scaler's pod still
            // starts, on the safe historic mode.
            config.principal_mode = match value.trim().to_ascii_lowercase().as_str() {
                "tenant" => wmp_core::principal::PrincipalMode::Tenant,
                _ => wmp_core::principal::PrincipalMode::User,
            };
        }
        config
    }
}
