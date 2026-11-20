//! The standalone container host of the Rust WMP engine — the drop-in
//! replacement for `go-wallet-backend --mode=engine`.
//!
//! Serves the WMP HTTPS binding (wmp-transport.md §4): `POST /wmp` for
//! JSON-RPC requests and responses, `GET /wmp/events` for the SSE stream
//! the engine's notifications flow on. Sessions live in the store the
//! config names; the flow families (the engine core's S0–S3 work) register
//! on the runtime the [`handler::EngineHandler`] delegates flow methods to.

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
// The clippy disallowed-types rule (std HashMap/HashSet, the WASI
// random_get seed) is matcher.wasm's: this server crate never links into
// it (a native tokio process, WASI-capable), and jose-rs's Claims.extra
// is a std HashMap - the tests' token mint fills one. Allowed here.
#![allow(clippy::disallowed_types)]

pub mod config;
pub mod groups;
pub mod handler;
pub mod host_bridge;
pub mod invitation;
pub mod mailbox;
pub mod mcp_tools;
pub mod outbox;
pub mod ports;
pub mod shared_outbox;
pub mod token;
pub mod transport;
#[cfg(feature = "valkey")]
pub mod valkey_outbox;

use std::sync::Arc;

use crate::outbox::Outbox;
use wmp_core::peer::Peer;
use wmp_core::session::MemorySessionStore;

/// The running engine server: everything the routes need.
pub struct EngineServer {
    /// The WMP peer the POST handler dispatches through.
    pub peer: Arc<Peer>,
    /// The session store the engine and the health probe share.
    pub store: Arc<MemorySessionStore>,
    /// The token validator both transport paths authenticate through.
    pub validator: Arc<token::TokenValidator>,
    /// The flow runtime the handler delegates flow methods to — where the
    /// flow families (S0–S3) register.
    pub runtime: Arc<engine_core::runtime::FlowRuntime>,
    /// The engine's outbound event log: the peer's notifications land in
    /// it (the [`outbox::OutboxTransport`]), the SSE route replays and streams
    /// from it, and `wmp.session.resume` counts its missed messages from
    /// it.
    pub outbox: Arc<Outbox>,
    /// The engine's per-token revocation list (engine-parity.md §8 G2):
    /// `revoke` a `jti` and every later bearer of that token is refused.
    pub revocation: Arc<token::JtiBlacklist>,
    /// The invitation store (issue #77): the issued nonces, consumed
    /// single-use at the `wmp.session.create` that answers them.
    pub invitations: Arc<wmp_core::invitation::MemoryInvitationStore>,
    /// The engine's invitation key (issue #77): the provider-delegate
    /// ES256 pair the create endpoint signs with and the consume path
    /// verifies. None when `public_url` is unset (the endpoint refuses).
    pub invitation_key: Option<Arc<crate::invitation::InvitationKey>>,
    /// The engine's configuration.
    pub config: config::Config,
}

impl EngineServer {
    /// Builds the server from `config`: the token validator, the flow
    /// runtime, the session-backed handler over both, and the peer.
    ///
    /// The flow families register on `runtime` after construction; a flow
    /// type nobody registered answers `-31005` (core §10.3).
    pub fn new(config: config::Config) -> Self {
        let store = Arc::new(MemorySessionStore::new());
        // The per-token revocation list (engine-parity.md §8 G2): the
        // tenant-bound deployment's cheap per-token revocation, consulted
        // on every bearer validation. Exposed for the deployment's
        // revocation path; in-memory in the standalone engine.
        let revocation = Arc::new(token::JtiBlacklist::default());
        let validator = Arc::new(
            token::TokenValidator::from_config(&config).with_revocation(revocation.clone()),
        );
        let outbox = Arc::new(Outbox::new());
        // The flow→session notes: each flow's start records its session,
        // and the host bridge starts the flow's asks under it.
        let flows = crate::host_bridge::FlowSessions::new();

        // The ports the engine core runs on. The server adapter supplies:
        // the HTTP client (the flow families' fetches; reqwest with rustls
        // on the server, or the TEE's client), the system clock, the OS
        // RNG, the remote wallet (the WMP client) as the Host — its asks
        // ride child flows through the host bridge — the PDP client, the
        // in-memory KV store, and a no-op telemetry.
        let remote_host = Arc::new(crate::ports::RemoteHost::new(flows.clone()));
        let ports = Arc::new(engine_core::Ports {
            http: Arc::new(crate::ports::ServerHttpClient::new(&config)),
            clock: Arc::new(crate::ports::SystemClock),
            rng: Arc::new(crate::ports::OsRng),
            host: remote_host.clone(),
            pdp: Arc::new(crate::ports::BackendProxyPdp::new(&config)),
            kv: Arc::new(crate::ports::InMemoryKv::default()),
            telemetry: Arc::new(crate::ports::NoopTelemetry),
            consent_check: engine_ports::ConsentCheckMode::Warn,
            // The FAPI `iss` knob (ENGINE_REQUIRE_AUTHORIZATION_RESPONSE_ISSUER,
            // go-wallet-backend#551's WALLET_SECURITY_* twin): off by default.
            require_authorization_response_issuer: config.require_authorization_response_issuer,
            notifications: std::sync::Arc::new(
                engine_core::oid4vci::notification::NotificationContexts::default(),
            ),
        });

        // Build the peer and the runtime together (the FlowRuntime
        // sends through the peer; the peer's handler dispatches to the
        // runtime). The peer carries the outbox transport: every
        // outbound notification lands in the log, so the SSE route
        // serves what the flows send.
        let peer_store = store.clone();
        let peer_config = config.clone();
        let _peer_validator = validator.clone();
        let peer_outbox = outbox.clone();
        // The invitation service (issue #77): the store always, the key
        // when the provider's public URL is configured.
        let invitations = Arc::new(wmp_core::invitation::MemoryInvitationStore::new());
        let invitation_key = (!config.public_url.is_empty())
            .then(|| {
                crate::invitation::InvitationKey::generate()
                    .map(Arc::new)
                    .map_err(|err| {
                        eprintln!("engine-server: {err}");
                        err
                    })
                    .ok()
            })
            .flatten();
        let (peer, runtime) = build_peer(
            &peer_config,
            &peer_store,
            ports.clone(),
            peer_outbox,
            flows,
            invitations.clone(),
            invitation_key.as_ref(),
        );

        // The host bridge: the engine's asks as child flows over the peer,
        // their completions routed back through the same registry the
        // dispatch uses. The remote host carries it from here on.
        let bridge = crate::host_bridge::WmpHostBridge::new(peer.clone());
        remote_host.set_bridge(bridge);

        // The flow families register on THE runtime the handler
        // dispatches to (the drop-in server: a flow type nobody
        // registered answers -31005, core §10.3). The
        // credential_notification family rides the same notification
        // context store its Ports carry.
        if let Err(err) = runtime.register(Arc::new(engine_core::oid4vci::Oid4vciFlow)) {
            eprintln!("engine-server: register the oid4vci family: {err}");
            std::process::exit(1);
        }
        if let Err(err) = runtime.register(Arc::new(engine_core::oid4vp::Oid4vpFlow)) {
            eprintln!("engine-server: register the oid4vp family: {err}");
            std::process::exit(1);
        }
        if let Err(err) = runtime.register(Arc::new(
            engine_core::oid4vci::notification::CredentialNotificationFlow,
        )) {
            eprintln!("engine-server: register the credential_notification family: {err}");
            std::process::exit(1);
        }

        Self {
            peer,
            store,
            validator,
            runtime,
            outbox,
            revocation,
            invitations,
            invitation_key,
            config,
        }
    }

    /// Revokes the token identified by `jti` (engine-parity.md §8 G2):
    /// every later bearer validation of that token refuses it. The
    /// tenant-bound deployment's per-token revocation, paired with its
    /// short-TTL tokens.
    pub fn revoke_jti(&self, jti: &str) {
        self.revocation.revoke(jti);
    }
}

fn build_peer(
    config: &config::Config,
    store: &Arc<MemorySessionStore>,
    ports: Arc<engine_core::Ports>,
    outbox: Arc<Outbox>,
    flows: Arc<crate::host_bridge::FlowSessions>,
    invitations: Arc<wmp_core::invitation::MemoryInvitationStore>,
    invitation_key: Option<&Arc<crate::invitation::InvitationKey>>,
) -> (Arc<Peer>, Arc<engine_core::runtime::FlowRuntime>) {
    // The peer needs a handler; the handler needs the runtime; the runtime
    // needs the peer. Break the cycle: build the runtime over a
    // placeholder peer first, then the real handler, then the real peer,
    // then swap it into the runtime — no flow can start before the swap
    // (the real peer is not reachable until it exists), so the flows
    // always send through it, and the SSE outbox sees every notification.
    let placeholder_peer = wmp_core::peer::PeerBuilder::new(Arc::new(PlaceholderHandler))
        .session_store(store.clone())
        .max_message_size(config.max_message_size)
        .build();
    let runtime = Arc::new(engine_core::runtime::FlowRuntime::new(
        ports,
        placeholder_peer,
    ));
    let handler = handler::EngineHandler::new_with_invitations(
        config,
        store,
        &outbox,
        &flows,
        &runtime,
        invitations,
        invitation_key,
    );
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store.clone())
        .transport(Arc::new(crate::outbox::OutboxTransport::new(outbox)))
        .max_message_size(config.max_message_size)
        // #48: the flow-start capability gate's session-expiry check —
        // a start naming an expired session answers -31001 instead of
        // running against a dead record.
        .clock(handler::system_clock())
        // #76: the MCP tool surface — `tools/list`/`tools/call` behind the
        // negotiated `mcp` capability, on the registry's custom-method
        // dispatch. A registration collision would be a programming error
        // (no other profile claims the method names); refuse to start.
        .profile(Arc::new(crate::mcp_tools::McpToolProfile::new(
            config.mcp_tools,
        )))
        .unwrap_or_else(|err| {
            eprintln!("engine-server: register the mcp tool surface: {err}");
            std::process::exit(1);
        });
    // The MLS group encryption (the wmp-mls spec, RFC 9420): the
    // OpenMLS-backed provider + the handler bridge, the MlsProfile
    // registered the same way. The engine's own member identity: the
    // deployment (the groups key the member that runs them).
    #[cfg(feature = "mls")]
    let peer = {
        let identity = "engine";
        let provider = match wmp_mls::OpenMlsProvider::for_identity(identity) {
            Ok(provider) => provider,
            Err(err) => {
                eprintln!("engine-server: the MLS provider cannot start: {err:?}");
                std::process::exit(1);
            }
        };
        let handler = wmp_mls::EngineMlsHandler::new(provider);
        match peer.profile(wmp_core::mls::MlsProfile::new(Arc::new(handler))) {
            Ok(peer) => peer,
            Err(err) => {
                eprintln!("engine-server: register the mls profile: {err}");
                std::process::exit(1);
            }
        }
    };
    let peer = peer.build();
    runtime.set_peer(peer.clone());
    (peer, runtime)
}

/// A placeholder handler that answers every request with `-32601`,
/// used only to break the peer ↔ runtime construction cycle.
struct PlaceholderHandler;

impl wmp_core::handler::Handler for PlaceholderHandler {}

/// The binary's entry point, on the library root so the panic-lint
/// discipline covers it. Reads the config from `ENGINE_CONFIG` (a JSON
/// file path) or the defaults, binds, serves, and shuts down gracefully.
pub fn main_entry() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| {
            eprintln!("engine-server: cannot start the tokio runtime: {err}");
            std::process::exit(1);
        });

    runtime.block_on(async_main());
}

async fn async_main() {
    // The full-fidelity form first: `ENGINE_CONFIG` names a JSON file.
    // Then the container's form: the `ENGINE_*` variables over the
    // defaults. Both empty: the defaults (the dev engine).
    let config: config::Config = std::env::var("ENGINE_CONFIG")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(config::Config::from_env);

    let server = Arc::new(EngineServer::new(config.clone()));
    let app = transport::router(server);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("engine-server: cannot bind {}: {err}", config.listen_addr);
            std::process::exit(1);
        });

    println!(
        "engine-server: listening on {} (mode=engine replacement, WMP over HTTPS)",
        config.listen_addr
    );

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .unwrap_or_else(|_| std::process::exit(1));
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    };

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("engine-server: {err}");
        std::process::exit(1);
    }
}
