//! The standalone container host of the Rust WMP engine — the drop-in
//! replacement for `go-wallet-backend --mode=engine`.
//!
//! Serves the WMP HTTPS binding (wmp-transport.md §4): `POST /wmp` for
//! JSON-RPC requests and responses, `GET /wmp/events` for the SSE stream
//! the engine's notifications flow on. Sessions live in the store the
//! config names; the flow families (the engine core's S0–S3 work) plug into
//! the [`EngineHandler`] when they land.

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

pub mod config;
pub mod handler;
pub mod transport;

use std::sync::Arc;

use wmp_core::peer::Peer;
use wmp_core::session::MemorySessionStore;

/// The running engine server: everything the routes need.
pub struct EngineServer {
    /// The WMP peer the POST handler dispatches through.
    pub peer: Arc<Peer>,
    /// The session store the engine and the health probe share.
    pub store: Arc<MemorySessionStore>,
    /// The engine's configuration.
    pub config: config::Config,
}

impl EngineServer {
    /// Builds the server from `config`: the session service, the handler
    /// (the engine's flow families register here when they land), the
    /// peer, and the SSE transport channel.
    pub fn new(config: config::Config) -> Self {
        let store = Arc::new(MemorySessionStore::new());
        let service = handler::build_service(&config, &store);
        let peer = wmp_core::peer::PeerBuilder::new(service)
            .session_store(store.clone())
            .max_message_size(config.max_message_size)
            .build();
        Self {
            peer,
            store,
            config,
        }
    }
}

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
    let config: config::Config = std::env::var("ENGINE_CONFIG")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();

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
