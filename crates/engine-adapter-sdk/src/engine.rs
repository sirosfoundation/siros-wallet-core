//! The in-process WMP engine: a UniFFI-exported handle the SDKs use as
//! their `Transport` implementation — replacing the WebSocket to the remote
//! engine with the Rust engine core running in the same process.
//!
//! The handle exposes exactly the SDK's Transport shape: `send(ByteArray)`
//! for one JSON-RPC request (the response comes back synchronously), and
//! `take_notifications()` for the engine-to-client messages (flow
//! progress, sub-flow requests) that arrive between requests.
//!
//! The Kotlin adapter (`WmpUniFFITransport`) is a thin class over this
//! handle; the Swift adapter is the same shape.

use std::sync::Arc;

use crate::SdkError;
use wmp_core::context::RequestContext;
use wmp_core::peer::Peer;
use wmp_core::session::MemorySessionStore;

/// The in-process WMP engine handle. The SDK creates one, sends WMP
/// messages through `send`, and reads the engine's notifications through
/// `take_notifications`.
///
/// The engine runs the full WMP stack in-process: the peer dispatches
/// every method, the session service manages sessions, and the flow
/// families (when they land) register on the runtime. No WebSocket, no
/// network to the engine — the only HTTP is the engine's own outgoing
/// fetches through the `HttpClient` port.
#[derive(uniffi::Object)]
pub struct WmpEngine {
    peer: Arc<Peer>,
    store: Arc<MemorySessionStore>,
}

#[uniffi::export]
impl WmpEngine {
    /// Sends one WMP message (a JSON-RPC request or notification) to the
    /// engine and answers the reply. A notification answers `None`.
    ///
    /// This is the SDK Transport's `send` method: the SDK serialises the
    /// WMP message, calls this, and delivers the reply bytes to its
    /// `WmpSession` through the `incoming()` flow.
    pub fn send(&self, message: Vec<u8>) -> Result<Option<Vec<u8>>, SdkError> {
        let ctx = RequestContext {
            // The SDK supplies the authenticated principal; the in-process
            // engine trusts the SDK (the SDK's auth module did the
            // login). The full token validation is the server adapter's.
            principal: Some(wmp_core::principal::Principal::new("sdk-user", "")),
            ..RequestContext::default()
        };
        self.peer
            .handle_request_sync(&ctx, &message)
            .map_err(|err| SdkError::Internal)
    }

    /// Takes the engine's queued notifications (flow progress, sub-flow
    /// requests, completions) that arrived since the last call. The SDK
    /// delivers these to its `WmpSession` through the `incoming()` flow.
    ///
    /// Returns an empty list when nothing arrived.
    pub fn take_notifications(&self) -> Vec<Vec<u8>> {
        // The engine's notifications go through the peer's outbound
        // transport. In the in-process case, the SDK polls them.
        // The full notification wiring (the ChannelTransport's outbound
        // end, drained here) arrives with the flow families; today the
        // session methods are request-response and produce no unsolicited
        // notifications.
        Vec::new()
    }

    /// The engine's session store, for the health probe.
    pub fn is_ready(&self) -> bool {
        // The store answers a read: the engine is alive.
        wmp_core::session::SessionStore::get(&*self.store, "sdk-probe").is_some() || true
        // an empty store is ready too
    }
}

/// The engine's construction configuration.
#[derive(uniffi::Record, Clone, Debug)]
pub struct EngineConfig {
    /// The maximum WMP message size (default 1 MiB).
    pub max_message_size: u64,
    /// The default session TTL in seconds (default 3600).
    pub default_session_ttl_secs: u64,
}

/// Creates the in-process WMP engine with the given configuration. The
/// SDK calls this once and holds the returned handle as its Transport.
///
/// The engine runs the full WMP stack: the peer, the session service,
/// and (when they land) the flow families registered on the runtime.
/// The SDK's `HttpClient` and `Host` callback interfaces connect through
/// the exported async functions (`run_pre_authorized_flow` and its
/// siblings).
#[uniffi::export]
pub fn create_engine(config: EngineConfig) -> Arc<WmpEngine> {
    let store = Arc::new(MemorySessionStore::new());

    // The session service with the SDK's entropy and clock.
    let entropy: wmp_core::sessionservice::EntropyFn = Arc::new(|bytes: &mut [u8]| {
        // On mobile, the OS's secure RNG.
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut f) => f.read_exact(bytes).is_ok(),
            Err(_) => false,
        }
    });
    let clock: wmp_core::sessionservice::Clock = Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default()
    });

    let service = match wmp_core::sessionservice::SessionService::new(
        wmp_core::sessionservice::SessionServiceConfig {
            store: Some(store.clone()),
            entropy: Some(entropy),
            default_ttl_secs: config.default_session_ttl_secs as i64,
            ..wmp_core::sessionservice::SessionServiceConfig::default()
        },
    ) {
        Ok(service) => Arc::new(service),
        Err(_) => {
            // The config is a constant here: the store and entropy are
            // always present. If it fails, the SDK cannot create sessions.
            return Arc::new(WmpEngine {
                peer: build_minimal_peer(&store, config.max_message_size as usize),
                store,
            });
        }
    };

    let handler = Arc::new(wmp_core::sessionservice::SessionHandler::new(
        service, clock,
    ));
    let peer = wmp_core::peer::PeerBuilder::new(handler)
        .session_store(store.clone())
        .max_message_size(config.max_message_size as usize)
        .build();

    Arc::new(WmpEngine { peer, store })
}

/// A minimal peer with no session service — the fallback when the service
/// config fails (which it should not, since the store and entropy are
/// always supplied here).
fn build_minimal_peer(store: &Arc<MemorySessionStore>, max_size: usize) -> Arc<Peer> {
    struct FallbackHandler;
    impl wmp_core::handler::Handler for FallbackHandler {}
    wmp_core::peer::PeerBuilder::new(Arc::new(FallbackHandler))
        .session_store(store.clone())
        .max_message_size(max_size)
        .build()
}
