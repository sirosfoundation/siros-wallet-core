//! The engine's WMP handler: session management through the session
//! service, and the flow families plugged in when they land.
//!
//! This is the `--mode=engine` replacement's brain: every WMP method the
//! engine serves dispatches here. Today the session methods work (create,
//! resume, close, authenticate) and the rest answer `-32601` method not
//! found — the flow families (S0–S3) register through the engine core's
//! flow seam and take over from there.

use std::sync::Arc;

use wmp_core::handler::Handler;
use wmp_core::session::MemorySessionStore;
use wmp_core::sessionservice::{Clock, SessionHandler, SessionService, SessionServiceConfig};

use crate::config::Config;

/// Builds the engine's handler over the session service, wired to the
/// store. The flow families register on the returned handler when they
/// land (they replace the defaults for the methods they own).
pub fn build_service(config: &Config, store: &Arc<MemorySessionStore>) -> Arc<dyn Handler> {
    let entropy: wmp_core::sessionservice::EntropyFn = Arc::new(|bytes: &mut [u8]| {
        // The operating system's secure RNG — the only ambient effect the
        // server adapter owns. In a TEE this is the host's attested source.
        use std::io::Read;
        match std::fs::File::open("/dev/urandom") {
            Ok(mut f) => f.read_exact(bytes).is_ok(),
            Err(_) => false,
        }
    });
    let service = Arc::new(
        SessionService::new(SessionServiceConfig {
            store: Some(store.clone()),
            default_ttl_secs: config.default_session_ttl_secs,
            entropy: Some(entropy),
            ..SessionServiceConfig::default()
        })
        .unwrap_or_else(|err| {
            // The config is a programming constant here: the store is always
            // present and the entropy always opens. If it fails the server
            // cannot serve sessions, so exit rather than limp.
            eprintln!("engine-server: invalid session service config: {err}");
            std::process::exit(1);
        }),
    );
    Arc::new(SessionHandler::new(service, system_clock()))
}

/// The system clock, unix seconds — the only ambient effect the server
/// adapter owns (the SDK adapter takes the platform clock; the TEE adapter
/// takes the clock its host attests).
fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default()
    })
}
