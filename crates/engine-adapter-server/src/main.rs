//! The binary of the standalone engine server — the container's entry
//! point. The library crate carries the actual entry point; this root
//! exists to name the binary and carry the workspace's crate-root lint
//! discipline.

// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see. The
// fail-fast paths (cannot bind, cannot start the runtime) are in the
// library's main_entry, which exits the process rather than panicking.
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

fn main() {
    engine_adapter_server::main_entry()
}
