//! The bindgen binary of the engine adapter SDK: `uniffi_bindgen_main` is
//! uniffi's own; this root exists to carry the workspace's crate-root lint
//! discipline (the panic lints, checked by `scripts/check_panic_sites.py`)
//! and nothing else.

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

fn main() {
    uniffi::uniffi_bindgen_main()
}
