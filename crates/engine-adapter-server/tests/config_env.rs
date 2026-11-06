//! The engine server's environment configuration (`Config::from_env`):
//! the `ENGINE_*` variables the container platform writes, over the
//! defaults — the deployment shape of the dev engine (the compose file,
//! the chart).

use engine_adapter_server::config::Config;

/// Serializes the env-mutating tests: cargo runs a binary's tests in
/// parallel by default, and the environment is process-wide. Other
/// test binaries are separate processes — no interference.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One variable set, one config built, one field read.
fn with_var(name: &str, value: &str, read: impl Fn(&Config) -> bool) {
    std::env::set_var(name, value);
    let config = Config::from_env();
    std::env::remove_var(name);
    assert!(read(&config), "{name}={value}: {config:?}");
}

/// A variable the test framework or another test may have left set:
/// cleared before and after each read, so the test sees only its own.
fn clear(vars: &[&str]) {
    for name in vars {
        std::env::remove_var(name);
    }
}

/// The variables, one per config member, over the defaults.
#[test]
fn the_engine_variables_over_the_defaults() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let vars = [
        "ENGINE_LISTEN_ADDR",
        "ENGINE_ADDR",
        "ENGINE_MAX_MESSAGE_SIZE",
        "ENGINE_DEFAULT_SESSION_TTL_SECS",
        "ENGINE_AS_EXTERNAL_URL",
        "ENGINE_AS_JWKS_URL",
        "ENGINE_AS_ISSUER",
        "ENGINE_AS_AUDIENCES",
        "ENGINE_PDP_URL",
        "ENGINE_ALLOW_PLAINTEXT",
        "ENGINE_METADATA_TYPE",
        "ENGINE_MAX_CONCURRENT_FLOWS",
    ];
    clear(&vars);

    // The listen address, both names (the Dockerfile's
    // ENGINE_LISTEN_ADDR; the shorter ENGINE_ADDR a compose file
    // writes).
    with_var("ENGINE_LISTEN_ADDR", "127.0.0.1:9999", |c| {
        c.listen_addr == "127.0.0.1:9999"
    });
    with_var("ENGINE_ADDR", "0.0.0.0:80", |c| {
        c.listen_addr == "0.0.0.0:80"
    });

    with_var("ENGINE_MAX_MESSAGE_SIZE", "65536", |c| {
        c.max_message_size == 65536
    });
    with_var("ENGINE_DEFAULT_SESSION_TTL_SECS", "600", |c| {
        c.default_session_ttl_secs == 600
    });
    with_var("ENGINE_AS_EXTERNAL_URL", "https://as.example", |c| {
        c.as_external_url == "https://as.example"
    });
    with_var(
        "ENGINE_AS_JWKS_URL",
        "http://backend:8080/auth/.well-known/jwks.json",
        |c| c.as_jwks_url == "http://backend:8080/auth/.well-known/jwks.json",
    );
    with_var("ENGINE_AS_ISSUER", "http://localhost:8080", |c| {
        c.as_issuer == "http://localhost:8080"
    });
    // Comma-separated; whitespace-tolerant.
    with_var(
        "ENGINE_AS_AUDIENCES",
        "wallet-engine, wallet-backend",
        |c| c.as_audiences == ["wallet-engine", "wallet-backend"],
    );
    // Set but empty accepts every audience (the go-tokenauth behaviour
    // the backend's AS relies on) — the var is read even when empty.
    with_var("ENGINE_AS_AUDIENCES", "", |c| c.as_audiences.is_empty());
    with_var("ENGINE_PDP_URL", "http://backend:8080", |c| {
        c.pdp_url == "http://backend:8080"
    });
    // The truthy forms a compose file or a chart writes.
    with_var("ENGINE_ALLOW_PLAINTEXT", "true", |c| c.allow_plaintext);
    with_var("ENGINE_ALLOW_PLAINTEXT", "1", |c| c.allow_plaintext);
    with_var("ENGINE_ALLOW_PLAINTEXT", "yes", |c| c.allow_plaintext);
    with_var("ENGINE_ALLOW_PLAINTEXT", "on", |c| c.allow_plaintext);
    // The falsy forms, and the case-insensitive truth.
    with_var("ENGINE_ALLOW_PLAINTEXT", "false", |c| !c.allow_plaintext);
    with_var("ENGINE_ALLOW_PLAINTEXT", "TRUE", |c| c.allow_plaintext);
    with_var("ENGINE_METADATA_TYPE", "require-signed", |c| {
        c.metadata_type == "require-signed"
    });
    with_var("ENGINE_MAX_CONCURRENT_FLOWS", "32", |c| {
        c.max_concurrent_flows == 32
    });

    clear(&vars);
}

/// The defaults, with nothing set: the dev engine's shape.
#[test]
fn the_defaults_with_nothing_set() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let vars = [
        "ENGINE_LISTEN_ADDR",
        "ENGINE_ADDR",
        "ENGINE_MAX_MESSAGE_SIZE",
        "ENGINE_DEFAULT_SESSION_TTL_SECS",
        "ENGINE_AS_EXTERNAL_URL",
        "ENGINE_AS_JWKS_URL",
        "ENGINE_AS_ISSUER",
        "ENGINE_AS_AUDIENCES",
        "ENGINE_PDP_URL",
        "ENGINE_ALLOW_PLAINTEXT",
        "ENGINE_METADATA_TYPE",
        "ENGINE_MAX_CONCURRENT_FLOWS",
        "ENGINE_CONFIG",
    ];
    clear(&vars);
    let config = Config::from_env();
    assert_eq!(config.listen_addr, "0.0.0.0:8780");
    assert_eq!(config.max_message_size, 1 << 20);
    assert_eq!(config.default_session_ttl_secs, 3600);
    assert_eq!(config.as_external_url, "");
    assert_eq!(config.as_jwks_url, "");
    assert_eq!(config.as_issuer, "");
    assert_eq!(config.as_audiences, ["wallet-engine"]);
    assert_eq!(config.pdp_url, "");
    assert!(!config.allow_plaintext);
    assert_eq!(config.metadata_type, "prefer-signed");
    assert_eq!(config.max_concurrent_flows, 16);
}

/// An unparseable number is the default, not a refusal: a
/// misconfigured scaler's pod still starts and serves its probes
/// (the Go engine's config treats its environment the same way).
#[test]
fn an_unparseable_number_is_the_default() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let vars = [
        "ENGINE_MAX_MESSAGE_SIZE",
        "ENGINE_DEFAULT_SESSION_TTL_SECS",
        "ENGINE_MAX_CONCURRENT_FLOWS",
    ];
    clear(&vars);
    with_var("ENGINE_MAX_MESSAGE_SIZE", "not-a-number", |c| {
        c.max_message_size == 1 << 20
    });
    with_var("ENGINE_DEFAULT_SESSION_TTL_SECS", "soon", |c| {
        c.default_session_ttl_secs == 3600
    });
    with_var("ENGINE_MAX_CONCURRENT_FLOWS", "many", |c| {
        c.max_concurrent_flows == 16
    });
    clear(&vars);
}
