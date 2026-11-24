//! The well-known configuration: its document types, the domain extraction
//! from every WMP identifier, and the discovery over an injected fetcher —
//! the mirror of go-wmp's `discovery.go`.
//!
//! go-wmp fetches `/.well-known/wmp-configuration` with `http.DefaultClient`;
//! this crate is sans-network, so [`discover_config`] takes the fetcher and
//! enforces the response limits itself.

use serde::{Deserialize, Serialize};

use crate::version::Version;

/// The maximum size of a well-known document: 1 MiB.
const MAX_CONFIG_BYTES: usize = 1 << 20;

/// A WMP well-known configuration document, served at
/// `/.well-known/wmp-configuration`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WellKnownConfig {
    /// The discovery base the document describes:
    /// `https://<host><tenant-path>`. Required for a tenant path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_base: Option<String>,
    /// The protocol versions the endpoint speaks (core §2.2.1). Decoding
    /// refuses a document with an entry that is not `MAJOR.MINOR`.
    pub supported_versions: Vec<Version>,
    /// The endpoints, keyed by name.
    pub endpoints: std::collections::BTreeMap<String, String>,
    /// The capabilities the endpoint offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    /// The identifier schemes the endpoint accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_schemes: Vec<String>,
    /// The security modes the endpoint accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_modes: Vec<String>,
    /// The URL of the MLS key packages.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mls_key_packages: String,
    /// The relay endpoint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay: String,
    /// The identity providers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_providers: Vec<String>,
    /// The trust frameworks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_frameworks: Vec<String>,
    /// The ERDS metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erds: Option<ErdsMetadata>,
    /// The recipient's delivery preferences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_metadata: Option<RecipientMetadata>,
}

/// Advertises ERDS (Electronic Registered Delivery Service) capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErdsMetadata {
    /// The consignment modes supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consignment_modes: Vec<String>,
    /// The assurance levels supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assurance_levels: Vec<String>,
    /// The policies supported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_policies: Vec<String>,
    /// Whether delegation is supported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delegation: bool,
    /// The evidence repository.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_repository: String,
    /// The evidence retention policy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_retention: String,
    /// Whether scheduled delivery is supported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub scheduled_delivery: bool,
}

/// Advertises a recipient's delivery preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipientMetadata {
    /// The accepted content types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_content_types: Vec<String>,
    /// The maximum message size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_message_size: Option<i64>,
    /// The consignment preferences.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub consignment_preferences: String,
    /// Whether encryption is required.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub encryption_required: bool,
}

/// Why a discovery failed.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The domain is empty or contains characters that could redirect the
    /// request elsewhere.
    #[error("wmp: invalid domain {0:?}")]
    InvalidDomain(String),
    /// The identifier names no domain.
    #[error("cannot extract domain from identifier {0:?}")]
    NoDomain(String),
    /// The identifier has no well-known configuration (WMP Core 7.5.1):
    /// its endpoint comes from a profile resolver or session parameters.
    #[error("wmp: identifier {0:?} has no discovery base")]
    NoDiscoveryBase(String),
    /// The configuration does not describe the discovery base it was
    /// fetched for (WMP Core 7.5.1).
    #[error("wmp: well-known configuration is for {got:?}, want {want:?}")]
    BaseMismatch {
        /// The `discovery_base` the document carries, if any.
        got: Option<String>,
        /// The base the identifier names.
        want: String,
    },
    /// The fetcher failed; the underlying detail is the adapter's, and it is
    /// carried as received.
    #[error("fetch well-known: {0}")]
    Fetch(String),
    /// The document is not a well-known configuration.
    #[error("decode well-known: {0}")]
    Decode(String),
}

/// Extracts the domain from a WMP identifier. It answers the host only: use
/// [`DiscoveryBase::for_identifier`] to locate a well-known configuration.
/// `did:web:`, `https://`, `x509:san:dns:` and `x509:san:uri:https://`
/// identifiers carry one; anything else answers an empty string.
pub fn extract_domain(identifier: &str) -> String {
    if identifier.starts_with("did:web:") {
        return parse_did_web(identifier).map_or_else(String::new, |(domain, _)| domain);
    }
    if let Some(rest) = identifier.strip_prefix("https://") {
        return host_of(rest).to_owned();
    }
    if let Some(rest) = identifier.strip_prefix("x509:san:dns:") {
        return rest.to_owned();
    }
    if let Some(rest) = identifier.strip_prefix("x509:san:uri:https://") {
        return host_of(rest).to_owned();
    }
    String::new()
}

/// The host of a URL: everything before the first path, query or fragment.
fn host_of(rest: &str) -> &str {
    match rest.find(['/', '?', '#']) {
        Some(idx) => &rest[..idx],
        None => rest,
    }
}

/// Safely constructs the well-known configuration URL for a domain,
/// rejecting domain values that contain path separators, query strings,
/// fragments, or userinfo that could redirect the request elsewhere.
pub fn build_well_known_url(domain: &str) -> Result<String, DiscoveryError> {
    if domain.is_empty() {
        return Err(DiscoveryError::InvalidDomain(String::new()));
    }
    if domain.contains(['/', '?', '#', '@', '\\']) {
        return Err(DiscoveryError::InvalidDomain(domain.to_owned()));
    }
    Ok(format!("https://{domain}/.well-known/wmp-configuration"))
}

/// Extracts the domain (and the sub-path, which well-known resolution never
/// follows) from a `did:web` identifier:
/// `did:web:example.com` → `example.com`;
/// `did:web:example.com:users:alice` → `example.com` and `users/alice`;
/// `did:web:example.com%3A8080` → `example.com:8080`.
///
/// Per the WMP spec's privacy principle (§7.5), per-user sub-path resolution
/// publicly exposes the user-to-provider binding; well-known resolution always
/// goes to the provider's domain-level configuration, and go-wmp's
/// `DiscoverConfigForDID` is deprecated in the same way — the mirror does not
/// carry it.
pub fn parse_did_web(did: &str) -> Option<(String, String)> {
    let rest = did.strip_prefix("did:web:")?;
    let mut parts = rest.split(':');
    let domain = parts.next().unwrap_or_default().replace("%3A", ":");
    if !is_valid_did_web_domain(&domain) {
        return None;
    }
    let path = parts.collect::<Vec<_>>().join("/");
    Some((domain, path))
}

/// Rejects domains that could redirect discovery to unexpected hosts — via
/// embedded path separators or userinfo, or a leading dot.
fn is_valid_did_web_domain(domain: &str) -> bool {
    !domain.is_empty() && !domain.contains(['/', '\\', '?', '#', '@']) && !domain.starts_with('.')
}

/// Where the well-known configuration of a domain-based identifier is found
/// (WMP Core 7.5.1): a host and, for a tenant of a host that serves several
/// providers, the tenant's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryBase {
    /// The host, with its port when the identifier names one.
    pub host: String,
    /// Empty for the whole host; otherwise starts with `/` and has no
    /// trailing `/`.
    pub tenant_path: String,
}

impl DiscoveryBase {
    /// Derives the discovery base of an identifier:
    ///
    /// - `x509:san:dns:example.com` → `example.com`
    /// - `https://example.com/tenant1` → `example.com`, `/tenant1`
    /// - `x509:san:uri:https://example.com/tenant` → `example.com`, `/tenant`
    /// - `did:web:example.com` → `example.com`
    ///
    /// A `did:web` identifier with a path has none: the did:web method
    /// resolves it through its DID Document, whose `WMPMessaging` service
    /// names the endpoint (WMP Core 7.5.4). An identifier with a query, a
    /// fragment, userinfo or a `.` or `..` path segment has none either.
    pub fn for_identifier(identifier: &str) -> Result<Self, DiscoveryError> {
        let none = || DiscoveryError::NoDiscoveryBase(identifier.to_owned());
        if identifier.starts_with("did:web:") {
            return match parse_did_web(identifier) {
                Some((domain, path)) if path.is_empty() => Self::for_host(&domain).ok_or_else(none),
                _ => Err(none()),
            };
        }
        if let Some(host) = identifier.strip_prefix("x509:san:dns:") {
            return Self::for_host(host).ok_or_else(none);
        }
        if let Some(url) = identifier.strip_prefix("x509:san:uri:") {
            return Self::for_url(url).ok_or_else(none);
        }
        if identifier.starts_with("https://") {
            return Self::for_url(identifier).ok_or_else(none);
        }
        Err(none())
    }

    /// The base of a whole host.
    fn for_host(host: &str) -> Option<Self> {
        if host.is_empty() || host.starts_with('.') || host.contains(['/', '?', '#', '@', '\\']) {
            return None;
        }
        if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            tenant_path: String::new(),
        })
    }

    /// The base of an `https` URL, read from the string as written: its host
    /// and its path without a trailing `/`.
    fn for_url(raw: &str) -> Option<Self> {
        let rest = raw.strip_prefix("https://")?;
        if raw.contains(['?', '#', '\\']) || raw.chars().any(char::is_whitespace) {
            return None;
        }
        let (host, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        let base = Self::for_host(host)?;
        let tenant_path = path.trim_end_matches('/');
        for segment in tenant_path.split('/') {
            let decoded = percent_decode(segment)?;
            if decoded == b"." || decoded == b".." {
                return None;
            }
        }
        Some(Self {
            host: base.host,
            tenant_path: tenant_path.to_owned(),
        })
    }

    /// The URL of the configuration: the well-known segment inserted between
    /// the host and the tenant path, as RFC 8414 Section 3.1 does.
    pub fn well_known_url(&self) -> String {
        format!(
            "https://{}/.well-known/wmp-configuration{}",
            self.host, self.tenant_path
        )
    }

    /// The base as the `https` URL a configuration carries in
    /// `discovery_base`.
    pub fn url(&self) -> String {
        format!("https://{}{}", self.host, self.tenant_path)
    }

    /// Verifies that a configuration describes this base. A configuration
    /// for a tenant path must name the base; one for a whole host may leave
    /// it out.
    pub fn check(&self, config: &WellKnownConfig) -> Result<(), DiscoveryError> {
        let mismatch = || DiscoveryError::BaseMismatch {
            got: config.discovery_base.clone(),
            want: self.url(),
        };
        let declared = match config.discovery_base.as_deref() {
            None | Some("") if self.tenant_path.is_empty() => return Ok(()),
            None | Some("") => return Err(mismatch()),
            Some(declared) => declared,
        };
        // The scheme compares case-insensitively, like the host.
        let normalized = match declared.get(..6) {
            Some(scheme) if scheme.eq_ignore_ascii_case("https:") => {
                format!("https:{}", &declared[6..])
            }
            _ => declared.to_owned(),
        };
        match Self::for_url(&normalized) {
            Some(got)
                if got.host.eq_ignore_ascii_case(&self.host)
                    && got.tenant_path == self.tenant_path =>
            {
                Ok(())
            }
            _ => Err(mismatch()),
        }
    }
}

/// Percent-decodes a path segment; `None` when an escape is malformed.
fn percent_decode(segment: &str) -> Option<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes.iter();
    while let Some(&byte) = rest.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let hi = char::from(*rest.next()?).to_digit(16)?;
        let lo = char::from(*rest.next()?).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Fetches the configuration of a base through `fetch` and checks that it is
/// the base's own. There is no fallback from a tenant to its host: the
/// host's configuration belongs to another provider.
fn discover(
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
    base: &DiscoveryBase,
) -> Result<WellKnownConfig, DiscoveryError> {
    let body = fetch(&base.well_known_url()).map_err(DiscoveryError::Fetch)?;
    if body.len() > MAX_CONFIG_BYTES {
        return Err(DiscoveryError::Fetch("well-known too large".to_owned()));
    }
    let config: WellKnownConfig =
        serde_json::from_slice(&body).map_err(|err| DiscoveryError::Decode(err.to_string()))?;
    base.check(&config)?;
    Ok(config)
}

/// Fetches the WMP well-known configuration of a whole host through `fetch`,
/// which receives the well-known URL and answers the response body. The body
/// is limited to 1 MiB, must decode as a configuration, and must not name
/// another discovery base.
///
/// Use [`discover_config_for_identifier`] for an identifier, which may name
/// a tenant.
pub fn discover_config(
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
    domain: &str,
) -> Result<WellKnownConfig, DiscoveryError> {
    build_well_known_url(domain)?;
    let base = DiscoveryBase {
        host: domain.to_owned(),
        tenant_path: String::new(),
    };
    discover(fetch, &base)
}

/// Fetches the well-known configuration of any domain-based WMP identifier
/// at the URL of its discovery base ([`DiscoveryBase::for_identifier`]) and
/// checks the document's `discovery_base`. Errors with
/// [`DiscoveryError::NoDiscoveryBase`] when the identifier has no well-known
/// configuration: the caller falls back to session parameters or a profile
/// resolver.
pub fn discover_config_for_identifier(
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
    identifier: &str,
) -> Result<WellKnownConfig, DiscoveryError> {
    let base = DiscoveryBase::for_identifier(identifier)?;
    discover(fetch, &base)
}
