//! The Authorization Request parameter builders: the RFC 8707 resource
//! indicator, the `authorization_details` projection, the `issuer_state`
//! forwarding, and the credential identifier substitution — the
//! P0.6-verified compliance behaviours of the auth-code grant's parameter
//! assembly, as pure functions so the PAR client (when it lands) sends
//! exactly these.
//!
//! - **RFC 8707**: the access token is audience-restricted to the
//!   Credential Issuer via the `resource` parameter, but only when the
//!   issuer is a different origin than the Authorization Server — the same
//!   decision this module makes for both the authorization request and
//!   the later token request, so they always agree (RFC 8707 requires it).
//! - **authorization_details** (OID4VCI §5.1.1): the client's details are
//!   *projected*, never forwarded: `credential_identifiers` are
//!   response-only (the AS grants them; a wallet may not ask), `type` is
//!   fixed at `openid_credential`, and an entry naming no configuration
//!   identifies nothing and is dropped.
//! - **issuer_state**: an issuer-initiated offer carries the issuance
//!   session in the `authorization_code` grant; it is forwarded alongside
//!   scope and authorization_details.
//! - **The guard**: something must name the credential — `scope`,
//!   `authorization_details`, or `issuer_state` — or the AS has nothing
//!   to act on, and failing here names the cause instead of producing an
//!   opaque rejection or an arbitrary credential.

use serde_json::Value;

/// The `type` fixed for a credential authorization detail (OID4VCI §5.1.1).
pub const AUTHORIZATION_DETAIL_TYPE: &str = "openid_credential";

/// Why the authorization parameter assembly refused.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuthParamError {
    /// Nothing names the credential: no scope, no authorization_details
    /// naming a configuration, and no issuer_state in the offer.
    #[error(
        "oid4vci: credential configuration declares no scope, the wallet sent no \
         authorization_details naming a configuration, and the offer carries no \
         issuer_state"
    )]
    NothingNamesCredential,
}

/// The assembled Authorization Request parameters, in wire order.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequestParams {
    /// The ordered (name, value) pairs.
    pub params: Vec<(String, String)>,
}

impl AuthorizationRequestParams {
    /// Whether at least one parameter names the credential the AS should
    /// act on: `scope`, `authorization_details`, or `issuer_state`.
    pub fn names_a_credential(&self) -> bool {
        self.params.iter().any(|(name, value)| {
            matches!(
                name.as_str(),
                "scope" | "authorization_details" | "issuer_state"
            ) && !value.is_empty()
        })
    }

    /// A parameter's value, when set.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The inputs to the Authorization Request parameter assembly.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestSpec<'a> {
    /// The wallet's client_id (the registered id, or the redirect_uri for
    /// an unregistered client).
    pub client_id: &'a str,
    /// The wallet's redirect URI.
    pub redirect_uri: &'a str,
    /// The OAuth state (fresh per request, from the Rng port).
    pub state: &'a str,
    /// The selected configuration's scope, when it declares one.
    pub scope: Option<&'a str>,
    /// The client-supplied authorization_details (raw, projected here).
    pub authorization_details: &'a [Value],
    /// The offer's grants, for the `issuer_state`.
    pub grants: &'a Value,
    /// The Authorization Server's issuer.
    pub as_issuer: &'a str,
    /// The Credential Issuer's identifier.
    pub credential_issuer: &'a str,
}

/// Builds the common Authorization Request parameters.
///
/// The caller supplies the client's identity and redirect, the selected
/// configuration's scope (when it declares one), the client-supplied
/// authorization_details, the offer's grants (for `issuer_state`), and
/// both issuers (for the RFC 8707 same-origin decision). The PKCE
/// challenge parameters are the PAR client's to add — they are derived
/// per-request from fresh entropy, not assembled here.
pub fn build_authorization_request_params(
    spec: &AuthorizationRequestSpec<'_>,
) -> Result<AuthorizationRequestParams, AuthParamError> {
    let mut params: Vec<(String, String)> = vec![
        ("response_type".to_owned(), "code".to_owned()),
        ("client_id".to_owned(), spec.client_id.to_owned()),
        ("redirect_uri".to_owned(), spec.redirect_uri.to_owned()),
        ("state".to_owned(), spec.state.to_owned()),
    ];

    if let Some(scope) = spec.scope.filter(|s| !s.is_empty()) {
        params.push(("scope".to_owned(), scope.to_owned()));
    }

    // RFC 8707: audience-restrict to the Credential Issuer, cross-origin
    // only. Both this step and the token request derive the decision from
    // the same metadata, so they always agree.
    if !same_origin(spec.as_issuer, spec.credential_issuer) {
        params.push(("resource".to_owned(), spec.credential_issuer.to_owned()));
    }

    // The projected authorization_details.
    let projected = project_authorization_details(spec.authorization_details);
    if !projected.is_empty() {
        let encoded = serde_json::to_string(&projected).unwrap_or_default();
        if !encoded.is_empty() {
            params.push(("authorization_details".to_owned(), encoded));
        }
    }

    // The issuer_state from the offer's authorization_code grant.
    if let Some(issuer_state) = issuer_state_from_grant(spec.grants) {
        params.push(("issuer_state".to_owned(), issuer_state));
    }

    let params = AuthorizationRequestParams { params };
    if !params.names_a_credential() {
        return Err(AuthParamError::NothingNamesCredential);
    }

    Ok(params)
}

/// The RFC 8707 token-request decision: the `resource` parameter for the
/// token endpoint, `Some` only when the issuer is a different origin than
/// the Authorization Server. The same `same_origin` as the authorization
/// request, so the two always agree.
pub fn token_request_resource(as_issuer: &str, credential_issuer: &str) -> Option<String> {
    if same_origin(as_issuer, credential_issuer) {
        None
    } else {
        Some(credential_issuer.to_owned())
    }
}

/// Projects client-supplied authorization details down to the fields that
/// belong in an Authorization Request.
///
/// - `credential_identifiers` is response-only: the AS grants those in its
///   token response (§6); a wallet may not ask for them. Forwarding the
///   client's value would let flow_start put them in the request.
/// - `type` is not a client choice: it is fixed at `openid_credential`.
/// - An entry naming no configuration identifies nothing; forwarding it
///   would ask the AS for nothing while satisfying the guard.
pub fn project_authorization_details(details: &[Value]) -> Vec<Value> {
    details
        .iter()
        .filter(|detail| {
            detail
                .get("credential_configuration_id")
                .and_then(Value::as_str)
                .map(|id| !id.is_empty())
                .unwrap_or(false)
        })
        .map(|detail| {
            serde_json::json!({
                "type": AUTHORIZATION_DETAIL_TYPE,
                "credential_configuration_id": detail
                    .get("credential_configuration_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// The `issuer_state` from the offer's `authorization_code` grant, when
/// the offer carries one. The grant identifies the credential server-side
/// just as `scope` and `authorization_details` do.
pub fn issuer_state_from_grant(grants: &Value) -> Option<String> {
    grants
        .get("authorization_code")?
        .get("issuer_state")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The credential identifier the AS granted for `config_id`, when it
/// granted one (the Credential Request's `credential_identifier`
/// substitution, OID4VCI §6).
///
/// Matching is by `credential_configuration_id`, so a token response
/// covering several configurations picks the right one; an entry naming
/// no configuration is accepted only when it is the sole one, since then
/// there is nothing to confuse it with. One credential per request: the
/// first identifier is returned and the rest name further credentials
/// that each need their own request.
pub fn granted_credential_identifier(
    authorization_details: Option<&Value>,
    config_id: &str,
) -> Option<String> {
    let details = authorization_details?.as_array()?;
    if details.is_empty() {
        return None;
    }

    fn config_of(detail: &Value) -> &str {
        detail
            .get("credential_configuration_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
    fn first_identifier(detail: &Value) -> Option<String> {
        detail
            .get("credential_identifiers")?
            .as_array()?
            .iter()
            .find_map(Value::as_str)
            .map(str::to_owned)
    }

    // With no configuration to match on, only a sole unlabelled entry is
    // unambiguous — matching "" against the entries would pick whichever
    // unlabelled one came first: a guess dressed up as a match.
    if config_id.is_empty() {
        if let [only] = details.as_slice() {
            if config_of(only).is_empty() {
                return first_identifier(only);
            }
        }
        return None;
    }

    for detail in details {
        if config_of(detail) == config_id {
            if let Some(identifier) = first_identifier(detail) {
                return Some(identifier);
            }
        }
    }

    // An entry naming no configuration is accepted only when it is the
    // sole one.
    if let [only] = details.as_slice() {
        if config_of(only).is_empty() {
            return first_identifier(only);
        }
    }

    None
}

// ─── Origin comparison (RFC 8707 / RFC 6454) ──────────────────────────────

/// Whether two URL origins agree: scheme (case-insensitive), hostname
/// (case-insensitive), and the effective port (the explicit port, or the
/// scheme's default — `https://h` and `https://h:443` compare equal).
///
/// An unparseable URL never matches: the caller then sends the `resource`
/// parameter, which is the fail-safe direction (an AS that cannot accept
/// it says so, rather than issuing a token for the wrong audience).
pub fn same_origin(a: &str, b: &str) -> bool {
    match (parse_origin(a), parse_origin(b)) {
        (Some(a), Some(b)) => a.scheme == b.scheme && a.host == b.host && a.port == b.port,
        _ => false,
    }
}

/// A parsed origin: scheme, host, and the effective port.
struct Origin {
    scheme: String,
    host: String,
    port: String,
}

/// Parses an origin from an absolute URL, defaulting the port for the
/// http and https schemes. Handles bracketed IPv6 literals.
fn parse_origin(url: &str) -> Option<Origin> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();

    // The authority runs to the first path, query, or fragment.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

    // Strip the userinfo, when present (user:pass@host:port).
    let authority = authority.rsplit('@').next().unwrap_or_default();
    if authority.is_empty() {
        return None;
    }

    // Bracketed IPv6: [::1]:8443.
    let (host, port): (String, &str) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':').unwrap_or_default();
        (host.to_ascii_lowercase(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
                (host.to_ascii_lowercase(), port)
            }
            _ => (authority.to_ascii_lowercase(), ""),
        }
    };

    // The scheme's default port when none is explicit.
    let port: String = if port.is_empty() {
        match scheme.as_str() {
            "https" => "443",
            "http" => "80",
            _ => "",
        }
        .to_owned()
    } else {
        port.to_owned()
    };

    Some(Origin { scheme, host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─── same_origin ───────────────────────────────────────────────────

    #[test]
    fn same_origin_agrees_on_scheme_host_and_effective_port() {
        assert!(same_origin("https://as.example", "https://as.example"));
        assert!(same_origin(
            "https://as.example/v1",
            "https://as.example?x=1"
        ));
        // Different hosts are different origins — that is the
        // cross-origin case the resource indicator covers.
        assert!(!same_origin("https://as.example", "https://issuer.example"));
    }

    #[test]
    fn default_ports_compare_equal() {
        assert!(same_origin("https://as.example", "https://as.example:443"));
        assert!(same_origin("http://as.example", "http://as.example:80"));
    }

    #[test]
    fn different_origins_disagree() {
        assert!(!same_origin(
            "https://as.example",
            "https://issuer.example:8443"
        ));
        assert!(!same_origin("https://as.example", "http://as.example"));
        assert!(!same_origin(
            "https://as.example:8443",
            "https://as.example"
        ));
        assert!(!same_origin("https://as.example", "not-a-url"));
    }

    #[test]
    fn host_and_scheme_compare_case_insensitively() {
        assert!(same_origin("HTTPS://AS.example", "https://as.EXAMPLE"));
    }

    #[test]
    fn userinfo_does_not_change_the_origin() {
        assert!(same_origin(
            "https://user:pass@as.example",
            "https://as.example"
        ));
    }

    // ─── the parameter assembly ────────────────────────────────────────

    fn offer_grants() -> Value {
        json!({
            "authorization_code": { "issuer_state": "session-1" }
        })
    }

    /// The assembly spec with the fixed client identity and variable
    /// credential-naming inputs.
    fn spec<'a>(
        scope: Option<&'a str>,
        authorization_details: &'a [Value],
        grants: &'a Value,
        as_issuer: &'a str,
        credential_issuer: &'a str,
    ) -> AuthorizationRequestSpec<'a> {
        AuthorizationRequestSpec {
            client_id: "client-1",
            redirect_uri: "https://wallet.example/cb",
            state: "state-1",
            scope,
            authorization_details,
            grants,
            as_issuer,
            credential_issuer,
        }
    }

    #[test]
    fn the_resource_indicator_is_sent_cross_origin_only() {
        let params = build_authorization_request_params(&spec(
            Some("openid credential"),
            &[],
            &offer_grants(),
            "https://as.example",
            "https://issuer.example",
        ))
        .expect("build");
        assert_eq!(params.get("resource"), Some("https://issuer.example"));

        let same = build_authorization_request_params(&spec(
            Some("openid credential"),
            &[],
            &offer_grants(),
            "https://as.example",
            "https://as.example:443",
        ))
        .expect("build");
        assert_eq!(same.get("resource"), None);
    }

    #[test]
    fn the_token_request_agrees_with_the_authorization_request() {
        assert_eq!(
            token_request_resource("https://as.example", "https://issuer.example"),
            Some("https://issuer.example".to_owned())
        );
        assert_eq!(
            token_request_resource("https://as.example", "https://as.example:443"),
            None
        );
    }

    #[test]
    fn issuer_state_is_forwarded_from_the_offer_grant() {
        let params = build_authorization_request_params(&spec(
            None,
            &[],
            &offer_grants(),
            "https://as.example",
            "https://as.example",
        ))
        .expect("build");
        assert_eq!(params.get("issuer_state"), Some("session-1"));
    }

    #[test]
    fn nothing_naming_the_credential_refuses() {
        let err = build_authorization_request_params(&spec(
            None,
            &[],
            &json!({}),
            "https://as.example",
            "https://as.example",
        ));
        assert_eq!(err, Err(AuthParamError::NothingNamesCredential));
    }

    #[test]
    fn scope_authorization_details_and_issuer_state_each_satisfy_the_guard() {
        for (scope, details, grants) in [
            (Some("openid"), json!([]), json!({})),
            (
                None,
                json!([{ "credential_configuration_id": "X" }]),
                json!({}),
            ),
            (None, json!([]), offer_grants()),
        ] {
            let params = build_authorization_request_params(&spec(
                scope,
                details.as_array().unwrap_or(&Vec::new()),
                &grants,
                "https://as.example",
                "https://as.example",
            ));
            assert!(params.is_ok(), "the guard must accept each form alone");
        }
    }

    // ─── the authorization_details projection ─────────────────────────

    #[test]
    fn the_projection_drops_entries_naming_no_configuration() {
        let projected = project_authorization_details(&[
            json!({ "type": "openid_credential", "credential_identifiers": ["nope"] }),
            json!({ "type": "something", "credential_configuration_id": "Degree", "extra": true }),
        ]);
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0]["credential_configuration_id"], "Degree");
    }

    #[test]
    fn the_projection_never_forwards_credential_identifiers() {
        let projected = project_authorization_details(&[json!({
            "type": "openid_credential",
            "credential_configuration_id": "Degree",
            "credential_identifiers": ["granted-1", "granted-2"],
        })]);
        assert!(projected[0].get("credential_identifiers").is_none());
    }

    #[test]
    fn the_projection_fixes_the_type() {
        let projected = project_authorization_details(&[json!({
            "type": "not_a_client_choice",
            "credential_configuration_id": "Degree",
        })]);
        assert_eq!(projected[0]["type"], "openid_credential");
    }

    // ─── the credential identifier substitution ─────────────────────────

    #[test]
    fn the_granted_identifier_matches_by_configuration_id() {
        let details = json!([
            { "type": "openid_credential", "credential_configuration_id": "PID",
              "credential_identifiers": ["pid-1"] },
            { "type": "openid_credential", "credential_configuration_id": "Degree",
              "credential_identifiers": ["degree-1", "degree-2"] },
        ]);
        assert_eq!(
            granted_credential_identifier(Some(&details), "Degree"),
            Some("degree-1".to_owned())
        );
        // The first identifier only: the rest need their own requests.
    }

    #[test]
    fn a_sole_unlabelled_entry_is_accepted() {
        let details = json!([
            { "credential_identifiers": ["granted-1"] }
        ]);
        assert_eq!(
            granted_credential_identifier(Some(&details), "Degree"),
            Some("granted-1".to_owned())
        );
        assert_eq!(
            granted_credential_identifier(Some(&details), ""),
            Some("granted-1".to_owned())
        );
    }

    #[test]
    fn multiple_unlabelled_entries_are_ambiguous_and_refused() {
        let details = json!([
            { "credential_identifiers": ["a"] },
            { "credential_identifiers": ["b"] }
        ]);
        assert_eq!(
            granted_credential_identifier(Some(&details), "Degree"),
            None
        );
        assert_eq!(granted_credential_identifier(Some(&details), ""), None);
    }

    #[test]
    fn no_granted_identifiers_means_no_substitution() {
        assert_eq!(granted_credential_identifier(None, "Degree"), None);
        assert_eq!(
            granted_credential_identifier(Some(&json!([])), "Degree"),
            None
        );
        // A matching entry that granted no identifiers.
        assert_eq!(
            granted_credential_identifier(
                Some(&json!([{ "credential_configuration_id": "Degree" }])),
                "Degree"
            ),
            None
        );
    }
}
