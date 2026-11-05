//! DCQL handling: the vp_token assembly for multi-credential answers, the
//! requested-credential-type listing (so a "nothing matched" error can name
//! what was missing), the valid-JSON check on the raw query, and the
//! response endpoint sanitization — the engine-side slice of the DCQL
//! matching (the host UI does the local credential matching; the engine
//! assembles what it answers with).

use engine_ports::VpSelection;
use serde_json::Value;

/// Why the DCQL assembly refused.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DcqlError {
    /// The raw `dcql_query` is not valid JSON.
    #[error("oid4vp: invalid dcql_query: not valid JSON")]
    InvalidJson,
    /// The vp_token's token count does not match the selection count.
    #[error("oid4vp: DCQL vp_token has {tokens} tokens but {selected} credentials selected")]
    TokenCount {
        /// The tokens the host signed.
        tokens: usize,
        /// The credentials the user selected.
        selected: usize,
    },
    /// The response endpoint is not an http(s) URL.
    #[error("oid4vp: invalid response endpoint URL: {0}")]
    InvalidEndpoint(String),
}

/// Checks a raw `dcql_query` (as received, before any parsing): it must be
/// valid JSON when present.
pub fn validate_raw_query(raw: &str) -> Result<(), DcqlError> {
    if raw.is_empty() {
        return Ok(());
    }
    if serde_json::from_str::<Value>(raw).is_err() {
        return Err(DcqlError::InvalidJson);
    }
    Ok(())
}

/// The required DCQL queries with no selection: a required query the
/// wallet cannot satisfy makes the whole presentation an `access_denied`
/// response (OID4VP 1.0 §6.2, §6.4.2) — never a partial vp_token.
///
/// The required set (§6.2):
/// - A query NOT referenced by any credential_set is required unless it
///   says `"required": false`.
/// - A credential_set (required unless `"required": false`) is
///   satisfied when ANY of its options has all its queries answered —
///   an option names the queries of one combination. The option
///   queries themselves are not independently required.
pub fn unsatisfied_required_queries(
    dcql_query: Option<&Value>,
    selections: &[VpSelection],
) -> Vec<String> {
    let Some(query) = dcql_query else {
        return Vec::new();
    };
    let Some(queries) = query.get("credentials").and_then(Value::as_array) else {
        return Vec::new();
    };
    let answered = |id: &str| selections.iter().any(|s| s.credential_query_id == id);

    // The option ids: an option is an array of query ids (the
    // combination's queries), a bare id, or an object naming one.
    let option_ids = |option: &Value| -> Vec<String> {
        match option {
            Value::Array(ids) => ids
                .iter()
                .filter_map(|id| match id {
                    Value::String(name) => Some(name.clone()),
                    Value::Object(object) => object
                        .get("credential_query_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    _ => None,
                })
                .collect(),
            Value::String(id) => vec![id.clone()],
            Value::Object(object) => object
                .get("credential_query_id")
                .and_then(Value::as_str)
                .map(|id| vec![id.to_owned()])
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    };

    let sets = query.get("credential_sets").and_then(Value::as_array);
    let referenced: Vec<String> = sets
        .into_iter()
        .flatten()
        .filter_map(|set| set.get("options"))
        .filter_map(Value::as_array)
        .flatten()
        .flat_map(option_ids)
        .collect();

    let mut unsatisfied: Vec<String> = queries
        .iter()
        .filter(|q| {
            let id = q.get("id").and_then(Value::as_str).unwrap_or_default();
            let required = q.get("required").and_then(Value::as_bool).unwrap_or(true);
            required && !id.is_empty() && !referenced.iter().any(|r| r == id) && !answered(id)
        })
        .filter_map(|q| q.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();

    // The required credential_sets: at least one fully-answered option.
    for set in sets.into_iter().flatten() {
        let required = set.get("required").and_then(Value::as_bool).unwrap_or(true);
        if !required {
            continue;
        }
        let options_answered =
            set.get("options")
                .and_then(Value::as_array)
                .is_some_and(|options| {
                    options
                        .iter()
                        .any(|option| option_ids(option).iter().all(|id| answered(id)))
                });
        if !options_answered {
            unsatisfied.push("credential_set".to_owned());
        }
    }

    unsatisfied
}

/// Assembles the DCQL `vp_token`: a JSON object keyed by the DCQL
/// credential query id, each mapping to the signed token(s) for that
/// query.
///
/// The P0.6-verified behaviour (`buildDCQLVPToken`):
/// - A host that already returned a JSON object passes through as is.
/// - Otherwise the vp_token is newline-separated tokens, exactly one per
///   selected credential; the count must match or the assembly refuses.
/// - A selection with no `credential_query_id` is dropped from the
///   object (it answers no query).
pub fn build_dcql_vp_token(vp_token: &str, selected: &[VpSelection]) -> Result<String, DcqlError> {
    // A host that already returned a JSON object: pass it through.
    let trimmed = vp_token.trim();
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            if value.is_object() {
                return Ok(trimmed.to_owned());
            }
        }
    }

    let tokens: Vec<&str> = vp_token.split('\n').collect();
    if tokens.len() != selected.len() {
        return Err(DcqlError::TokenCount {
            tokens: tokens.len(),
            selected: selected.len(),
        });
    }

    let mut vp_object = serde_json::Map::new();
    for (token, selection) in tokens.iter().zip(selected) {
        if selection.credential_query_id.is_empty() {
            continue;
        }
        let entry = vp_object
            .entry(selection.credential_query_id.clone())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(array) = entry.as_array_mut() {
            array.push(Value::String((*token).to_owned()));
        }
    }

    serde_json::to_string(&Value::Object(vp_object)).map_err(|_| DcqlError::InvalidJson)
}

/// Lists the credential types a DCQL query asks for, so a "nothing
/// matched" error can name what was missing rather than say nothing.
///
/// Best-effort, exactly as the Go engine: an unparseable or exotic query
/// yields no names rather than an error. The vct_values, the doctype
/// (either form), and — for a query naming none of those — the query id
/// itself.
pub fn requested_credential_types(dcql_query: Option<&Value>) -> Vec<String> {
    let Some(query) = dcql_query else {
        return Vec::new();
    };
    let Some(credentials) = query.get("credentials").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut types: Vec<String> = Vec::new();
    let mut seen = rustc_hash::FxHashSet::default();
    let add = |value: &str, types: &mut Vec<String>, seen: &mut rustc_hash::FxHashSet<String>| {
        if value.is_empty() || !seen.insert(value.to_owned()) {
            return;
        }
        types.push(value.to_owned());
    };

    for credential in credentials {
        let meta = credential.get("meta");
        let id = credential
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut named_something = false;

        if let Some(vct_values) = meta
            .and_then(|m| m.get("vct_values"))
            .and_then(Value::as_array)
        {
            for vct in vct_values {
                if let Some(value) = vct.as_str() {
                    named_something = true;
                    add(value, &mut types, &mut seen);
                }
            }
        }
        if let Some(doctype) = meta.and_then(|m| {
            m.get("doctype_value")
                .and_then(Value::as_str)
                .or_else(|| m.get("doctype_values").and_then(Value::as_str))
        }) {
            named_something = true;
            add(doctype, &mut types, &mut seen);
        }
        if let Some(doctype_values) = meta
            .and_then(|m| m.get("doctype_values"))
            .and_then(Value::as_array)
        {
            for doctype in doctype_values {
                if let Some(value) = doctype.as_str() {
                    named_something = true;
                    add(value, &mut types, &mut seen);
                }
            }
        }
        if !named_something {
            add(id, &mut types, &mut seen);
        }
    }

    types
}

/// Sanitizes a response endpoint URL: https or http only, rebuilt from its
/// parsed components so no unvalidated fragment of the request's string
/// reaches the fetch (the SSRF guard the Go engine runs on every response
/// endpoint).
pub fn sanitize_endpoint_url(endpoint: &str) -> Result<String, DcqlError> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| DcqlError::InvalidEndpoint("no scheme".to_owned()))?;
    if scheme != "https" && scheme != "http" {
        return Err(DcqlError::InvalidEndpoint(format!("scheme {scheme:?}")));
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(DcqlError::InvalidEndpoint("no host".to_owned()));
    }

    // Rebuild from the validated components: scheme, host, path, query.
    let after_authority = &rest[authority.len()..];
    let (path, query) = match after_authority.split_once('?') {
        Some((path, query)) => (path, Some(query.split('#').next().unwrap_or(query))),
        None => (after_authority.split('#').next().unwrap_or_default(), None),
    };

    let mut clean = format!("{scheme}://{authority}{path}");
    if let Some(query) = query {
        clean.push('?');
        clean.push_str(query);
    }
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn selection(query_id: &str) -> VpSelection {
        VpSelection {
            credential_query_id: query_id.to_owned(),
            credential_id: format!("cred-{query_id}"),
            disclosed_claims: Vec::new(),
        }
    }

    #[test]
    fn the_raw_query_must_be_valid_json() {
        assert!(validate_raw_query("").is_ok());
        assert!(validate_raw_query("{\"credentials\":[]}").is_ok());
        assert_eq!(validate_raw_query("not json"), Err(DcqlError::InvalidJson));
    }

    #[test]
    fn one_token_per_selection_builds_the_object() {
        let vp = build_dcql_vp_token("token-a\ntoken-b", &[selection("pid"), selection("degree")])
            .expect("build");
        let value: Value = serde_json::from_str(&vp).expect("json");
        assert_eq!(value["pid"], json!(["token-a"]));
        assert_eq!(value["degree"], json!(["token-b"]));
    }

    #[test]
    fn a_count_mismatch_refuses() {
        let err = build_dcql_vp_token("token-a", &[selection("pid"), selection("degree")]);
        assert_eq!(
            err,
            Err(DcqlError::TokenCount {
                tokens: 1,
                selected: 2
            })
        );
    }

    #[test]
    fn a_host_object_passes_through() {
        let object = "{\"pid\":[\"token-a\"]}";
        let vp = build_dcql_vp_token(object, &[selection("pid")]).expect("build");
        assert_eq!(vp, object);
    }

    #[test]
    fn two_tokens_for_one_query_collect() {
        let vp = build_dcql_vp_token("token-a\ntoken-b", &[selection("pid"), selection("pid")])
            .expect("build");
        let value: Value = serde_json::from_str(&vp).expect("json");
        assert_eq!(value["pid"], json!(["token-a", "token-b"]));
    }

    #[test]
    fn a_selection_answering_no_query_is_dropped() {
        let vp = build_dcql_vp_token(
            "token-a\ntoken-b",
            &[selection("pid"), VpSelection::default()],
        )
        .expect("build");
        let value: Value = serde_json::from_str(&vp).expect("json");
        assert_eq!(value.as_object().map(|o| o.len()), Some(1));
    }

    #[test]
    fn the_requested_types_name_the_queries() {
        let query = json!({
            "credentials": [
                { "id": "q1", "meta": { "vct_values": ["urn:degree"] } },
                { "id": "q2", "meta": { "doctype_value": "org.iso.pid" } },
                { "id": "q3", "meta": {} }
            ]
        });
        let types = requested_credential_types(Some(&query));
        assert_eq!(types, vec!["urn:degree", "org.iso.pid", "q3"]);
    }

    #[test]
    fn the_requested_types_are_best_effort() {
        assert!(requested_credential_types(None).is_empty());
        // An exotic query yields no names, not an error.
        assert!(requested_credential_types(Some(&json!("anything"))).is_empty());
    }

    #[test]
    fn endpoints_are_sanitized_and_rebuilt() {
        assert_eq!(
            sanitize_endpoint_url("https://verifier.example/response?x=1#frag").expect("clean"),
            "https://verifier.example/response?x=1"
        );
        assert_eq!(
            sanitize_endpoint_url("http://verifier.example/r").expect("clean"),
            "http://verifier.example/r"
        );
    }

    #[test]
    fn non_http_schemes_and_hostless_urls_refuse() {
        assert_eq!(
            sanitize_endpoint_url("file:///etc/passwd"),
            Err(DcqlError::InvalidEndpoint("scheme \"file\"".to_owned()))
        );
        assert_eq!(
            sanitize_endpoint_url("https:///no-host"),
            Err(DcqlError::InvalidEndpoint("no host".to_owned()))
        );
        assert_eq!(
            sanitize_endpoint_url("not-a-url"),
            Err(DcqlError::InvalidEndpoint("no scheme".to_owned()))
        );
    }
}
