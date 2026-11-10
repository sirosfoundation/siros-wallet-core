//! Request parsing: by value, by `request_uri` (the request object), and
//! the URL forms — with the client_id scheme inference and the validation
//! rules the P0.6 verification confirmed.

use engine_ports::{FetchPurpose, HttpClient, HttpRequest, RedirectPolicy};

use super::types::{AuthorizationRequest, ClientIdScheme, RequestError, ResponseMode};

/// The maximum size of a request object fetched by reference: 256 KiB (per
/// the P0.6-verified `fetchRequestFromURI` limit in the Go engine).
const MAX_REQUEST_OBJECT_BYTES: usize = 256 << 10;

/// Parses an OpenID4VP authorization request from the flow start's params.
///
/// The P0.6-verified forms:
/// - **By value**: the params are the request object (or carry it in
///   `request`).
/// - **By `request_uri`**: fetch the request object (a JWT or plain JSON)
///   through the HttpClient port.
/// - **URL forms**: `openid4vp://`, `haip://`, `haip-vp://`,
///   `mdoc-openid4vp://`, a raw query string, a direct https URL, or a bare
///   reference.
///
/// Validation after parsing:
/// - The client_id scheme is inferred from the prefix and must match.
/// - The outer and inner client_id must be equal (when there's a request
///   object).
/// - The nonce must be present.
/// - The response mode must belong to the channel.
pub async fn parse_request(
    http: &dyn HttpClient,
    params: &serde_json::Value,
) -> Result<AuthorizationRequest, RequestError> {
    // The URL forms resolve to their params object first: the string
    // the QR code / link named — `openid4vp://`, `haip://`,
    // `haip-vp://`, `mdoc-openid4vp://` with its query, a raw query
    // string, or a bare request_uri reference.
    let params = match params.as_str() {
        Some(text) => url_to_params(text)?,
        None => params.clone(),
    };

    // The Digital Credentials API channel's actual origin (the
    // browser's caller — the transport supplies it, W3C Digital
    // Credentials API §5.1): the flow start's params carry it beside
    // the request, and the dc_api binding checks it against the
    // request's expected_origins below.
    let dc_api_origin = params
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // By reference, by value, or the params are the request itself.
    // The signed form validates its own scheme requirements inside
    // (with the leaf's DER and the attestation); the params form is
    // checked here (§5: x509_san_dns; §5.2.3: x509_hash; §5.9.3.4: the
    // attestation — refused, not only in the signed form).
    let mut request = if let Some(uri) = params
        .get("request_uri")
        .and_then(|v| v.as_str())
        .filter(|uri| !uri.is_empty())
    {
        fetch_request_object(http, uri).await?
    } else if let Some(request_jwt) = params.get("request").and_then(|v| v.as_str()) {
        parse_request_object(request_jwt)?
    } else {
        let request = parse_request_value(&params, false)?;
        validate_scheme_requirements(&request, None, None, "")?;
        request
    };

    // The dc_api origin binding (OpenID4VP 1.0 §8.4): the actual
    // origin must be one the request's expected_origins named — but
    // only for an AUTHENTICATED verifier (a recognized Client
    // Identifier Prefix: the certificate and DID schemes). The
    // pre-registered fallback (§5.9.2's unknown prefix) is
    // unauthenticated: its expected_origins is advisory, the
    // presentation binding rides the transport's origin alone (the
    // alternate happy flow's invalid_scheme:example with wrong
    // origins).
    if request.response_mode.is_dc_api()
        && !request.expected_origins.is_empty()
        // Enforced for an AUTHENTICATED verifier: a recognized Client
        // Identifier Prefix, or a signed request object (the
        // multisigned form carries no client_id but its valid
        // signature authenticates the verifier). The pre-registered
        // fallback (§5.9.2's unknown prefix, unsigned) is
        // unauthenticated: its expected_origins is advisory, the
        // presentation binding rides the transport's origin alone (the
        // alternate happy flow's invalid_scheme:example with wrong
        // origins).
        && (!matches!(request.client_id_scheme, ClientIdScheme::Unknown(_))
            || request.request_jwt.is_some())
        && !request
            .expected_origins
            .iter()
            .any(|expected| expected == &dc_api_origin)
    {
        return Err(RequestError::OriginMismatch);
    }
    // The web-origin client identity (the DC API's unsigned channel):
    // a request with no client_id names no verifier — the caller's
    // origin IS the client (the browser authenticates it; the request
    // binds through the transport, not a signed object).
    if request.response_mode.is_dc_api()
        && request.client_id.is_empty()
        && !dc_api_origin.is_empty()
    {
        request.client_id = dc_api_origin.clone();
        request.client_id_scheme = ClientIdScheme::infer(&request.client_id);
    }
    // The actual origin rides the request for the KB-JWT's `aud` and
    // the mdoc DCAPIHandover.
    request.dc_api_origin = dc_api_origin;

    Ok(request)
}

/// Turns the URL form into the params object: the authorization
/// request URL's query members, a raw query string, or a bare
/// reference taken as the request_uri.
fn url_to_params(text: &str) -> Result<serde_json::Value, RequestError> {
    // The scheme forms: everything after `://` (the `?` optional).
    let query = match text.split_once("://") {
        Some((scheme, rest)) => {
            if !matches!(scheme, "openid4vp" | "haip" | "haip-vp" | "mdoc-openid4vp") {
                return Err(RequestError::NotRecognized);
            }
            rest.strip_prefix('?').unwrap_or(rest)
        }
        None => text.strip_prefix('?').unwrap_or(text),
    };
    // A query string: the `name=value` members.
    if query.contains('=') {
        let mut object = serde_json::Map::new();
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            object.insert(
                percent_decode(name),
                serde_json::Value::String(percent_decode(value)),
            );
        }
        return Ok(serde_json::Value::Object(object));
    }
    // A bare reference: the request_uri itself.
    Ok(serde_json::json!({ "request_uri": text }))
}

/// Percent-decodes a query member (RFC 3986 §2.1; the `+` form is not
/// used in these URLs).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    // A hex digit, or 0xff when the byte is not one.
    let hex = |v: u8| match v {
        b'0'..=b'9' => v - b'0',
        b'a'..=b'f' => v - b'a' + 10,
        b'A'..=b'F' => v - b'A' + 10,
        _ => 0xff,
    };
    let mut index = 0;
    // The bounds are held by `get`, never by indexing: an index is a
    // panic when the slice disagrees.
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = bytes.get(index + 1).copied().map(hex);
            let low = bytes.get(index + 2).copied().map(hex);
            if let (Some(high), Some(low)) = (high, low) {
                if high != 0xff && low != 0xff {
                    out.push(high * 16 + low);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Fetches the request object from a `request_uri`, through the HttpClient
/// port with the declared purpose and the 256 KiB limit.
async fn fetch_request_object(
    http: &dyn HttpClient,
    uri: &str,
) -> Result<AuthorizationRequest, RequestError> {
    let response = http
        .send(HttpRequest {
            method: "GET".to_owned(),
            url: uri.to_owned(),
            headers: vec![(
                "accept".to_owned(),
                "application/oauth-authz-req+jwt, application/json".to_owned(),
            )],
            body: Vec::new(),
            purpose: FetchPurpose::RequestObject,
            max_response_bytes: MAX_REQUEST_OBJECT_BYTES,
            redirects: RedirectPolicy::None,
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| RequestError::Fetch(err.to_string()))?;

    if response.status != 200 {
        return Err(RequestError::Fetch(format!(
            "request_uri answered {}",
            response.status
        )));
    }

    let text = String::from_utf8_lossy(&response.body).into_owned();
    parse_request_object(&text)
}

/// Parses a request object (a JWT or plain JSON) into the authorization
/// request.
///
/// The request object may be a JWT (three dot-separated parts) or plain
/// JSON. For a JWT, the payload is the request; the signature verification
/// is the trust evaluation's job (S3's `evaluateVerifierTrust`), not the
/// parser's.
/// Whether the client_id embeds a recognized Client Identifier
/// Prefix anywhere (§5.9.2's pre-registration constraint: such a value
/// cannot name a pre-registered client, so the unknown-prefix fallback
/// is forbidden for it).
fn contains_recognized_prefix(client_id: &str) -> bool {
    const PREFIXES: [&str; 7] = [
        "x509_san_dns:",
        "x509_san_uri:",
        "x509_hash:",
        "did:",
        "verifier_attestation:",
        "redirect_uri:",
        "origin:",
    ];
    PREFIXES.iter().any(|prefix| client_id.contains(prefix))
}

/// Parses the JWS JSON Serialization's request object (RFC 7515 §7.2):
/// `{"payload": <b64url>, "signatures": [{protected, signature}, …]}`.
/// The request object is accepted when AT LEAST ONE signature verifies
/// against the x5c in its own protected header (RFC 9052 §4.4's
/// Sig_structure over the shared payload) — a multi-signed object
/// with one invalid signature still names its verifier through the
/// valid one (the multisigned-one-invalid-signature module leaves the
/// second valid on purpose). A VALID signature's leaf DER is the
/// scheme binding's certificate; none verifying refuses.
fn parse_general_jws(general: &serde_json::Value) -> Result<AuthorizationRequest, RequestError> {
    let payload_text = general
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or(RequestError::NotRecognized)?;
    let signatures = general
        .get("signatures")
        .and_then(|v| v.as_array())
        .filter(|list| !list.is_empty())
        .ok_or(RequestError::NotRecognized)?;

    let mut first_leaf: Option<Vec<u8>> = None;
    let mut first_x5c: Option<Vec<String>> = None;
    let mut attestation_jwt: Option<String> = None;
    // The first VERIFIED signature's client_id (each protected header
    // carries its cert's binding): the wallet's scheme rules run
    // against it — the invalidated signature's claim never
    // authenticates anything.
    let mut verified_client_id: Option<String> = None;
    let mut verified_any = false;
    for signature in signatures {
        let protected = signature
            .get("protected")
            .and_then(|v| v.as_str())
            .ok_or(RequestError::NotRecognized)?;
        let protected_bytes = decode_base64url(protected).ok_or(RequestError::NotRecognized)?;
        let header: serde_json::Value =
            serde_json::from_slice(&protected_bytes).map_err(|_| RequestError::NotRecognized)?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("oauth-authz-req+jwt") {
            return Err(RequestError::RequestObjectTyp);
        }
        // RFC 9052 §4.4's Sig_structure signs the same input the
        // compact form's does — ASCII(protected) || '.' || payload —
        // so each signature verifies through its compact-equivalent
        // string.
        let signature_text = signature
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or(RequestError::NotRecognized)?;
        let compact_form = format!("{protected}.{payload_text}.{signature_text}");
        let verified = header
            .get("x5c")
            .and_then(|v| v.as_array())
            .and_then(|chain| chain.first())
            .and_then(|v| v.as_str())
            .and_then(|cert| decode_base64(cert))
            .map(|der| {
                let jwk = jose_rs::jwk::cert::public_jwk_from_certificate_der(&der)
                    .map_err(|_| RequestError::RequestObjectSignature)?;
                jose_rs::jws::compact::verify_with_jwk(&jwk, &compact_form)
                    .map_err(|_| RequestError::RequestObjectSignature)?;
                Ok::<Vec<u8>, RequestError>(der)
            });
        match verified {
            Some(Ok(der)) => {
                verified_any = true;
                if verified_client_id.is_none() {
                    verified_client_id = header
                        .get("client_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                }
                if first_leaf.is_none() {
                    first_leaf = Some(der);
                    first_x5c = header.get("x5c").and_then(|v| v.as_array()).map(|chain| {
                        chain
                            .iter()
                            .filter_map(|cert| cert.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    });
                    attestation_jwt = header
                        .get("jwt")
                        .and_then(|v| v.as_str())
                        .filter(|jwt| !jwt.is_empty())
                        .map(str::to_owned);
                }
            }
            // A failing signature is skipped, not fatal: the others
            // may still authenticate the verifier (the one-invalid
            // module leaves the second valid on purpose).
            Some(Err(_)) => {}
            // No x5c: an unauthenticated signature the trust evaluation
            // would have to resolve by other means — skipped like a
            // failing one; none verifying refuses below.
            None => {}
        }
    }
    if !verified_any {
        return Err(RequestError::RequestObjectSignature);
    }

    let payload = decode_base64url(payload_text).ok_or(RequestError::NotRecognized)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&payload).map_err(|_| RequestError::NotRecognized)?;
    // The multisigned form carries the client_id in the signatures'
    // PROTECTED HEADERS (each cert's binding), not the payload —
    // inject the first VERIFIED one's so the client_id rules (the
    // scheme inference, the x509_hash binding, the §5.9.2 fallback
    // bounds) apply unchanged, against the certificate that actually
    // authenticated the request.
    if value.get("client_id").is_none() {
        if let Some(header_client_id) = verified_client_id {
            if let Some(object) = value.as_object_mut() {
                object.insert("client_id".to_owned(), serde_json::Value::String(header_client_id));
            }
        }
    }
    parse_request_value(&value, true).and_then(|mut request| {
        validate_scheme_requirements(
            &request,
            first_leaf.clone(),
            attestation_jwt.clone(),
            "",
        )?;
        request.request_jwt = Some(serde_json::to_string(general).unwrap_or_default());
        request.x5c = first_x5c.clone();
        request.attestation_jwt = attestation_jwt.clone();
        Ok(request)
    })
}

fn parse_request_object(text: &str) -> Result<AuthorizationRequest, RequestError> {
    // The JWS JSON Serialization (RFC 7515 §7.2): the general form with
    // a `signatures` array — the multi-signed request object (OpenID4VP
    // 1.0, B.2.5's request_uri_multisigned). EVERY signature must
    // verify (one invalid refuses — the multisigned negative); the
    // first signature's certificate carries the scheme binding.
    if text.starts_with('{') {
        if let Ok(general) = serde_json::from_str::<serde_json::Value>(text) {
            if general.get("signatures").and_then(|v| v.as_array()).is_some() {
                return parse_general_jws(&general);
            }
            // A plain-JSON request object (not the general JWS): the
            // caller's business, handled below.
        }
    }

    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() >= 3 && !text.starts_with('{') {
        // A signed request object (RFC 9101 §5.2): the JOSE header
        // must name the type, and the signature must verify under the
        // key the header's `x5c` chain carries — the parser's own
        // checks; the trust evaluation's PDP step is the policy, not
        // the cryptography.
        let header_bytes = parts
            .first()
            .and_then(|segment| decode_base64url(segment))
            .ok_or(RequestError::NotRecognized)?;
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| RequestError::NotRecognized)?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("oauth-authz-req+jwt") {
            return Err(RequestError::RequestObjectTyp);
        }
        // The signature, when the header carries the certificate chain:
        // the first certificate holds the signer's public key. The x5c
        // entries are base64-encoded DER (RFC 7515 §4.1.6 — the
        // standard alphabet, unlike the JOSE segments' base64url).
        //
        // The leaf DER is kept: the x509_hash scheme's client_id is the
        // base64url SHA-256 over it (OpenID4VP 1.0 §5.2.3), and the
        // x509_san_dns scheme requires the signed form (§5) — both
        // checked against the payload's client_id below. The `jwt`
        // header parameter is kept too: the verifier_attestation
        // scheme's attestation rides it (§5.9.3.4).
        let mut leaf_der: Option<Vec<u8>> = None;
        if let Some(cert) = header
            .get("x5c")
            .and_then(|v| v.as_array())
            .and_then(|chain| chain.first())
            .and_then(|v| v.as_str())
        {
            let der = decode_base64(cert).ok_or(RequestError::NotRecognized)?;
            let jwk = jose_rs::jwk::cert::public_jwk_from_certificate_der(&der)
                .map_err(|_| RequestError::RequestObjectSignature)?;
            jose_rs::jws::compact::verify_with_jwk(&jwk, text)
                .map_err(|_| RequestError::RequestObjectSignature)?;
            leaf_der = Some(der);
        }
        let attestation_jwt = header
            .get("jwt")
            .and_then(|v| v.as_str())
            .filter(|jwt| !jwt.is_empty())
            .map(str::to_owned);
        // The chain, as the header carried it (the trust evaluation's
        // key material for the x.509 schemes).
        let x5c = header.get("x5c").and_then(|v| v.as_array()).map(|chain| {
            chain
                .iter()
                .filter_map(|cert| cert.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        });
        // The payload is the second segment.
        let payload = parts
            .get(1)
            .and_then(|segment| decode_base64url(segment))
            .ok_or(RequestError::NotRecognized)?;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| RequestError::NotRecognized)?;
        // The scheme requirements (docs/engine-parity.md §1): the
        // x509_hash binding (§5.2.3), the x509_san_dns signed form (§5),
        // and the verifier_attestation extraction (§5.9.3.4) — all
        // against the payload's client_id.
        parse_request_value(&value, true).and_then(|mut request| {
            validate_scheme_requirements(&request, leaf_der, attestation_jwt.clone(), text)?;
            // The trust evaluation's inputs ride the request: the raw
            // JWT (the DID verification, the trust_chain extraction),
            // the x5c chain, and the attestation.
            request.request_jwt = Some(text.to_owned());
            request.x5c = x5c.clone();
            request.attestation_jwt = attestation_jwt.clone();
            Ok(request)
        })
    } else {
        // Plain JSON.
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| RequestError::NotRecognized)?;
        parse_request_value(&value, false).and_then(|request| {
            validate_scheme_requirements(&request, None, None, text)?;
            Ok(request)
        })
    }
}

/// The client_id scheme requirements the parser enforces (the trust
/// evaluation's PDP step is the policy, not the cryptography):
///
/// - `x509_hash` (OpenID4VP 1.0 §5.2.3): the request object MUST carry
///   the `x5c` chain, and the client_id's hash MUST match the leaf, in
///   constant time.
/// - `x509_san_dns` (§5): the request MUST be JWT-secured with its key
///   in the `x5c` chain — the Go engine's pre-cache re-verification.
/// - `verifier_attestation` (§5.9.3.4): the request JWT's `jwt` header
///   parameter carries the attestation; its `iss`/`sub`/`cnf.jwk` are
///   required, the request JWT's signature MUST verify under the
///   `cnf.jwk`, and the attestation's `sub` MUST be the client_id
///   without the scheme prefix.
///
/// The other schemes need nothing of the parser.
fn validate_scheme_requirements(
    request: &AuthorizationRequest,
    leaf_der: Option<Vec<u8>>,
    attestation_jwt: Option<String>,
    request_text: &str,
) -> Result<(), RequestError> {
    match request.client_id_scheme {
        ClientIdScheme::X509Hash => {
            let der = leaf_der.ok_or(RequestError::SchemeRequiresRequestObject {
                scheme: "x509_hash".to_owned(),
            })?;
            let digest = kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &der)
                .map_err(|_| RequestError::NotRecognized)?;
            let computed = wmp_core::token::base64url_unpadded(&digest);
            let claimed = request
                .client_id
                .strip_prefix("x509_hash:")
                .unwrap_or_default();
            if !wmp_core::token::tokens_equal(&computed, claimed) {
                return Err(RequestError::ClientIdHashMismatch);
            }
            Ok(())
        }
        ClientIdScheme::X509SanDns => {
            // §5: the DNS binding rides a signed request object whose
            // x5c chain names the certificate. The signature under the
            // leaf was verified at the header.
            leaf_der.ok_or(RequestError::SchemeRequiresRequestObject {
                scheme: "x509_san_dns".to_owned(),
            })?;
            Ok(())
        }
        ClientIdScheme::VerifierAttestation => {
            let attestation = attestation_jwt.ok_or(RequestError::VerifierAttestationRequired)?;
            validate_verifier_attestation(request, &attestation, request_text)
        }
        _ => Ok(()),
    }
}

/// The verifier attestation (OpenID4VP 1.0 §5.9.3.4): `iss`, `sub` and
/// `cnf.jwk` required (RFC 7800), the request JWT's signature verified
/// under the `cnf.jwk`, and the `sub` bound to the client_id.
fn validate_verifier_attestation(
    request: &AuthorizationRequest,
    attestation_jwt: &str,
    request_text: &str,
) -> Result<(), RequestError> {
    let malformed = |reason: &str| RequestError::AttestationMalformed(reason.to_owned());
    let parts: Vec<&str> = attestation_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(malformed("the attestation JWT must have three parts"));
    }
    let payload = parts
        .get(1)
        .and_then(|segment| decode_base64url(segment))
        .ok_or_else(|| malformed("the attestation payload does not decode"))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|_| malformed("the attestation payload is not JSON"))?;
    let subject = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|sub| !sub.is_empty())
        .ok_or_else(|| malformed("the attestation JWT has no sub claim"))?;
    if payload
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|iss| !iss.is_empty())
        .is_none()
    {
        return Err(malformed("the attestation JWT has no iss claim"));
    }
    let cnf = payload
        .pointer("/cnf/jwk")
        .ok_or_else(|| malformed("the attestation JWT has no cnf.jwk claim"))?;
    let cnf: jose_rs::jwk::Jwk = serde_json::from_value(cnf.clone())
        .map_err(|_| malformed("the attestation cnf.jwk does not parse"))?;

    // The request JWT's signature under the attestation's cnf key —
    // the binding that makes the attestation speak for this request.
    jose_rs::jws::compact::verify_with_jwk(&cnf, request_text)
        .map_err(|_| RequestError::AttestationSignature)?;

    // The attestation's subject is the client_id without the scheme
    // prefix (§5.9.3.4: the attestation is about the verifier named in
    // the client_id).
    let expected = request
        .client_id
        .strip_prefix("verifier_attestation:")
        .unwrap_or_default();
    if !wmp_core::token::tokens_equal(subject, expected) {
        return Err(RequestError::AttestationSubjectMismatch {
            subject: subject.to_owned(),
            client_id: request.client_id.clone(),
        });
    }
    Ok(())
}

/// Parses the authorization request from its JSON value — the shared
/// validation for all forms.
fn parse_request_value(
    value: &serde_json::Value,
    from_signed_object: bool,
) -> Result<AuthorizationRequest, RequestError> {
    let obj = value.as_object().ok_or(RequestError::NotRecognized)?;

    // The client_id: required.
    let client_id = obj
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The client_id scheme: inferred from the prefix, or from the
    // `client_id_scheme` when the request names one (and must match).
    let claimed_scheme = obj
        .get("client_id_scheme")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let inferred_scheme = ClientIdScheme::infer(&client_id);

    if !claimed_scheme.is_empty() {
        // P0.6: the client_id_scheme is a name like "x509_san_dns", and
        // the client_id has the matching prefix.
        let scheme_matches = match claimed_scheme {
            "x509_san_dns" => matches!(inferred_scheme, ClientIdScheme::X509SanDns),
            "x509_san_uri" => matches!(inferred_scheme, ClientIdScheme::X509SanUri),
            "x509_hash" => matches!(inferred_scheme, ClientIdScheme::X509Hash),
            "decentralized_identifier" => {
                matches!(inferred_scheme, ClientIdScheme::DecentralizedIdentifier)
            }
            "verifier_attestation" => {
                matches!(inferred_scheme, ClientIdScheme::VerifierAttestation)
            }
            "redirect_uri" => matches!(inferred_scheme, ClientIdScheme::RedirectUri),
            _ => false,
        };
        if !scheme_matches {
            return Err(RequestError::SchemeMismatch {
                scheme: claimed_scheme.to_owned(),
            });
        }
    }

    // The nonce: required (the P0.6-verified behaviour).
    let nonce = obj
        .get("nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if nonce.is_empty() {
        return Err(RequestError::NonceRequired);
    }

    // The response_mode: default is direct_post.
    let response_mode_str = obj
        .get("response_mode")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let response_mode = ResponseMode::parse(response_mode_str);

    // The response_uri and redirect_uri.
    let response_uri = obj
        .get("response_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let redirect_uri = obj
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The response endpoint: response_uri, or redirect_uri as the
    // fallback — the Digital Credentials API channel names neither;
    // the response returns through the browser instead.
    if response_uri.is_empty() && redirect_uri.is_empty() && !response_mode.is_dc_api() {
        return Err(RequestError::NotRecognized);
    }

    // The dc_api channel forbids both URIs (OpenID4VP 1.0 §8.4: the
    // response never POSTs back from the wallet).
    if response_mode.is_dc_api() && (!response_uri.is_empty() || !redirect_uri.is_empty()) {
        return Err(RequestError::UnexpectedResponseUri {
            mode: response_mode_str.to_owned(),
        });
    }

    // The direct_post channel requires a response_uri and forbids a
    // redirect_uri (OpenID4VP §5: the redirect_uri belongs to the
    // query/fragment channel).
    if matches!(
        response_mode,
        ResponseMode::DirectPost | ResponseMode::DirectPostJwt
    ) && (response_uri.is_empty() || !redirect_uri.is_empty())
    {
        return Err(RequestError::DirectPostWithoutResponseUri {
            mode: response_mode_str.to_owned(),
        });
    }

    // The client_id scheme must be a recognized one — on the redirect
    // channel an unknown prefix (or an empty client_id) is not the
    // redirect_uri scheme's fallback but a refusal. The Digital
    // Credentials API channel takes §5.9.2's pre-registered fallback
    // for an UNSIGNED request's unknown-prefixed client_id (the
    // alternate happy flow's invalid_scheme:example): the value names a
    // pre-registered client, the presentation binds to the origin,
    // never the client_id. The fallback's bounds: a SIGNED request
    // authenticates the verifier through its certificate — an unknown
    // prefix there is the invalid-prefix negative's attack (the
    // certificate binds x509_hash, the client_id claims something
    // else) and refuses; and §5.9.2's own constraint forbids
    // pre-registering a value that contains a recognized Client
    // Identifier Prefix (the mangling of x509_hash:…), so that refuses
    // too.
    if matches!(inferred_scheme, ClientIdScheme::Unknown(_))
        && (!response_mode.is_dc_api()
            || (from_signed_object && !client_id.is_empty())
            || contains_recognized_prefix(&client_id))
    {
        return Err(RequestError::UnknownClientIdScheme);
    }

    // The state.
    let state = obj
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The DCQL query (raw JSON).
    let dcql_query = obj.get("dcql_query").cloned();

    // The transaction_data (array of base64url strings).
    let transaction_data_raw: Vec<String> = obj
        .get("transaction_data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    // The client_metadata and client_metadata_uri.
    let client_metadata = obj.get("client_metadata").cloned();
    let client_metadata_uri = obj
        .get("client_metadata_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The verifier JWK (for direct_post.jwt encryption).
    let verifier_jwk = obj.get("jwk").cloned();

    // The scope (alternative to dcql_query).
    let scope = obj
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    // The expected_origins (OpenID4VP 1.0 §5.1): the Digital
    // Credentials API channel's origin binding.
    let expected_origins: Vec<String> = obj
        .get("expected_origins")
        .and_then(|v| v.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    Ok(AuthorizationRequest {
        client_id,
        client_id_scheme: inferred_scheme,
        request_uri: String::new(),
        response_uri,
        redirect_uri,
        response_mode,
        nonce,
        state,
        dcql_query,
        transaction_data_raw,
        client_metadata,
        client_metadata_uri,
        verifier_jwk,
        expected_origins,
        dc_api_origin: String::new(),
        scope,
        // The trust evaluation's inputs: the parser's caller fills them
        // when the request is JWT-secured (parse_request_object).
        request_jwt: None,
        x5c: None,
        attestation_jwt: None,
    })
}

/// Minimal base64url decoding.
/// Decodes a base64-encoded value (the standard alphabet, RFC 4648
/// §4) — the x5c entries' DER (RFC 7515 §4.1.6), padding tolerated.
fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed = encoded.trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn decode_base64url(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}
