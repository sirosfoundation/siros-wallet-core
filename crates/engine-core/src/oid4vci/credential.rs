//! The credential request: the key proofs through the Host, the credential
//! endpoint POST, and the response — S2's second step.

use engine_ports::{FetchPurpose, Host, HttpClient, HttpError, HttpRequest, RedirectPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::token::TokenResponse;
use super::types::IssuerMetadata;

/// The maximum size of a credential response: 4 MiB (the encrypted forms
/// are larger than the plain form).
const MAX_CREDENTIAL_BYTES: usize = 4 << 20;

/// One entry of a batch `credentials[]` credential response (OID4VCI §7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// The credential itself (the JWT / SD-JWT string).
    #[serde(default)]
    pub credential: Option<String>,
    /// The entry's format (e.g. `dc+sd-jwt`), when it carries one.
    #[serde(default)]
    pub format: Option<String>,
    /// The entry's notification id (OID4VCI §11.1), when it carries one.
    #[serde(default)]
    pub notification_id: Option<String>,
}

/// The parsed credential response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The credential, when the issuer answered directly (the plain form
    /// or the format-specific member).
    #[serde(default)]
    pub credential: Option<String>,
    /// The batch member `credentials[]` (OID4VCI §7.5's batch shape) -
    /// SUNET's GDC apigw answers a single-credential request with this
    /// array anyway, so the first entry IS the credential (found driving
    /// the GDC issuance, 2026-11-07: the engine read a flat `credential`
    /// and answered "the issuance delivered no credential" while the
    /// credential sat in `credentials[0]`).
    #[serde(default)]
    pub credentials: Vec<CredentialEntry>,
    /// The format-specific member (`jwt`, `sd_jwt`, etc), when present.
    #[serde(default)]
    pub format_specific: Option<serde_json::Value>,
    /// The transaction id, when the issuer deferred the credential.
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// The acceptance interval, when deferred.
    #[serde(default)]
    pub interval: Option<i64>,
    /// The nonce, when the issuer sent a new one.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The `notification_id` (OID4VCI 1.0 §11.1), when the issuer
    /// requires the credential-accepted notification: the wallet's
    /// notification MUST echo this exact value.
    #[serde(default)]
    pub notification_id: Option<String>,
    /// The response-level `credential_metadata` (the 1.0/1.1 member),
    /// kept raw: the plain-secret check reads it (Auxiliary Data v0.1
    /// §7.1 — auxiliary_data MUST NOT travel a plain response), the
    /// display data is the client's to take.
    #[serde(default)]
    pub credential_metadata: Option<serde_json::Value>,
}

/// Why the credential request refused.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The host could not provide the proofs.
    #[error("oid4vci: key proofs failed: {0}")]
    Proofs(String),
    /// The credential endpoint answered a non-200.
    #[error("oid4vci: credential endpoint answered {0}")]
    Status(u16),
    /// The transport failed.
    #[error("oid4vci: credential request failed: {0}")]
    Fetch(String),
    /// The response body is not a credential response.
    #[error("oid4vci: credential response is not JSON")]
    NotJson,
    /// The response is a JWE but the wallet offered no key (§7.3).
    #[error("oid4vci: the response is encrypted but no key was offered")]
    EncryptedWithoutKey,
    /// A plain response carried auxiliary_data (Credential Auxiliary Data
    /// v0.1 §7.1): a Secret Value travelled unencrypted — nothing was
    /// stored, nothing logged.
    #[error("oid4vci: auxiliary_data arrived in a plain response; the issuer must encrypt it")]
    PlainSecret,
    /// The issuer rejected the auxiliary data (v0.1 §8): an entry
    /// conflicts with a value it holds for the subject. Never retried.
    #[error("oid4vci: the issuer reported an auxiliary_data_conflict")]
    AuxiliaryDataConflict,
    /// The wallet offered a key and the issuer answered plain (§7.3:
    /// the issuer MUST encrypt when a key was offered). The P0.6
    /// verification found the Go engine accepts this; the Rust core
    /// follows the spec and refuses — the vectors pin the decision.
    #[error("oid4vci: plain response after the encryption key was offered")]
    PlainAfterKeyOffered,
    /// The encrypted response could not be decrypted.
    #[error("oid4vci: response decrypt failed: {0}")]
    Decrypt(String),
    /// The issuer answered `invalid_nonce` (or an error body carrying a
    /// refreshed `c_nonce`): retry once with a fresh nonce.
    #[error("oid4vci: invalid_nonce from the credential endpoint")]
    InvalidNonce {
        /// The `c_nonce` from the error body, when the issuer sent one.
        c_nonce: Option<String>,
    },
}

/// The DPoP binding of a resource request (the credential request),
/// when the token the AS issued is DPoP-bound (RFC 9449 §4.3): a fresh
/// proof over the credential endpoint, with `ath` bound to the token.
pub struct ResourceDpop<'a> {
    /// The flow the request belongs to (the client-held proof ask).
    pub flow_id: &'a str,
    /// The device key to sign with, when the flow names one — a
    /// renewal reuses the key its refresh_token was bound to.
    pub key_id: Option<&'a str>,
    /// The flow's DPoP key — the same key that proved the token request.
    pub key: &'a super::dpop::DpopKey,
    /// The Rng port (the proof's `jti`).
    pub rng: &'a dyn engine_ports::Rng,
    /// The Clock port's now (the proof's `iat`).
    pub now_unix: i64,
    /// The server-provided DPoP nonce (RFC 9449 §8), captured from the
    /// token response: the resource request's proof carries it.
    pub dpop_nonce: Option<&'a str>,
}

/// The auxiliary inputs of the credential request: the response-
/// encryption offer and the DPoP binding, both optional.
#[derive(Default)]
pub struct CredentialRequestAux<'a> {
    /// The negotiated response encryption with the wallet's ephemeral
    /// key, when the issuer supports it.
    pub encryption: Option<&'a super::encryption::NegotiatedResponseEncryption>,
    /// The DPoP binding, when the token is DPoP-bound.
    pub dpop: Option<ResourceDpop<'a>>,
    /// The reissuance kid: a renewal's proof is signed with the
    /// EXISTING keypair the issuer knows (ARF ISSU_65 same-key
    /// re-signing) — the key id on the host's sign ask.
    pub reissuance_kid: Option<&'a str>,
    /// The advertised `to_issuer` auxiliary-data entries the wallet can
    /// send (Credential Auxiliary Data v0.1 §6): verbatim, riding the
    /// proof JWT's `auxiliary_data` member — the engine places them
    /// (it builds the TBS), so no opening can enter by construction.
    pub auxiliary_data_to_issuer: &'a [serde_json::Value],
    /// The advertised `to_wallet` entries, verbatim, so the client can
    /// check its response against them (§7.2).
    pub auxiliary_data_to_wallet: &'a [serde_json::Value],
    /// The Clock port's now (the proof's `iat`).
    pub now_unix: i64,
}

/// Requests a credential from the issuer's credential endpoint, with the
/// key proofs the host signed and the access token.
///
/// The proof is a JWT the host signs over the `proof_tokens` the engine
/// builds: the JWT header + payload for the issuer's `nonce` and
/// `credential_issuer` audience. The engine builds the to-be-signed input
/// and asks the host through `Host::request_sign`; the host signs with the
/// key the credential is bound to.
#[allow(clippy::too_many_arguments)] // the credential request's explicit context; a bundle would hide the flow id the e2e found
pub async fn request_credential(
    http: &dyn HttpClient,
    host: &dyn Host,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    configuration_id: &str,
    flow_id: &str,
    aux: Option<&CredentialRequestAux<'_>>,
    nonce: Option<&str>,
) -> Result<CredentialResponse, CredentialError> {
    // `flow_id` is the RUNNING flow's id (the server's FlowSessions notes
    // it at the flow's start): the host asks below route their child
    // flows by it. A constant here (as the engine once had) sends the
    // child start with no session to deliver it under — the ask times
    // out, stalling the flow its own 30 seconds.
    let encryption = aux.and_then(|aux| aux.encryption);
    let dpop = aux.and_then(|aux| aux.dpop.as_ref());
    // Build the proof's to-be-signed input: a JWT with the `nonce` and
    // the `credential_issuer` audience (OpenID4VCI §7.5, JWT proof).
    let mut proof_payload = serde_json::json!({
        "iss": metadata.credential_issuer,
        "aud": metadata.credential_issuer,
        "iat": aux.map(|aux| aux.now_unix).unwrap_or_default(),
        "nonce": nonce.unwrap_or_default(),
    });
    // The advertised to_issuer entries ride the proof (§6): the engine
    // places them verbatim — it builds the TBS, so a secret can never
    // enter (the parse already refused an opening in the advertisement,
    // and the host signs what the engine built, byte for byte).
    let to_issuer = aux.map(|aux| aux.auxiliary_data_to_issuer).unwrap_or(&[]);
    if !to_issuer.is_empty() {
        if let Some(object) = proof_payload.as_object_mut() {
            object.insert(
                "auxiliary_data".to_owned(),
                serde_json::Value::Array(to_issuer.to_vec()),
            );
        }
    }
    // The proof header identifies the signing key (OpenID4VCI 1.0
    // §7.5.1: exactly one of `jwk`, `kid`, or `x5c` — the unregistered
    // device key travels as the `jwk`, with the RFC 7638 thumbprint as
    // its `kid` — the SDK's `jose.calculateJwkThumbprint(jwk,
    // "sha256")` convention). Keys live in the app; the host answers
    // with the public JWK only. A host that cannot answer keeps the
    // bare header (the legacy shape).
    // The batch size (OID4VCI §E.1): how many proofs this request carries —
    // `batch_size` from the issuer metadata, 1 when the issuer advertises none
    // (or ≤1). The suite's batch-credential-issuance module requires the
    // proofs count to match the batch it granted (found driving it: one
    // proof read as "batch issuance behavior cannot be evaluated"). The
    // `jwt` proof type is one proof per credential; a single `attestation`
    // proof covers the whole batch (the Go engine's rule).
    let batch_size: usize = metadata
        .batch_credential_issuance
        .as_ref()
        .map(|batch| batch.batch_size.max(1) as usize)
        .unwrap_or(1);
    let mut proofs: Vec<String> = Vec::with_capacity(batch_size);
    for i in 0..batch_size {
        let mut proof_header = serde_json::json!({
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
        });
        // The batch rule (batch_size > 1): every proof in a batch binds to
        // a FRESH key — two proofs over the same key link the credentials
        // to each other (SDJWT-10.1, the suite's
        // VCIEnsureProofKeysAreDistinct: "Two proofs in the credential
        // request prove possession of the same key; each credential in a
        // batch must be bound to a fresh key so verifiers cannot link
        // them"). A single proof (batch_size 1 — every ordinary issuance
        // runs this loop too) keeps the flow's device key; a batch
        // renewal's first proof keeps its named reissuance kid — THE key
        // the credential must bind to.
        let fresh = batch_size > 1 && !(i == 0 && aux.and_then(|aux| aux.reissuance_kid).is_some());
        // The kid of the key the proof header carries — a fresh key's
        // answer names it; thread it into the sign ask so the host signs
        // with the very key it handed over.
        let mut answer_kid: Option<String> = None;
        if let Ok(answer) = host
            .request_signing_key(engine_ports::SigningKeyParams {
                flow_id: flow_id.to_owned(),
                key_id: aux.and_then(|aux| aux.reissuance_kid).map(str::to_owned),
                fresh,
            })
            .await
        {
            if let Some(header) = proof_header.as_object_mut() {
                header.insert("jwk".to_owned(), public_jwk_for_header(&answer.jwk));
            }
            answer_kid = answer
                .jwk
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        let proof_tbs = format!(
            "{}.{}",
            base64url_json(&proof_header),
            base64url_json(&proof_payload),
        );
        let sign_result = host
            .request_sign(engine_ports::SignParams {
                flow_id: flow_id.to_owned(),
                to_sign: proof_tbs.as_bytes().to_vec(),
                key_id: answer_kid
                    .or_else(|| aux.and_then(|aux| aux.reissuance_kid).map(str::to_owned)),
                algorithm: "ES256".to_owned(),
            })
            .await
            .map_err(|err| CredentialError::Proofs(err.to_string()))?;
        proofs.push(format!(
            "{}.{}",
            proof_tbs,
            base64url(&sign_result.signature)
        ));
    }

    // Build the credential request body. OID4VCI 1.0 §7.5: `proofs` is
    // an object keyed by the proof type, its value the array of proofs
    // of that type — `{"jwt": ["..."]}` (the single `proof` member was
    // the pre-1.0 drafts' shape, and the draft-era array of
    // `{proof_type, jwt}` objects is not the 1.0 form either). And §6:
    // when the AS granted credential identifiers in response to our
    // authorization_details, the Credential Request names one of those
    // INSTEAD of the configuration id — an issuer that honours
    // authorization_details rejects the pair.
    let mut request_body = serde_json::json!({
        "credential_configuration_id": configuration_id,
        "proofs": {
            "jwt": proofs,
        },
    });
    // The encryption offer (§7.3): the negotiated alg/enc and the
    // wallet's ephemeral public key. When offered, the issuer MUST
    // encrypt the response.
    if let Some(encryption) = encryption {
        let offer = super::encryption::build_encryption_request(
            &encryption.negotiated,
            encryption.key.public_jwk.clone(),
        );
        if let Some(body) = request_body.as_object_mut() {
            body.insert(
                "credential_response_encryption".to_owned(),
                serde_json::to_value(&offer).unwrap_or(Value::Null),
            );
        }
    }
    if let Some(identifier) = super::auth_params::granted_credential_identifier(
        token.authorization_details.as_ref(),
        configuration_id,
    ) {
        let Some(body) = request_body.as_object_mut() else {
            return Err(CredentialError::NotJson);
        };
        body.remove("credential_configuration_id");
        body.insert(
            "credential_identifier".to_owned(),
            Value::String(identifier),
        );
    }

    // The credential endpoint: the metadata's member when it carries
    // one (the P0.6-verified Go behaviour — never a constructed path
    // when the metadata named it), else the constructed fallback.
    let credential_endpoint = if metadata.credential_endpoint.is_empty() {
        format!(
            "{}/credential",
            metadata.credential_issuer.trim_end_matches('/'),
        )
    } else {
        metadata.credential_endpoint.clone()
    };

    // The DPoP binding (RFC 9449 §4.3): a DPoP-bound token authorizes
    // with the DPoP scheme, and the request carries a fresh proof with
    // `ath` bound to the token.
    let dpop_token = token.token_type.eq_ignore_ascii_case("DPoP");
    let authorization = if dpop_token {
        format!("DPoP {}", token.access_token)
    } else {
        format!("Bearer {}", token.access_token)
    };

    // The DPoP nonce retry loop (RFC 9449 §8.1): the resource server
    // may demand its own nonce — the token response's nonce binds the
    // AS, not the credential endpoint — answering 401
    // `use_dpop_nonce` with a fresh `DPoP-Nonce` header. The proof is
    // rebuilt with the fresh nonce and the request retried once; a
    // second demand is terminal (the status check below reports it).
    let mut dpop_nonce = dpop.and_then(|dpop| dpop.dpop_nonce).map(str::to_owned);
    let mut response: Option<engine_ports::HttpResponse> = None;
    for attempt in 0..2 {
        let mut headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".to_owned(), "application/json".to_owned()),
            ("authorization".to_owned(), authorization.clone()),
        ];
        if dpop_token {
            if let Some(dpop) = dpop {
                if let Some(proof) = super::dpop::proof_for(
                    host,
                    Some(dpop.key),
                    super::dpop::ProofRequest {
                        flow_id: dpop.flow_id,
                        key_id: dpop.key_id,
                        htm: "POST",
                        htu: &credential_endpoint,
                        access_token: Some(&token.access_token),
                        nonce: dpop_nonce.as_deref(),
                        rng: dpop.rng,
                        now_unix: dpop.now_unix,
                    },
                )
                .await
                {
                    headers.push(("DPoP".to_owned(), proof));
                }
            }
        }

        let sent = http
            .send(HttpRequest {
                method: "POST".to_owned(),
                url: credential_endpoint.clone(),
                headers,
                body: serde_json::to_vec(&request_body).map_err(|_| CredentialError::NotJson)?,
                purpose: FetchPurpose::Credential,
                max_response_bytes: MAX_CREDENTIAL_BYTES,
                redirects: RedirectPolicy::None,
                allow_plaintext: false,
                timeout_ms: 30_000,
            })
            .await
            .map_err(|err| match err {
                HttpError::Refused => CredentialError::Fetch("refused by the adapter".to_owned()),
                HttpError::Transport(detail) => CredentialError::Fetch(detail),
            })?;

        if attempt == 1 || !super::dpop::is_dpop_nonce_error(&sent) {
            response = Some(sent);
            break;
        }
        // The fresh nonce for the retried proof.
        dpop_nonce = super::dpop::dpop_nonce_from_response(&sent);
    }
    let response = match response {
        Some(response) => response,
        // Unreachable: the last attempt always stores its response
        // before it breaks.
        None => {
            return Err(CredentialError::Fetch(
                "the endpoint never answered".to_owned(),
            ))
        }
    };

    if response.status != 200 {
        // The P0.6-verified rule: an error body carrying `invalid_nonce` —
        // or any refreshed `c_nonce` — is retryable; everything else is
        // terminal. The flow error is the caller's to send (the Go engine
        // deliberately does not send one from the request helper).
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null);
        let c_nonce = body
            .get("c_nonce")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
        let is_invalid_nonce = body
            .get("error")
            .and_then(|v| v.as_str())
            .map(|e| e == "invalid_nonce")
            .unwrap_or(false);
        if is_invalid_nonce || c_nonce.is_some() {
            return Err(CredentialError::InvalidNonce { c_nonce });
        }
        // The deferred acceptance (OID4VCI 1.0 §8): 202 with a
        // `transaction_id` — the caller polls the deferred credential
        // endpoint for the credential. A 202 without a parseable body
        // stays an error.
        if response.status == 202 {
            if let Ok(deferred) = serde_json::from_value::<CredentialResponse>(body) {
                if deferred.transaction_id.is_some() {
                    return Ok(deferred);
                }
            }
        }
        return Err(CredentialError::Status(response.status));
    }

    // Decode the response.
    //
    // §7.3: when the wallet offered a key, the issuer MUST encrypt the
    // response — a plain answer is refused (the P0.6-verified Go engine
    // accepts it; the Rust core follows the spec, and the vectors pin
    // the decision). An encrypted answer without an offered key cannot
    // be opened and is refused too.
    if super::encryption::is_encrypted_response("", &response.body) {
        let Some(encryption) = encryption else {
            return Err(CredentialError::EncryptedWithoutKey);
        };
        let jwe = String::from_utf8_lossy(&response.body).into_owned();
        return super::encryption::decrypt_encrypted_response(&jwe, &encryption.key)
            .map_err(|err| CredentialError::Decrypt(err.to_string()));
    }
    if encryption.is_some() {
        return Err(CredentialError::PlainAfterKeyOffered);
    }

    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| CredentialError::NotJson)?;

    // The conflict relay (Credential Auxiliary Data v0.1 §8, the issuer's
    // `auxiliary_data_conflict`): an entry conflicts with a value the
    // issuer holds for the subject; retrying never helps, the issuer
    // resolves it out of band. The issuer's code rides unchanged under
    // `error`; no other issuer text is relayed.
    if value.get("error").and_then(|v| v.as_str()) == Some("auxiliary_data_conflict") {
        return Err(CredentialError::AuxiliaryDataConflict);
    }

    let credential_response: CredentialResponse =
        serde_json::from_value(value).map_err(|_| CredentialError::NotJson)?;
    // The batch shape's credential: the first entry (this request was for
    // one configuration). See the field's doc comment.
    let credential_response = if credential_response.credential.is_none() {
        let mut filled = credential_response.clone();
        if let Some(entry) = filled.credentials.first() {
            filled.credential = entry.credential.clone();
            if filled.format_specific.is_none() {
                filled.format_specific = entry.format.clone().map(serde_json::Value::String);
            }
            if filled.notification_id.is_none() {
                filled.notification_id = entry.notification_id.clone();
            }
        }
        filled
    } else {
        credential_response
    };

    // The plain-secret check (v0.1 §7.1): a PLAIN response carrying
    // auxiliary_data travelled a Secret Value unencrypted — the flow
    // refuses, nothing of the content logged. A plain response is here
    // only when the wallet offered no key, so the check is unconditional
    // on the plain path (an encrypted response was decrypted above; the
    // member is the client's to read there).
    if let Some(metadata) = credential_response.credential_metadata.as_ref() {
        if super::auxiliary::has_auxiliary_data_member(metadata) {
            return Err(CredentialError::PlainSecret);
        }
    }

    Ok(credential_response)
}

/// Requests the credential with the `invalid_nonce` retry-once loop.
///
/// The P0.6-verified behaviour (the Go engine's `retries <= 1` loop):
/// - The initial nonce comes from the issuer's nonce endpoint (§7) when
///   the metadata advertises one, falling back to the token's `c_nonce`.
/// - On `invalid_nonce` (or an error body carrying a refreshed `c_nonce`),
///   the fresh nonce comes from the endpoint first, then the body's
///   `c_nonce`; the proofs are re-requested and the request retried once.
/// - A second `invalid_nonce` is terminal, with the underlying error.
#[allow(clippy::too_many_arguments)] // the credential request's explicit context; a bundle would hide the flow id the e2e found
pub async fn request_credential_with_retry(
    http: &dyn HttpClient,
    host: &dyn Host,
    metadata: &IssuerMetadata,
    token: &TokenResponse,
    configuration_id: &str,
    flow_id: &str,
    aux: Option<&CredentialRequestAux<'_>>,
    initial_nonce: Option<&str>,
) -> Result<CredentialResponse, CredentialError> {
    // The initial nonce: the endpoint first (§7), then the token's c_nonce.
    let mut nonce = resolve_nonce(http, host, metadata, aux, initial_nonce).await;

    for retry in 0..=1 {
        // The retry re-sends the same encryption offer and DPoP binding
        // (a fresh proof, the same key) — P0.6.
        match request_credential(
            http,
            host,
            metadata,
            token,
            configuration_id,
            flow_id,
            aux,
            nonce.as_deref(),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(CredentialError::InvalidNonce { c_nonce }) if retry == 0 => {
                // The fresh nonce: the endpoint first, then the body's
                // c_nonce (the legacy fallback).
                nonce = resolve_nonce(http, host, metadata, aux, c_nonce.as_deref()).await;
                if nonce.is_none() {
                    return Err(CredentialError::InvalidNonce { c_nonce });
                }
                continue;
            }
            Err(CredentialError::InvalidNonce { c_nonce }) => {
                // Terminal after the retry: surface the underlying error.
                return Err(CredentialError::InvalidNonce { c_nonce });
            }
            Err(other) => return Err(other),
        }
    }

    Err(CredentialError::Status(0))
}

/// Resolves the nonce: the issuer's nonce endpoint first (§7), then the
/// fallback from the token response or the error body.
async fn resolve_nonce(
    http: &dyn HttpClient,
    host: &dyn Host,
    metadata: &IssuerMetadata,
    aux: Option<&CredentialRequestAux<'_>>,
    fallback: Option<&str>,
) -> Option<String> {
    if let Some(endpoint) = metadata.nonce_endpoint.as_deref().filter(|e| !e.is_empty()) {
        if let Ok(fresh) = super::nonce::fetch_nonce(http, host, endpoint, aux).await {
            return Some(fresh);
        }
    }
    fallback.filter(|n| !n.is_empty()).map(str::to_owned)
}

/// Minimal base64url encoding of JSON bytes.
fn base64url_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    base64url(&bytes)
}

/// Minimal base64url encoding.
fn base64url(bytes: &[u8]) -> String {
    fn six_to_char(v: u8) -> char {
        // The base64url character for a 6-bit value: A-Z, a-z, 0-9, -, _.
        if v < 26 {
            (b'A' + v) as char
        } else if v < 52 {
            (b'a' + (v - 26)) as char
        } else if v < 62 {
            (b'0' + (v - 52)) as char
        } else if v == 62 {
            '-'
        } else {
            '_'
        }
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or_default();
        let b1 = chunk.get(1).copied().unwrap_or_default();
        let b2 = chunk.get(2).copied().unwrap_or_default();
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(six_to_char(((n >> 18) & 0x3f) as u8));
        out.push(six_to_char(((n >> 12) & 0x3f) as u8));
        if chunk.len() > 1 {
            out.push(six_to_char(((n >> 6) & 0x3f) as u8));
        }
        if chunk.len() > 2 {
            out.push(six_to_char((n & 0x3f) as u8));
        }
    }
    out
}

/// The public JWK as a proof header carries it: the public members
/// only (no private material ever crosses the port boundary twice),
/// the RFC 7638 thumbprint as the `kid` (no `key_ops` - the Go engine's
/// verification — the SDK's proof-header shape.
fn public_jwk_for_header(jwk: &Value) -> Value {
    let Some(object) = jwk.as_object() else {
        return jwk.clone();
    };
    // The private members (RFC 7518 §6) never ride a proof header.
    const PRIVATE: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
    let public: serde_json::Map<String, Value> = object
        .iter()
        .filter(|(name, _)| !PRIVATE.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let mut jwk = Value::Object(public);
    let kid = rfc7638_thumbprint(&jwk);
    // The members are inserted, never indexed into: the JWK is an
    // object by construction, and indexing panics.
    if let Some(object) = jwk.as_object_mut() {
        object.insert("kid".to_owned(), Value::String(kid));
        // No `key_ops` (RFC 7517 §4) in a PROOF header's JWK: the Go engine's
        // wallet-generated proofs carry the bare JWK + kid, and `key_ops:
        // ["verify"]` on a key that is SIGNING is semantically contradictory
        // (a strict issuer rejects the proof - found driving the GDC
        // issuance: the credential endpoint answered 400).
    }
    jwk
}

/// The RFC 7638 JWK thumbprint (SHA-256, base64url): the hash of the
/// canonical JSON built from the key type's required members only, in
/// lexicographic order, with no whitespace — the SDK's
/// `jose.calculateJwkThumbprint(jwk, "sha256")` convention. The `kid`
/// is always this thumbprint, never a random or conventional name.
fn rfc7638_thumbprint(jwk: &Value) -> String {
    // The required members per key type (RFC 7638 §3.2).
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
    let required: Vec<&str> = match kty {
        "EC" => vec!["crv", "kty", "x", "y"],
        "OKP" => vec!["crv", "kty", "x"],
        "RSA" => vec!["e", "kty", "n"],
        _ => Vec::new(),
    };
    if required.is_empty() {
        return String::new();
    }
    // The canonical form: the required members, sorted, no whitespace.
    let mut members: Vec<(&str, &Value)> = required
        .into_iter()
        .filter_map(|name| jwk.get(name).map(|value| (name, value)))
        .collect();
    members.sort_by_key(|(name, _)| *name);
    let canonical = format!(
        "{{{}}}",
        members
            .iter()
            .map(|(name, value)| format!(
                "{}:{}",
                serde_json::to_string(name).unwrap_or_default(),
                serde_json::to_string(value).unwrap_or_default()
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let digest =
        kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, canonical.as_bytes())
            .unwrap_or_default();
    base64url(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_ports::{HostError, SignParams, SignResult};

    struct FakeHttp {
        status: u16,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl HttpClient for FakeHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            assert_eq!(request.purpose, FetchPurpose::Credential);
            assert_eq!(request.max_response_bytes, MAX_CREDENTIAL_BYTES);
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    struct FakeHost;

    #[async_trait::async_trait]
    impl Host for FakeHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult {
                signature: vec![0xde, 0xad, 0xbe, 0xef],
            })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match in the test".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent in the test".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    /// A host that answers the signing-key ask: the app holds the key,
    /// so the proof header can identify it (the public JWK + the RFC
    /// 7638 thumbprint kid — the SDK's shape).
    struct KeyHost {
        jwk: Value,
    }

    #[async_trait::async_trait]
    impl Host for KeyHost {
        async fn request_sign(&self, _p: SignParams) -> Result<SignResult, HostError> {
            Ok(SignResult {
                signature: vec![0xde, 0xad, 0xbe, 0xef],
            })
        }
        async fn request_signing_key(
            &self,
            _params: engine_ports::SigningKeyParams,
        ) -> Result<engine_ports::SigningKeyResult, HostError> {
            Ok(engine_ports::SigningKeyResult {
                jwk: self.jwk.clone(),
            })
        }
        async fn request_match(
            &self,
            _params: engine_ports::MatchParams,
        ) -> Result<engine_ports::MatchResult, HostError> {
            Err(HostError::Cannot("no match in the test".to_owned()))
        }
        async fn request_consent(
            &self,
            _p: engine_ports::ConsentParams,
        ) -> Result<engine_ports::ConsentResult, HostError> {
            Err(HostError::Cannot("no consent in the test".to_owned()))
        }
        async fn request_tx_code(&self, _f: &str) -> Result<String, HostError> {
            Ok("1234".to_owned())
        }
        async fn open_authorization(&self, _f: &str, _u: &str) -> Result<(), HostError> {
            Ok(())
        }
        fn progress(&self, _f: &str, _s: &str, _d: Option<String>) {}
    }

    fn test_metadata() -> IssuerMetadata {
        IssuerMetadata {
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            batch_credential_issuance: None,
            credential_endpoint: String::new(),
            token_endpoint: String::new(),
            notification_endpoint: String::new(),
            credential_issuer: "https://issuer.example".to_owned(),
            authorization_servers: Vec::new(),
            credential_configurations: serde_json::json!({}),
            signed_metadata: None,
            envelope_key_material: None,
            is_signed: false,
            raw: Vec::new(),
        }
    }

    fn test_token() -> TokenResponse {
        TokenResponse {
            access_token: "at-test".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: Some(3600),
            refresh_token: None,
            c_nonce: None,
            nonce: Some("nonce-1".to_owned()),
            authorization_details: None,
            dpop_nonce: None,
        }
    }

    #[tokio::test]
    async fn requests_a_credential_with_the_host_signed_proof() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"credential":"eyJhbGciOiJFUzI1NiJ9.payload.sig"}"#.to_vec(),
        };
        let response = request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert!(response.credential.is_some());
    }

    #[tokio::test]
    async fn a_deferred_credential_answer_names_the_transaction() {
        let http = FakeHttp {
            status: 200,
            body: br#"{"transaction_id":"tx-1","interval":5}"#.to_vec(),
        };
        let response = request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert_eq!(response.transaction_id, Some("tx-1".to_owned()));
        assert_eq!(response.interval, Some(5));
    }

    #[tokio::test]
    async fn a_non_200_refuses() {
        let http = FakeHttp {
            status: 400,
            body: Vec::new(),
        };
        assert!(matches!(
            request_credential(
                &http,
                &FakeHost,
                &test_metadata(),
                &test_token(),
                "X",
                "flow-1",
                None,
                None
            )
            .await,
            Err(CredentialError::Status(400))
        ));
    }

    /// An issuer that honours §7.3: reads the request's encryption offer
    /// and answers a JWE to the offered key.
    struct EncryptingHttp;

    #[async_trait::async_trait]
    impl HttpClient for EncryptingHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("request body json");
            let offer = body["credential_response_encryption"]
                .as_object()
                .expect("the offer is in the request");
            // The 1.0 wire form: jwk + enc only — the key-management
            // algorithm rides the JWE header, not the offer.
            assert!(offer.get("alg").is_none());
            assert_eq!(offer["enc"], "A256GCM");
            assert_eq!(offer["jwk"]["kty"], "EC");

            // The issuer's encrypt: to the wallet's offered public key
            // (ECDH-ES, the 1.0 response-encryption algorithm).
            let jwk: jose_rs::jwk::Jwk =
                serde_json::from_value(offer["jwk"].clone()).expect("offered jwk");
            let mut recipient = jwk.clone();
            recipient.alg = Some("ECDH-ES".to_owned());
            let plaintext = br#"{"credential":"encrypted-credential-1"}"#.to_vec();
            let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
                &recipient,
                jose_rs::header::JoseHeader::for_jwe(
                    jose_rs::algorithm::JweAlgorithm::EcdhEs,
                    jose_rs::algorithm::JweEncryption::A256GCM,
                ),
                &plaintext,
                jose_rs::algorithm::JweEncryption::A256GCM,
            )
            .expect("issuer encrypt");

            Ok(engine_ports::HttpResponse {
                status: 200,
                headers: vec![("content-type".to_owned(), "application/jwt".to_owned())],
                body: jwe.into_bytes(),
            })
        }
    }

    fn negotiated_encryption() -> super::super::encryption::NegotiatedResponseEncryption {
        super::super::encryption::negotiate_with_key(
            &super::super::encryption::ResponseEncryptionConfig {
                alg_values: vec!["ECDH-ES".to_owned()],
                enc_values: vec!["A256GCM".to_owned()],
                required: true,
            },
        )
        .expect("negotiate")
    }

    #[tokio::test]
    async fn an_encrypted_answer_to_the_offer_decrypts() {
        let encryption = negotiated_encryption();
        let response = request_credential(
            &EncryptingHttp,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            Some(&CredentialRequestAux {
                auxiliary_data_to_issuer: &[],
                auxiliary_data_to_wallet: &[],
                encryption: Some(&encryption),
                dpop: None,
                reissuance_kid: None,
                now_unix: 1_000,
            }),
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert_eq!(
            response.credential.as_deref(),
            Some("encrypted-credential-1")
        );
    }

    #[tokio::test]
    async fn a_plain_answer_after_the_offer_refuses() {
        let encryption = negotiated_encryption();
        let http = FakeHttp {
            status: 200,
            body: br#"{"credential":"plain"}"#.to_vec(),
        };
        // §7.3: the issuer MUST encrypt when a key was offered. The Go
        // engine accepts the plain answer (P0.6); the Rust core refuses.
        assert!(matches!(
            request_credential(
                &http,
                &FakeHost,
                &test_metadata(),
                &test_token(),
                "UniversityDegree",
                "flow-1",
                Some(&CredentialRequestAux {
                    auxiliary_data_to_issuer: &[],
                    auxiliary_data_to_wallet: &[],
                    encryption: Some(&encryption),
                    dpop: None,
                    reissuance_kid: None,
                    now_unix: 1_000,
                }),
                Some("nonce-1"),
            )
            .await,
            Err(CredentialError::PlainAfterKeyOffered)
        ));
    }

    #[tokio::test]
    async fn an_encrypted_answer_without_an_offer_refuses() {
        let http = FakeHttp {
            status: 200,
            body: b"header.key.iv.ciphertext.tag".to_vec(),
        };
        assert!(matches!(
            request_credential(
                &http,
                &FakeHost,
                &test_metadata(),
                &test_token(),
                "UniversityDegree",
                "flow-1",
                None,
                Some("nonce-1"),
            )
            .await,
            Err(CredentialError::EncryptedWithoutKey)
        ));
    }

    /// A fake that records the URL it was asked for.
    struct RecordingHttp {
        status: u16,
        body: Vec<u8>,
        urls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for RecordingHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            self.urls
                .lock()
                .map(|mut u| u.push(request.url.clone()))
                .ok();
            Ok(engine_ports::HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }
    }

    #[tokio::test]
    async fn the_credential_endpoint_comes_from_the_metadata_not_the_path() {
        // The metadata names its endpoint: the request goes there, never
        // to the constructed `{issuer}/credential` path.
        let metadata = IssuerMetadata {
            credential_endpoint: "https://issuer.example/issue-credential".to_owned(),
            ..test_metadata()
        };
        let http = RecordingHttp {
            status: 200,
            body: br#"{"credential":"jwt-1"}"#.to_vec(),
            urls: std::sync::Mutex::new(Vec::new()),
        };
        request_credential(
            &http,
            &FakeHost,
            &metadata,
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert_eq!(
            http.urls.lock().expect("lock").as_slice(),
            ["https://issuer.example/issue-credential"]
        );

        // Without the member: the constructed fallback.
        let http = RecordingHttp {
            status: 200,
            body: br#"{"credential":"jwt-1"}"#.to_vec(),
            urls: std::sync::Mutex::new(Vec::new()),
        };
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("request");
        assert_eq!(
            http.urls.lock().expect("lock").as_slice(),
            ["https://issuer.example/credential"]
        );
    }

    /// A stateful fake: the nonce endpoint answers the fresh nonce; the
    /// credential endpoint fails the first N calls with `invalid_nonce`,
    /// then answers the credential.
    struct RetryHttp {
        nonce_body: Vec<u8>,
        error_body: Vec<u8>,
        error_status: u16,
        failures: std::sync::atomic::AtomicUsize,
        credential_calls: std::sync::atomic::AtomicUsize,
        nonce_calls: std::sync::atomic::AtomicUsize,
    }

    impl RetryHttp {
        fn always_invalid_nonce() -> Self {
            Self {
                nonce_body: br#"{"nonce":"fresh-2"}"#.to_vec(),
                error_body: br#"{"error":"invalid_nonce","c_nonce":"fresh-1"}"#.to_vec(),
                error_status: 400,
                failures: std::sync::atomic::AtomicUsize::new(usize::MAX),
                credential_calls: std::sync::atomic::AtomicUsize::new(0),
                nonce_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn fail_once() -> Self {
            Self {
                failures: std::sync::atomic::AtomicUsize::new(1),
                ..Self::always_invalid_nonce()
            }
        }

        fn calls(&self, which: &str) -> usize {
            match which {
                "credential" => self
                    .credential_calls
                    .load(std::sync::atomic::Ordering::SeqCst),
                "nonce" => self.nonce_calls.load(std::sync::atomic::Ordering::SeqCst),
                _ => 0,
            }
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for RetryHttp {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<engine_ports::HttpResponse, HttpError> {
            match request.purpose {
                FetchPurpose::Nonce => {
                    self.nonce_calls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(engine_ports::HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: self.nonce_body.clone(),
                    })
                }
                FetchPurpose::Credential => {
                    self.credential_calls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let failed = self.failures.load(std::sync::atomic::Ordering::SeqCst) > 0;
                    self.failures
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    if failed {
                        Ok(engine_ports::HttpResponse {
                            status: self.error_status,
                            headers: Vec::new(),
                            body: self.error_body.clone(),
                        })
                    } else {
                        Ok(engine_ports::HttpResponse {
                            status: 200,
                            headers: Vec::new(),
                            body: br#"{"credential":"jwt-1"}"#.to_vec(),
                        })
                    }
                }
                _ => panic!("unexpected fetch purpose: {:?}", request.purpose),
            }
        }
    }

    fn metadata_with_nonce_endpoint() -> IssuerMetadata {
        IssuerMetadata {
            nonce_endpoint: Some("https://issuer.example/nonce".to_owned()),
            ..test_metadata()
        }
    }

    #[tokio::test]
    async fn an_invalid_nonce_retries_once_with_the_endpoint_nonce_and_succeeds() {
        let http = RetryHttp::fail_once();
        let response = request_credential_with_retry(
            &http,
            &FakeHost,
            &metadata_with_nonce_endpoint(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("retry succeeds");
        assert_eq!(response.credential.as_deref(), Some("jwt-1"));
        // The initial nonce came from the endpoint; the retry refreshed it
        // from the endpoint again (preferred over the error body's
        // c_nonce, per §7).
        assert_eq!(http.calls("nonce"), 2);
        assert_eq!(http.calls("credential"), 2);
    }

    #[tokio::test]
    async fn an_invalid_nonce_after_the_retry_is_terminal() {
        let http = RetryHttp::always_invalid_nonce();
        assert!(matches!(
            request_credential_with_retry(
                &http,
                &FakeHost,
                &metadata_with_nonce_endpoint(),
                &test_token(),
                "UniversityDegree",
                "flow-1",
                None,
                Some("nonce-1"),
            )
            .await,
            Err(CredentialError::InvalidNonce { .. })
        ));
        assert_eq!(http.calls("credential"), 2);
    }

    #[tokio::test]
    async fn a_c_nonce_carrying_error_body_triggers_the_retry_without_a_nonce_endpoint() {
        // P0.6: any error body carrying a refreshed c_nonce is retryable,
        // and without an advertised endpoint the body's c_nonce is the
        // fallback source.
        let http = RetryHttp::fail_once();
        // With no endpoint, the fresh nonce comes from the body.
        let mut http = http;
        http.nonce_body = Vec::new(); // unused; the endpoint is never called
        let response = request_credential_with_retry(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "UniversityDegree",
            "flow-1",
            None,
            Some("nonce-1"),
        )
        .await
        .expect("retry succeeds");
        assert_eq!(response.credential.as_deref(), Some("jwt-1"));
        assert_eq!(http.calls("nonce"), 0);
        assert_eq!(http.calls("credential"), 2);
    }

    struct TestRng;
    impl engine_ports::Rng for TestRng {
        fn fill(&self, buf: &mut [u8]) -> bool {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            true
        }
    }

    #[tokio::test]
    async fn a_dpop_bound_token_authorizes_the_credential_request_with_a_proof() {
        // A DPoP-bound token: the credential request carries the DPoP
        // scheme and a fresh `ath`-bound proof, signed with the same
        // key that proved the token request.
        let key = super::super::dpop::DpopKey::generate().expect("keygen");
        let token = TokenResponse {
            access_token: "at-dpop".to_owned(),
            token_type: "DPoP".to_owned(),
            ..test_token()
        };
        // A recording fake that also captures headers.
        struct HeaderHttp {
            status: u16,
            body: Vec<u8>,
            headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
        }
        #[async_trait::async_trait]
        impl HttpClient for HeaderHttp {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> Result<engine_ports::HttpResponse, HttpError> {
                self.headers
                    .lock()
                    .map(|mut h| h.push(request.headers.clone()))
                    .ok();
                Ok(engine_ports::HttpResponse {
                    status: self.status,
                    headers: Vec::new(),
                    body: self.body.clone(),
                })
            }
        }
        let http = HeaderHttp {
            status: 200,
            body: br#"{"credential":"jwt-1"}"#.to_vec(),
            headers: std::sync::Mutex::new(Vec::new()),
        };

        let aux = CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: None,
            reissuance_kid: None,
            now_unix: 1_000,
            dpop: Some(ResourceDpop {
                flow_id: "flow-1",
                key_id: None,
                key: &key,
                rng: &TestRng,
                now_unix: 1_000,
                dpop_nonce: None,
            }),
        };
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &token,
            "X",
            "flow-1",
            Some(&aux),
            None,
        )
        .await
        .expect("request");

        let headers = http.headers.lock().expect("lock");
        assert_eq!(headers.len(), 1);
        let authorization = headers[0]
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone());
        assert_eq!(authorization.as_deref(), Some("DPoP at-dpop"));
        let proof = headers[0]
            .iter()
            .find(|(n, _)| n == "DPoP")
            .map(|(_, v)| v.clone())
            .expect("a DPoP header");
        let payload = proof.split('.').nth(1).unwrap_or_default();
        let decoded = jose_rs::base64url::decode(payload).expect("base64url");
        let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("claims");
        assert_eq!(claims["ath"], super::super::dpop::ath_of("at-dpop"));
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://issuer.example/credential");
    }

    #[tokio::test]
    async fn a_dpop_nonce_demand_on_the_credential_endpoint_is_retried_with_the_fresh_nonce() {
        // The resource server may demand its own DPoP nonce (RFC 9449
        // §8.1): the first credential request answers 401
        // `use_dpop_nonce` with a fresh `DPoP-Nonce` header, and the
        // retried proof carries that nonce.
        struct NonceHttp {
            responses: Vec<engine_ports::HttpResponse>,
            headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
        }
        #[async_trait::async_trait]
        impl HttpClient for NonceHttp {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> Result<engine_ports::HttpResponse, HttpError> {
                let index = {
                    let mut calls = self.headers.lock().expect("lock");
                    let index = calls.len();
                    calls.push(request.headers.clone());
                    index
                };
                Ok(self.responses.get(index).cloned().unwrap_or_else(|| {
                    engine_ports::HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: br#"{"credential":"jwt-1"}"#.to_vec(),
                    }
                }))
            }
        }
        let key = super::super::dpop::DpopKey::generate().expect("keygen");
        let token = TokenResponse {
            access_token: "at-dpop".to_owned(),
            token_type: "DPoP".to_owned(),
            ..test_token()
        };
        let http = NonceHttp {
            responses: vec![engine_ports::HttpResponse {
                status: 401,
                headers: vec![("DPoP-Nonce".to_owned(), "fresh-nonce".to_owned())],
                body: br#"{"error":"invalid_token"}"#.to_vec(),
            }],
            headers: std::sync::Mutex::new(Vec::new()),
        };

        let aux = CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: None,
            reissuance_kid: None,
            now_unix: 1_000,
            dpop: Some(ResourceDpop {
                flow_id: "flow-1",
                key_id: None,
                key: &key,
                rng: &TestRng,
                now_unix: 1_000,
                dpop_nonce: None,
            }),
        };
        let response = request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &token,
            "X",
            "flow-1",
            Some(&aux),
            None,
        )
        .await
        .expect("the nonce retry succeeds");
        assert_eq!(response.credential.as_deref(), Some("jwt-1"));

        let headers = http.headers.lock().expect("lock");
        assert_eq!(headers.len(), 2, "the request is sent twice");
        let first_proof = headers[0]
            .iter()
            .find(|(n, _)| n == "DPoP")
            .map(|(_, v)| v.clone())
            .expect("the first request carries a proof");
        let second_proof = headers[1]
            .iter()
            .find(|(n, _)| n == "DPoP")
            .map(|(_, v)| v.clone())
            .expect("the retried request carries a proof");
        let decode = |proof: &str| {
            let payload = proof.split('.').nth(1).unwrap_or_default();
            let decoded = jose_rs::base64url::decode(payload).expect("base64url");
            let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("claims");
            claims
        };
        assert!(decode(&first_proof)["nonce"].is_null());
        assert_eq!(decode(&second_proof)["nonce"], "fresh-nonce");
    }

    #[tokio::test]
    async fn the_proof_header_identifies_the_key_with_the_jwk_and_the_thumbprint_kid() {
        // The app holds the signing key, so the engine asks for its
        // public JWK and identifies it in the proof header: the public
        // JWK and the RFC 7638 thumbprint as the `kid` (the SDK's
        // `jose.calculateJwkThumbprint` convention — never a random or
        // conventional name). The proof's `iat` is the Clock's now.
        struct BodyHttp {
            body: std::sync::Mutex<Vec<u8>>,
        }
        #[async_trait::async_trait]
        impl HttpClient for BodyHttp {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> Result<engine_ports::HttpResponse, HttpError> {
                self.body.lock().map(|mut b| *b = request.body.clone()).ok();
                Ok(engine_ports::HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: br#"{"credential":"jwt-1"}"#.to_vec(),
                })
            }
        }
        let host = KeyHost {
            jwk: serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "yD-oreWV0aEuPH94c_DGCtOvqIvFujzIoloNCcfjZyY",
                "y": "HO-K1-uhDZXpdSn3U6sxr0792PwurIcGraTFIV4x51k",
            }),
        };
        let http = BodyHttp {
            body: std::sync::Mutex::new(Vec::new()),
        };

        let aux = CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: None,
            reissuance_kid: None,
            now_unix: 1_000,
            dpop: None,
        };
        request_credential(
            &http,
            &host,
            &test_metadata(),
            &test_token(),
            "X",
            "flow-1",
            Some(&aux),
            Some("nonce-1"),
        )
        .await
        .expect("request");

        let body = http.body.lock().expect("lock").clone();
        let request: serde_json::Value = serde_json::from_slice(&body).expect("body");
        let jwt = request["proofs"]["jwt"][0].as_str().expect("the proof jwt");
        let decode = |part: usize| {
            let payload = jwt.split('.').nth(part).unwrap_or_default();
            jose_rs::base64url::decode(payload).expect("base64url")
        };
        let header: Value = serde_json::from_slice(&decode(0)).expect("the JOSE header");
        let claims: Value = serde_json::from_slice(&decode(1)).expect("the claims");

        // The public JWK rides the header, public members only, with
        // the thumbprint kid and verify-only key ops — and it is the
        // ONLY key identification (exactly one of jwk/kid/x5c).
        let expected_thumbprint = super::rfc7638_thumbprint(&host.jwk);
        assert!(!expected_thumbprint.is_empty());
        assert_eq!(header["jwk"]["kty"], "EC");
        assert!(header["jwk"].get("d").is_none());
        assert_eq!(header["jwk"]["kid"], expected_thumbprint);
        assert!(header.get("kid").is_none());
        assert!(header.get("x5c").is_none());
        assert!(
            header["jwk"].get("key_ops").is_none(),
            "a proof header's JWK carries no key_ops (found driving: the issuer refused it)"
        );
        // The iat is the Clock's now, not a placeholder.
        assert_eq!(claims["iat"], 1_000);
    }

    #[tokio::test]
    async fn a_bearer_token_does_not_carry_a_dpop_proof() {
        struct HeaderHttp {
            status: u16,
            body: Vec<u8>,
            headers: std::sync::Mutex<Vec<Vec<(String, String)>>>,
        }
        #[async_trait::async_trait]
        impl HttpClient for HeaderHttp {
            async fn send(
                &self,
                request: HttpRequest,
            ) -> Result<engine_ports::HttpResponse, HttpError> {
                self.headers
                    .lock()
                    .map(|mut h| h.push(request.headers.clone()))
                    .ok();
                Ok(engine_ports::HttpResponse {
                    status: self.status,
                    headers: Vec::new(),
                    body: self.body.clone(),
                })
            }
        }

        let key = super::super::dpop::DpopKey::generate().expect("keygen");
        let http = HeaderHttp {
            status: 200,
            body: br#"{"credential":"jwt-1"}"#.to_vec(),
            headers: std::sync::Mutex::new(Vec::new()),
        };
        let aux = CredentialRequestAux {
            auxiliary_data_to_issuer: &[],
            auxiliary_data_to_wallet: &[],
            encryption: None,
            reissuance_kid: None,
            now_unix: 1_000,
            dpop: Some(ResourceDpop {
                flow_id: "flow-1",
                key_id: None,
                key: &key,
                rng: &TestRng,
                now_unix: 1_000,
                dpop_nonce: None,
            }),
        };
        // A Bearer token: the Bearer scheme, and no DPoP header even
        // with the key available.
        request_credential(
            &http,
            &FakeHost,
            &test_metadata(),
            &test_token(),
            "X",
            "flow-1",
            Some(&aux),
            None,
        )
        .await
        .expect("request");
        let headers = http.headers.lock().expect("lock");
        let authorization = headers[0]
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone());
        assert_eq!(authorization.as_deref(), Some("Bearer at-test"));
        assert!(!headers[0].iter().any(|(n, _)| n == "DPoP"));
    }
}
