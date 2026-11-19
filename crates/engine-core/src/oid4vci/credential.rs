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
    /// The response's `format` member (OpenID4VCI 1.0 Final §7.2.2:
    /// `mso_mdoc`, `dc+sd-jwt`, …), when the issuer sends one — the
    /// single-credential shape carries it; the batch shape carries it
    /// per entry (`credentials[].format`, §7.5), and the batch fill
    /// copies the first entry's into the response. The completion's
    /// per-entry `format` (go-wallet-backend messages.go's
    /// `CredentialResult.Format`, the SDK's `CredentialResult.format`)
    /// reads it — a member the #419 SDK decode refuses to run without.
    #[serde(default)]
    pub format: Option<String>,
    /// The batch member `credentials[]` (OID4VCI §7.5's batch shape) -
    /// SUNET's GDC apigw answers a single-credential request with this
    /// array anyway, so the first entry IS the credential (found driving
    /// the GDC issuance, 2026-11-07: the engine read a flat `credential`
    /// and answered "the issuance delivered no credential" while the
    /// credential sat in `credentials[0]`). Swept off by the #11
    /// tests-out-of-src merge's conflict resolution (the branch predated
    /// 1b78321), found via the wallet-frontend wasm integration
    /// 2026-11-16 - RESTORED, and the regression test pins it.
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
    /// display data is the client's to take. The completion relays it
    /// (issue #59, the Go engine's `oid4vci_blind_response.go` parity)
    /// so the wallet's receipt check can store what the issuer
    /// delivered — the ssc seed's delivery path.
    #[serde(default)]
    pub credential_metadata: Option<serde_json::Value>,
    /// Whether this response arrived ENCRYPTED (issue #59): the
    /// completion's per-result `credential_response_encrypted` flag
    /// reads it, so the wallet knows a `to_wallet` secret travelled a
    /// response it (not the engine) opened. Not a wire member of the
    /// response — set by the fetch paths.
    #[serde(skip, default)]
    pub encrypted: bool,
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
    //
    // RESTORED 2026-11-17 (the #11 merge sweep's third instance —
    // found via the conformance suite): the sweep also took the batch
    // proof loop and, fatally for every issuance, the `answer_kid`
    // threading. The header's jwk names the key the signing-key ask
    // returned; the sign ask MUST name that same kid back — a host
    // routes sign asks by kid (the mini host, the SDK adapters), so
    // without the threading the host signs with its default key while
    // the header claims another: the suite's issuer answers 401
    // `invalid_proof: JWT signature validation failed` on every
    // credential request (the v0.2.19 conformance HAR, both variants,
    // all modules).
    //
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
                // go-wallet-backend#558's twin: the configuration this key
                // is for, so the client pairs it with the completion entry
                // carrying the same id.
                credential_configuration_id: Some(configuration_id.to_owned()),
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
                // go-wallet-backend#558's twin: this proof is one
                // configuration's credential.
                credential_configuration_id: Some(configuration_id.to_owned()),
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
            encryption.key.public_jwk().clone(),
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
            .map_err(|err| {
                // Issue #72's diagnostics: the transport failure's class.
                eprintln!(
                    "engine: credential POST to {} failed: {}",
                    credential_endpoint,
                    match &err {
                        HttpError::Refused => "refused".to_owned(),
                        HttpError::Transport(detail) => format!("transport {detail}"),
                    }
                );
                match err {
                    HttpError::Refused => {
                        CredentialError::Fetch("refused by the adapter".to_owned())
                    }
                    HttpError::Transport(detail) => CredentialError::Fetch(detail),
                }
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

    // Issue #72's diagnostics: the stall point (the engine went silent between
    // the proof and the POST on a v0.2.28 phone scan). The outcome lines name
    // the path taken; nothing of the request or response content.
    eprintln!(
        "engine: credential response for {} answered {} (encrypted={})",
        configuration_id,
        response.status,
        super::encryption::is_encrypted_response("", &response.body)
    );
    let was_encrypted = super::encryption::is_encrypted_response("", &response.body);
    let mut credential_response: CredentialResponse = if was_encrypted {
        let Some(encryption) = encryption else {
            return Err(CredentialError::EncryptedWithoutKey);
        };
        let jwe = String::from_utf8_lossy(&response.body).into_owned();
        // §7.3: the issuer MUST encrypt when the wallet offered a key;
        // a plain answer is refused (the P0.6-verified Go engine accepts
        // it; the Rust core follows the spec, and the vectors pin the
        // decision).
        if encryption.key.is_client() {
            // Issue #59's client-held key: the host holds the private
            // half, so the HOST opens the response (the Go engine's
            // `decrypt_credential_response` ask, #558's shape: the
            // configuration this response is for, `deferred` false —
            // this answers the credential request, not a deferred one).
            // The plaintext response exists only on the host; the engine
            // parses the JSON it relays back, nothing else.
            let answer = host
                .request_decrypt_credential_response(
                    engine_ports::DecryptCredentialResponseParams {
                        flow_id: flow_id.to_owned(),
                        credential_configuration_id: configuration_id.to_owned(),
                        deferred: false,
                        jwe,
                    },
                )
                .await
                .map_err(|err| CredentialError::Decrypt(err.to_string()))?;
            serde_json::from_value(answer.response).map_err(|_| CredentialError::NotJson)?
        } else {
            // The legacy engine-held key: the in-process decrypt.
            let key = engine_encryption_key(&encryption.key)
                .map_err(|err| CredentialError::Decrypt(err.to_string()))?;
            super::encryption::decrypt_encrypted_response(&jwe, key)
                .map_err(|err| CredentialError::Decrypt(err.to_string()))?
        }
    } else {
        if encryption.is_some() {
            return Err(CredentialError::PlainAfterKeyOffered);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| CredentialError::NotJson)?;
        // The conflict relay (Credential Auxiliary Data v0.1 §8, the
        // issuer's `auxiliary_data_conflict`): an entry conflicts with a
        // value the issuer holds for the subject; retrying never helps,
        // the issuer resolves it out of band. The issuer's code rides
        // unchanged under `error`; no other issuer text is relayed.
        if value.get("error").and_then(|v| v.as_str()) == Some("auxiliary_data_conflict") {
            return Err(CredentialError::AuxiliaryDataConflict);
        }
        serde_json::from_value(value).map_err(|_| CredentialError::NotJson)?
    };
    // The encrypted-arrival flag (issue #59): the completion's
    // per-result `credential_response_encrypted` reads it.
    credential_response.encrypted = was_encrypted;

    // The batch shape's credential: the first entry (this request was for
    // one configuration). See the field's doc comment.
    let credential_response = if credential_response.credential.is_none() {
        let mut filled = credential_response.clone();
        if let Some(entry) = filled.credentials.first() {
            filled.credential = entry.credential.clone();
            // The batch entry's `format` (§7.5) is the response's
            // `format` (§7.2.2) — the completion's per-entry member
            // reads it (issue #57).
            if filled.format.is_none() {
                filled.format = entry.format.clone();
            }
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
    // refuses, nothing of the content logged. ENCRYPTED responses are
    // exempt — the member is exactly what the to_wallet plan expects,
    // delivered encrypted as required (the realeyes issuer's v0.1.3 shape:
    // every encrypted answer carries it; an unconditional gate refused
    // them all, found 2026-11-18 as the wall behind the "no credential"
    // report - the decrypt path's early return never reached here, and
    // un-conditioning the gate after re-routing it did).
    if !was_encrypted {
        if let Some(metadata) = credential_response.credential_metadata.as_ref() {
            if super::auxiliary::has_auxiliary_data_member(metadata) {
                return Err(CredentialError::PlainSecret);
            }
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
/// verification) — the SDK's proof-header shape.
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
        // issuance: the credential endpoint answered 400). The #11 merge
        // sweep restored the pre-drive `key_ops` insert with its conflict
        // resolution (the branch predated 1b78321); removed again
        // 2026-11-17 with the rest of the sweep's casualties here.
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

/// The engine-held key of a [super::encryption::ResponseKey], for the
/// legacy in-process decrypt. The client-held arm never reaches the
/// decrypt: its responses open on the host (the caller matches the
/// custody first), so this reads the engine arm and nothing else.
fn engine_encryption_key(
    key: &super::encryption::ResponseKey,
) -> Result<&super::encryption::EphemeralResponseKey, CredentialError> {
    match key {
        super::encryption::ResponseKey::Engine(key) => Ok(key),
        super::encryption::ResponseKey::Client { .. } => Err(CredentialError::EncryptedWithoutKey),
    }
}
