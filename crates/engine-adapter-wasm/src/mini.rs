//! The mini host: a built-in Host implementation for driving the raw
//! engine against the OIDF certification suites — the wallet side of the
//! conformance harness (`docs/oidf-conformance.md`).
//!
//! The suites judge the wallet by its wire traffic; the host answers the
//! sub-flows so the engine's protocol is the only thing under test. The
//! mini host holds two keys: a generated P-256 device key (the OID4VCI
//! proof's signing key) and, when the plan's configuration registered
//! one, the wallet's client key (the RFC 7523 private_key_jwt
//! assertion's signing key). It auto-consents, answers the transaction
//! code from configuration, and forwards the authorization step to the
//! page so Playwright can drive the suite's AS login. It refuses
//! everything it does not implement — attestation and client-held DPoP
//! fall back to the engine's own behaviours, exactly as an SDK host
//! without those capabilities would.

use engine_ports::{
    AttestationParams, AttestationResult, ConsentParams, ConsentResult, DpopProofParams,
    DpopProofResult, Host, HostError, MatchParams, MatchResult, SignParams, SignResult, VpParams,
    VpResult,
};

use wasm_bindgen::prelude::*;

/// The ES256 P-256 software signer shape both keys use.
type Signer = kryptering::SoftwareSigner;

fn p256_signer(jwk: &jose_rs::jwk::Jwk) -> Result<Signer, String> {
    let software = jose_rs::jwk::jwk_to_software_key(jwk)
        .map_err(|err| format!("the key does not convert: {err}"))?;
    kryptering::SoftwareSigner::new(
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
        software,
    )
    .map_err(|err| format!("the key does not sign: {err}"))
}

/// The claims the mini PID carries, selectively disclosed (RFC 9901
/// §5.1): the values are fixtures — the suites check the disclosed
/// claims match the DCQL query, not the holder's actual name. The
/// EUDI PID 1.0 mandatory set the HAIP profile asks for (HAIP-6.2),
/// with the types the path modules exercise — `nationalities` an array
/// (the index and the all-elements paths select into it),
/// `place_of_birth` an object.
fn pid_claims() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("family_name", serde_json::json!("Smith")),
        ("given_name", serde_json::json!("Alice")),
        ("birthdate", serde_json::json!("1980-01-01")),
        (
            "place_of_birth",
            serde_json::json!({ "locality": "Stockholm", "region": "Stockholm", "country": "SE" }),
        ),
        ("nationalities", serde_json::json!(["SE"])),
        ("issuing_authority", serde_json::json!("Polismyndigheten")),
        ("issuing_country", serde_json::json!("SE")),
        (
            "picture",
            serde_json::json!("aGVsbG8tbWluaS1waWQtcGljdHVyZQ"),
        ),
    ]
}

/// The vct the suites' DCQL queries name.
const PID_VCT: &str = "urn:eudi:pid:1";

/// Issues the mini host's held PID: a compact SD-JWT VC (RFC 9901)
/// holder-bound to the device key, with the salted-hash disclosures of
/// the fixture claims. The trailing `~` marks the key-binding form
/// (§4.1); the harness's stand-in for a real wallet's stored
/// credential.
///
/// With a configured PID signing key (the HAIP profile demands the
/// credential carry its X.509 chain, HAIP-6.1.1), the issuer is that
/// key and the chain rides the JWS header's `x5c` (RFC 7515 §4.1.6);
/// without one, a fresh generated key signs a bare header (the plain
/// plans' form).
fn issue_mini_pid(
    device_public: &serde_json::Value,
    pid_signing: Option<&jose_rs::jwk::Jwk>,
) -> Result<String, String> {
    let issuer_key = match pid_signing {
        Some(key) => key.clone(),
        None => jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the PID issuer key generation failed: {err}"))?,
    };
    let issuer_signer = p256_signer(&issuer_key)?;
    let now = (js_sys::Date::now() / 1000.0) as i64;

    // The disclosures (§5.1): base64url of the JSON array
    // [salt, claim name, value], each digest-listed in `_sd`. The
    // digest is over the ENCODED disclosure text (§4.2.3) — the same
    // bytes `SdJwt::parse` hashes when it resolves the references.
    let mut disclosures = Vec::new();
    let mut digests = Vec::new();
    for (index, (name, value)) in pid_claims().into_iter().enumerate() {
        let salt = format!("mini-pid-salt-{now}-{index}");
        let disclosure = serde_json::json!([salt, name, value]).to_string();
        let encoded = siros_codec::base64url::encode(disclosure.as_bytes())
            .as_str()
            .to_owned();
        let digest =
            kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, encoded.as_bytes())
                .map_err(|err| format!("the disclosure digest failed: {err}"))?;
        disclosures.push(encoded);
        digests.push(siros_codec::base64url::encode(&digest).as_str().to_owned());
    }

    // The issuer JWT: the fixture claims are undisclosed; the device
    // key binds the holder (§4.2's cnf).
    let mut header = serde_json::json!({
        "typ": "dc+sd-jwt",
        "alg": "ES256",
        "kid": issuer_key.kid.clone().unwrap_or_else(|| "mini-pid-issuer".to_owned()),
    });
    // The HAIP form (HAIP-6.1.1): the credential's X.509 chain rides
    // the header (RFC 7515 §4.1.6 — standard base64 DER, unlike the
    // JOSE segments' base64url), so the verifier can validate it
    // against the profile's trust anchor.
    if let Some(chain) = pid_signing.and_then(|key| key.extra.get("x5c")) {
        // Inserted as a member, never indexed: the header is an object
        // by construction.
        if let Some(object) = header.as_object_mut() {
            object.insert("x5c".to_owned(), chain.clone());
        }
    }
    let payload = serde_json::json!({
        "iss": "https://mini-wallet.example",
        "iat": now,
        "exp": now + 31_536_000,
        "vct": PID_VCT,
        "cnf": { "jwk": device_public },
        "_sd_alg": "sha-256",
        "_sd": digests,
    });
    let header_text = siros_codec::base64url::encode(header.to_string().as_bytes())
        .as_str()
        .to_owned();
    let payload_text = siros_codec::base64url::encode(payload.to_string().as_bytes())
        .as_str()
        .to_owned();
    let tbs = format!("{header_text}.{payload_text}");
    let signature = kryptering::Signer::sign(&issuer_signer, tbs.as_bytes())
        .map_err(|err| format!("the PID signing failed: {err}"))?;

    // The compact SD-JWT: the JWT, the disclosures, the trailing `~`
    // of the key-binding form (§4.1).
    let mut pid = format!(
        "{tbs}.{}",
        siros_codec::base64url::encode(&signature).as_str()
    );
    for disclosure in disclosures {
        pid.push('~');
        pid.push_str(&disclosure);
    }
    pid.push('~');
    Ok(pid)
}

/// The doctype the mini mDL carries (ISO/IEC 18013-5, Annex A): the
/// suite's mso_mdoc DCQL queries name it in `doctype_value`.
const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
/// The namespace the mini mDL's driver-claims live in (ISO/IEC
/// 18013-5, A.1): the suite's mso_mdoc DCQL paths start with it.
const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// The mini mDL's driver claims: the mDL's mandatory family and given
/// names (ISO/IEC 18013-5, A.4.1.1), the fixtures behind the mso_mdoc
/// DCQL query's claim paths.
const MDL_CLAIMS: [(&str, &str); 2] = [("family_name", "Smith"), ("given_name", "Alice")];

/// Issues the mini host's held mDL: an `IssuerSigned` (ISO/IEC
/// 18013-5, 8.3.2.1.2.2) with the MSO (9.1.2) the fixture issuer
/// signs, its `valueDigests` listing the items, the device key bound
/// as the MSO's `deviceKey`, and the issuer's `COSE_Sign1`
/// (`issuerAuth`, 9.1.2.4) carrying the fixture issuer's `x5chain`
/// (RFC 9360 §2) — the base64url of the `IssuerSigned` CBOR, the form
/// `Mdoc::parse` reads back.
fn issue_mini_mdl(
    device_public: &serde_json::Value,
    issuer_signing: Option<&jose_rs::jwk::Jwk>,
) -> Result<String, String> {
    let now = (js_sys::Date::now() / 1000.0) as i64;
    // The device key's COSE_Key coordinates (EC2: {1: 2, -1: 1, -2: x,
    // -3: y}, RFC 9053 §2): the 32-byte big-endian coordinates of the
    // bound device key.
    let coordinate = |name: &str| -> Result<Vec<u8>, String> {
        device_public
            .get(name)
            .and_then(|v| v.as_str())
            .and_then(|encoded| {
                let bytes = siros_codec::base64url::decode(encoded).ok()?;
                <[u8; 32]>::try_from(bytes.as_slice()).ok()
            })
            .map(|coordinate| coordinate.to_vec())
            .ok_or_else(|| format!("the device key's {name} does not parse"))
    };
    let x = coordinate("x")?;
    let y = coordinate("y")?;

    let time = siros_codec::date::DateTime::from_unix(now)
        .ok_or_else(|| "the clock is out of range".to_owned())?;
    // The MSO's validity: 180 days — strictly inside the fixture DS
    // certificate's own validity (ISO/IEC 18013-5 §9.3.1: an mdoc reader
    // may reject a credential whose validUntil exceeds the document
    // signer certificate's notAfter).
    let until = siros_codec::date::DateTime::from_unix(now + 15_552_000)
        .ok_or_else(|| "the clock is out of range".to_owned())?;
    let date = |t: siros_codec::date::DateTime| {
        // validityInfo's FullDate (ISO/IEC 18013-5, 9.1.2.4): tag 0, a
        // `YYYY-MM-DDThh:mm:ssZ` text.
        siros_codec::cbor::Value::Tag(0, Box::new(siros_codec::cbor::Value::Text(t.to_string())))
    };

    // The items (8.3.2.1.2.2, Table 5): digestID, random,
    // elementIdentifier, elementValue — each `#6.24(bstr .cbor
    // IssuerSignedItem)` in its namespace's array, its digest in the
    // MSO's valueDigests.
    let mut items = Vec::new();
    let mut digests = Vec::new();
    for (index, (name, value)) in MDL_CLAIMS.iter().enumerate() {
        let random: Vec<u8> = (0..16)
            .map(|byte| (now.wrapping_mul(index as i64 + byte as i64)) as u8)
            .collect();
        let item = siros_codec::cbor::Value::Map(vec![
            (
                siros_codec::cbor::Value::text("digestID"),
                siros_codec::cbor::Value::Unsigned(index as u64),
            ),
            (
                siros_codec::cbor::Value::text("random"),
                siros_codec::cbor::Value::Bytes(random),
            ),
            (
                siros_codec::cbor::Value::text("elementIdentifier"),
                siros_codec::cbor::Value::Text((*name).to_owned()),
            ),
            (
                siros_codec::cbor::Value::text("elementValue"),
                siros_codec::cbor::Value::Text((*value).to_owned()),
            ),
        ]);
        let item = siros_codec::cbor::Value::Tag(
            24,
            Box::new(siros_codec::cbor::Value::Bytes(item.encode())),
        );
        let digest =
            kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, item.encode().as_slice())
                .map_err(|err| format!("the item digest failed: {err}"))?;
        items.push(item);
        digests.push((index as u64, digest));
    }

    // The MSO (9.1.2): the docType, SHA-256, the device key, the
    // valueDigests, the validity.
    let mso = siros_codec::cbor::Value::Map(vec![
        (
            siros_codec::cbor::Value::text("version"),
            siros_codec::cbor::Value::text("1.0"),
        ),
        (
            siros_codec::cbor::Value::text("docType"),
            siros_codec::cbor::Value::Text(MDL_DOCTYPE.to_owned()),
        ),
        (
            siros_codec::cbor::Value::text("digestAlgorithm"),
            siros_codec::cbor::Value::Text("SHA-256".to_owned()),
        ),
        (
            siros_codec::cbor::Value::text("deviceKeyInfo"),
            siros_codec::cbor::Value::Map(vec![(
                siros_codec::cbor::Value::text("deviceKey"),
                // COSE_Key (RFC 9053 §2): {1: kty = 2 (EC2), -1: crv =
                // 1 (P-256), -2: x, -3: y}.
                siros_codec::cbor::Value::Map(vec![
                    (
                        siros_codec::cbor::Value::Unsigned(1),
                        siros_codec::cbor::Value::Unsigned(2),
                    ),
                    (
                        siros_codec::cbor::Value::Negative(0),
                        siros_codec::cbor::Value::Unsigned(1),
                    ),
                    (
                        siros_codec::cbor::Value::Negative(1),
                        siros_codec::cbor::Value::Bytes(x),
                    ),
                    (
                        siros_codec::cbor::Value::Negative(2),
                        siros_codec::cbor::Value::Bytes(y),
                    ),
                ]),
            )]),
        ),
        (
            siros_codec::cbor::Value::text("valueDigests"),
            siros_codec::cbor::Value::Map(vec![(
                siros_codec::cbor::Value::Text(MDL_NAMESPACE.to_owned()),
                siros_codec::cbor::Value::Map(
                    digests
                        .into_iter()
                        .map(|(id, digest)| {
                            (
                                siros_codec::cbor::Value::Unsigned(id),
                                siros_codec::cbor::Value::Bytes(digest),
                            )
                        })
                        .collect(),
                ),
            )]),
        ),
        (
            siros_codec::cbor::Value::text("validityInfo"),
            siros_codec::cbor::Value::Map(vec![
                (siros_codec::cbor::Value::text("signed"), date(time)),
                (siros_codec::cbor::Value::text("validFrom"), date(time)),
                (siros_codec::cbor::Value::text("validUntil"), date(until)),
            ]),
        ),
    ]);
    // MobileSecurityObjectBytes = #6.24(bstr .cbor MSO) (9.1.2.1).
    let payload =
        siros_codec::cbor::Value::Tag(24, Box::new(siros_codec::cbor::Value::Bytes(mso.encode())))
            .encode();

    // The fixture issuer: the PID's signing key when the harness
    // carries one (the HAIP form's x5c chain rides issuerAuth);
    // without one a fresh generated key signs a chainless issuerAuth.
    let issuer_key = match issuer_signing {
        Some(key) => key.clone(),
        None => jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the mDL issuer key generation failed: {err}"))?,
    };
    let issuer_signer = p256_signer(&issuer_key)?;

    // issuerAuth = COSE_Sign1 (9.1.2.4): the protected header {alg: -7}
    // (ES256; major type 1 encodes -1-n, so -7 is content 6), the x5chain
    // at label 33 (RFC 9360 §2) when the issuer key carries one, the
    // tagged MSO as the payload, and the ES256 signature over the
    // Sig_structure ["Signature1", protected, external_aad = h'', payload]
    // (RFC 9052 §4.4).
    let protected = siros_codec::cbor::Value::Map(vec![(
        siros_codec::cbor::Value::Unsigned(1),
        siros_codec::cbor::Value::Negative(6),
    )])
    .encode();
    let mut unprotected = Vec::new();
    if let Some(chain) = issuer_key.extra.get("x5c").and_then(|v| v.as_array()) {
        // The x5c entries are standard-base64 DER (RFC 7515 §4.1.6),
        // unlike the JOSE segments' base64url.
        let certificates: Vec<siros_codec::cbor::Value> = chain
            .iter()
            .filter_map(|der| {
                der.as_str()
                    .and_then(|text| siros_codec::base64::decode(text).ok())
                    .map(siros_codec::cbor::Value::Bytes)
            })
            .collect();
        if !certificates.is_empty() {
            unprotected.push((
                siros_codec::cbor::Value::Unsigned(33),
                siros_codec::cbor::Value::Array(certificates),
            ));
        }
    }
    // The Sig_structure (RFC 9052 §4.4): ["Signature1", protected,
    // external_aad = h'', payload] — the protected header and the
    // payload as they appear in the COSE_Sign1, bstr headers
    // included (the verifier signs over the same concatenation).
    let protected_bstr = siros_codec::cbor::Value::Bytes(protected.clone()).encode();
    let payload_bstr = siros_codec::cbor::Value::Bytes(payload.clone()).encode();
    let sig_structure = [
        &[0x84, 0x6a][..],
        b"Signature1",
        protected_bstr.as_slice(),
        &[0x40][..],
        payload_bstr.as_slice(),
    ]
    .concat();
    let signature = kryptering::Signer::sign(&issuer_signer, &sig_structure)
        .map_err(|err| format!("the mDL issuerAuth signing failed: {err}"))?;
    let issuer_auth = siros_codec::cbor::Value::Array(vec![
        siros_codec::cbor::Value::Bytes(protected),
        siros_codec::cbor::Value::Map(unprotected),
        siros_codec::cbor::Value::Bytes(payload),
        siros_codec::cbor::Value::Bytes(signature),
    ]);

    // IssuerSigned (8.3.2.1.2.2): the nameSpaces and the issuerAuth.
    let issuer_signed = siros_codec::cbor::Value::Map(vec![
        (
            siros_codec::cbor::Value::text("nameSpaces"),
            siros_codec::cbor::Value::Map(vec![(
                siros_codec::cbor::Value::Text(MDL_NAMESPACE.to_owned()),
                siros_codec::cbor::Value::Array(items),
            )]),
        ),
        (siros_codec::cbor::Value::text("issuerAuth"), issuer_auth),
    ])
    .encode();
    let encoded = siros_codec::base64url::encode(&issuer_signed);
    // The round trip: what the host hands out must parse back.
    siros_mdoc::Mdoc::parse(encoded.as_str())
        .map_err(|err| format!("the issued mDL does not parse: {err}"))?;
    Ok(encoded.as_str().to_owned())
}

/// The built-in mini host: `{"host": "mini"}` in the engine config
/// selects it.
pub struct MiniHost {
    /// The device key's public JWK (the plan's key registration and the
    /// tests' verification).
    key: jose_rs::jwk::Jwk,
    /// The device key's signer — the OID4VCI proof's and the KB-JWT's
    /// signing key.
    signer: Signer,
    /// The held PID: a self-issued SD-JWT VC (RFC 9901) with the claims
    /// the suites' DCQL queries ask for, holder-bound to the device key
    /// — the harness's stand-in for a credential a real wallet holds
    /// from its issuer. The presentation's structure and key binding
    /// are what the suites validate; the engine's OID4VP protocol is
    /// the thing under test.
    pid: String,
    /// The held mDL: a self-issued mso_mdoc (ISO/IEC 18013-5) with the
    /// driver claims the mso_mdoc DCQL queries ask for, the device key
    /// bound as its MSO's deviceKey — the mdoc presentation's answers
    /// (the `DeviceResponse` of ISO/IEC 18013-5, 8.3.2.1.2.2). None when
    /// no PID signing key is configured: the mdoc parser requires the
    /// issuerAuth's x5chain, which only the configured fixture issuer
    /// carries, so a harness without it simply holds no mdoc (the
    /// mso_mdoc queries match nothing), rather than refusing to start.
    mdl: Option<String>,
    /// The wallet's registered client key, when the plan's
    /// configuration supplies one: the private_key_jwt assertion's
    /// signing key.
    client_signer: Option<Signer>,
    /// The client key's kid — how the assertion's sign ask names the
    /// key (the registered kid, e.g. `client-key-1`).
    client_key_kid: Option<String>,
    /// The client key's public JWK — the signing-key ask's answer when
    /// the engine identifies the client key in a proof header.
    client_key: Option<serde_json::Value>,
    /// The transaction code the plan's issuer expects (the OIDF suite
    /// publishes it in the plan configuration).
    tx_code: String,
    /// The page's authorization callback: `(url) => Promise<void>` —
    /// navigate, and the suite's AS redirects back to the page.
    open_authorization: Option<js_sys::Function>,
}

impl MiniHost {
    /// Generates the device key and binds the configuration.
    pub fn new(
        tx_code: String,
        client_key_jwk: Option<String>,
        pid_signing_jwk: Option<String>,
        open_authorization: Option<js_sys::Function>,
    ) -> Result<Self, String> {
        let key = jose_rs::jwk::generate::generate_ec("P-256")
            .map_err(|err| format!("the device key generation failed: {err}"))?;
        let signer = p256_signer(&key)?;

        let (client_signer, client_key_kid, client_key) = match client_key_jwk {
            Some(jwk) => {
                let jwk: jose_rs::jwk::Jwk = serde_json::from_str(&jwk)
                    .map_err(|err| format!("the client key does not parse: {err}"))?;
                let kid = jwk.kid.clone();
                // The public form: the private member never leaves the
                // host (the engine only ever sees the public JWK).
                let public = jwk.to_public_jwk();
                let text = public.to_json().unwrap_or_default();
                let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                (Some(p256_signer(&jwk)?), kid, Some(value))
            }
            None => (None, None, None),
        };

        // The PID's signing key, when the harness carries one: the HAIP
        // profile's x5c-chained credential (HAIP-6.1.1). A test
        // harness key — the chain validates to the trust anchor the
        // plan's configuration carries.
        let pid_signing = match pid_signing_jwk {
            Some(jwk) => {
                let jwk: jose_rs::jwk::Jwk = serde_json::from_str(&jwk)
                    .map_err(|err| format!("the PID signing key does not parse: {err}"))?;
                Some(jwk)
            }
            None => None,
        };

        // The held PID: the device key's public JWK binds the holder.
        let public = key.to_public_jwk();
        let public_text = public.to_json().unwrap_or_default();
        let device_public: serde_json::Value =
            serde_json::from_str(&public_text).unwrap_or_default();
        let pid = issue_mini_pid(&device_public, pid_signing.as_ref())?;
        // The held mDL: best-effort — a harness with no PID signing key
        // (no x5c chain for the issuerAuth) holds no mdoc; the mso_mdoc
        // queries then match nothing, but the host starts (the SD-JWT
        // presentations work without it).
        let mdl = issue_mini_mdl(&device_public, pid_signing.as_ref()).ok();

        Ok(Self {
            key,
            signer,
            pid,
            mdl,
            client_signer,
            client_key_kid,
            client_key,
            tx_code,
            open_authorization,
        })
    }

    /// The device key's public JWK — for the plan's key registration, if
    /// the suite asks for it.
    pub fn public_jwk(&self) -> serde_json::Value {
        let public = self.key.to_public_jwk();
        let text = public.to_json().unwrap_or_default();
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Presents the held mDL for one selection: the `DeviceResponse`
    /// (ISO/IEC 18013-5, 8.3.2.1.2.2) of the selected items, bound to
    /// the request by the device key's ES256 signature over the
    /// session transcript of the `OpenID4VPHandover` (OpenID4VP 1.0,
    /// B.2.6.1) — `[null, null, ["OpenID4VPHandover",
    /// SHA-256(cbor([client_id, nonce, thumb|null, response_uri]))]]`,
    /// base64url-encoded.
    fn present_mdl(
        &self,
        params: &VpParams,
        selection: &engine_ports::VpSelection,
    ) -> Result<String, HostError> {
        let mdl = self
            .mdl
            .as_deref()
            .and_then(|encoded| siros_mdoc::Mdoc::parse(encoded).ok())
            .ok_or_else(|| {
                HostError::Cannot("the mini host holds no mdoc (no PID signing key)".to_owned())
            })?;
        // The selected elements: the paths' [namespace, claim name]
        // pairs.
        let mut selected: Vec<(String, String)> = Vec::new();
        for claim in &selection.disclosed_claims {
            let path: Vec<String> = serde_json::from_str(claim).map_err(|_| {
                HostError::Cannot(format!("the disclosed claim {claim:?} is no §7 path"))
            })?;
            // The path components: keys — a namespace then a claim
            // name for mdoc (OpenID4VP 1.0, B.4.1); anything else
            // is no mdoc element.
            let Some((name_space, identifier)) = path.first().zip(path.get(1)) else {
                return Err(HostError::Cannot(format!(
                    "the mdoc claim path {claim:?} is not a [namespace, claim] pair"
                )));
            };
            selected.push((name_space.clone(), identifier.clone()));
        }
        let elements: Vec<siros_mdoc::ElementId<'_>> = selected
            .iter()
            .map(|(name_space, identifier)| siros_mdoc::ElementId {
                name_space,
                identifier,
            })
            .collect();
        let disclosure = mdl
            .disclose(&elements, Vec::new())
            .map_err(|err| HostError::Cannot(format!("the mdoc disclosure: {err}")))?;

        // The OpenID4VPHandover (B.2.6.1): ["OpenID4VPHandover",
        // SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]
        // — the thumbprint of the verifier's encryption key for an
        // encrypted response (`direct_post.jwt`), `null` otherwise. The
        // engine hands it over base64url; the handover carries the raw
        // digest.
        let mut thumbprint = siros_codec::cbor::Value::Null;
        if !params.verifier_jwk_thumbprint.is_empty() {
            let digest =
                siros_codec::base64url::decode(&params.verifier_jwk_thumbprint).map_err(|err| {
                    HostError::Cannot(format!("the thumbprint does not decode: {err}"))
                })?;
            thumbprint = siros_codec::cbor::Value::Bytes(digest);
        }
        let info = siros_codec::cbor::Value::Array(vec![
            siros_codec::cbor::Value::text(&params.audience),
            siros_codec::cbor::Value::text(&params.nonce),
            thumbprint,
            siros_codec::cbor::Value::text(&params.response_uri),
        ]);
        let handover_digest =
            kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, info.encode().as_slice())
                .map_err(|err| HostError::Cannot(format!("the handover digest: {err}")))?;
        let handover = siros_codec::cbor::Value::Array(vec![
            siros_codec::cbor::Value::text("OpenID4VPHandover"),
            siros_codec::cbor::Value::Bytes(handover_digest),
        ]);
        // SessionTranscript = [null, null, Handover] (B.2.6).
        let transcript = siros_codec::cbor::Value::Array(vec![
            siros_codec::cbor::Value::Null,
            siros_codec::cbor::Value::Null,
            handover,
        ]);
        let session = siros_mdoc::SessionTranscript::new(transcript.encode());

        // The device signature: the device key — the MSO's deviceKey —
        // signs the DeviceAuthentication (ISO/IEC 18013-5, 8.3.2.1.2.2).
        let signing_input = disclosure.signing_input(&session);
        let signature = kryptering::Signer::sign(&self.signer, signing_input.as_bytes())
            .map_err(|err| HostError::Cannot(format!("the mDL device signing failed: {err}")))?;
        let signature = siros_codec::signature::Es256Signature::parse(&signature)
            .map_err(|err| HostError::Cannot(format!("the mDL device signature: {err}")))?;
        let response = disclosure.device_response(&signature);
        let encoded = siros_codec::base64url::encode(&response);
        Ok(encoded.as_str().to_owned())
    }
}

#[async_trait::async_trait]
impl Host for MiniHost {
    /// Signs what the engine built: the OID4VCI proof's TBS with the
    /// device key, the RFC 7523 client assertion's TBS (key id
    /// `client-auth`) with the registered client key — the same
    /// division the real SDK has, with the keystore replaced by the
    /// mini host's pairs.
    async fn request_sign(&self, params: SignParams) -> Result<SignResult, HostError> {
        // The key id routes: the engine asks for the registered kid
        // (or the conventional client-auth name) when the client
        // assertion needs the client key; anything else is the device
        // key (the OID4VCI proof).
        let use_client =
            params
                .key_id
                .as_deref()
                .is_some_and(|id| match self.client_key_kid.as_deref() {
                    Some(kid) => id == kid,
                    None => id == engine_core::oid4vci::token::CLIENT_AUTH_KEY_ID,
                });
        let signer = if use_client {
            self.client_signer.as_ref().ok_or_else(|| {
                HostError::Cannot("the mini host carries no client key".to_owned())
            })?
        } else {
            &self.signer
        };
        let signature = kryptering::Signer::sign(signer, &params.to_sign)
            .map_err(|err| HostError::Cannot(format!("the key refused: {err}")))?;
        Ok(SignResult { signature })
    }

    /// The signing-key ask: the public JWK of the key the engine is
    /// about to sign with, so the proof header can identify it (the
    /// public JWK + the RFC 7638 thumbprint kid). The key routes the
    /// same way request_sign routes — the registered client kid or
    /// the conventional client-auth name answers the client key,
    /// anything else the device key.
    async fn request_signing_key(
        &self,
        params: engine_ports::SigningKeyParams,
    ) -> Result<engine_ports::SigningKeyResult, HostError> {
        let use_client =
            params
                .key_id
                .as_deref()
                .is_some_and(|id| match self.client_key_kid.as_deref() {
                    Some(kid) => id == kid,
                    None => id == engine_core::oid4vci::token::CLIENT_AUTH_KEY_ID,
                });
        // A FRESH key ask (the OID4VCI batch rule): generate one for this
        // ask alone — each credential in a batch binds to its own key
        // (SDJWT-10.1, the suite's VCIEnsureProofKeysAreDistinct).
        if params.fresh {
            let key = jose_rs::jwk::generate_ec("P-256")
                .map_err(|e| HostError::Cannot(e.to_string()))?;
            let text = key.to_public_jwk().to_json().map_err(|e| HostError::Cannot(e.to_string()))?;
            return Ok(engine_ports::SigningKeyResult {
                jwk: serde_json::from_str(&text)
                    .map_err(|e| HostError::Cannot(e.to_string()))?,
            });
        }
        let jwk = if use_client {
            self.client_key.clone().ok_or_else(|| {
                HostError::Cannot("the mini host carries no client key".to_owned())
            })?
        } else {
            self.public_jwk()
        };
        Ok(engine_ports::SigningKeyResult { jwk })
    }

    /// The match: the held PID against the DCQL query. A query for the
    /// dc+sd-jwt PID (the vct the mini credential carries) selects it
    /// with the claims the query names; anything else matches
    /// nothing, and the flow ends without an error — the engine's
    /// empty-selection contract.
    async fn request_match(&self, params: MatchParams) -> Result<MatchResult, HostError> {
        let Some(query) = params.dcql_query.as_ref() else {
            return Ok(MatchResult::default());
        };
        let Some(queries) = query.get("credentials").and_then(|c| c.as_array()) else {
            return Ok(MatchResult::default());
        };
        let mut selections = Vec::new();
        for entry in queries {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let format = entry.get("format").and_then(|v| v.as_str());
            let vct_matches = entry
                .pointer("/meta/vct_values")
                .and_then(|v| v.as_array())
                .is_some_and(|values| values.iter().any(|v| v.as_str() == Some(PID_VCT)));
            // The mso_mdoc DCQL query (OpenID4VP 1.0, B.4.1): the
            // doctype the mDL carries selects it, and the paths are
            // [namespace, claim name] pairs.
            let doctype_matches = entry
                .pointer("/meta/doctype_value")
                .and_then(|v| v.as_str())
                .is_some_and(|doctype| doctype == MDL_DOCTYPE);
            let (credential_id, matches) = match format {
                Some("dc+sd-jwt") if vct_matches => ("mini-pid", true),
                // Only when the mdoc is held: a harness with no PID
                // signing key matches nothing for mso_mdoc.
                Some("mso_mdoc") if doctype_matches && self.mdl.is_some() => ("mini-mdl", true),
                _ => ("", false),
            };
            if !matches {
                continue;
            }
            // The claims the query asks for, as the paths the
            // presentation selects. The path rides JSON-encoded — the
            // components are keys, indices and nulls (§7), and a dotted
            // join would drop the non-string ones.
            let mut disclosed_claims = Vec::new();
            if let Some(claims) = entry.get("claims").and_then(|v| v.as_array()) {
                for claim in claims {
                    if let Some(path) = claim.get("path") {
                        if path.as_array().is_some_and(|p| !p.is_empty()) {
                            disclosed_claims.push(path.to_string());
                        }
                    }
                }
            }
            selections.push(engine_ports::VpSelection {
                credential_query_id: id,
                credential_id: credential_id.to_owned(),
                disclosed_claims,
            });
        }
        Ok(MatchResult {
            selections,
            // The mini host has no transport handle: the ask is
            // answered in-process.
            handle: None,
        })
    }

    /// The presentation: the held PID's SD-JWT with the selected
    /// disclosures and the KB-JWT binding it to the verifier's
    /// audience and nonce (RFC 9901 §7) — signed by the device key,
    /// the credential's holder. One token per selection, the engine's
    /// DCQL vp_token contract (OID4VP §8.1).
    async fn request_vp(&self, params: VpParams) -> Result<VpResult, HostError> {
        let now = (js_sys::Date::now() / 1000.0) as i64;
        let time = siros_codec::date::DateTime::from_unix(now)
            .ok_or_else(|| HostError::Cannot("the clock is out of range".to_owned()))?;
        let iat = siros_sdjwt::NumericDate::of(time)
            .map_err(|err| HostError::Cannot(format!("the iat is out of range: {err}")))?;
        let audience = siros_sdjwt::Audience::new(&params.audience);
        let nonce = siros_sdjwt::KbNonce::new(&params.nonce);

        let mut tokens = Vec::new();
        for selection in &params.selections {
            // The mdoc presentation (OpenID4VP 1.0, B.4): the mso_mdoc
            // answer is a `DeviceResponse` (ISO/IEC 18013-5, 8.3.2.1.2.2)
            // — the selected items, the issuerAuth as issued, and the
            // device key's ES256 signature over the session transcript
            // of the request's OpenID4VPHandover (B.2.6.1) — base64url.
            if selection.credential_id == "mini-mdl" {
                tokens.push(self.present_mdl(&params, selection)?);
                continue;
            }
            let sd_jwt = siros_sdjwt::SdJwt::parse(&self.pid)
                .map_err(|err| HostError::Cannot(format!("the held PID does not parse: {err}")))?;
            // The disclosed claims' paths, as the DCQL names them: the
            // JSON-encoded component arrays — keys, indices and nulls
            // (§7) all preserved.
            let mut pointers = Vec::new();
            for claim in &selection.disclosed_claims {
                let components: Vec<siros_dcql::PathComponent> = serde_json::from_str(claim)
                    .ok()
                    .and_then(|value: serde_json::Value| {
                        let array = value.as_array()?;
                        if array.is_empty() {
                            return None; // §7: a pointer MUST be non-empty
                        }
                        let mut components = Vec::new();
                        for component in array {
                            match component {
                                serde_json::Value::String(key) => {
                                    components.push(siros_dcql::PathComponent::Key(key.clone()));
                                }
                                serde_json::Value::Number(index) => {
                                    let index = index.as_u64()?; // a negative index is no §7 component
                                    components.push(siros_dcql::PathComponent::Index(index));
                                }
                                serde_json::Value::Null => {
                                    components.push(siros_dcql::PathComponent::Null);
                                }
                                _ => return None, // not a §7 component
                            }
                        }
                        Some(components)
                    })
                    .ok_or_else(|| {
                        HostError::Cannot(format!("the disclosed claim {claim:?} is no §7 path"))
                    })?;
                let path = siros_dcql::ClaimPath::new(components)
                    .map_err(|err| HostError::Cannot(format!("the claim path: {err}")))?;
                pointers.push(path);
            }
            let presentation = sd_jwt
                .select(&pointers)
                .map_err(|err| HostError::Cannot(format!("the disclosure selection: {err}")))?;
            let key_binding = presentation
                .key_binding(iat, &audience, &nonce, &[])
                .map_err(|err| HostError::Cannot(format!("the key binding: {err}")))?;
            // The KB-JWT's signature: the device key — the holder.
            let signature = kryptering::Signer::sign(&self.signer, key_binding.signing_input())
                .map_err(|err| HostError::Cannot(format!("the KB-JWT signing failed: {err}")))?;
            let signature = siros_codec::signature::Es256Signature::parse(&signature)
                .map_err(|err| HostError::Cannot(format!("the KB-JWT signature: {err}")))?;
            tokens.push(key_binding.assemble(&signature));
        }
        Ok(VpResult {
            vp_token: tokens.join("\n"),
            refusal: None,
        })
    }

    /// Consent: automatic. The suites test the wallet's protocol, not a
    /// person's judgement; a decline variant would come from the page's
    /// own callback.
    async fn request_consent(&self, _params: ConsentParams) -> Result<ConsentResult, HostError> {
        Ok(ConsentResult { consented: true })
    }

    /// The transaction code from configuration — the plan's issuer
    /// publishes the code it will accept.
    async fn request_tx_code(&self, _flow_id: &str) -> Result<String, HostError> {
        if self.tx_code.is_empty() {
            return Err(HostError::Cannot(
                "the mini host has no transaction code configured".to_owned(),
            ));
        }
        Ok(self.tx_code.clone())
    }

    /// The authorization step: forwarded to the page, whose callback
    /// navigates — the suite's AS shows its login, Playwright answers
    /// it, and the redirect returns to the page with the code.
    async fn open_authorization(&self, _flow_id: &str, url: &str) -> Result<(), HostError> {
        let Some(callback) = &self.open_authorization else {
            return Err(HostError::Cannot(
                "the mini host has no authorization callback".to_owned(),
            ));
        };
        let callback = callback.clone();
        let url = url.to_owned();
        crate::ports::await_js(crate::ports::spawn_js(async move {
            let value = serde_wasm_bindgen::to_value(&url)
                .map_err(|err| format!("serialize the url: {err}"))?;
            let promise = callback
                .call1(&JsValue::NULL, &value)
                .map_err(|err| format!("the callback refused: {err:?}"))?;
            wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise))
                .await
                .map(|_| ())
                .map_err(|err| format!("the navigation failed: {err:?}"))
        }))
        .await
        .and_then(|inner| inner)
        .map_err(HostError::Cannot)
    }

    /// Client-held DPoP: refused — the engine falls back to its own
    /// ephemeral key, which the suites accept.
    async fn request_dpop_proof(
        &self,
        _params: DpopProofParams,
    ) -> Result<DpopProofResult, HostError> {
        Err(HostError::Cannot(
            "the mini host holds no DPoP key".to_owned(),
        ))
    }

    /// Attestation: refused — the flow proceeds without, and an issuer
    /// that requires it rejects on its own (the suites' test issuers do
    /// not).
    async fn request_attestation(
        &self,
        _params: AttestationParams,
    ) -> Result<AttestationResult, HostError> {
        Err(HostError::Cannot(
            "the mini host carries no wallet instance attestation".to_owned(),
        ))
    }

    /// Progress: swallowed. The page observes the flow through the
    /// resolved request promises; the suites see only the wire.
    fn progress(&self, _flow_id: &str, _step: &str, _detail: Option<String>) {}
}

/// The Arc helper the dispatcher's ports need.
pub fn arc(host: MiniHost) -> std::sync::Arc<dyn engine_ports::Host> {
    std::sync::Arc::new(host)
}
