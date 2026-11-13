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

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ciborium::Value as Cbor;
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
    // digest is over the ENCODED disclosure text (§4.2.3) — the bytes a
    // verifier hashes when it resolves the references.
    let mut disclosures = Vec::new();
    let mut digests = Vec::new();
    for (index, (name, value)) in pid_claims().into_iter().enumerate() {
        let salt = format!("mini-pid-salt-{now}-{index}");
        let disclosure = serde_json::json!([salt, name, value]).to_string();
        let encoded = URL_SAFE_NO_PAD.encode(disclosure.as_bytes());
        let digest =
            kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, encoded.as_bytes())
                .map_err(|err| format!("the disclosure digest failed: {err}"))?;
        disclosures.push(encoded);
        digests.push(URL_SAFE_NO_PAD.encode(&digest));
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
    let header_text = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_text = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let tbs = format!("{header_text}.{payload_text}");
    let signature = kryptering::Signer::sign(&issuer_signer, tbs.as_bytes())
        .map_err(|err| format!("the PID signing failed: {err}"))?;

    // The compact SD-JWT: the JWT, the disclosures, the trailing `~`
    // of the key-binding form (§4.1).
    let mut pid = format!("{tbs}.{}", URL_SAFE_NO_PAD.encode(&signature));
    for disclosure in disclosures {
        pid.push('~');
        pid.push_str(&disclosure);
    }
    pid.push('~');
    Ok(pid)
}

/// The KB-JWT's header (RFC 9901 §4.3): ES256, the device key's
/// algorithm.
const KB_HEADER: &str = r#"{"typ":"kb+jwt","alg":"ES256"}"#;

/// The held PID as presented to a verifier (RFC 9901 §4): the issuer
/// JWT, then the disclosures `claims` select in their order, each once
/// and followed by `~`, then the KB-JWT (§4.3) over `iat`, the
/// verifier's `audience` and `nonce`, and the `sd_hash` of what precedes
/// it under the PID's `_sd_alg`, sha-256. Each claim is a claims path
/// (OpenID4VP §7) JSON-encoded: its first component names the PID's
/// claim whose disclosure is presented, and the rest resolve inside
/// that claim's value (a key of an object, an index of an array, null
/// for every element of an array). `sign` signs the KB-JWT's signing
/// input with the holder's key and answers ES256's 64-octet `r ‖ s`
/// (RFC 7518 §3.4). Refused when the PID is not in the key-binding
/// form, a disclosure is no `[salt, name, value]` array (§4.2.1), a
/// claim is no §7 path, or the PID holds no claim at a path.
fn present_mini_pid(
    pid: &str,
    claims: &[String],
    iat: u64,
    audience: &str,
    nonce: &str,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    let Some(form) = pid.strip_suffix('~') else {
        return Err("the held PID is not in the key-binding form (§4.1)".to_owned());
    };
    let (jwt, encoded) = match form.split_once('~') {
        Some((jwt, disclosures)) => (jwt, disclosures.split('~').collect()),
        None => (form, Vec::new()),
    };
    let mut named = Vec::new();
    for disclosure in encoded {
        let bytes = URL_SAFE_NO_PAD
            .decode(disclosure)
            .map_err(|err| format!("a disclosure of the held PID is no base64url: {err}"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|err| format!("a disclosure of the held PID is no JSON: {err}"))?;
        let Some([_, serde_json::Value::String(name), claim]) = value.as_array().map(Vec::as_slice)
        else {
            return Err(
                "a disclosure of the held PID is no [salt, name, value] array (§4.2.1)".to_owned(),
            );
        };
        named.push((name.clone(), claim.clone(), disclosure));
    }

    let mut presented = format!("{jwt}~");
    let mut chosen: Vec<&str> = Vec::new();
    for claim in claims {
        let path = claims_path(claim)
            .ok_or_else(|| format!("the disclosed claim {claim} is no §7 claims path"))?;
        let Some((_, _, disclosure)) = named.iter().find(|(name, value, _)| {
            matches!(path.split_first(), Some((serde_json::Value::String(first), rest))
                if first == name && resolves(value, rest))
        }) else {
            return Err(format!("the held PID holds no claim at {claim}"));
        };
        let disclosure = *disclosure;
        if !chosen.contains(&disclosure) {
            chosen.push(disclosure);
            presented.push_str(disclosure);
            presented.push('~');
        }
    }

    let sd_hash =
        kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, presented.as_bytes())
            .map_err(|err| format!("the sd_hash digest failed: {err}"))?;
    let payload = serde_json::json!({
        "iat": iat,
        "aud": audience,
        "nonce": nonce,
        "sd_hash": URL_SAFE_NO_PAD.encode(&sd_hash),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(KB_HEADER),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let signature = sign(signing_input.as_bytes())?;
    if signature.len() != 64 {
        return Err(format!(
            "the KB-JWT signature has {} octets, where ES256's has 64",
            signature.len()
        ));
    }
    presented.push_str(&signing_input);
    presented.push('.');
    presented.push_str(&URL_SAFE_NO_PAD.encode(&signature));
    Ok(presented)
}

/// A claims path (OpenID4VP §7) from its JSON encoding: a non-empty
/// array of string keys, non-negative integer indices and nulls.
fn claims_path(encoded: &str) -> Option<Vec<serde_json::Value>> {
    let components = match serde_json::from_str(encoded).ok()? {
        serde_json::Value::Array(components) if !components.is_empty() => components,
        _ => return None,
    };
    components
        .iter()
        .all(|component| match component {
            serde_json::Value::String(_) | serde_json::Value::Null => true,
            serde_json::Value::Number(index) => index.as_u64().is_some(),
            _ => false,
        })
        .then_some(components)
}

/// Whether the rest of a claims path selects an element inside a claim's
/// value, processed as OpenID4VP §7.2 does: a key selects each selected
/// object's member, an index each selected array's element, null every
/// element of each selected array; an element missing its key or index
/// leaves the selection, an element of another type ends it, and an
/// empty selection at the end selects nothing.
fn resolves(value: &serde_json::Value, rest: &[serde_json::Value]) -> bool {
    let mut selected = vec![value];
    for component in rest {
        let mut next = Vec::new();
        for item in selected {
            match (component, item) {
                (serde_json::Value::String(key), serde_json::Value::Object(members)) => {
                    next.extend(members.get(key));
                }
                (serde_json::Value::Number(index), serde_json::Value::Array(items)) => {
                    next.extend(
                        index
                            .as_u64()
                            .and_then(|index| usize::try_from(index).ok())
                            .and_then(|index| items.get(index)),
                    );
                }
                (serde_json::Value::Null, serde_json::Value::Array(items)) => next.extend(items),
                _ => return false,
            }
        }
        selected = next;
    }
    !selected.is_empty()
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

/// The held mDL as issued (ISO/IEC 18013-5, 8.3.2.1.2.2): the parts of
/// its `IssuerSigned` a presentation copies.
struct MiniMdl {
    /// `issuerAuth`: the fixture issuer's `COSE_Sign1` over the MSO
    /// (9.1.2.4).
    issuer_auth: Cbor,
    /// The [`MDL_NAMESPACE`] items, in the issuer's order.
    items: Vec<IssuedItem>,
}

/// An item of the held mDL.
struct IssuedItem {
    /// The element identifier.
    identifier: &'static str,
    /// `IssuerSignedItemBytes`: `#6.24(bstr .cbor IssuerSignedItem)`
    /// (8.3.2.1.2.2), its digest in the MSO's `valueDigests`.
    bytes: Cbor,
}

/// The encoding of `value` (RFC 8949 §4.1): the shortest heads and
/// definite lengths.
fn cbor(value: &Cbor) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|err| format!("the CBOR does not encode: {err}"))?;
    Ok(out)
}

/// A map in the core deterministic encoding's order (RFC 8949 §4.2.1):
/// its keys sorted by their encodings, bytewise.
fn cbor_map(entries: Vec<(Cbor, Cbor)>) -> Result<Cbor, String> {
    let mut keyed = entries
        .into_iter()
        .map(|(key, value)| Ok((cbor(&key)?, key, value)))
        .collect::<Result<Vec<_>, String>>()?;
    keyed.sort_by(|(a, ..), (b, ..)| a.cmp(b));
    Ok(Cbor::Map(
        keyed
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    ))
}

/// `#6.24(bstr .cbor value)`: an embedded data item (RFC 8949
/// §3.4.5.1).
fn embedded(value: &Cbor) -> Result<Cbor, String> {
    Ok(Cbor::Tag(24, Box::new(Cbor::Bytes(cbor(value)?))))
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}

fn integer(value: i64) -> Cbor {
    Cbor::Integer(value.into())
}

/// The protected header of an ES256 `COSE_Sign1`, `{1: -7}`: `alg`
/// (RFC 9052 §3.1) is ES256 (RFC 9053 §2.1).
const ES256_PROTECTED: [u8; 3] = [0xa1, 0x01, 0x26];

/// The `Sig_structure` a `COSE_Sign1` signs (RFC 9052 §4.4):
/// `["Signature1", protected, external_aad = h'', payload]`.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    cbor(&Cbor::Array(vec![
        text("Signature1"),
        Cbor::Bytes(protected.to_vec()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.to_vec()),
    ]))
}

/// The UTC seconds a `tdate` writes with a four-digit year:
/// 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z.
const TDATE_SECONDS: std::ops::RangeInclusive<i64> = -62_167_219_200..=253_402_300_799;

/// A `tdate` (RFC 8949 §3.4.1), the form of validityInfo's times
/// (ISO/IEC 18013-5, 9.1.2.4): tag 0 over the UTC second `unix` names,
/// `YYYY-MM-DDThh:mm:ssZ`, read off the JS Date. Refused outside
/// [`TDATE_SECONDS`].
fn tdate(unix: i64) -> Result<Cbor, String> {
    if !TDATE_SECONDS.contains(&unix) {
        return Err("the clock is out of range".to_owned());
    }
    let date = js_sys::Date::new(&JsValue::from_f64(unix as f64 * 1000.0));
    let time = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.get_utc_full_year(),
        date.get_utc_month() + 1,
        date.get_utc_date(),
        date.get_utc_hours(),
        date.get_utc_minutes(),
        date.get_utc_seconds()
    );
    Ok(Cbor::Tag(0, Box::new(Cbor::Text(time))))
}

/// Issues the mini host's held mDL: an `IssuerSigned` (ISO/IEC
/// 18013-5, 8.3.2.1.2.2) with the MSO (9.1.2) the fixture issuer
/// signs, its `valueDigests` listing the items, the device key bound
/// as the MSO's `deviceKey`, and the issuer's `COSE_Sign1`
/// (`issuerAuth`, 9.1.2.4) carrying the fixture issuer's `x5chain`
/// (RFC 9360 §2); each map in the core deterministic encoding (RFC 8949
/// §4.2.1). None when no PID signing key carries an x5c chain:
/// issuerAuth's unprotected header holds the issuer's x5chain (9.1.2.4).
fn issue_mini_mdl(
    device_public: &serde_json::Value,
    issuer_signing: Option<&jose_rs::jwk::Jwk>,
) -> Result<Option<MiniMdl>, String> {
    // The x5c entries are standard-base64 DER (RFC 7515 §4.1.6),
    // unlike the JOSE segments' base64url.
    let chained = issuer_signing.and_then(|key| {
        let certificates: Vec<Cbor> = key
            .extra
            .get("x5c")?
            .as_array()?
            .iter()
            .filter_map(|der| {
                der.as_str()
                    .and_then(|encoded| STANDARD.decode(encoded).ok())
            })
            .map(Cbor::Bytes)
            .collect();
        (!certificates.is_empty()).then_some((key, certificates))
    });
    let Some((issuer_key, certificates)) = chained else {
        return Ok(None);
    };
    let now = (js_sys::Date::now() / 1000.0) as i64;
    // The device key's COSE_Key coordinates (EC2: {1: 2, -1: 1, -2: x,
    // -3: y}, RFC 9053 §2): the 32-byte big-endian coordinates of the
    // bound device key.
    let coordinate = |name: &str| -> Result<Cbor, String> {
        device_public
            .get(name)
            .and_then(|v| v.as_str())
            .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
            .filter(|bytes| bytes.len() == 32)
            .map(Cbor::Bytes)
            .ok_or_else(|| format!("the device key's {name} does not parse"))
    };
    let device_key = cbor_map(vec![
        (integer(1), integer(2)),
        (integer(-1), integer(1)),
        (integer(-2), coordinate("x")?),
        (integer(-3), coordinate("y")?),
    ])?;

    // The MSO's validity: 180 days — strictly inside the fixture DS
    // certificate's own validity (ISO/IEC 18013-5 §9.3.1: an mdoc reader
    // may reject a credential whose validUntil exceeds the document
    // signer certificate's notAfter).
    let signed = tdate(now)?;
    let until = tdate(now + 15_552_000)?;

    // The items (8.3.2.1.2.2, Table 5): digestID, random,
    // elementIdentifier, elementValue — each `#6.24(bstr .cbor
    // IssuerSignedItem)` in its namespace's array, its digest in the
    // MSO's valueDigests.
    let mut items = Vec::new();
    let mut digests = Vec::new();
    for (index, (name, value)) in MDL_CLAIMS.into_iter().enumerate() {
        let random: Vec<u8> = (0..16)
            .map(|byte| (now.wrapping_mul(index as i64 + byte as i64)) as u8)
            .collect();
        let bytes = embedded(&cbor_map(vec![
            (text("digestID"), Cbor::Integer(index.into())),
            (text("random"), Cbor::Bytes(random)),
            (text("elementIdentifier"), text(name)),
            (text("elementValue"), text(value)),
        ])?)?;
        let digest = kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &cbor(&bytes)?)
            .map_err(|err| format!("the item digest failed: {err}"))?;
        digests.push((Cbor::Integer(index.into()), Cbor::Bytes(digest)));
        items.push(IssuedItem {
            identifier: name,
            bytes,
        });
    }

    // The MSO (9.1.2): the docType, SHA-256, the device key, the
    // valueDigests, the validity.
    let mso = cbor_map(vec![
        (text("version"), text("1.0")),
        (text("docType"), text(MDL_DOCTYPE)),
        (text("digestAlgorithm"), text("SHA-256")),
        (
            text("deviceKeyInfo"),
            cbor_map(vec![(text("deviceKey"), device_key)])?,
        ),
        (
            text("valueDigests"),
            cbor_map(vec![(text(MDL_NAMESPACE), cbor_map(digests)?)])?,
        ),
        (
            text("validityInfo"),
            cbor_map(vec![
                (text("signed"), signed.clone()),
                (text("validFrom"), signed),
                (text("validUntil"), until),
            ])?,
        ),
    ])?;
    // MobileSecurityObjectBytes = #6.24(bstr .cbor MSO) (9.1.2.1).
    let payload = cbor(&embedded(&mso)?)?;

    // issuerAuth = COSE_Sign1 (9.1.2.4): the protected header {alg: -7}
    // (ES256), the x5chain at label 33 (RFC 9360 §2), the tagged MSO as
    // the payload, and the issuer's ES256 signature over its
    // Sig_structure.
    let issuer_signer = p256_signer(issuer_key)?;
    let signature =
        kryptering::Signer::sign(&issuer_signer, &sig_structure(&ES256_PROTECTED, &payload)?)
            .map_err(|err| format!("the mDL issuerAuth signing failed: {err}"))?;
    let issuer_auth = Cbor::Array(vec![
        Cbor::Bytes(ES256_PROTECTED.to_vec()),
        cbor_map(vec![(integer(33), Cbor::Array(certificates))])?,
        Cbor::Bytes(payload),
        Cbor::Bytes(signature),
    ]);
    Ok(Some(MiniMdl { issuer_auth, items }))
}

/// The held mDL presented to a verifier: the base64url of the
/// `DeviceResponse` (ISO/IEC 18013-5, 8.3.2.1.2.2) of the selected
/// items, in the issuer's order and as issued, bound to the request by
/// the device key's ES256 signature over the session transcript of the
/// `OpenID4VPHandover` (OpenID4VP 1.0, B.2.6.1): `[null, null,
/// ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, thumb|null,
/// response_uri]))]]`, or on the Digital Credentials API channel of the
/// `OpenID4VPDCAPIHandover` (B.2.6.2) over `[origin, nonce,
/// thumb|null]`; each map in the core deterministic encoding (RFC
/// 8949 §4.2.1). Each claim is a claims path (OpenID4VP §7)
/// JSON-encoded, its keys a namespace then an element identifier
/// (B.4.1). `sign` signs the device signature's `Sig_structure` with
/// the device key and answers ES256's 64-octet `r ‖ s` (RFC 7518
/// §3.4). Refused when a claim is no array of keys or holds fewer than
/// two, an element is selected twice or is no item of the mDL, or the
/// verifier's thumbprint is no base64url.
fn present_mini_mdl(
    mdl: &MiniMdl,
    params: &VpParams,
    claims: &[String],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    // The selected elements: the paths' [namespace, claim name] pairs.
    let mut selected: Vec<(String, String)> = Vec::new();
    for claim in claims {
        let path: Vec<String> = serde_json::from_str(claim)
            .map_err(|_| format!("the disclosed claim {claim:?} is no §7 path"))?;
        let Some((name_space, identifier)) = path.first().zip(path.get(1)) else {
            return Err(format!(
                "the mdoc claim path {claim:?} is not a [namespace, claim] pair"
            ));
        };
        let element = (name_space.clone(), identifier.clone());
        if selected.contains(&element) {
            return Err(format!("the mdoc disclosure selects {claim:?} twice"));
        }
        selected.push(element);
    }
    let disclosed: Vec<Cbor> = mdl
        .items
        .iter()
        .filter(|item| {
            selected.iter().any(|(name_space, identifier)| {
                name_space == MDL_NAMESPACE && identifier == item.identifier
            })
        })
        .map(|item| item.bytes.clone())
        .collect();
    if disclosed.len() != selected.len() {
        return Err("the mdoc disclosure selects an element the mDL does not hold".to_owned());
    }

    // The OpenID4VPHandover (B.2.6.1): ["OpenID4VPHandover",
    // SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]
    // — the thumbprint of the verifier's encryption key for an
    // encrypted response (`direct_post.jwt`), `null` otherwise. The
    // engine hands it over base64url; the handover carries the raw
    // digest.
    let thumbprint = if params.verifier_jwk_thumbprint.is_empty() {
        Cbor::Null
    } else {
        Cbor::Bytes(
            URL_SAFE_NO_PAD
                .decode(&params.verifier_jwk_thumbprint)
                .map_err(|err| format!("the thumbprint does not decode: {err}"))?,
        )
    };
    // The Digital Credentials API channel (B.2.6.2): the
    // OpenID4VPDCAPIHandover covers [origin, nonce, jwkThumbprint], the
    // origin the request's expected_origins named.
    let (handover_name, info) = if params.origin.is_empty() {
        (
            "OpenID4VPHandover",
            Cbor::Array(vec![
                text(&params.audience),
                text(&params.nonce),
                thumbprint,
                text(&params.response_uri),
            ]),
        )
    } else {
        (
            "OpenID4VPDCAPIHandover",
            Cbor::Array(vec![text(&params.origin), text(&params.nonce), thumbprint]),
        )
    };
    let handover_digest =
        kryptering::digest::digest(kryptering::HashAlgorithm::Sha256, &cbor(&info)?)
            .map_err(|err| format!("the handover digest: {err}"))?;
    // SessionTranscript = [null, null, Handover] (B.2.6).
    let transcript = Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Array(vec![text(handover_name), Cbor::Bytes(handover_digest)]),
    ]);

    // DeviceNameSpacesBytes = #6.24(bstr .cbor {}): the response carries
    // no DeviceSigned element.
    let device_name_spaces = embedded(&Cbor::Map(Vec::new()))?;
    // The device signature (9.1.3.4, 9.1.3.6): the device key — the
    // MSO's deviceKey — signs DeviceAuthenticationBytes =
    // #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
    // DocType, DeviceNameSpacesBytes]), a detached payload.
    let authentication = embedded(&Cbor::Array(vec![
        text("DeviceAuthentication"),
        transcript,
        text(MDL_DOCTYPE),
        device_name_spaces.clone(),
    ]))?;
    let signature = sign(&sig_structure(&ES256_PROTECTED, &cbor(&authentication)?)?)?;
    if signature.len() != 64 {
        return Err(format!(
            "the mDL device signature has {} octets, where ES256's has 64",
            signature.len()
        ));
    }

    // The document: issuerSigned holds the disclosed items and
    // issuerAuth as issued, `nameSpaces` left out when none is
    // disclosed; deviceSigned holds deviceSignature, a COSE_Sign1 with
    // the protected header {1: -7} and a null payload.
    let mut issuer_signed = vec![(text("issuerAuth"), mdl.issuer_auth.clone())];
    if !disclosed.is_empty() {
        issuer_signed.push((
            text("nameSpaces"),
            cbor_map(vec![(text(MDL_NAMESPACE), Cbor::Array(disclosed))])?,
        ));
    }
    let device_signature = Cbor::Array(vec![
        Cbor::Bytes(ES256_PROTECTED.to_vec()),
        Cbor::Map(Vec::new()),
        Cbor::Null,
        Cbor::Bytes(signature),
    ]);
    let document = cbor_map(vec![
        (text("docType"), text(MDL_DOCTYPE)),
        (text("issuerSigned"), cbor_map(issuer_signed)?),
        (
            text("deviceSigned"),
            cbor_map(vec![
                (text("nameSpaces"), device_name_spaces),
                (
                    text("deviceAuth"),
                    cbor_map(vec![(text("deviceSignature"), device_signature)])?,
                ),
            ])?,
        ),
    ])?;
    let response = cbor_map(vec![
        (text("version"), text("1.0")),
        (text("documents"), Cbor::Array(vec![document])),
        (text("status"), integer(0)),
    ])?;
    Ok(URL_SAFE_NO_PAD.encode(cbor(&response)?))
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
    /// no PID signing key with an x5c chain is configured: issuerAuth
    /// carries the issuer's x5chain (9.1.2.4), which only the configured
    /// fixture issuer has, so a harness without it holds no mdoc (the
    /// mso_mdoc queries match nothing) and still starts.
    mdl: Option<MiniMdl>,
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
    /// The fresh batch keys this host has handed out (kid → signer).
    /// A fresh-key ask generates a key for that ask alone (the OID4VCI
    /// batch rule — each credential in a batch binds to its own key,
    /// SDJWT-10.1); the sign asks that follow must reach the very key
    /// the proof header carries, so the host keeps them by kid. The
    /// Host port hands out `&self`, so the map sits in a RefCell —
    /// the wasm page is single-threaded.
    fresh_signers: std::sync::Mutex<rustc_hash::FxHashMap<String, Signer>>,
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
        // The held mDL: a harness with no PID signing key (no x5c chain
        // for the issuerAuth) holds no mdoc; the mso_mdoc queries then
        // match nothing, but the host starts (the SD-JWT presentations
        // work without it).
        let mdl = issue_mini_mdl(&device_public, pid_signing.as_ref())?;

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
            fresh_signers: std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
        })
    }

    /// The device key's public JWK — for the plan's key registration, if
    /// the suite asks for it.
    pub fn public_jwk(&self) -> serde_json::Value {
        let public = self.key.to_public_jwk();
        let text = public.to_json().unwrap_or_default();
        serde_json::from_str(&text).unwrap_or_default()
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
        // assertion needs the client key; a fresh batch key's kid
        // reaches the key the proof header carries; anything else is
        // the device key (the OID4VCI proof).
        if let Some(id) = params.key_id.as_deref() {
            if let Ok(table) = self.fresh_signers.lock() {
                if let Some(signer) = table.get(id) {
                    let signature =
                        kryptering::Signer::sign(signer, &params.to_sign).map_err(|e| {
                            HostError::Cannot(format!("the fresh key does not sign: {e}"))
                        })?;
                    return Ok(SignResult { signature });
                }
            }
        }
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
        // (SDJWT-10.1, the suite's VCIEnsureProofKeysAreDistinct). The
        // kid is the RFC 7638 thumbprint; the sign asks that follow name
        // it, and this host signs with the very key it handed out.
        if params.fresh {
            let key =
                jose_rs::jwk::generate_ec("P-256").map_err(|e| HostError::Cannot(e.to_string()))?;
            let kid = jose_rs::jwk::thumbprint::thumbprint_sha256(&key)
                .map_err(|e| HostError::Cannot(e.to_string()))?;
            let signer = p256_signer(&key).map_err(|e| HostError::Cannot(e.to_string()))?;
            let mut public = key.to_public_jwk();
            public.kid = Some(kid.clone());
            let text = public
                .to_json()
                .map_err(|e| HostError::Cannot(e.to_string()))?;
            let jwk: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| HostError::Cannot(e.to_string()))?;
            self.fresh_signers
                .lock()
                .map_err(|_| HostError::Cannot("the fresh-key table is poisoned".to_owned()))?
                .insert(kid, signer);
            return Ok(engine_ports::SigningKeyResult { jwk });
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
        let iat = u64::try_from(now)
            .map_err(|_| HostError::Cannot("the clock is before the epoch".to_owned()))?;
        // The KB-JWT's `aud`: on the Digital Credentials API channel
        // the origin in its HAIP-7.3.2 serialization, `origin:` and the
        // expected origin URL (the suite's CheckAudInBindingJwtDcApi);
        // the client_id on the redirect channel.
        let dc_api_origin = format!("origin:{}", params.origin);
        let audience = if params.origin.is_empty() {
            params.audience.as_str()
        } else {
            dc_api_origin.as_str()
        };

        let mut tokens = Vec::new();
        for selection in &params.selections {
            // The mdoc presentation (OpenID4VP 1.0, B.4): the mso_mdoc
            // answer is a `DeviceResponse` (ISO/IEC 18013-5, 8.3.2.1.2.2)
            // — the selected items, the issuerAuth as issued, and the
            // device key's ES256 signature over the session transcript
            // of the request's OpenID4VPHandover (B.2.6.1) — base64url.
            if selection.credential_id == "mini-mdl" {
                let mdl = self.mdl.as_ref().ok_or_else(|| {
                    HostError::Cannot("the mini host holds no mdoc (no PID signing key)".to_owned())
                })?;
                let token = present_mini_mdl(mdl, &params, &selection.disclosed_claims, |input| {
                    kryptering::Signer::sign(&self.signer, input)
                        .map_err(|err| format!("the mDL device signing failed: {err}"))
                })
                .map_err(HostError::Cannot)?;
                tokens.push(token);
                continue;
            }
            // The disclosed claims' paths, as the DCQL names them, JSON-encoded
            // (§7); the KB-JWT's signature: the device key — the holder.
            let token = present_mini_pid(
                &self.pid,
                &selection.disclosed_claims,
                iat,
                audience,
                &params.nonce,
                |input| {
                    kryptering::Signer::sign(&self.signer, input)
                        .map_err(|err| format!("the KB-JWT signing failed: {err}"))
                },
            )
            .map_err(HostError::Cannot)?;
            tokens.push(token);
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
