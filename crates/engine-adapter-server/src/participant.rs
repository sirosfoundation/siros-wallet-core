//! The participant's signing credential (issue #100): the certificate
//! chain the signed forms carry and the signer under the leaf's key —
//! behind a port trait, because the key's HOME is deployment material.
//! CS-15 §8.4: the subscriber key is generated inside a WSCA/QSCD
//! where available and **MUST NOT leave it** — a PEM pair on disk is
//! one shape, a PKCS#11 token is the qualified deployments' shape, and
//! the trait is the boundary between them. The well-known's signed form
//! (CS-15 §7.2), the KeyPackage publishing at the QTSP (§10.3) and the
//! onboarding CSR (§8.2) all draw on this one surface.

use std::sync::Arc;

use crate::config::Config;

/// The participant's signing credential: the certificate chain (leaf
/// first, DER — the `x5c` the signed forms carry), the JOSE algorithm
/// the key signs with, and the compact-JWS signing itself. The
/// implementation owns its key's home — software material or an
/// HSM-backed token — behind this one surface; nothing above it knows
/// where the bytes come from.
pub trait ParticipantCredential: Send + Sync {
    /// The certificate chain, leaf first, DER — the `x5c`.
    fn certificate_chain(&self) -> Vec<Vec<u8>>;
    /// The JOSE algorithm name the signing key uses (`ES256`, …).
    fn algorithm(&self) -> &'static str;
    /// Signs `payload` as a compact JWS under the leaf's key with the
    /// given protected header. The error string is the operator's log
    /// line.
    fn sign_compact(
        &self,
        payload: &[u8],
        header: &jose_rs::header::JoseHeader,
    ) -> Result<String, String>;
}

/// The startup self-check shared by every credential home: the key
/// signs a probe the chain's leaf must verify — the same check a
/// counterpart's parser runs on the served document, moved to the
/// deployment's start line so a pair that does not hold together fails
/// loudly once, not per request.
fn probe(credential: &dyn ParticipantCredential, chain_leaf: &[u8]) -> Result<(), String> {
    let verifying = jose_rs::jwk::cert::public_jwk_from_certificate_der(chain_leaf)
        .map_err(|err| format!("the chain's leaf does not parse: {err}"))?;
    let header = jose_rs::header::JoseHeader::new(credential.algorithm());
    let probe = credential
        .sign_compact(b"participant-credential-probe", &header)
        .map_err(|err| format!("the signing key does not sign: {err}"))?;
    jose_rs::jws::compact::verify_with_jwk(&verifying, &probe)
        .map_err(|_| "the signing key does not match the certificate chain's leaf".to_owned())?;
    Ok(())
}

// ── The PEM home ──────────────────────────────────────────────────────────

/// The PEM-backed credential: the config's certificate chain + key
/// pair, the software home. The pair is validated once, at
/// construction — the probe — so the deployment's material fails at
/// its start line, not at the first counterpart's request.
pub struct PemParticipantCredential {
    chain: Vec<Vec<u8>>,
    jwk: jose_rs::jwk::Jwk,
    algorithm: &'static str,
}

impl PemParticipantCredential {
    /// Builds the credential from the PEM pair: the chain (leaf first),
    /// the private key, and the JOSE algorithm the key's own shape
    /// names.
    pub fn new(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        let chain = crate::well_known::certificate_chain_der(cert_pem).ok_or_else(|| {
            "the participant certificate PEM carries no parseable chain".to_owned()
        })?;
        let mut jwk = jose_rs::jwk::pem::jwk_from_pem(key_pem)
            .map_err(|err| format!("the participant key PEM does not import: {err}"))?;
        let algorithm = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("EC", Some("P-256")) => "ES256",
            ("EC", Some("P-384")) => "ES384",
            ("RSA", _) => "RS256",
            _ => {
                return Err("the participant key is not an EC P-256/P-384 or RSA key".to_owned());
            }
        };
        jwk.alg = Some(algorithm.to_owned());
        let credential = Self {
            chain,
            jwk,
            algorithm,
        };
        let leaf = credential
            .chain
            .first()
            .cloned()
            .ok_or_else(|| "the chain is empty".to_owned())?;
        probe(&credential, &leaf)?;
        Ok(credential)
    }
}

impl ParticipantCredential for PemParticipantCredential {
    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn sign_compact(
        &self,
        payload: &[u8],
        header: &jose_rs::header::JoseHeader,
    ) -> Result<String, String> {
        let mut options = jose_rs::jws::compact::SignOptions::default();
        // The x5c chain rides the protected header — a key-reference
        // member jose-rs gates on the caller's say-so.
        options.allow_key_reference_headers = true;
        jose_rs::jws::compact::sign_with_jwk_options(&self.jwk, payload, header, &options)
            .map_err(|err| err.to_string())
    }
}

// ── The PKCS#11 home (the `pkcs11` feature) ──────────────────────────────

/// The PKCS#11-backed credential: the signing key lives on a token —
/// CS-15 §8.4's WSCA/QSCD, the key never leaves it — and signing goes
/// through kryptering's `Pkcs11Signer`, jose-rs's own backend seam, so
/// the JWS layer is the same one the software credential rides. The
/// certificate chain still comes from the config's PEM: the `x5c` is
/// public material, and kryptering's session exposes no certificate
/// objects.
#[cfg(feature = "pkcs11")]
pub struct Pkcs11ParticipantCredential {
    chain: Vec<Vec<u8>>,
    algorithm: &'static str,
    signer: kryptering::pkcs11::Pkcs11Signer,
    // The token session the signer's key lives behind: the provider and
    // the session outlive the signer here, because the signer holds only
    // the session's inner Arc — the module's C_Finalize must not run
    // while a credential still signs through it.
    _session: kryptering::pkcs11::Pkcs11Session,
    _provider: kryptering::pkcs11::Pkcs11Provider,
}

/// The JOSE name and the kryptering algorithm together — the token's
/// key is found by label, so the deployment names the algorithm
/// (`ENGINE_PKCS11_ALG`).
#[cfg(feature = "pkcs11")]
fn token_algorithm(name: &str) -> Result<(&'static str, kryptering::SignatureAlgorithm), String> {
    match name.trim() {
        "ES256" => Ok((
            "ES256",
            kryptering::SignatureAlgorithm::Ecdsa(
                kryptering::EcCurve::P256,
                kryptering::HashAlgorithm::Sha256,
            ),
        )),
        "ES384" => Ok((
            "ES384",
            kryptering::SignatureAlgorithm::Ecdsa(
                kryptering::EcCurve::P384,
                kryptering::HashAlgorithm::Sha384,
            ),
        )),
        "RS256" => Ok((
            "RS256",
            kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
        )),
        other => Err(format!(
            "the PKCS#11 algorithm {other:?} is not one of ES256, ES384, RS256"
        )),
    }
}

#[cfg(feature = "pkcs11")]
impl Pkcs11ParticipantCredential {
    /// Builds the credential from the token: the module, the slot (the
    /// first slot with a token when unnamed), the login PIN, the
    /// private key object's label, the signing algorithm, and the
    /// chain PEM.
    pub fn new(
        module: &str,
        slot_id: Option<u64>,
        pin: &str,
        key_label: &str,
        algorithm: &str,
        cert_pem: &str,
    ) -> Result<Self, String> {
        let chain = crate::well_known::certificate_chain_der(cert_pem).ok_or_else(|| {
            "the participant certificate PEM carries no parseable chain".to_owned()
        })?;
        let (algorithm, signature_algorithm) = token_algorithm(algorithm)?;
        let library = std::path::Path::new(module);
        let provider = slot_id
            .map(|slot| {
                kryptering::pkcs11::Pkcs11Provider::new_with_slot_id(library, slot)
                    .map_err(|err| format!("the PKCS#11 slot {slot} does not open: {err}"))
            })
            .unwrap_or_else(|| {
                kryptering::pkcs11::Pkcs11Provider::new(library)
                    .map_err(|err| format!("the PKCS#11 module does not open: {err}"))
            })?;
        let session = provider
            .open_session(pin)
            .map_err(|err| format!("the PKCS#11 session does not open: {err}"))?;
        let signer =
            kryptering::pkcs11::Pkcs11Signer::new(&session, key_label, signature_algorithm)
                .map_err(|err| {
                    format!("the PKCS#11 key object {key_label:?} does not sign: {err}")
                })?;
        let credential = Self {
            chain,
            algorithm,
            signer,
            _session: session,
            _provider: provider,
        };
        let leaf = credential
            .chain
            .first()
            .cloned()
            .ok_or_else(|| "the chain is empty".to_owned())?;
        probe(&credential, &leaf)?;
        Ok(credential)
    }
}

#[cfg(feature = "pkcs11")]
impl ParticipantCredential for Pkcs11ParticipantCredential {
    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn sign_compact(
        &self,
        payload: &[u8],
        header: &jose_rs::header::JoseHeader,
    ) -> Result<String, String> {
        let mut options = jose_rs::jws::compact::SignOptions::default();
        options.allow_key_reference_headers = true;
        jose_rs::jws::compact::sign_with_options(&self.signer, payload, header, &options)
            .map_err(|err| err.to_string())
    }
}

// ── The assembly ─────────────────────────────────────────────────────────

/// Assembles the deployment's credential from the config (issue #100):
/// the PKCS#11 knobs when a module is named — the key lives on the
/// token, the chain still rides the PEM — else the PEM pair; none
/// configured answers `None` (the signed form's `406`).
///
/// A pair that does not hold together is logged and answers `None`
/// rather than refusing the start: a misconfigured credential must not
/// take the engine's other services down with it, and the signed form's
/// refusal is the operator's signal.
pub fn from_config(config: &Config) -> Option<Arc<dyn ParticipantCredential>> {
    let built: Result<Arc<dyn ParticipantCredential>, String> = if !config.pkcs11_module.is_empty()
    {
        #[cfg(feature = "pkcs11")]
        {
            Pkcs11ParticipantCredential::new(
                &config.pkcs11_module,
                config.pkcs11_slot_id,
                &config.pkcs11_pin,
                &config.pkcs11_key_label,
                &config.pkcs11_alg,
                &config.participant_cert_pem,
            )
            .map(|credential| Arc::new(credential) as Arc<dyn ParticipantCredential>)
        }
        #[cfg(not(feature = "pkcs11"))]
        {
            Err("ENGINE_PKCS11_MODULE is set but this build carries no pkcs11 feature".to_owned())
        }
    } else if !config.participant_key_pem.is_empty() {
        PemParticipantCredential::new(&config.participant_cert_pem, &config.participant_key_pem)
            .map(|credential| Arc::new(credential) as Arc<dyn ParticipantCredential>)
    } else {
        return None;
    };
    match built {
        Ok(credential) => Some(credential),
        Err(reason) => {
            eprintln!("engine-server: the participant credential does not hold together: {reason}");
            None
        }
    }
}
