//! A test issuer, holder, requests and host, shared by this crate's tests and those of the
//! bindings and the provers.
//!
//! The issuer writes credentials in the compact profile, with the readdit issuer's layout
//! (`native/vega/issuer`): `birth_date` and `ssc` items, 16-byte salts, digestIDs 0 and 1, the
//! protected header `{1: -7}` and `x5chain` in the unprotected header. Keys are fixed scalars,
//! so each run builds the same credentials. The test prover binds every public value and the
//! pseudonym into its `zk_proof`; its verifier refuses any other value.
//!
//! Behind the `test-fixtures` feature: a dev-time facility, outside the shipped surface. It
//! panics on a broken fixture, as a test does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

mod presenting;

pub use presenting::{nym_query, prepared, present, usable, verified_request, Presenting};

use std::str::FromStr;
use std::time::Duration;

use crate::presenter::Session;
use crate::prover::{
    NymAuthProofVerifier, NymAuthProver, ProofFailure, ProofJob, ProofOutput, ProverFailure,
    Statement,
};
use crate::request_object::{check_request, Channel, Signing};
use crate::system::NymAuthSystem;
use crate::verifier_id::{Intermediary, PseudonymValue, VerifierId};
use der::asn1::{GeneralizedTime, UtcTime};
use der::Encode;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_codec::signature::Es256Signature;
use siros_oid4vp::ec_jwk_thumbprint;
use siros_zkp_req::ZkProof;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

pub const DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
pub const CLIENT_ID: &str = "x509_san_dns:verifier.example";
pub const NONCE: &str = "pOA0oqEAhLnqug2r7Ve4tQ";
pub const RESPONSE_URI: &str = "https://verifier.example/response";
pub const SEED: [u8; 16] = [
    0x4a, 0x8f, 0x9c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b, 0x2c, 0x3d,
];

/// 2026-10-09T12:00:00Z: D of the catalogue's example.
pub const NOW: i64 = 1_791_547_200;

pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32].into()).unwrap()
}

pub fn unix(text: &str) -> i64 {
    DateTime::parse(text).unwrap().unix()
}

/// A certificate authority or Document Signer with its key.
pub struct Issuer {
    pub key: SigningKey,
    pub name: Name,
    pub der: Vec<u8>,
}

fn validity(from: &str, until: &str) -> Validity {
    let at = |t: &str| Duration::from_secs(unix(t) as u64);
    Validity {
        not_before: Time::UtcTime(UtcTime::from_unix_duration(at(from)).unwrap()),
        not_after: Time::GeneralTime(GeneralizedTime::from_unix_duration(at(until)).unwrap()),
    }
}

impl Issuer {
    /// A self-signed certificate.
    pub fn root(byte: u8, cn: &str) -> Self {
        let key = key(byte);
        let name = Name::from_str(&format!("CN={cn},O=Test only")).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::new(&[byte]).unwrap(),
            validity("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
            name.clone(),
            spki,
            &key,
        )
        .unwrap();
        let der = builder.build::<DerSignature>().unwrap().to_der().unwrap();
        Self { key, name, der }
    }

    /// A certificate this issuer signs.
    pub fn sign_child(&self, byte: u8, cn: &str) -> Self {
        let key = key(byte);
        let name = Name::from_str(&format!("CN={cn},O=Test only")).unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(
            Profile::SubCA {
                issuer: self.name.clone(),
                path_len_constraint: Some(0),
            },
            SerialNumber::new(&[byte]).unwrap(),
            validity("2026-01-01T00:00:00Z", "2029-01-01T00:00:00Z"),
            name.clone(),
            spki,
            &self.key,
        )
        .unwrap();
        let der = builder.build::<DerSignature>().unwrap().to_der().unwrap();
        Self { key, name, der }
    }
}

/// What the test issuer writes, and the defects a fixture can ask for.
#[derive(Clone)]
pub struct Spec {
    pub birth_date: &'static str,
    pub valid_from: &'static str,
    pub valid_until: &'static str,
    pub doc_type: &'static str,
    pub seed: [u8; 16],
    pub device: u8,
    /// The MSO lists another digest for `ssc`.
    pub wrong_ssc_digest: bool,
    /// The signature is of another message.
    pub wrong_signature: bool,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            birth_date: "2000-01-01",
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: "2027-01-01T00:00:00Z",
            doc_type: DOCTYPE,
            seed: SEED,
            device: 0x33,
            wrong_ssc_digest: false,
            wrong_signature: false,
        }
    }
}

fn text(s: &str) -> Cbor {
    Cbor::text(s)
}

fn item(digest_id: u64, salt: u8, identifier: &str, value: Cbor) -> Vec<u8> {
    let item = Cbor::Map(vec![
        (text("digestID"), Cbor::Unsigned(digest_id)),
        (text("random"), Cbor::Bytes(vec![salt; 16])),
        (text("elementIdentifier"), text(identifier)),
        (text("elementValue"), value),
    ]);
    Cbor::Tag(24, Box::new(Cbor::Bytes(item.encode()))).encode()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// An `IssuerSigned`, base64url.
pub fn issue(issuer: &Issuer, spec: &Spec) -> String {
    let device = key(spec.device);
    let point = device.verifying_key().to_encoded_point(false);
    let birth = item(
        0,
        0xb1,
        "birth_date",
        Cbor::Tag(1004, Box::new(text(spec.birth_date))),
    );
    let ssc = item(1, 0xb2, "ssc", Cbor::Bytes(sha256(&spec.seed).to_vec()));
    let ssc_digest = if spec.wrong_ssc_digest {
        sha256(b"another item")
    } else {
        sha256(&ssc)
    };
    let mso = Cbor::Map(vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (
            text("valueDigests"),
            Cbor::Map(vec![(
                text(DOCTYPE),
                Cbor::Map(vec![
                    (Cbor::Unsigned(0), Cbor::Bytes(sha256(&birth).to_vec())),
                    (Cbor::Unsigned(1), Cbor::Bytes(ssc_digest.to_vec())),
                ]),
            )]),
        ),
        (
            text("deviceKeyInfo"),
            Cbor::Map(vec![(
                text("deviceKey"),
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Negative(0), Cbor::Unsigned(1)),
                    (Cbor::Negative(1), Cbor::Bytes(point.x().unwrap().to_vec())),
                    (Cbor::Negative(2), Cbor::Bytes(point.y().unwrap().to_vec())),
                ]),
            )]),
        ),
        (text("docType"), text(spec.doc_type)),
        (
            text("validityInfo"),
            Cbor::Map(vec![
                (
                    text("signed"),
                    Cbor::Tag(0, Box::new(text(spec.valid_from))),
                ),
                (
                    text("validFrom"),
                    Cbor::Tag(0, Box::new(text(spec.valid_from))),
                ),
                (
                    text("validUntil"),
                    Cbor::Tag(0, Box::new(text(spec.valid_until))),
                ),
            ]),
        ),
    ]);
    let payload = Cbor::Tag(24, Box::new(Cbor::Bytes(mso.encode()))).encode();
    let protected = Cbor::Map(vec![(Cbor::Unsigned(1), Cbor::Negative(6))]).encode();
    let sig_structure = Cbor::Array(vec![
        text("Signature1"),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.clone()),
    ])
    .encode();
    let signed: &[u8] = if spec.wrong_signature {
        b"another message"
    } else {
        &sig_structure
    };
    let signature: Signature = issuer.key.sign(signed);
    let issuer_signed = Cbor::Map(vec![
        (
            text("nameSpaces"),
            Cbor::Map(vec![(
                text(DOCTYPE),
                Cbor::Array(vec![Cbor::Encoded(birth), Cbor::Encoded(ssc)]),
            )]),
        ),
        (
            text("issuerAuth"),
            Cbor::Array(vec![
                Cbor::Bytes(protected),
                Cbor::Map(vec![(Cbor::Unsigned(33), Cbor::Bytes(issuer.der.clone()))]),
                Cbor::Bytes(payload),
                Cbor::Bytes(signature.to_bytes().to_vec()),
            ]),
        ),
    ]);
    base64url::encode(&issuer_signed.encode()).into()
}

/// A pseudonym item and, unless `range` is `None`, an age_check item.
pub fn query(range: Option<&str>, age_return: bool) -> Value {
    let mut req = vec![json!({"fn_id": "pseudonym", "return": "nym",
        "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}})];
    if let Some(range) = range {
        let mut age = json!({"fn_id": "age_check", "params": {"range": range}});
        if age_return {
            age["return"] = json!("adult");
        }
        req.push(age);
    }
    json!({"id": "nym", "format": "zkp_req",
        "meta": {"source_format": "mso_mdoc", "doctype_value": DOCTYPE}, "_req": req})
}

pub fn client_metadata() -> Value {
    json!({
        "jwks": {"keys": [encryption_jwk()]},
        "vp_formats_supported": {"zkp_req": {
            "proof_backend_values": ["longfellow-libzk-v1", "vega-v1"],
            "system_id_values": ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v1"]
        }}
    })
}

/// The response-encryption key of the catalogue's example Request Object.
pub fn encryption_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "1",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"})
}

pub fn request_object(query: &Value, nonce: &str) -> Value {
    json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": RESPONSE_URI,
        "client_id": CLIENT_ID,
        "nonce": nonce,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [query]}
    })
}

/// The session of a redirect request with this nonce.
pub fn session(query: &Value, nonce: &str) -> Session {
    let checked = check_request(
        &request_object(query, nonce),
        Signing::Signed,
        Channel::Redirect,
    )
    .unwrap();
    let thumbprint = ec_jwk_thumbprint(&encryption_jwk()).unwrap();
    Session {
        handover: checked.handover(&thumbprint).unwrap(),
        verifier_id: VerifierId::x509_san_dns(checked.client_id(), Intermediary::Absent).unwrap(),
    }
}

/// The ES256 signature of `data` by the device key of scalar `device`.
pub fn device_signature(device: u8, data: &[u8]) -> Es256Signature {
    let signature: Signature = key(device).sign(data);
    Es256Signature::new(signature.to_bytes().into())
}

/// The pseudonym of `SHA256(DST ‖ seed ‖ 0^32 ‖ SHA256(verifier_id))`, written out.
pub fn expected_pseudonym(seed: &[u8; 16], verifier_id: &str) -> [u8; 32] {
    let mut message = b"nym_auth/v1/known-offender-matching-ssc".to_vec();
    message.extend_from_slice(seed);
    message.extend_from_slice(&[0; 32]);
    message.extend_from_slice(&sha256(verifier_id.as_bytes()));
    sha256(&message)
}

/// A digest of every public value and the pseudonym: a test proof binds them as a real proof
/// does, so a verifier with any other value refuses it.
fn binding(statement: &Statement, pseudonym: &PseudonymValue) -> [u8; 32] {
    let date = |d: Option<siros_codec::date::Date>| d.map_or("-".to_owned(), |d| d.to_string());
    let mut h = Sha256::new();
    for part in [
        statement.system.id().as_str().as_bytes(),
        statement.proof_backend.as_str().as_bytes(),
        statement.issuer.certificate().der(),
        statement.issuer.key().x(),
        statement.issuer.key().y(),
        statement.proof_time.to_string().as_bytes(),
        date(statement.earliest).as_bytes(),
        date(statement.cutoff).as_bytes(),
        statement.verifier_input.as_bytes(),
        statement.session_transcript.as_bytes(),
        statement.challenge_digest.as_bytes(),
        pseudonym.as_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// The length of a test `zk_proof`: the rulebook's for Vega, 1 KiB for Longfellow.
fn proof_len(system: NymAuthSystem) -> usize {
    system.zk_proof_len().unwrap_or(1024)
}

/// A test prover: its `zk_proof` repeats `binding` to the system's length.
pub struct TestProver {
    /// What the prover answers instead of a proof.
    pub fail: Option<ProverFailure>,
}

impl NymAuthProver for TestProver {
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure> {
        if let Some(failure) = self.fail {
            return Err(failure);
        }
        let pseudonym = {
            let mut message = b"nym_auth/v1/known-offender-matching-ssc".to_vec();
            message.extend_from_slice(job.secret_seed());
            message.extend_from_slice(&[0; 32]);
            message.extend_from_slice(job.statement().verifier_input.as_bytes());
            PseudonymValue::new(sha256(&message))
        };
        let digest = binding(job.statement(), &pseudonym);
        let zk_proof = digest
            .iter()
            .copied()
            .cycle()
            .take(proof_len(job.statement().system))
            .collect();
        Ok(ProofOutput {
            zk_proof: ZkProof::new(zk_proof),
            pseudonym,
        })
    }
}

/// The verifier of [`TestProver`]'s proofs.
pub struct TestVerifier;

impl NymAuthProofVerifier for TestVerifier {
    fn verify(
        &self,
        statement: &Statement,
        pseudonym: &PseudonymValue,
        zk_proof: &ZkProof,
    ) -> Result<(), ProofFailure> {
        let zk_proof = zk_proof.as_bytes();
        if zk_proof.len() != proof_len(statement.system) {
            return Err(ProofFailure::Encoding);
        }
        let digest = binding(statement, pseudonym);
        let expected: Vec<u8> = digest
            .iter()
            .copied()
            .cycle()
            .take(zk_proof.len())
            .collect();
        if zk_proof == expected {
            Ok(())
        } else {
            Err(ProofFailure::Invalid)
        }
    }
}
