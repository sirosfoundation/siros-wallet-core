//! A verifier that signs requests and issues its certificates, and a host that answers intake's
//! effects.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Map, Value};
use siros_codec::base64url;
pub use siros_codec::date::DateTime;
use siros_oid4vp::{
    DcApiData, Effect, EffectResult, IntakeError, IntakeState, KeyMaterial, Kid, RequestObjectText,
    Step, Submission, TrustAnswer, VerifiedRequest,
};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, UtcTime};
use x509_cert::der::Encode;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{CertificatePolicies, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

/// 2026-10-26T00:00:00Z.
pub const NOW: u64 = 1_792_972_800;

/// The Credential Query id `text`.
pub fn query_id(text: &str) -> siros_dcql::QueryId {
    siros_dcql::QueryId::parse(text).unwrap()
}

/// [`NOW`] as a time.
pub fn now() -> DateTime {
    DateTime::from_unix(NOW as i64).unwrap()
}

/// A deterministic generator (SplitMix64) standing in for the host's CSPRNG.
pub struct Rng(pub u64);

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32].into()).unwrap()
}

pub fn b64(bytes: &[u8]) -> String {
    base64url::encode(bytes).into_string()
}

/// base64 with padding, as `x5c` carries certificates.
pub fn b64_padded(bytes: &[u8]) -> String {
    let mut text = base64url::encode(bytes)
        .into_string()
        .replace('-', "+")
        .replace('_', "/");
    while text.len() % 4 != 0 {
        text.push('=');
    }
    text
}

/// The public JWK of a P-256 key.
pub fn jwk(key: &VerifyingKey) -> Value {
    let point = key.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(point.x().unwrap()),
        "y": b64(point.y().unwrap()),
    })
}

/// A self-signed certificate of `key` with the dNSName SANs `dns`.
pub fn certificate(key: &SigningKey, dns: &[&str]) -> Vec<u8> {
    subject_certificate(
        key,
        dns,
        "CN=Test verifier,O=Test only",
        Policies::Listed(&[]),
    )
}

/// The certificate policies extension of a certificate.
#[derive(Clone, Copy)]
pub enum Policies {
    /// These policy identifiers; no extension for none.
    Listed(&'static [&'static str]),
    /// An extension whose value is no `CertificatePolicies`.
    Malformed,
}

/// The certificatePolicies extension with a value that does not decode.
struct MalformedPolicies;

impl x509_cert::der::oid::AssociatedOid for MalformedPolicies {
    const OID: x509_cert::der::oid::ObjectIdentifier =
        x509_cert::der::oid::ObjectIdentifier::new_unwrap("2.5.29.32");
}

impl x509_cert::der::Encode for MalformedPolicies {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        x509_cert::der::asn1::Null.encoded_len()
    }

    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        x509_cert::der::asn1::Null.encode(encoder)
    }
}

impl x509_cert::ext::AsExtension for MalformedPolicies {
    fn critical(&self, _: &Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
}

/// A self-signed certificate of `key` for `subject` (RFC 4514), with the dNSName SANs `dns`
/// and the certificate policies `policies`.
pub fn subject_certificate(
    key: &SigningKey,
    dns: &[&str],
    subject: &str,
    policies: Policies,
) -> Vec<u8> {
    let at =
        |unix: u64| Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(unix)).unwrap());
    let validity = Validity {
        not_before: at(1_767_225_600),
        not_after: at(1_893_456_000),
    };
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::new(&[1]).unwrap(),
        validity,
        Name::from_str(subject).unwrap(),
        spki,
        key,
    )
    .unwrap();
    if !dns.is_empty() {
        let names = dns
            .iter()
            .map(|d| GeneralName::DnsName(Ia5String::new(d).unwrap()))
            .collect();
        builder.add_extension(&SubjectAltName(names)).unwrap();
    }
    match policies {
        Policies::Listed([]) => {}
        Policies::Listed(oids) => {
            let listed = oids
                .iter()
                .map(|oid| PolicyInformation {
                    policy_identifier: x509_cert::der::oid::ObjectIdentifier::new(oid).unwrap(),
                    policy_qualifiers: None,
                })
                .collect();
            builder.add_extension(&CertificatePolicies(listed)).unwrap();
        }
        Policies::Malformed => builder.add_extension(&MalformedPolicies).unwrap(),
    }
    builder.build::<DerSignature>().unwrap().to_der().unwrap()
}

/// The ES256 signature of `signing_input`, `r || s`, base64url.
pub fn es256(key: &SigningKey, signing_input: &str) -> String {
    let signature: Signature = key.sign(signing_input.as_bytes());
    b64(&signature.to_bytes())
}

/// A JWS Compact Serialization of `payload` under `header`.
pub fn sign(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let signature = es256(key, &input);
    format!("{input}.{signature}")
}

/// One `signatures` member of a JWS JSON Serialization over `payload_b64`.
pub fn signature_object(protected: &Value, payload_b64: &str, key: &SigningKey) -> Value {
    let protected = b64(protected.to_string().as_bytes());
    let signature = es256(key, &format!("{protected}.{payload_b64}"));
    json!({"protected": protected, "signature": signature})
}

/// The header of a Request Object signed with `x5c`.
pub fn x5c_header(certificate: &[u8]) -> Value {
    json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [b64_padded(certificate)]})
}

/// A DCQL query for one SD-JWT VC.
pub fn query() -> Value {
    json!({"credentials": [{
        "id": "pid",
        "format": "dc+sd-jwt",
        "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]},
        "claims": [{"path": ["last_name"]}, {"path": ["first_name"]}]
    }]})
}

/// The wallet's `vp_formats_supported`.
pub fn formats() -> Map<String, Value> {
    json!({"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}})
        .as_object()
        .unwrap()
        .clone()
}

/// What the host's trust evaluation gives. A test that asks for a Request Object answers it.
pub struct Host {
    /// The AuthZEN decision on every subject.
    pub trusted: bool,
    /// The keys the host resolves, by `kid`.
    pub keys: Vec<(String, Value)>,
    /// The Verifier metadata of an OpenID Federation Trust Chain.
    pub metadata: Option<Value>,
}

impl Host {
    pub fn trusting() -> Self {
        Self {
            trusted: true,
            keys: Vec::new(),
            metadata: None,
        }
    }

    pub fn answer(&self, effect: &Effect) -> EffectResult {
        match effect {
            Effect::RequestObject(request) => {
                panic!("no Request Object expected: {request:?}")
            }
            Effect::Trust(trust) => match trust.key() {
                KeyMaterial::Resolve { kid, trust_chain } => {
                    let key = self
                        .keys
                        .iter()
                        .find(|(k, _)| Some(k.as_str()) == kid.as_ref().map(Kid::as_str))
                        .map(|(_, jwk)| jwk.clone());
                    let metadata = trust_chain.as_ref().and(self.metadata.clone());
                    EffectResult::Trusted(TrustAnswer::new(self.trusted.into(), key, metadata))
                }
                _ => EffectResult::Trusted(TrustAnswer::new(self.trusted.into(), None, None)),
            },
        }
    }
}

/// The Request Object `jws`, as the host obtained it.
pub fn request_object(jws: &str) -> RequestObjectText {
    RequestObjectText::new(jws.to_owned()).unwrap()
}

/// The `data` of a DC API submission.
pub fn dc_api_data(submission: &Submission) -> Value {
    let Submission::DcApi(data) = submission else {
        panic!("a DC API response, got {submission:?}")
    };
    data.json()
}

/// The JWE of a `dc_api.jwt` submission.
pub fn dc_api_jwe(submission: &Submission) -> String {
    let Submission::DcApi(DcApiData::Jwt(jwe)) = submission else {
        panic!("a dc_api.jwt response, got {submission:?}")
    };
    jwe.as_str().to_owned()
}

/// Intake to its end, each effect answered by `host`; the verified request and the effects.
pub fn run(
    mut state: IntakeState,
    mut host: impl FnMut(&Effect) -> EffectResult,
) -> Result<(VerifiedRequest, Vec<Effect>), IntakeError> {
    let mut effects = Vec::new();
    loop {
        match state.step()? {
            Step::Verified(request) => return Ok((*request, effects)),
            Step::Effect(effect) => {
                state.answer(host(&effect));
                effects.push(effect);
            }
        }
    }
}

/// A DC API request of one entry.
pub fn dc_api(protocol: &str, data: Value) -> Vec<u8> {
    json!({"requests": [{"protocol": protocol, "data": data}]})
        .to_string()
        .into_bytes()
}

/// An authorization request URI with form-encoded `params`.
pub fn authorization_uri(params: &[(&str, &str)]) -> String {
    let mut uri = String::from("openid4vp://?");
    for (index, (name, value)) in params.iter().enumerate() {
        if index > 0 {
            uri.push('&');
        }
        uri.push_str(name);
        uri.push('=');
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                uri.push(char::from(byte));
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    uri
}

/// The parameters of form-encoded text.
pub fn form(body: &str) -> Vec<(String, String)> {
    let decode = |text: &str| {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                other => {
                    out.push(other);
                    i += 1;
                }
            }
        }
        String::from_utf8(out).unwrap()
    };
    body.split('&')
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap();
            (decode(name), decode(value))
        })
        .collect()
}
