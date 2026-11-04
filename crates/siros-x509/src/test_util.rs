//! X.509 certificates generated for tests (feature `test-util`): DER written here from RFC 5280
//! §4.1's structure, apart from x509-cert, which parses it; signed with ES256 (ecdsa-with-SHA256)
//! by p256.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

/// The issuer's scalar: SHA-256 of `siros-x509 test root`.
const ROOT: [u8; 32] = [
    0x14, 0x06, 0x07, 0x82, 0xf5, 0x3a, 0x45, 0xe4, 0x80, 0x4a, 0x91, 0x65, 0xc9, 0x1f, 0x87, 0x51,
    0x66, 0x29, 0x20, 0x70, 0xa0, 0x75, 0x4a, 0xa8, 0x1f, 0x6e, 0x82, 0x4a, 0x27, 0x5f, 0xc1, 0x7d,
];

/// id-ecPublicKey, secp256r1, ecdsa-with-SHA256, commonName, subjectAltName (RFC 5480, RFC 5758,
/// RFC 5280).
const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const SECP256R1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const SUBJECT_ALT_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];

/// A DER TLV: the tag, the definite length in its shortest form, the content.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let mut out = vec![tag];
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let octets: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|octet| *octet == 0)
            .collect();
        out.push(0x80 | u8::try_from(octets.len()).unwrap_or(0));
        out.extend(octets);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn name(common: &str) -> Vec<u8> {
    let attribute = sequence(&[COMMON_NAME, &tlv(0x0c, common.as_bytes())]);
    sequence(&[&tlv(0x31, &attribute)])
}

/// The uncompressed point of a scalar's public key: 0x04, x, y (SEC 1 §2.3.3).
#[must_use]
pub fn point(secret: &[u8; 32]) -> Vec<u8> {
    p256::SecretKey::from_slice(secret)
        .map(|key| key.public_key().to_sec1_point(false).as_bytes().to_vec())
        .unwrap_or_default()
}

/// What a test certificate holds: its subject, its key as a SEC 1 point, its dNSName entries.
#[derive(Debug, Clone)]
pub struct Leaf<'a> {
    /// The subject's common name.
    pub subject: &'a str,
    /// The public key as SEC 1 writes it.
    pub point: Vec<u8>,
    /// The subjectAltName's dNSName entries; none leaves the extension out.
    pub dns: &'a [&'a str],
}

/// The DER certificate of the leaf, issued by the test root and signed with its key.
#[must_use]
pub fn certificate(leaf: &Leaf<'_>) -> Vec<u8> {
    let algorithm = sequence(&[ECDSA_SHA256]);
    let key_algorithm = sequence(&[EC_PUBLIC_KEY, SECP256R1]);
    let spki = sequence(&[
        &key_algorithm,
        &tlv(0x03, &[&[0u8][..], &leaf.point].concat()),
    ]);
    let validity = sequence(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"360101000000Z")]);
    let mut tbs = vec![
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, &[0x01, 0x23]),
        algorithm.clone(),
        name("SIROS test root"),
        validity,
        name(leaf.subject),
        spki,
    ];
    if !leaf.dns.is_empty() {
        let names: Vec<u8> = leaf
            .dns
            .iter()
            .flat_map(|dns| tlv(0x82, dns.as_bytes()))
            .collect();
        let extension = sequence(&[SUBJECT_ALT_NAME, &tlv(0x04, &tlv(0x30, &names))]);
        tbs.push(tlv(0xa3, &sequence(&[&extension])));
    }
    let tbs = tlv(0x30, &tbs.concat());
    let signature = SigningKey::from_slice(&ROOT)
        .map(|signer| {
            let signed: DerSignature = signer.sign(&tbs);
            signed.as_bytes().to_vec()
        })
        .unwrap_or_default();
    sequence(&[
        &tbs,
        &algorithm,
        &tlv(0x03, &[&[0u8][..], &signature].concat()),
    ])
}

/// The test root's self-issued certificate.
#[must_use]
pub fn root() -> Vec<u8> {
    certificate(&Leaf {
        subject: "SIROS test root",
        point: point(&ROOT),
        dns: &[],
    })
}

/// The `x5c` items of a chain, base64 (RFC 7515 §4.1.6): the leaf, then the root.
#[must_use]
pub fn x5c(leaf: &[u8]) -> Vec<String> {
    vec![STANDARD.encode(leaf), STANDARD.encode(root())]
}

/// The protected header of a Request Object signed under the chain's leaf.
#[must_use]
pub fn header(items: &[String]) -> String {
    let items: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
    format!(
        r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":[{}]}}"#,
        items.join(",")
    )
}

/// The `x509_hash` Client Identifier of a leaf: base64url of its DER's SHA-256.
#[must_use]
pub fn x509_hash(leaf: &[u8]) -> String {
    format!("x509_hash:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(leaf)))
}
