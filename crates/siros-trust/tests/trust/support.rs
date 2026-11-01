//! Certificates built at test time with x509-cert's builder, keys from fixed scalars, and the
//! queries and stores the cases read.

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::signature::{Keypair, Signer};
use siros_codec::chain::CertificateChain;
use siros_codec::date::DateTime;
use siros_dcql::DcqlQuery;
use siros_trust::{IssuerChain, QueryAuthorities, TrustStore};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{AnyRef, GeneralizedTime, ObjectIdentifier, OctetString};
use x509_cert::der::Encode;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, InhibitAnyPolicy, KeyUsage};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifier, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::time::{Time, Validity};

/// The time of every case: 2026-10-26T12:00:00Z.
pub const NOW: &str = "2026-10-26T12:00:00Z";

pub fn at(text: &str) -> DateTime {
    DateTime::parse(text).unwrap()
}

/// A signing key of a fixed scalar.
#[derive(Clone)]
pub enum Key {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl Key {
    pub fn p256(byte: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap())
    }

    pub fn p384(byte: u8) -> Self {
        Self::P384(p384::ecdsa::SigningKey::from_bytes(&[byte; 48].into()).unwrap())
    }

    fn spki(&self) -> SubjectPublicKeyInfoOwned {
        match self {
            Self::P256(key) => SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
            Self::P384(key) => SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
        }
    }
}

/// A P-256 key that declares `ecdsa-with-SHA512` (RFC 5758), an algorithm TR3 does not accept.
struct Sha512Declared(p256::ecdsa::SigningKey);

impl Keypair for Sha512Declared {
    type VerifyingKey = p256::ecdsa::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        *self.0.verifying_key()
    }
}

impl SignatureAlgorithmIdentifier for Sha512Declared {
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<AnyRef<'static>> =
        AlgorithmIdentifier {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
            parameters: None,
        };
}

impl Signer<p256::ecdsa::DerSignature> for Sha512Declared {
    fn try_sign(&self, message: &[u8]) -> Result<p256::ecdsa::DerSignature, p256::ecdsa::Error> {
        self.0.try_sign(message)
    }
}

/// A certificate to build: its subject, key, validity and extensions, and who signs it.
#[derive(Clone)]
pub struct Cert {
    subject: String,
    key: Key,
    issuer: String,
    signer: Key,
    validity: (&'static str, &'static str),
    ca: Option<bool>,
    path_len: Option<u8>,
    key_usage: Option<KeyUsage>,
    inhibit_any_policy: bool,
    aki: Option<Vec<u8>>,
    sha512_declared: bool,
    explicit_false_critical: bool,
}

impl Cert {
    /// A self-signed certificate authority, valid through 2026 and 2027.
    pub fn root(cn: &str, key: Key) -> Self {
        let subject = format!("CN={cn},O=Test only");
        Self {
            issuer: subject.clone(),
            signer: key.clone(),
            subject,
            key,
            validity: ("2026-01-01T00:00:00Z", "2027-12-31T23:59:59Z"),
            ca: Some(true),
            path_len: None,
            key_usage: None,
            inhibit_any_policy: false,
            aki: None,
            sha512_declared: false,
            explicit_false_critical: false,
        }
    }

    /// An end-entity certificate `issuer` signs, valid through 2026 and 2027.
    pub fn issued_by(cn: &str, key: Key, issuer: &Self) -> Self {
        Self {
            subject: format!("CN={cn},O=Test only"),
            key,
            issuer: issuer.subject.clone(),
            signer: issuer.key.clone(),
            validity: ("2026-01-01T00:00:00Z", "2027-12-31T23:59:59Z"),
            ca: None,
            path_len: None,
            key_usage: None,
            inhibit_any_policy: false,
            aki: None,
            sha512_declared: false,
            explicit_false_critical: false,
        }
    }

    pub fn ca(mut self, ca: Option<bool>) -> Self {
        self.ca = ca;
        self
    }

    /// basicConstraints states the pathLenConstraint `length`.
    pub fn path_len(mut self, length: u8) -> Self {
        self.path_len = Some(length);
        self
    }

    /// The certificate has the keyUsage `usage`, critical.
    pub fn key_usage(mut self, usage: KeyUsage) -> Self {
        self.key_usage = Some(usage);
        self
    }

    /// The certificate has inhibitAnyPolicy, critical: an extension TR3 does not process.
    pub fn inhibit_any_policy(mut self) -> Self {
        self.inhibit_any_policy = true;
        self
    }

    pub fn valid(mut self, from: &'static str, until: &'static str) -> Self {
        self.validity = (from, until);
        self
    }

    pub fn aki(mut self, key_identifier: &[u8]) -> Self {
        self.aki = Some(key_identifier.to_vec());
        self
    }

    /// The certificate names `cn` as its issuer, and its signer stays.
    pub fn issuer_named(mut self, cn: &str) -> Self {
        self.issuer = format!("CN={cn},O=Test only");
        self
    }

    /// The certificate is signed with `key`, and its issuer name stays.
    pub fn signed_with(mut self, key: Key) -> Self {
        self.signer = key;
        self
    }

    /// The certificate declares `ecdsa-with-SHA512`; a P-256 signer signs it.
    pub fn sha512_declared(mut self) -> Self {
        self.sha512_declared = true;
        self
    }

    /// Each extension writes `critical` FALSE out, where DER omits the default; the signer signs
    /// the bytes as written.
    pub fn explicit_false_critical(mut self) -> Self {
        self.explicit_false_critical = true;
        self
    }

    pub fn der(&self) -> Vec<u8> {
        let der = self.built();
        if self.explicit_false_critical {
            explicit_false_critical(&der, &self.signer)
        } else {
            der
        }
    }

    fn built(&self) -> Vec<u8> {
        let time = |text: &str| {
            let unix = Duration::from_secs(at(text).unix() as u64);
            Time::GeneralTime(GeneralizedTime::from_unix_duration(unix).unwrap())
        };
        let validity = Validity {
            not_before: time(self.validity.0),
            not_after: time(self.validity.1),
        };
        match (&self.signer, self.sha512_declared) {
            (Key::P256(key), true) => {
                self.build::<_, p256::ecdsa::DerSignature>(validity, &Sha512Declared(key.clone()))
            }
            (Key::P256(key), false) => self.build::<_, p256::ecdsa::DerSignature>(validity, key),
            (Key::P384(key), _) => self.build::<_, p384::ecdsa::DerSignature>(validity, key),
        }
    }

    fn build<S, Signature>(&self, validity: Validity, signer: &S) -> Vec<u8>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Signature>,
        S::VerifyingKey: EncodePublicKey,
        Signature: SignatureBitStringEncoding,
    {
        let mut builder = CertificateBuilder::new(
            Profile::Manual {
                issuer: Some(Name::from_str(&self.issuer).unwrap()),
            },
            SerialNumber::new(&[0x01, self.subject.len() as u8]).unwrap(),
            validity,
            Name::from_str(&self.subject).unwrap(),
            self.key.spki(),
            signer,
        )
        .unwrap();
        if let Some(ca) = self.ca {
            builder
                .add_extension(&BasicConstraints {
                    ca,
                    path_len_constraint: self.path_len,
                })
                .unwrap();
        }
        if let Some(usage) = &self.key_usage {
            builder.add_extension(usage).unwrap();
        }
        if self.inhibit_any_policy {
            builder.add_extension(&InhibitAnyPolicy(0)).unwrap();
        }
        if let Some(aki) = &self.aki {
            builder
                .add_extension(&AuthorityKeyIdentifier {
                    key_identifier: Some(OctetString::new(aki.clone()).unwrap()),
                    authority_cert_issuer: None,
                    authority_cert_serial_number: None,
                })
                .unwrap();
        }
        builder.build::<Signature>().unwrap().to_der().unwrap()
    }
}

/// The content of the TLV `tlv`, a DER tag of one byte and its length.
fn content(tlv: &[u8]) -> &[u8] {
    let (length, header) = match tlv[1] {
        short @ 0..=0x7f => (usize::from(short), 2),
        long => {
            let count = usize::from(long & 0x7f);
            let length = tlv[2..2 + count]
                .iter()
                .fold(0, |n, b| (n << 8) | usize::from(*b));
            (length, 2 + count)
        }
    };
    &tlv[header..header + length]
}

/// The TLVs of `content`, in order.
fn tlvs(mut content: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let inner = self::content(content);
        let end = inner.as_ptr() as usize - content.as_ptr() as usize + inner.len();
        out.push(&content[..end]);
        content = &content[end..];
    }
    out
}

/// The TLV of tag `tag` and content `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = content.len().to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (bytes.len() - skip) as u8);
            out.extend_from_slice(&bytes[skip..]);
        }
    }
    out.extend_from_slice(content);
    out
}

/// `der` with `critical` FALSE written out in each extension, in place of the default or of
/// the builder's TRUE, signed again by `signer`.
fn explicit_false_critical(der: &[u8], signer: &Key) -> Vec<u8> {
    let parts = tlvs(content(der));
    let fields: Vec<u8> = tlvs(content(parts[0]))
        .into_iter()
        .flat_map(|field| {
            if field[0] != 0xa3 {
                return field.to_vec();
            }
            let extensions: Vec<u8> = tlvs(content(content(field)))
                .into_iter()
                .flat_map(|extension| {
                    let members = tlvs(content(extension));
                    let mut written = members[0].to_vec();
                    written.extend_from_slice(&[0x01, 0x01, 0x00]);
                    written.extend_from_slice(members[members.len() - 1]);
                    tlv(0x30, &written)
                })
                .collect();
            tlv(0xa3, &tlv(0x30, &extensions))
        })
        .collect();
    let tbs = tlv(0x30, &fields);
    let signature = match signer {
        Key::P256(key) => {
            let signature: p256::ecdsa::DerSignature = key.sign(&tbs);
            signature.to_bytes().to_vec()
        }
        Key::P384(key) => {
            let signature: p384::ecdsa::DerSignature = key.sign(&tbs);
            signature.to_bytes().to_vec()
        }
    };
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    let mut certificate = tbs;
    certificate.extend_from_slice(parts[1]);
    certificate.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &certificate)
}

/// The chain of the DER certificates `first` and `rest`.
pub fn chain_of(first: &[u8], rest: &[&[u8]]) -> IssuerChain {
    let rest = rest.iter().map(|der| der.to_vec()).collect();
    IssuerChain::parse(&CertificateChain::new(first.to_vec(), rest)).unwrap()
}

/// The chain of `certificates`, the signer's first.
pub fn chain(certificates: &[&Cert]) -> IssuerChain {
    let (first, rest) = certificates.split_first().unwrap();
    let rest = rest.iter().map(|c| c.der()).collect();
    IssuerChain::parse(&CertificateChain::new(first.der(), rest)).unwrap()
}

/// The authorities of a `mso_mdoc` query with `trusted_authorities` `authorities`; `null`
/// writes a query without the member.
pub fn authorities(authorities: serde_json::Value) -> QueryAuthorities {
    let mut query = serde_json::json!({"id": "pid", "format": "mso_mdoc", "meta": {}});
    if !authorities.is_null() {
        query["trusted_authorities"] = authorities;
    }
    let query = DcqlQuery::parse(&serde_json::json!({ "credentials": [query] })).unwrap();
    QueryAuthorities::of(&query.credentials()[0]).unwrap()
}

/// A store record with one entry per `(type, value, certificates)`.
pub fn record(entries: &[(&str, &str, &[&Cert])]) -> String {
    let entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|(kind, value, certificates)| {
            let certificates: Vec<String> = certificates.iter().map(|c| base64(&c.der())).collect();
            serde_json::json!({"type": kind, "value": value, "certificates": certificates})
        })
        .collect();
    serde_json::Value::Array(entries).to_string()
}

pub fn store(entries: &[(&str, &str, &[&Cert])]) -> TrustStore {
    TrustStore::parse(&record(entries)).unwrap()
}

/// base64 with padding (RFC 4648, Section 4), written here.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
