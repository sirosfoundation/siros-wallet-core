//! The certificate chain of an `x5c` Header Parameter (RFC 7515, Section 4.1.6) and what the
//! wallet reads from its leaf: the P-256 key, the dNSName SANs (RFC 5280, Section 4.2.1.6) and
//! the semantics identifier of its subject (ETSI TS 119 475, Clauses 5.1.3 and 5.1.5).
//!
//! The chain is validated by the host's trust evaluation; the core binds the leaf.

use der::asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef};
use der::{Any, Decode};
use p256::PublicKey;
use serde_json::Value;
use siros_codec::base64;
use siros_codec::chain::CertificateChain;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{CertificatePolicies, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::{Certificate, TbsCertificate};

use crate::intake::{ChainFault, IntakeError, LeafKeyFault};
use crate::semantic::{Person, SemanticIdError, SemanticIdentifier};
use crate::verified::{AccessCertificate, CertificateDer};

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` (RFC 5480).
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `id-at-organizationIdentifier` (Recommendation ITU-T X.520).
const ORGANIZATION_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.97");
/// `id-at-serialNumber` (Recommendation ITU-T X.520).
const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
/// The access certificate policies for natural persons, NCP-n-eudiwrp and QCP-n-eudiwrp (ETSI
/// TS 119 411-8, Clause 5.3).
const NATURAL_POLICIES: [ObjectIdentifier; 2] = [
    ObjectIdentifier::new_unwrap("0.4.0.194118.1.1"),
    ObjectIdentifier::new_unwrap("0.4.0.194118.1.3"),
];
/// The access certificate policies for legal persons, NCP-l-eudiwrp and QCP-l-eudiwrp (ETSI
/// TS 119 411-8, Clause 5.3).
const LEGAL_POLICIES: [ObjectIdentifier; 2] = [
    ObjectIdentifier::new_unwrap("0.4.0.194118.1.2"),
    ObjectIdentifier::new_unwrap("0.4.0.194118.1.4"),
];

/// An `x5c` chain and what the wallet reads from its leaf.
#[derive(Debug, Clone)]
pub(crate) struct Chain {
    chain: CertificateChain,
    leaf: CertificateDer,
    key: PublicKey,
    dns_names: Vec<String>,
    semantic_identifier: Result<SemanticIdentifier, SemanticIdError>,
}

impl Chain {
    /// The chain of the Header Parameter value `x5c`: a non-empty array of base64 DER
    /// certificates, leaf first.
    pub(crate) fn parse(x5c: Option<&Value>) -> Result<Self, IntakeError> {
        let invalid = IntakeError::CertificateChainInvalid;
        let mut ders = x5c
            .and_then(Value::as_array)
            .ok_or(invalid(ChainFault::Absent))?
            .iter()
            .map(|c| {
                let text = c.as_str().ok_or(invalid(ChainFault::NotString))?;
                base64::decode(text).map_err(|e| invalid(ChainFault::Encoding(e)))
            });
        let leaf_der = ders.next().ok_or(invalid(ChainFault::Absent))??;
        let chain = CertificateChain::new(leaf_der, ders.collect::<Result<_, _>>()?);
        let leaf = Certificate::from_der(chain.first())
            .map_err(|error| invalid(ChainFault::LeafNotCertificate(error)))?;
        let tbs = &leaf.tbs_certificate;
        let key = p256_key(tbs).map_err(|fault| invalid(ChainFault::LeafKey(fault)))?;
        let dns_names = match tbs.get::<SubjectAltName>() {
            Ok(Some((_, san))) => san
                .0
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DnsName(dns) => Some(dns.as_str().to_owned()),
                    _ => None,
                })
                .collect(),
            Ok(None) => Vec::new(),
            Err(error) => return Err(invalid(ChainFault::SubjectAltName(error))),
        };
        Ok(Self {
            leaf: CertificateDer(chain.first().to_vec()),
            key,
            dns_names,
            semantic_identifier: semantic_identifier(tbs),
            chain,
        })
    }

    /// The leaf as the Wallet-Relying Party's access certificate.
    pub(crate) fn access_certificate(&self) -> AccessCertificate {
        AccessCertificate {
            der: self.leaf.clone(),
            semantic_identifier: self.semantic_identifier.clone(),
        }
    }

    /// The leaf certificate's key.
    pub(crate) fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The leaf certificate.
    pub(crate) fn leaf(&self) -> &CertificateDer {
        &self.leaf
    }

    /// Whether a dNSName SAN of the leaf is `name`, in ASCII case-insensitive comparison
    /// (RFC 4343).
    pub(crate) fn names_dns(&self, name: &str) -> bool {
        self.dns_names
            .iter()
            .any(|dns| dns.eq_ignore_ascii_case(name))
    }

    /// The certificates.
    pub(crate) fn into_certificates(self) -> CertificateChain {
        self.chain
    }
}

/// The P-256 key of the certificate of `tbs`.
fn p256_key(tbs: &TbsCertificate) -> Result<PublicKey, LeafKeyFault> {
    let spki = &tbs.subject_public_key_info;
    if spki.algorithm.oid != EC_PUBLIC_KEY {
        return Err(LeafKeyFault::Algorithm(spki.algorithm.oid));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(LeafKeyFault::CurveAbsent)?
        .decode_as::<ObjectIdentifier>()
        .map_err(LeafKeyFault::Curve)?;
    if curve != PRIME256V1 {
        return Err(LeafKeyFault::OtherCurve(curve));
    }
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or(LeafKeyFault::Unaligned)?;
    PublicKey::from_sec1_bytes(point).map_err(|_| LeafKeyFault::Point)
}

/// The semantics identifier of the subject of `tbs`: under a natural-person policy its one
/// `serialNumber`; under a legal-person policy its one `organizationIdentifier`, or without
/// one its one `serialNumber`.
fn semantic_identifier(tbs: &TbsCertificate) -> Result<SemanticIdentifier, SemanticIdError> {
    let person = person(tbs)?;
    let organization = values(&tbs.subject, ORGANIZATION_IDENTIFIER);
    let text = match person {
        Person::Legal if !organization.is_empty() => directory_string(one(&organization)?)?,
        Person::Legal | Person::Natural => {
            printable_string(one(&values(&tbs.subject, SERIAL_NUMBER))?)?
        }
    };
    SemanticIdentifier::parse(&text, person)
}

/// Whom the certificate of `tbs` is issued to, by its access certificate policies.
fn person(tbs: &TbsCertificate) -> Result<Person, SemanticIdError> {
    let policies = match tbs.get::<CertificatePolicies>() {
        Ok(Some((_, policies))) => policies.0,
        Ok(None) => Vec::new(),
        Err(error) => return Err(SemanticIdError::Policies(error)),
    };
    let names = |listed: &[ObjectIdentifier]| {
        policies
            .iter()
            .any(|policy| listed.contains(&policy.policy_identifier))
    };
    match (names(&NATURAL_POLICIES), names(&LEGAL_POLICIES)) {
        (true, true) => Err(SemanticIdError::Contradictory),
        (true, false) => Ok(Person::Natural),
        (false, true) => Ok(Person::Legal),
        (false, false) => Err(SemanticIdError::Unclassified),
    }
}

/// The values of the attribute `oid` in `subject`.
fn values(subject: &Name, oid: ObjectIdentifier) -> Vec<&Any> {
    subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attribute| attribute.oid == oid)
        .map(|attribute| &attribute.value)
        .collect()
}

/// The one value of `values`.
fn one<'v>(values: &[&'v Any]) -> Result<&'v Any, SemanticIdError> {
    match values {
        [] => Err(SemanticIdError::Absent),
        [value] => Ok(value),
        _ => Err(SemanticIdError::Repeated),
    }
}

/// The text of a `DirectoryString` value: UTF-8 or printable.
fn directory_string(value: &Any) -> Result<String, SemanticIdError> {
    value
        .decode_as::<Utf8StringRef<'_>>()
        .map(|text| text.as_str().to_owned())
        .or_else(|_| printable_string(value))
}

/// The text of a `PrintableString` value.
fn printable_string(value: &Any) -> Result<String, SemanticIdError> {
    value
        .decode_as::<PrintableStringRef<'_>>()
        .map(|text| text.as_str().to_owned())
        .map_err(SemanticIdError::Encoding)
}
