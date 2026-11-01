//! TR3's path validation, one case per rule, each refusal by its reason; and the picker's
//! admission from the TR5 facts, which must equal the wallet's in every case.

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_dcql::AuthorityType;
use siros_trust::{
    Admission, AdmittedIssuer, CertificateIndex, ChainIndex, ChainRefusal, Ground, IssuerChain,
    IssuerFacts, KeyIdentifier, OnPath, PathRefusal, Refusal, StoreAuthority, StoreType,
    TrustStore,
};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

use crate::support::{at, authorities, base64, chain, chain_of, store, Cert, Key, NOW};

/// The Document Signer of ISO/IEC 18013-5, Annex D: keyUsage and extKeyUsage critical.
const ANNEX_D_DOCUMENT_SIGNER: &[u8] = include_bytes!("vectors/annex_d_document_signer.der");

const LIST: &str = "https://tl.example/eu";

/// `id-ce-inhibitAnyPolicy` (RFC 5280, Section 4.2.1.14).
const INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");

/// One rule's case: the chain, the store, the query's `trusted_authorities`, the time, and
/// the outcome.
struct Case {
    name: &'static str,
    chain: IssuerChain,
    store: TrustStore,
    authorities: Value,
    time: DateTime,
    expected: Result<Ground, Vec<Refusal<ChainRefusal>>>,
}

fn etsi_tl(value: &str) -> Value {
    json!([{"type": "etsi_tl", "values": [value]}])
}

fn listed() -> Ground {
    Ground::Store(StoreAuthority::new(
        StoreType::EtsiTl,
        siros_dcql::AuthorityValue::new(LIST),
    ))
}

fn path(refusal: PathRefusal) -> Result<Ground, Vec<Refusal<ChainRefusal>>> {
    Err(vec![Refusal::Issuer(ChainRefusal::Path(refusal))])
}

/// A Document Signer that `iaca` signs, and the store that lists `iaca` under [`LIST`].
fn signed_by(iaca: &Cert, edit: impl FnOnce(Cert) -> Cert) -> (IssuerChain, TrustStore) {
    let document_signer = edit(Cert::issued_by(
        "Test Document Signer",
        Key::p256(0x32),
        iaca,
    ));
    (
        chain(&[&document_signer]),
        store(&[("etsi_tl", LIST, &[iaca])]),
    )
}

fn case(
    name: &'static str,
    (chain, store): (IssuerChain, TrustStore),
    authorities: Value,
    expected: Result<Ground, Vec<Refusal<ChainRefusal>>>,
) -> Case {
    Case {
        name,
        chain,
        store,
        authorities,
        time: at(NOW),
        expected,
    }
}

fn cases() -> Vec<Case> {
    let iaca = Cert::root("Test IACA", Key::p256(0x31));
    let first = ChainIndex::new(0);
    let anchor = OnPath::Store(CertificateIndex::new(0));
    let p384_root = Cert::root("Test P-384 IACA", Key::p384(0x41));
    let intermediate =
        Cert::issued_by("Test intermediate", Key::p384(0x42), &p384_root).ca(Some(true));
    let leaf = Cert::issued_by("Test Document Signer", Key::p256(0x43), &intermediate);
    let named_key = [0x5a; 20];
    vec![
        case(
            "no trusted_authorities",
            signed_by(&iaca, |ds| ds),
            Value::Null,
            Ok(Ground::Unconstrained),
        ),
        case(
            "an aki value a chain certificate's AuthorityKeyIdentifier names",
            signed_by(&iaca, |ds| ds.aki(&named_key)),
            json!([{"type": "aki", "values": [base64url::encode(&named_key).as_str()]}]),
            Ok(Ground::KeyIdentifier(
                KeyIdentifier::new(&named_key).unwrap(),
            )),
        ),
        case(
            "a two-level chain admitted through a store entry",
            signed_by(&iaca, |ds| ds),
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "a three-level chain, the intermediate in the chain, over P-384",
            (
                chain(&[&leaf, &intermediate]),
                store(&[("etsi_tl", LIST, &[&p384_root])]),
            ),
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "an ISO/IEC 18013-5 link certificate: the new IACA key, signed by the listed one",
            {
                let link = Cert::issued_by("Test IACA", Key::p256(0x35), &iaca).ca(Some(true));
                let document_signer =
                    Cert::issued_by("Test Document Signer", Key::p256(0x32), &link);
                (
                    chain(&[&document_signer, &link]),
                    store(&[("etsi_tl", LIST, &[&iaca])]),
                )
            },
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "a Document Signer whose basicConstraints writes critical FALSE out",
            signed_by(&iaca, |ds| ds.ca(Some(false)).explicit_false_critical()),
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "an expired leaf",
            signed_by(&iaca, |ds| {
                ds.valid("2025-01-01T00:00:00Z", "2026-10-26T11:59:59Z")
            }),
            etsi_tl(LIST),
            path(PathRefusal::NotValid(OnPath::Chain(first))),
        ),
        case(
            "an expired anchor",
            signed_by(
                &iaca
                    .clone()
                    .valid("2024-01-01T00:00:00Z", "2026-10-26T11:59:59Z"),
                |ds| ds,
            ),
            etsi_tl(LIST),
            path(PathRefusal::NotValid(anchor)),
        ),
        case(
            "a signer without basicConstraints cA",
            signed_by(&iaca.clone().ca(None), |ds| ds),
            etsi_tl(LIST),
            path(PathRefusal::NotCa(anchor)),
        ),
        case(
            "a wrong signature",
            signed_by(&iaca, |ds| ds.signed_with(Key::p256(0x39))),
            etsi_tl(LIST),
            path(PathRefusal::Signature {
                certificate: first,
                signer: anchor,
            }),
        ),
        case(
            "a signature algorithm of another curve than the signer's key",
            signed_by(&iaca, |ds| ds.signed_with(Key::p384(0x39))),
            etsi_tl(LIST),
            path(PathRefusal::IssuerKey {
                certificate: first,
                signer: anchor,
            }),
        ),
        case(
            "an issuer-name mismatch",
            signed_by(&iaca, |ds| ds.issuer_named("Another IACA")),
            etsi_tl(LIST),
            path(PathRefusal::IssuerName(first)),
        ),
        case(
            "an unsupported signature algorithm",
            signed_by(&iaca, Cert::sha512_declared),
            etsi_tl(LIST),
            path(PathRefusal::Algorithm(first)),
        ),
        case(
            "a value without a store entry",
            signed_by(&iaca, |ds| ds),
            etsi_tl("https://tl.example/other"),
            Err(vec![Refusal::Issuer(ChainRefusal::NoStoreEntry)]),
        ),
        case(
            "a signer whose keyUsage leaves keyCertSign out",
            signed_by(
                &iaca.clone().key_usage(KeyUsage(KeyUsages::CRLSign.into())),
                |ds| ds,
            ),
            etsi_tl(LIST),
            path(PathRefusal::KeyCertSign(anchor)),
        ),
        case(
            "an anchor of pathLenConstraint 0 above an intermediate CA",
            {
                let root = p384_root.clone().path_len(0);
                let intermediate =
                    Cert::issued_by("Test intermediate", Key::p384(0x42), &root).ca(Some(true));
                let leaf = Cert::issued_by("Test Document Signer", Key::p256(0x43), &intermediate);
                (
                    chain(&[&leaf, &intermediate]),
                    store(&[("etsi_tl", LIST, &[&root])]),
                )
            },
            etsi_tl(LIST),
            path(PathRefusal::PathLength(OnPath::Store(
                CertificateIndex::new(0),
            ))),
        ),
        case(
            "a self-issued link certificate below an anchor of pathLenConstraint 0",
            {
                let iaca = iaca.clone().path_len(0);
                let link = Cert::issued_by("Test IACA", Key::p256(0x35), &iaca)
                    .ca(Some(true))
                    .path_len(0);
                let document_signer =
                    Cert::issued_by("Test Document Signer", Key::p256(0x32), &link);
                (
                    chain(&[&document_signer, &link]),
                    store(&[("etsi_tl", LIST, &[&iaca])]),
                )
            },
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "a critical extension TR3 does not process",
            signed_by(&iaca, Cert::inhibit_any_policy),
            etsi_tl(LIST),
            path(PathRefusal::CriticalExtension {
                certificate: OnPath::Chain(first),
                extension: INHIBIT_ANY_POLICY,
            }),
        ),
        Case {
            time: at("2021-01-01T00:00:00Z"),
            ..case(
                "the Annex D Document Signer, listed in the store itself",
                (
                    chain_of(ANNEX_D_DOCUMENT_SIGNER, &[]),
                    TrustStore::parse(
                        &json!([{"type": "etsi_tl", "value": LIST,
                            "certificates": [base64(ANNEX_D_DOCUMENT_SIGNER)]}])
                        .to_string(),
                    )
                    .unwrap(),
                ),
                etsi_tl(LIST),
                Ok(listed()),
            )
        },
        case(
            "an unknown type",
            signed_by(&iaca, |ds| ds),
            json!([{"type": "x_unknown", "values": [LIST]}]),
            Err(vec![Refusal::Type(AuthorityType::new("x_unknown"))]),
        ),
    ]
}

#[test]
fn each_rule_of_tr3() {
    let failures: Vec<String> = cases()
        .into_iter()
        .filter_map(|case| {
            let query = authorities(case.authorities);
            let got = AdmittedIssuer::resolve(&query, Some(&case.chain), &case.store, case.time)
                .map(|admitted| admitted.ground())
                .map_err(|unadmitted| unadmitted.refusals().to_vec());
            (got != case.expected)
                .then(|| format!("{}: got {got:?}, want {:?}", case.name, case.expected))
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// TR5: the facts the wallet records give the picker the wallet's admission, ground included,
/// for every case at the same time.
#[test]
fn the_picker_admits_from_the_facts_as_the_wallet_does() {
    let failures: Vec<String> = cases()
        .into_iter()
        .filter_map(|case| {
            let query = authorities(case.authorities);
            let wallet = AdmittedIssuer::resolve(&query, Some(&case.chain), &case.store, case.time)
                .map(|admitted| admitted.ground())
                .ok();
            let facts = IssuerFacts::at(Some(&case.chain), &case.store, case.time);
            let picker = Admission::of(&query, &facts)
                .map(|admission| admission.ground().clone())
                .ok();
            (wallet != picker)
                .then(|| format!("{}: wallet {wallet:?}, picker {picker:?}", case.name))
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
