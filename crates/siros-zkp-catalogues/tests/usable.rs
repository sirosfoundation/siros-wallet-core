//! N3: a usable attestation takes only the admission of its own Document Signer by the
//! authorities of its own query.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use serde_json::{json, Value};
use siros_mdoc::stored::StoredMdoc;
use siros_openid4vp::host::Timestamp;
use siros_trust::{
    AdmittedIssuer, ChainRefusal, IssuerChain, QueryAuthorities, TrustStore, Unadmitted,
};
use siros_zkp_catalogues::attestation::{OtherIssuer, TestedAttestation, UsableAttestation};
use siros_zkp_catalogues::date::DateTime;
use siros_zkp_catalogues::testing::read_query;
use support::*;

/// The admission, for the Credential Query `query`, of the issuer whose chain is `der`.
fn admission(
    query: &Value,
    der: &[u8],
    now: DateTime,
) -> Result<AdmittedIssuer, Unadmitted<ChainRefusal>> {
    let authorities = read_query(query, |query| {
        QueryAuthorities::of(
            &query.id().clone().into_owned(),
            query.trusted_authorities(),
        )
    })
    .unwrap()
    .unwrap();
    let chain = IssuerChain::parse(der, []).unwrap();
    let store = TrustStore::parse("[]").unwrap();
    let now = Timestamp(u64::try_from(now.unix()).unwrap());
    AdmittedIssuer::resolve(&authorities, Some(&chain), &store, now)
}

/// The admission that [`admission`] gives.
fn admitted(query: &Value, der: &[u8], now: DateTime) -> AdmittedIssuer {
    admission(query, der, now).unwrap()
}

#[test]
fn the_admission_of_another_certificate_or_query_is_refused() {
    let now = DateTime::from_unix(NOW).unwrap();
    let query = query(None, false);
    let nym = nym_query(&query);
    let ds = Issuer::root(0x11, "Test Document Signer");
    let other_signer = Issuer::root(0x22, "Another Document Signer");
    let mdoc = StoredMdoc::parse(&issue(&ds, &Spec::default())).unwrap();
    let mut other_query = query.clone();
    other_query["id"] = json!("other");
    let usable = |issuer: AdmittedIssuer| {
        let tested = TestedAttestation::of(&mdoc, now).unwrap();
        UsableAttestation::new(tested, issuer, &nym).map(drop)
    };

    assert_eq!(usable(admitted(&query, &ds.der, now)), Ok(()));
    assert_eq!(
        usable(admitted(&query, &other_signer.der, now)),
        Err(OtherIssuer::Certificate)
    );
    assert_eq!(
        usable(admitted(&other_query, &ds.der, now)),
        Err(OtherIssuer::Query)
    );
}

/// An admission by a query without `trusted_authorities` does not make the attestation usable
/// for a query of the same `id` whose `aki` refuses its Document Signer.
#[test]
fn the_admission_of_the_same_id_with_other_authorities_is_refused() {
    let now = DateTime::from_unix(NOW).unwrap();
    let unconstrained = query(None, false);
    let mut constrained = unconstrained.clone();
    constrained["trusted_authorities"] = json!([{"type": "aki", "values": ["AAAA"]}]);
    let ds = Issuer::root(0x11, "Test Document Signer");
    let mdoc = StoredMdoc::parse(&issue(&ds, &Spec::default())).unwrap();
    assert!(admission(&constrained, &ds.der, now).is_err());

    let tested = TestedAttestation::of(&mdoc, now).unwrap();
    let issuer = admitted(&unconstrained, &ds.der, now);
    assert_eq!(
        UsableAttestation::new(tested, issuer, &nym_query(&constrained)).map(drop),
        Err(OtherIssuer::Query)
    );
}
