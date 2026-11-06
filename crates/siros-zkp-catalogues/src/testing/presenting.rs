//! The Holder's side as the plan drives it: the Verifier's signed request through the core, the
//! credential tested, its Document Signer admitted for the query, the answer of the first option
//! with a usable pair, the prepared presentation, the device signature and the proof.

use std::str::FromStr;
use std::time::Duration;

use crate::date::DateTime;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use der::asn1::{Ia5String, UtcTime};
use der::Encode;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use siros_mdoc::stored::{MdocError, StoredMdoc};
use siros_openid4vp::authenticate::{Authenticated, OriginPolicy, TrustConfig};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{Seconds, Timestamp};
use siros_openid4vp::jose::Skew;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::Query;
use siros_openid4vp::uri::{Fetch, FetchAnswer};
use siros_testkit::{TestFormat, TestHost, TestTrust};
use siros_trust::{AdmittedIssuer, IssuerChain, TrustStore, Unadmitted};
use siros_x509::X509SanDns;
use siros_zkp_req::{PairRefusal, ZkpFormats, ZkpPresentation, ZkpReqQuery};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

use super::{client_metadata, device_signature, key, request_object, CLIENT_ID, NOW};
use crate::attestation::{OtherIssuer, SecretSeed, TestedAttestation, Unusable, UsableAttestation};
use crate::catalogue::NymAuthQuery;
use crate::policy::RequestRefusal;
use crate::presenter::{Answer, Prepared, ProveError, Unanswerable};
use crate::prover::NymAuthProver;
use crate::request::NymAuthRequest;
use crate::system::{NymAuthSystem, Unsupported};
use crate::verifier_id::VerifierIdForm;

/// Where the Holder's side stops short of a prepared presentation.
#[derive(Debug)]
pub enum Presenting {
    /// No option has a usable pair with the system: each option's refusal.
    NoPair(Vec<PairRefusal<Unsupported>>),
    /// The credential is no mdoc.
    Mdoc(MdocError),
    /// The mdoc is no tested attestation.
    Unusable(Unusable),
    /// The query's `trusted_authorities` do not admit the Document Signer.
    Unadmitted(Unadmitted),
    /// The admission does not make the attestation usable.
    OtherIssuer(OtherIssuer),
    /// The attestation answers no option.
    Unanswerable(Unanswerable),
    /// The request breaks the nym_auth policy.
    Request(RequestRefusal),
    /// The statement.
    Prove(ProveError),
}

/// The Verifier's signing key and its self-signed access certificate, with the dNSName SAN of
/// [`CLIENT_ID`].
fn verifier() -> (SigningKey, Vec<u8>) {
    let key = key(0x05);
    let at =
        |unix: u64| Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(unix)).unwrap());
    let validity = Validity {
        not_before: at(1_767_225_600),
        not_after: at(1_893_456_000),
    };
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::new(&[5]).unwrap(),
        validity,
        Name::from_str("CN=Test verifier,O=Test only").unwrap(),
        spki,
        &key,
    )
    .unwrap();
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            Ia5String::new("verifier.example").unwrap(),
        )]))
        .unwrap();
    let der = builder.build::<DerSignature>().unwrap().to_der().unwrap();
    (key, der)
}

/// The Request Object of [`request_object`] for a query and a nonce, which the Verifier signs and
/// serves at its `request_uri`, and the link that names it.
pub struct SignedRequest {
    uri: String,
    object: String,
}

/// The Request Object of [`request_object`] for `query` and `nonce`, signed by the Verifier.
pub fn signed_request(query: &Value, nonce: &str) -> SignedRequest {
    let (key, der) = verifier();
    let header =
        json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [STANDARD.encode(&der)]});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(request_object(query, nonce).to_string().as_bytes())
    );
    let signature: Signature = key.sign(input.as_bytes());
    SignedRequest {
        uri: format!(
            "openid4vp://?client_id={}&request_uri=https%3A%2F%2Fverifier.example%2Frequest",
            CLIENT_ID.replace(':', "%3A")
        ),
        object: format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())),
    }
}

impl SignedRequest {
    /// `with` of the request as the core authenticates it: fetched by its `request_uri`, its
    /// `x509_san_dns` Client Identifier bound to the access certificate's key, and the trust
    /// service's permit.
    pub fn authenticated<R>(&self, with: impl FnOnce(&Authenticated<'_>) -> R) -> R {
        let mut builder = Registry::<TestHost>::builder();
        siros_testkit::fixtures::openid4vp(&mut builder);
        builder.format(TestFormat::new().unwrap());
        builder.client_prefix(X509SanDns);
        let registry = builder.build().unwrap();
        let host = TestHost::default();
        let config = TrustConfig {
            skew: Skew::new(Seconds(60)).unwrap(),
            origins: OriginPolicy::Accept,
        };
        let fetch = Fetch::of(&self.uri, &registry, &host).unwrap();
        let received = fetch
            .resume(FetchAnswer::Body(&self.object), &registry, &host)
            .unwrap();
        let envelope = Envelope::parse(&received, &registry).unwrap();
        let trust = TestTrust::default();
        let authenticated = envelope
            .questions(&registry, &config, &host)
            .unwrap()
            .authenticate(|evaluation| trust.decide(evaluation), &config, &host)
            .unwrap();
        with(&authenticated)
    }
}

/// `with` of the Credential Query `query` as the core's DCQL reader reads it.
///
/// # Errors
///
/// The rule of OpenID4VP 1.0, Section 6 the query breaks.
pub fn read_query<R>(query: &Value, with: impl FnOnce(&Query<'_>) -> R) -> Result<R, Refusal> {
    let dcql = RawValue::from_string(json!({ "credentials": [query] }).to_string()).unwrap();
    let queries = Query::read_all(&dcql)?;
    Ok(with(&queries[0]))
}

/// The `kid` of the Holder's device key.
/// The admission of the Document Signer of `mdoc` by `query`'s `trusted_authorities`, against an
/// empty trust store, at `now`.
fn admitted(query: &Value, mdoc: &StoredMdoc, now: DateTime) -> Result<AdmittedIssuer, Unadmitted> {
    let x5chain = mdoc.issuer_auth().x5chain();
    let chain = IssuerChain::parse(x5chain.first(), x5chain.certificates().skip(1)).unwrap();
    read_query(query, |query| {
        AdmittedIssuer::resolve(
            query,
            Some(&chain),
            &TrustStore::parse("[]").unwrap(),
            Timestamp(u64::try_from(now.unix()).unwrap()),
        )
    })
    .unwrap()
}

/// The nym_auth query of the Credential Query `query`.
pub fn nym_query(query: &Value) -> NymAuthQuery {
    read_query(query, |query| {
        NymAuthQuery::from_query(ZkpReqQuery::parse(query).unwrap())
            .unwrap()
            .nym_auth()
            .unwrap()
    })
    .unwrap()
}

/// The credential `data`, tested at `now` and usable for `nym`, the nym_auth query of `query`.
///
/// # Errors
///
/// [`Presenting`]: the first step that fails.
pub fn usable(
    query: &Value,
    nym: &NymAuthQuery,
    data: &str,
    now: DateTime,
) -> Result<UsableAttestation, Presenting> {
    let mdoc = StoredMdoc::parse(data).map_err(Presenting::Mdoc)?;
    let tested = TestedAttestation::of(&mdoc, now).map_err(Presenting::Unusable)?;
    let issuer = admitted(query, &mdoc, now).map_err(Presenting::Unadmitted)?;
    UsableAttestation::new(tested, issuer, nym).map_err(Presenting::OtherIssuer)
}

/// The presentation `request` asks for `query`, prepared from the credential `data` with the
/// delivered `seed`: the first option with a usable pair for `system`, at [`NOW`].
///
/// # Errors
///
/// [`Presenting`]: the first step that fails.
pub fn prepared(
    system: NymAuthSystem,
    query: &Value,
    data: &str,
    seed: &[u8; 16],
    request: &Authenticated<'_>,
) -> Result<Prepared, Presenting> {
    let now = DateTime::from_unix(NOW).unwrap();
    let nym = nym_query(query);
    let formats = ZkpFormats::from_client_metadata(&client_metadata()).unwrap();
    let (pairs, refusals): (Vec<_>, Vec<_>) = nym
        .options()
        .map(|option| option.pair(&formats, system, now.date()))
        .partition(Result::is_ok);
    let pair = pairs.into_iter().find_map(Result::ok).ok_or_else(|| {
        Presenting::NoPair(refusals.into_iter().filter_map(Result::err).collect())
    })?;
    let usable = usable(query, &nym, data, now)?;
    let answer = Answer::new(pair, usable, &SecretSeed::new(Zeroizing::new(*seed)))
        .map_err(Presenting::Unanswerable)?;
    let request =
        NymAuthRequest::new(request, VerifierIdForm::X509SanDns).map_err(Presenting::Request)?;
    Prepared::new(answer, &request).map_err(Presenting::Prove)
}

/// The presentation of `prepared`, signed by the device key of scalar `device`, proved by
/// `prover`.
///
/// # Errors
///
/// [`ProveError`]: the device signature, the prover's failure, or its output.
pub fn present(
    prepared: &Prepared,
    device: u8,
    prover: &dyn NymAuthProver,
) -> Result<ZkpPresentation, ProveError> {
    prepared.prove(
        &device_signature(device, prepared.data_to_sign().as_bytes()),
        prover,
    )
}
