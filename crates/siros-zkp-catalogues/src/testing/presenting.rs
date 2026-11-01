//! The Holder's side as the plan drives it: the Verifier's signed request through intake, the
//! credential tested, its Document Signer admitted for the query, the answer of the first option
//! with a usable pair, the prepared presentation, the device signature and the proof.

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{Ia5String, UtcTime};
use der::Encode;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Map, Value};
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_dcql::CredentialQuery;
use siros_mdoc::{Mdoc, MdocError};
use siros_oid4vp::{
    Effect, EffectResult, IntakeState, Step, TrustAnswer, Verdict, VerifiedRequest,
};
use siros_trust::{
    AdmittedIssuer, ChainRefusal, IssuerChain, QueryAuthorities, TrustStore, Unadmitted,
};
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
    Unadmitted(Unadmitted<ChainRefusal>),
    /// The admission does not make the attestation usable.
    OtherIssuer(OtherIssuer),
    /// The attestation answers no option.
    Unanswerable(Unanswerable),
    /// The request breaks the nym_auth policy.
    Request(RequestRefusal),
    /// The statement.
    Prove(ProveError),
}

/// A deterministic generator standing in for the host's CSPRNG.
struct Counter(u64);

impl RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_u64() as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Counter {}

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

/// The request of [`request_object`] for `query` and `nonce`, which the Verifier signs, by value
/// over redirects, through intake with a positive trust verdict.
pub fn verified_request(query: &Value, nonce: &str) -> VerifiedRequest {
    let (key, der) = verifier();
    let mut x5c = base64url::encode(&der)
        .as_str()
        .replace('-', "+")
        .replace('_', "/");
    while x5c.len() % 4 != 0 {
        x5c.push('=');
    }
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [x5c]});
    let input = format!(
        "{}.{}",
        base64url::encode(header.to_string().as_bytes()),
        base64url::encode(request_object(query, nonce).to_string().as_bytes())
    );
    let signature: Signature = key.sign(input.as_bytes());
    let jws = format!("{input}.{}", base64url::encode(&signature.to_bytes()));
    let uri = format!("openid4vp://?client_id={CLIENT_ID}&request={jws}");
    let now = DateTime::from_unix(NOW).unwrap();
    let mut state = IntakeState::redirect(&uri, Map::new(), now, &mut Counter(9));
    loop {
        match state.step().unwrap() {
            Step::Verified(request) => return *request,
            Step::Effect(Effect::Trust(_)) => {
                state.answer(EffectResult::Trusted(TrustAnswer::new(
                    Verdict::Trusted,
                    None,
                    None,
                )));
            }
            Step::Effect(other) => panic!("no Request Object expected: {other:?}"),
        }
    }
}

/// The `kid` of the Holder's device key.
/// The admission of the Document Signer of `mdoc` by `query`'s `trusted_authorities`, against an
/// empty trust store, at `now`.
fn admitted(
    query: &Value,
    mdoc: &Mdoc,
    now: DateTime,
) -> Result<AdmittedIssuer, Unadmitted<ChainRefusal>> {
    let authorities = QueryAuthorities::of(&CredentialQuery::parse(query).unwrap()).unwrap();
    let chain = IssuerChain::parse(mdoc.issuer_auth().x5chain()).unwrap();
    AdmittedIssuer::resolve(
        &authorities,
        Some(&chain),
        &TrustStore::parse("[]").unwrap(),
        now,
    )
}

/// The nym_auth query of the Credential Query `query`.
pub fn nym_query(query: &Value) -> NymAuthQuery {
    NymAuthQuery::from_query(ZkpReqQuery::parse(&CredentialQuery::parse(query).unwrap()).unwrap())
        .unwrap()
        .nym_auth()
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
    let mdoc = Mdoc::parse(data).map_err(Presenting::Mdoc)?;
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
    request: &VerifiedRequest,
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
