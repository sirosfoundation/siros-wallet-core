//! N2: a nym_auth request is a verified request that is signed under `openid4vp-v1-signed` over
//! the DC API, trusted, and encrypted, and whose `verifier_id` comes from its authenticated
//! certificate in the trust framework's form.
//!
//! `VerifierIdRule::Intermediary` has no row: a request that carries a registration certificate
//! is refused before an intermediary could be read.

use serde_json::{json, Value};
use siros_codec::date::DateTime;
use siros_oid4vp::{IntakeError, IntakeState, Origin, SemanticIdError, Verdict};
use siros_zkp_req_nym_auth::policy::{PolicyRule, RequestRefusal};
use siros_zkp_req_nym_auth::request::NymAuthRequest;
use siros_zkp_req_nym_auth::testing::query;
use siros_zkp_req_nym_auth::verifier_id::{VerifierIdForm, VerifierIdRule};

use crate::verifier::{
    client_metadata, dc_api_signed_state, intake_with, redirect_signed_state, SignedForm,
    SignedPrefix, Signer, NATURAL_POLICY, NONCE, ORIGIN, SIGNER,
};

/// A request for a nym_auth proof in `mode`, with the members of `extra`.
fn params(mode: &str, extra: Value) -> Value {
    let mut params = json!({
        "response_type": "vp_token",
        "response_mode": mode,
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [query(Some("18+"), false)]}
    });
    for (name, value) in extra.as_object().unwrap() {
        params[name] = value.clone();
    }
    params
}

/// The unsigned DC API request of `params`.
fn unsigned(params: &Value) -> IntakeState {
    let request = json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": params}]});
    IntakeState::dc_api(
        request.to_string().as_bytes(),
        Origin::new(ORIGIN),
        DateTime::from_unix(crate::verifier::NOW).unwrap(),
    )
}

enum Outcome {
    Accepted(&'static str),
    Refused(RequestRefusal),
    NotVerified(IntakeError),
}

#[test]
fn nym_auth_requests_meet_the_policy() {
    let cwt = || params("direct_post.cwt", json!({}));
    // A natural person, whose employer's organizationIdentifier names no Relying Party.
    let natural = Signer {
        subject: "CN=Jane Doe,O=Employer AB,2.5.4.97=VATSE-556000000101,2.5.4.5=PNOSE-200007292386",
        policy: NATURAL_POLICY,
        prefix: SignedPrefix::X509SanDns,
    };
    let anonymous = Signer {
        subject: "CN=Test verifier,O=Test only",
        ..SIGNER
    };
    let hashed = Signer {
        prefix: SignedPrefix::X509Hash,
        ..SIGNER
    };
    let policy = |rule| Outcome::Refused(RequestRefusal::Policy(rule));
    let identity = |rule| Outcome::Refused(RequestRefusal::VerifierId(rule));
    let x509 = VerifierIdForm::X509SanDns;
    let semantic = VerifierIdForm::Semantic;
    // (case, request, trust verdict, form, outcome)
    let cases = [
        (
            "the Client Identifier",
            redirect_signed_state(&cwt(), SIGNER),
            Verdict::Trusted,
            x509,
            Outcome::Accepted("x509_san_dns:verifier.example"),
        ),
        (
            "a legal person's organizationIdentifier",
            redirect_signed_state(&cwt(), SIGNER),
            Verdict::Trusted,
            semantic,
            Outcome::Accepted("semantic_id:VATBE-0876866142"),
        ),
        (
            "a natural person's serialNumber",
            redirect_signed_state(&cwt(), natural),
            Verdict::Trusted,
            semantic,
            Outcome::Accepted("semantic_id:PNOSE-200007292386"),
        ),
        (
            "unsigned",
            unsigned(&params("dc_api.jwt", json!({}))),
            Verdict::Trusted,
            x509,
            policy(PolicyRule::Unsigned),
        ),
        (
            "multisigned",
            dc_api_signed_state(
                &params("dc_api.jwt", json!({})),
                SIGNER,
                SignedForm::Multisigned,
            ),
            Verdict::Trusted,
            x509,
            policy(PolicyRule::Multisigned),
        ),
        (
            "untrusted",
            redirect_signed_state(&cwt(), SIGNER),
            Verdict::Untrusted,
            x509,
            policy(PolicyRule::Untrusted),
        ),
        (
            "an unencrypted response",
            redirect_signed_state(&params("direct_post", json!({})), SIGNER),
            Verdict::Trusted,
            x509,
            policy(PolicyRule::ResponseMode),
        ),
        (
            "an encrypted response without a key",
            redirect_signed_state(
                &params("direct_post.jwt", json!({"client_metadata": {}})),
                SIGNER,
            ),
            Verdict::Trusted,
            x509,
            Outcome::NotVerified(IntakeError::EncryptionKeyMissing),
        ),
        (
            "a registration certificate",
            redirect_signed_state(
                &params(
                    "direct_post.jwt",
                    json!({"verifier_info": [{"format": "registration_cert", "data": "ZXhhbXBsZQ"}]}),
                ),
                SIGNER,
            ),
            Verdict::Trusted,
            semantic,
            identity(VerifierIdRule::RegistrationCertificate),
        ),
        (
            "no semantic identifier",
            redirect_signed_state(&cwt(), anonymous),
            Verdict::Trusted,
            semantic,
            identity(VerifierIdRule::SemanticId(SemanticIdError::Absent)),
        ),
        (
            "another Client Identifier Prefix",
            redirect_signed_state(&cwt(), hashed),
            Verdict::Trusted,
            x509,
            identity(VerifierIdRule::ClientIdPrefix),
        ),
    ];
    for (case, state, verdict, form, outcome) in cases {
        let verified = intake_with(state, verdict);
        match outcome {
            Outcome::NotVerified(error) => assert_eq!(verified.err(), Some(error), "{case}"),
            Outcome::Accepted(id) => {
                let request = verified.unwrap();
                let nym_auth = NymAuthRequest::new(&request, form).unwrap();
                assert_eq!(nym_auth.session().verifier_id.as_str(), id, "{case}");
            }
            Outcome::Refused(refusal) => {
                let request = verified.unwrap();
                let refused = NymAuthRequest::new(&request, form).err();
                assert_eq!(refused, Some(refusal), "{case}");
            }
        }
    }
}
