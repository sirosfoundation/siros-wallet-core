//! P1: one fixture per construction rule of `VerifiedRequest`. Each refusal names the exact
//! rule it breaks; each fixture starts from a request that verifies and changes one thing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod requests;
#[path = "../support/mod.rs"]
mod support;

use serde_json::json;
use sha2::{Digest, Sha256};
use siros_codec::member::MemberFault;
use siros_oid4vp::{
    AttestationClaim, AttestationFault, ClaimsFault, Coordinate, EffectResult, IntakeError,
    IntakeState, JwkFault, ParameterFault,
};

use requests::*;
use support::*;

/// What a fixture must give: a refusal, or a request of this client and trust verdict.
enum Expect {
    Refused(IntakeError),
    Verified {
        client_id: &'static str,
        trusted: bool,
    },
}

struct Fixture {
    rule: &'static str,
    state: IntakeState,
    answer: Answer,
    expect: Expect,
}

fn fixtures() -> Vec<Fixture> {
    let (a, b) = (key(1), key(2));
    let x509 = x509_client();
    let reference = |rule: &'static str,
                     request_uri: &str,
                     method: Option<&str>,
                     echo: Echo,
                     expect: Expect| {
        let (state, answer) = by_reference(request_uri, method, echo);
        Fixture {
            rule,
            state,
            answer,
            expect,
        }
    };
    let by_value_with = |extra: (&str, &str)| {
        let jws = sign(
            &x5c_header(&certificate(&a, &[DNS])),
            &redirect_payload(&x509),
            &a,
        );
        let uri = authorization_uri(&[("client_id", &x509), ("request", &jws), extra]);
        IntakeState::redirect(&uri, formats(), now(), &mut Rng(1))
    };
    let mut fixtures = vec![
        // The signature verifies under the rule of the Client Identifier Prefix.
        Fixture {
            rule: "x509_san_dns: the leaf certificate names the DNS name",
            state: x509_san_dns("other.example", &a, &a, redirect_payload(&x509)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SanMismatch),
        },
        Fixture {
            rule: "x509_san_dns: the leaf certificate's key signs",
            state: x509_san_dns(DNS, &a, &b, redirect_payload(&x509)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "x509_hash: the value is the SHA-256 of the leaf certificate",
            state: {
                let other = certificate(&b, &[DNS]);
                let client_id = format!("x509_hash:{}", b64(&Sha256::digest(&other)));
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(&client_id),
                    &a,
                );
                by_value(&client_id, &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::CertificateHashMismatch),
        },
        Fixture {
            rule: "decentralized_identifier: kid is a key of the DID",
            state: did("did:example:456#key-1", &key(3)).0,
            answer: did("did:example:456#key-1", &key(3)).1,
            expect: Expect::Refused(IntakeError::KidNotOfClient),
        },
        Fixture {
            rule: "decentralized_identifier: the resolved key signs",
            state: did("did:example:123#key-1", &a).0,
            answer: did("did:example:123#key-1", &a).1,
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "verifier_attestation: the attestation has an exp",
            state: attested(
                json!({"iss": ATTESTATION_ISSUER, "sub": DNS,
                    "cnf": {"jwk": jwk(key(5).verifying_key())}}),
                &key(4),
                &key(5),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationInvalid(AttestationFault::Claims(
                ClaimsFault::Claim(AttestationClaim::Exp, MemberFault::Absent),
            ))),
        },
        Fixture {
            rule: "decentralized_identifier: the resolved JWK is a P-256 key",
            state: did("did:example:123#key-1", &key(3)).0,
            answer: did_resolving("did:example:123#key-1", &key(3), {
                let mut resolved = jwk(key(3).verifying_key());
                drop(resolved.as_object_mut().unwrap().remove("x"));
                resolved
            })
            .1,
            expect: Expect::Refused(IntakeError::ResolvedKeyInvalid(JwkFault::CoordinateAbsent(
                Coordinate::X,
            ))),
        },
        Fixture {
            rule: "verifier_attestation: the attestation's sub is the client",
            state: attestation("other.example", NOW + 3600, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationSubjectMismatch),
        },
        Fixture {
            rule: "verifier_attestation: the attestation has not expired",
            state: attestation(DNS, NOW, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationExpired),
        },
        Fixture {
            rule: "verifier_attestation: the cnf key signs the request",
            state: attestation(DNS, NOW + 3600, &key(4), &key(5), &a),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "verifier_attestation: the issuer's key signs the attestation",
            state: attestation(DNS, NOW + 3600, &a, &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationSignatureInvalid),
        },
        Fixture {
            rule: "openid_federation: the Trust Chain's key signs",
            state: federation(&a).0,
            answer: federation(&a).1,
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "redirect_uri: a signed request does not use it",
            state: {
                let client_id = "redirect_uri:https://verifier.example/post";
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(client_id),
                    &a,
                );
                by_value(client_id, &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignedRedirectUri),
        },
        Fixture {
            rule: "redirect_uri: an unsigned request uses no other prefix",
            state: {
                let query = query().to_string();
                let uri = authorization_uri(&[
                    ("client_id", &x509),
                    ("response_type", "vp_token"),
                    ("response_mode", "direct_post"),
                    ("response_uri", "https://verifier.example/post"),
                    ("nonce", "n-0S6_WzA2Mj"),
                    ("dcql_query", &query),
                ]);
                IntakeState::redirect(&uri, formats(), now(), &mut Rng(1))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::UnsignedNeedsRedirectUri),
        },
        Fixture {
            rule: "a Request Object has typ oauth-authz-req+jwt",
            state: {
                let mut header = x5c_header(&certificate(&a, &[DNS]));
                header.as_object_mut().unwrap().remove("typ");
                by_value(&x509, &sign(&header, &redirect_payload(&x509), &a))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::TypMismatch),
        },
        Fixture {
            rule: "a Request Object is signed with ES256",
            state: {
                let mut header = x5c_header(&certificate(&a, &[DNS]));
                header["alg"] = "ES384".into();
                by_value(&x509, &sign(&header, &redirect_payload(&x509), &a))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AlgorithmUnsupported),
        },
        // The outer and inner client_id are equal.
        Fixture {
            rule: "the client_id parameter is the Request Object's client_id",
            state: {
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(&x509),
                    &a,
                );
                by_value("x509_san_dns:other.example", &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ClientIdMismatch),
        },
        // A request by reference (RFC 9101, Section 5.2; Section 5.10).
        reference(
            "request_uri is an https URI",
            "http://verifier.example/request",
            Some("post"),
            Echo::Sent,
            Expect::Refused(IntakeError::RequestUriNotHttps),
        ),
        reference(
            "request_uri_method is get or post",
            REQUEST_URI,
            Some("put"),
            Echo::Sent,
            Expect::Refused(IntakeError::RequestUriMethodInvalid),
        ),
        reference(
            "post: the Request Object holds wallet_nonce",
            REQUEST_URI,
            Some("post"),
            Echo::Omitted,
            Expect::Refused(IntakeError::WalletNonceMismatch),
        ),
        reference(
            "post: the Request Object's wallet_nonce is the one sent",
            REQUEST_URI,
            Some("post"),
            Echo::Altered,
            Expect::Refused(IntakeError::WalletNonceMismatch),
        ),
        Fixture {
            rule: "request_uri_method comes with request_uri",
            state: by_value_with(("request_uri_method", "get")),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::RequestUriMethodWithoutRequestUri),
        },
        Fixture {
            rule: "request and request_uri exclude each other",
            state: by_value_with(("request_uri", REQUEST_URI)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::RequestAndRequestUri),
        },
        // A trust verdict was obtained.
        Fixture {
            rule: "the trust effect is answered by a trust verdict",
            state: x509_san_dns(DNS, &a, &a, redirect_payload(&x509)),
            answer: Box::new(|_| EffectResult::RequestObject(request_object("eyJ.e.s"))),
            expect: Expect::Refused(IntakeError::AnswerMismatch),
        },
        Fixture {
            rule: "the trust verdict is carried, untrusted included",
            state: x509_san_dns(DNS, &a, &a, redirect_payload(&x509)),
            answer: honest(Host {
                trusted: false,
                ..Host::trusting()
            }),
            expect: Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: false,
            },
        },
        // nonce is present.
        Fixture {
            rule: "nonce is present",
            state: {
                let mut payload = redirect_payload(&x509);
                payload.as_object_mut().unwrap().remove("nonce");
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::Parameter(ParameterFault::NonceInvalid)),
        },
        // A redirect's state is of ASCII URL-safe characters.
        Fixture {
            rule: "a redirect's state is ASCII URL-safe",
            state: {
                let mut payload = redirect_payload(&x509);
                payload["state"] = "a b".into();
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::Parameter(ParameterFault::StateInvalid)),
        },
        // The response mode belongs to the channel.
        Fixture {
            rule: "redirects use direct_post or direct_post.jwt",
            state: {
                let mut payload = redirect_payload(&x509);
                payload["response_mode"] = "dc_api".into();
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::Parameter(
                ParameterFault::ResponseModeUnsupported,
            )),
        },
        Fixture {
            rule: "the DC API uses dc_api or dc_api.jwt",
            state: unsigned_dc_api(|data| data["response_mode"] = "direct_post".into()),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::Parameter(
                ParameterFault::ResponseModeUnsupported,
            )),
        },
        // A redirect response has a response_uri.
        Fixture {
            rule: "a redirect request has a response_uri",
            state: {
                let mut payload = redirect_payload(&x509);
                payload.as_object_mut().unwrap().remove("response_uri");
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ResponseUriMissing),
        },
        // A signed DC API request lists the calling origin in expected_origins.
        Fixture {
            rule: "a signed DC API request lists the calling origin",
            state: signed_dc_api(dc_api_payload(&x509), "https://attacker.example"),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::OriginNotExpected),
        },
        Fixture {
            rule: "a signed DC API request has expected_origins",
            state: {
                let mut payload = dc_api_payload(&x509);
                payload.as_object_mut().unwrap().remove("expected_origins");
                signed_dc_api(payload, ORIGIN)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::Parameter(
                ParameterFault::ExpectedOriginsMissing,
            )),
        },
        // An encrypted mode has a chosen key and enc.
        Fixture {
            rule: "an encrypted mode has a P-256 ECDH-ES key",
            state: unsigned_dc_api(|data| {
                data["response_mode"] = "dc_api.jwt".into();
                data["client_metadata"] = json!({"jwks": {"keys": [{
                    "kty": "EC", "crv": "P-384", "alg": "ECDH-ES", "kid": "lc",
                    "x": "iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV",
                    "y": "MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"
                }]}});
            }),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::EncryptionKeyMissing),
        },
        Fixture {
            rule: "an encrypted mode's P-256 ECDH-ES key is a P-256 key",
            state: unsigned_dc_api(|data| {
                data["response_mode"] = "dc_api.jwt".into();
                let mut key = jwk(key(8).verifying_key());
                key["alg"] = "ECDH-ES".into();
                key["y"] = b64(&[1; 31]).into();
                data["client_metadata"] = json!({"jwks": {"keys": [key]}});
            }),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::EncryptionKeyInvalid(
                JwkFault::CoordinateLength(Coordinate::Y, 31),
            )),
        },
        Fixture {
            rule: "an encrypted mode passes over a P-256 key that does not read",
            state: signed_dc_api(
                {
                    let mut payload = dc_api_payload(&x509);
                    payload["response_mode"] = "dc_api.jwt".into();
                    let mut usable = jwk(key(8).verifying_key());
                    usable["alg"] = "ECDH-ES".into();
                    let mut unreadable = usable.clone();
                    unreadable["y"] = b64(&[1; 31]).into();
                    payload["client_metadata"] = json!({"jwks": {"keys": [unreadable, usable]}});
                    payload
                },
                ORIGIN,
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "an encrypted mode has an enc this wallet supports",
            state: unsigned_dc_api(|data| {
                data["response_mode"] = "dc_api.jwt".into();
                let mut key = jwk(key(8).verifying_key());
                key["alg"] = "ECDH-ES".into();
                data["client_metadata"] = json!({
                    "jwks": {"keys": [key]},
                    "encrypted_response_enc_values_supported": ["A128CBC-HS256"]
                });
            }),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::EncryptionUnsupported),
        },
        // Multisigned: the Client Identifier of the first signature that qualifies.
        Fixture {
            rule: "multisigned: a signature that does not verify is passed over",
            state: multisigned(
                &[("a.example", &a, &b), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_san_dns:b.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "multisigned: an untrusted signature is passed over for a trusted one",
            state: multisigned(
                &[("a.example", &a, &a), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: trusting_only("x509_san_dns:b.example"),
            expect: Expect::Verified {
                client_id: "x509_san_dns:b.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "multisigned: with none trusted, the first that verifies",
            state: multisigned(
                &[("a.example", &a, &a), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: trusting_only("x509_san_dns:c.example"),
            expect: Expect::Verified {
                client_id: "x509_san_dns:a.example",
                trusted: false,
            },
        },
        Fixture {
            rule: "multisigned: some signature verifies",
            state: multisigned(
                &[("a.example", &a, &b), ("b.example", &b, &a)],
                multisigned_payload(),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::NoVerifiableSignature),
        },
        Fixture {
            rule: "multisigned: client_id is in the protected headers only",
            state: multisigned(
                &[("a.example", &a, &a)],
                dc_api_payload("x509_san_dns:a.example"),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ClientIdInPayload),
        },
    ];
    // Each prefix's request verifies before it is broken.
    fixtures.extend([
        reference(
            "honest: request_uri get",
            REQUEST_URI,
            None,
            Echo::Sent,
            Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: true,
            },
        ),
        reference(
            "honest: request_uri post",
            REQUEST_URI,
            Some("post"),
            Echo::Sent,
            Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: true,
            },
        ),
        Fixture {
            rule: "honest: x509_hash",
            state: {
                let leaf = certificate(&a, &[DNS]);
                let client_id = format!("x509_hash:{}", b64(&Sha256::digest(&leaf)));
                by_value(
                    &client_id,
                    &sign(&x5c_header(&leaf), &redirect_payload(&client_id), &a),
                )
            },
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_hash:",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: decentralized_identifier",
            state: did("did:example:123#key-1", &key(3)).0,
            answer: did("did:example:123#key-1", &key(3)).1,
            expect: Expect::Verified {
                client_id: "decentralized_identifier:did:example:123",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: verifier_attestation",
            state: attestation(DNS, NOW + 3600, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "verifier_attestation:verifier.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: openid_federation",
            state: federation(&key(6)).0,
            answer: federation(&key(6)).1,
            expect: Expect::Verified {
                client_id: FEDERATION,
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: signed DC API",
            state: signed_dc_api(dc_api_payload(&x509), ORIGIN),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: true,
            },
        },
    ]);
    fixtures
}

#[test]
fn each_construction_rule_of_verified_request() {
    for fixture in fixtures() {
        let outcome = run(fixture.state, &fixture.answer);
        match (fixture.expect, outcome) {
            (Expect::Refused(expected), Err(error)) => {
                assert_eq!(error, expected, "{}", fixture.rule);
            }
            (Expect::Verified { client_id, trusted }, Ok((request, _))) => {
                let verifier = request.verifier();
                assert!(
                    verifier
                        .client_id()
                        .unwrap()
                        .as_str()
                        .starts_with(client_id),
                    "{}: {:?}",
                    fixture.rule,
                    verifier.client_id()
                );
                assert_eq!(verifier.verdict(), trusted.into(), "{}", fixture.rule);
            }
            (Expect::Refused(expected), Ok(_)) => {
                panic!("{}: verified, expected {expected:?}", fixture.rule)
            }
            (Expect::Verified { .. }, Err(error)) => {
                panic!("{}: refused with {error:?}", fixture.rule)
            }
        }
    }
}
