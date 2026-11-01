//! The Verifier's refusals.

use siros_trust::{CertificateError, ChainIndex, PathRefusal};
use siros_zkp_req_nym_auth::attestation::DocumentSignerError;
use x509_cert::der::Decode;

use super::Case;
use crate::*;

pub fn cases() -> Vec<Case> {
    let other_root = Issuer::root(0x22, "Another Root");
    vec![
        // zkp_req, Section 4.1, steps 1 to 5.
        (
            "presentation",
            verified(Verifying::default(), &[0x01]),
            Got::Verify(Rejection::Presentation(EncodingError::NotMap)),
        ),
        (
            "system_not_listed",
            verified(
                Verifying {
                    metadata: {
                        let mut m = client_metadata();
                        m["vp_formats_supported"]["zkp_req"]["system_id_values"] =
                            json!(["urn:circuits:vega:nym_auth:v1"]);
                        m
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::SystemNotListed)),
        ),
        (
            "backend_not_listed",
            verified(
                Verifying {
                    metadata: {
                        let mut m = client_metadata();
                        m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] =
                            json!(["vega-v1"]);
                        m
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::BackendNotListed)),
        ),
        (
            "system_not_on_backend",
            verify_edit(|p| p.proof_backend = ProofBackend::new("vega-v1")),
            Got::Verify(Rejection::Structure(StructureRejection::SystemNotOnBackend)),
        ),
        (
            "req_set_missing",
            verify_edit(|p| p.req_set = None),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetMissing)),
        ),
        (
            "req_set_extra",
            verified(
                Verifying {
                    query: query(Some("18+"), true),
                    ..Verifying::default()
                },
                &edited_no_sets(),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetExtra)),
        ),
        (
            "req_set_unknown",
            verify_edit(|p| p.req_set = Some(ReqSetIndex::new(5))),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetUnknown)),
        ),
        (
            "result_keys",
            verify_edit(|p| set_result(p, "adult", None)),
            Got::Verify(Rejection::Structure(StructureRejection::ResultKeys)),
        ),
        (
            "result_not_true",
            verify_edit(|p| set_result(p, "adult", Some(Cbor::Bool(false)))),
            Got::Verify(Rejection::Structure(StructureRejection::ResultNotTrue {
                item: ItemIndex::new(1),
            })),
        ),
        // The systems' Section 9, Verifier side.
        (
            "request: invalid",
            verified(
                Verifying {
                    query: {
                        let mut q = sets_query();
                        q["_req"][0]["params"]["ver"] = json!(2);
                        q
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Request(OwnQueryFault::Invalid(
                InvalidRequest::Catalogue(CatalogueRule::VerInvalid {
                    item: ItemIndex::new(0),
                    fault: ParamFault::Value,
                }),
            ))),
        ),
        (
            "request: unsupported",
            verified(
                Verifying {
                    query: {
                        let mut q = sets_query();
                        q["_req"][0]["params"]["config"] = json!("known-offender-matching-psc");
                        q
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Unsupported(Unsupported::Config)),
        ),
        (
            "proof_encoding: proof",
            verify_edit(|p| p.proof = ProofContent::new(vec![0xff])),
            Got::Verify(Rejection::ProofEncoding(ProofEncodingFault::Envelope(
                EncodingError::Cbor(CborError::Unsupported(CborUnsupported::IndefiniteLength)),
            ))),
        ),
        (
            "proof_encoding: inputs",
            verify_edit(|p| {
                edit_envelope(p, |e| e.inputs.push((InputName::new("extra"), Cbor::Null)))
            }),
            Got::Verify(Rejection::ProofEncoding(ProofEncodingFault::Inputs)),
        ),
        (
            "proof_encoding: tdate",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(e, "proof_time", Cbor::text("2026-10-09T12:00:00Z"))
                })
            }),
            Got::Verify(Rejection::ProofEncoding(ProofEncodingFault::ProofTime)),
        ),
        (
            "proof_encoding: zk_proof length",
            verify_edit_as(NymAuthSystem::VegaV1, Verifying::default(), |p| {
                edit_envelope(p, |e| e.zk_proof = shortened(&e.zk_proof))
            }),
            Got::Verify(Rejection::ProofEncoding(ProofEncodingFault::ZkProofLength)),
        ),
        (
            "proof_encoding: verifier",
            verify_edit(|p| edit_envelope(p, |e| e.zk_proof = shortened(&e.zk_proof))),
            Got::Verify(Rejection::Proof(ProofFailure::Encoding)),
        ),
        (
            "issuer_key_set: count",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "issuer_key_set",
                        Cbor::Array(vec![Cbor::Bytes(ds().der), Cbor::Bytes(ds().der)]),
                    )
                })
            }),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Count(2))),
        ),
        (
            "issuer_key_set: certificate",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "issuer_key_set",
                        Cbor::Array(vec![Cbor::Bytes(vec![0x30, 0x00])]),
                    )
                })
            }),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Certificate(
                DocumentSignerError::Certificate(CertificateError::Der(
                    x509_cert::Certificate::from_der(&[0x30, 0x00]).unwrap_err(),
                )),
            ))),
        ),
        (
            "issuer_key_set: untrusted",
            verify_edit_as(
                NymAuthSystem::LongfellowV1,
                Verifying {
                    trust_anchors: vec![Certificate::parse(&other_root.der).unwrap()],
                    ..Verifying::default()
                },
                |_| {},
            ),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Untrusted(
                PathRefusal::IssuerName(ChainIndex::new(0)),
            ))),
        ),
        (
            "proof_time: malformed",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "proof_time",
                        Cbor::Tag(0, Box::new(Cbor::text("2026-10-09T12:00:00.5Z"))),
                    )
                })
            }),
            Got::Verify(Rejection::ProofTime(ProofTimeError::Malformed)),
        ),
        (
            "proof_time: tolerance",
            verify_edit_as(
                NymAuthSystem::LongfellowV1,
                Verifying {
                    now: DateTime::from_unix(NOW + 601).unwrap(),
                    ..Verifying::default()
                },
                |_| {},
            ),
            Got::Verify(Rejection::ProofTime(ProofTimeError::Tolerance)),
        ),
        (
            "results",
            verify_edit(|p| set_result(p, "nym", Some(Cbor::Bytes(vec![0; 31])))),
            Got::Verify(Rejection::Results(ResultsFault::Length(LengthError(31)))),
        ),
    ]
}
