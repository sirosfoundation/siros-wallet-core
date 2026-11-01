//! The Wallet's refusals: `vp_formats_not_supported` and `access_denied`.

use super::Case;
use crate::*;

pub fn cases() -> Vec<Case> {
    let param = |q: &mut Value, i: usize, k: &str, v: Value| q["_req"][i]["params"][k] = v;
    vec![
        // zkp_req, Section 1.3, and the systems' Section 2: vp_formats_not_supported.
        (
            "system_not_listed",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["system_id_values"] =
                    json!(["urn:circuits:vega:nym_auth:v1"])
            }),
            Got::Unsupported(PairRefusal::SystemNotListed),
        ),
        (
            "no_listed_backend",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] = json!(["vega-v1"])
            }),
            Got::Unsupported(PairRefusal::NoListedBackend),
        ),
        (
            "credential_type",
            match_query_edit(|q| {
                q["meta"] = json!({"source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1"});
                param(q, 0, "prf", json!("hashdh-bls12381g1"));
            }),
            Got::Unsupported(PairRefusal::CredentialType),
        ),
        (
            "unsupported: no pseudonym",
            match_query_edit(|q| {
                q["_req"].as_array_mut().unwrap().remove(0);
            }),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::NoPseudonym)),
        ),
        (
            "unsupported: config",
            match_query_edit(|q| param(q, 0, "config", json!("known-offender-matching-psc"))),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::Config)),
        ),
        (
            "unsupported: age bounds",
            match_query_edit(|q| param(q, 1, "range", json!("2027+"))),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::AgeBounds)),
        ),
        // The systems' Section 9, Wallet side: access_denied.
        (
            "age_out_of_range",
            match_credential(
                Spec {
                    birth_date: "2015-01-01",
                    ..Spec::default()
                },
                Some("18+"),
                SEED,
            ),
            Got::Unanswerable(Unanswerable::Failed(vec![ZkpError::Item {
                option: None,
                item: ItemIndex::new(1),
                code: ItemCode::AgeOutOfRange,
            }])),
        ),
        (
            "seed_mismatch",
            match_credential(Spec::default(), None, [0x5a; 16]),
            Got::Unanswerable(Unanswerable::Failed(vec![ZkpError::Item {
                option: None,
                item: ItemIndex::new(0),
                code: ItemCode::SeedMismatch,
            }])),
        ),
        (
            "validity",
            match_credential(
                Spec {
                    valid_until: "2026-06-01T00:00:00Z",
                    ..Spec::default()
                },
                None,
                SEED,
            ),
            credential_error(CredentialCode::Validity),
        ),
        (
            "issuer_signature",
            match_credential(
                Spec {
                    wrong_signature: true,
                    ..Spec::default()
                },
                None,
                SEED,
            ),
            credential_error(CredentialCode::IssuerSignature),
        ),
        (
            "device_binding",
            prove(0x44, None),
            Got::Prove(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::DeviceBinding,
            )])),
        ),
        (
            "credential_form: prover",
            prove(Spec::default().device, Some(ProverFailure::CredentialForm)),
            Got::Prove(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::CredentialForm,
            )])),
        ),
    ]
}
