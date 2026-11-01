//! The request rules: `invalid_request`.

use super::Case;
use crate::*;

pub fn cases() -> Vec<Case> {
    let item = |q: &mut Value, i: usize, k: &str, v: Value| q["_req"][i][k] = v;
    let param = |q: &mut Value, i: usize, k: &str, v: Value| q["_req"][i]["params"][k] = v;
    vec![
        // zkp_req, Sections 1.1, 1.2, 2 and 2.1: invalid_request.
        (
            "format_not_zkp_req",
            match_query_edit(|q| q["format"] = json!("mso_mdoc")),
            protocol(RequestRule::FormatNotZkpReq),
        ),
        (
            "claims_present",
            match_query_edit(|q| q["claims"] = json!([{"path": ["birth_date"]}])),
            protocol(RequestRule::ClaimsPresent),
        ),
        (
            "source_format_invalid",
            match_query_edit(|q| q["meta"] = json!({"doctype_value": DOCTYPE})),
            protocol(RequestRule::SourceFormatInvalid(MemberFault::Absent)),
        ),
        (
            "type_value_invalid",
            match_query_edit(|q| q["meta"] = json!({"source_format": "mso_mdoc"})),
            protocol(RequestRule::TypeValueInvalid(TypeValueFault::Member(
                MemberFault::Absent,
            ))),
        ),
        (
            "req_invalid",
            match_query_edit(|q| q["_req"] = json!([])),
            protocol(RequestRule::ReqInvalid(MemberFault::Empty)),
        ),
        (
            "item_not_object",
            match_query_edit(|q| q["_req"][1] = json!(1)),
            protocol(RequestRule::ItemNotObject {
                item: ItemIndex::new(1),
            }),
        ),
        (
            "item_member_unknown",
            match_query_edit(|q| item(q, 0, "id", json!("x"))),
            protocol(RequestRule::ItemMemberUnknown {
                item: ItemIndex::new(0),
            }),
        ),
        (
            "fn_id_invalid",
            match_query_edit(|q| item(q, 1, "fn_id", json!(7))),
            protocol(RequestRule::FnIdInvalid {
                item: ItemIndex::new(1),
                fault: IdentifierFault::NotString,
            }),
        ),
        (
            "params_not_object",
            match_query_edit(|q| item(q, 1, "params", json!([]))),
            protocol(RequestRule::ParamsNotObject {
                item: ItemIndex::new(1),
            }),
        ),
        (
            "return_invalid",
            match_query_edit(|q| item(q, 0, "return", json!("a b"))),
            protocol(RequestRule::ReturnInvalid {
                item: ItemIndex::new(0),
                fault: ReturnFault::Syntax(ReturnHandleError::Character(' ')),
            }),
        ),
        (
            "return_repeated",
            match_query_edit(|q| item(q, 1, "return", json!("nym"))),
            protocol(RequestRule::ReturnRepeated {
                item: ItemIndex::new(1),
            }),
        ),
        (
            "req_sets_invalid",
            match_query_edit(|q| q["_req_sets"] = json!([])),
            protocol(RequestRule::ReqSetsInvalid(MemberFault::Empty)),
        ),
        (
            "option_invalid",
            match_query_edit(|q| q["_req_sets"] = json!([[0], [0, 0]])),
            protocol(RequestRule::OptionInvalid {
                option: ReqSetIndex::new(1),
                fault: OptionFault::Repeated(ItemIndex::new(0)),
            }),
        ),
        (
            "formats_missing",
            match_metadata_edit(|m| m["vp_formats_supported"] = json!({})),
            protocol(RequestRule::FormatsMissing(MemberFault::Absent)),
        ),
        (
            "proof_backend_values_invalid",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] = json!([])
            }),
            protocol(RequestRule::ProofBackendValuesInvalid(MemberFault::Empty)),
        ),
        (
            "system_id_values_invalid",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["system_id_values"] = json!(["a", 1])
            }),
            protocol(RequestRule::SystemIdValuesInvalid(MemberFault::Entry(
                ArrayIndex::new(1),
            ))),
        ),
        // The nym_auth catalogue: invalid_request.
        (
            "schema_id_invalid",
            match_query_edit(|q| q["meta"] = json!({"source_format": "bbs_cd"})),
            catalogue(CatalogueRule::SchemaIdInvalid(ParamFault::Absent)),
        ),
        (
            "holder_binding_waived",
            match_query_edit(|q| q["require_cryptographic_holder_binding"] = json!(false)),
            catalogue(CatalogueRule::HolderBindingWaived),
        ),
        (
            "function_unknown",
            match_query_edit(|q| item(q, 1, "fn_id", json!("valid_on"))),
            catalogue(CatalogueRule::FunctionUnknown {
                item: ItemIndex::new(1),
            }),
        ),
        (
            "param_unknown",
            match_query_edit(|q| param(q, 0, "verifier_id_type", json!("x509_san_dns"))),
            catalogue(CatalogueRule::ParamUnknown {
                item: ItemIndex::new(0),
            }),
        ),
        (
            "pseudonym_return_missing",
            match_query_edit(|q| {
                q["_req"][0].as_object_mut().unwrap().remove("return");
            }),
            catalogue(CatalogueRule::PseudonymReturnMissing {
                item: ItemIndex::new(0),
            }),
        ),
        (
            "config_invalid",
            match_query_edit(|q| param(q, 0, "config", json!("known-offender-matching"))),
            catalogue(CatalogueRule::ConfigInvalid {
                item: ItemIndex::new(0),
                fault: ParamFault::Value,
            }),
        ),
        (
            "ver_invalid",
            match_query_edit(|q| param(q, 0, "ver", json!(2))),
            catalogue(CatalogueRule::VerInvalid {
                item: ItemIndex::new(0),
                fault: ParamFault::Value,
            }),
        ),
        (
            "prf_invalid",
            match_query_edit(|q| param(q, 0, "prf", json!("hashdh-bls12381g1"))),
            catalogue(CatalogueRule::PrfUndefined {
                item: ItemIndex::new(0),
                prf: Prf::HashdhBls12381G1,
            }),
        ),
        (
            "verifier_context_invalid",
            match_query_edit(|q| param(q, 0, "verifier_context", json!("account 7"))),
            catalogue(CatalogueRule::VerifierContextInvalid {
                item: ItemIndex::new(0),
                fault: ContextFault::Forbidden,
            }),
        ),
        (
            "range_syntax",
            match_query_edit(|q| param(q, 1, "range", json!("18"))),
            catalogue(CatalogueRule::RangeSyntax {
                item: ItemIndex::new(1),
                fault: ParamFault::Value,
            }),
        ),
        (
            "range_inverted",
            match_query_edit(|q| param(q, 1, "range", json!("17-13"))),
            catalogue(CatalogueRule::RangeInverted {
                item: ItemIndex::new(1),
            }),
        ),
        (
            "pseudonym_repeated",
            match_query_edit(|q| {
                let mut second = q["_req"][0].clone();
                second["return"] = json!("nym2");
                q["_req"][1] = second;
            }),
            catalogue(CatalogueRule::PseudonymRepeated { option: None }),
        ),
        (
            "age_check_repeated",
            match_query_edit(|q| {
                let second = q["_req"][1].clone();
                q["_req"].as_array_mut().unwrap().push(second);
            }),
            catalogue(CatalogueRule::AgeCheckRepeated { option: None }),
        ),
        // The catalogue's Binding and Response confidentiality: invalid_request.
        (
            "unsigned",
            policy(|_| {}, Signing::Unsigned, Channel::Redirect),
            Got::Policy(PolicyRule::Unsigned),
        ),
        (
            "request_object_not_object",
            policy(|r| *r = json!("jwt"), Signing::Signed, Channel::Redirect),
            Got::Policy(PolicyRule::NotObject),
        ),
        (
            "client_id_missing",
            policy(
                |r| {
                    r.as_object_mut().unwrap().remove("client_id");
                },
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ClientIdMissing),
        ),
        (
            "client_id_unprefixed",
            policy(
                |r| r["client_id"] = json!("verifier"),
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ClientId(ClientIdError::Unprefixed)),
        ),
        (
            "nonce_missing",
            policy(
                |r| {
                    r.as_object_mut().unwrap().remove("nonce");
                },
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::NonceMissing),
        ),
        (
            "nonce_malformed",
            policy(
                |r| r["nonce"] = json!(""),
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::NonceMalformed),
        ),
        (
            "response_mode",
            policy(
                |r| r["response_mode"] = json!("direct_post"),
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ResponseMode),
        ),
        (
            "response_uri_missing",
            policy(
                |r| {
                    r.as_object_mut().unwrap().remove("response_uri");
                },
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ResponseUriMissing),
        ),
        (
            "origin_not_expected",
            policy(
                |r| {
                    r["response_mode"] = json!("dc_api.jwt");
                    r["expected_origins"] = json!(["https://rp.example"]);
                },
                Signing::Signed,
                Channel::DcApi {
                    origin: Origin::new("https://evil.example"),
                },
            ),
            Got::Policy(PolicyRule::OriginNotExpected),
        ),
        (
            "encryption_key_missing",
            policy(
                |r| r["client_metadata"]["jwks"] = json!({"keys": []}),
                Signing::Signed,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::EncryptionKeyMissing),
        ),
        // The catalogue's verifier identity: invalid_request.
        (
            "client_id_prefix",
            verifier_id(VerifierId::x509_san_dns(
                &ClientId::parse("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk").unwrap(),
                Intermediary::Absent,
            )),
            Got::VerifierId(VerifierIdRule::ClientIdPrefix),
        ),
        (
            "intermediary",
            verifier_id(VerifierId::x509_san_dns(
                &ClientId::parse(CLIENT_ID).unwrap(),
                Intermediary::Named,
            )),
            Got::VerifierId(VerifierIdRule::Intermediary),
        ),
    ]
}
