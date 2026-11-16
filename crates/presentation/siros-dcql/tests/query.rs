//! The query model's parse (§6.1–6.3): defaults, tolerated deviations, and the rules it
//! refuses.

// `expect` alongside `unwrap`: a test that states why it expects to succeed
// says what broke when it stops succeeding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{json, Value};
use siros_dcql::{
    ClaimId, ClaimMember, ClaimPathError, CredentialMember, DcqlQuery, FormFault, HolderBinding,
    Member, Multiplicity, Position, QueryError, QueryId, QueryIdError, SetMember, SetRequirement,
    TrustedAuthorityError,
};

/// The query of the JSON text `json`.
fn parsed(json: &str) -> Result<DcqlQuery, QueryError> {
    DcqlQuery::parse(&serde_json::from_str(json).expect("JSON"))
}

/// Defaults the spec states explicitly, all of which change behaviour if
/// got wrong: a missing `required` would make a mandatory set optional,
/// and a missing `require_cryptographic_holder_binding` would silently
/// accept an unbound credential.
#[test]
fn omitted_fields_take_their_specified_defaults() {
    let q = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["pid"]]}]}"#,
    )
    .unwrap();
    let c = &q.credentials()[0];
    assert_eq!(c.multiplicity(), Multiplicity::One);
    assert_eq!(c.holder_binding(), HolderBinding::Required);
    assert_eq!(
        q.credential_sets().unwrap()[0].requirement(),
        SetRequirement::Required
    );
}

/// "Implementations MUST ignore any unknown properties" (§6). A wallet
/// that rejects tomorrow's extension is worse than one that ignores it. A Credential Query keeps
/// its own for the profile of its format, which `zkp_req`'s `_req` relies on.
#[test]
fn unknown_properties_are_ignored() {
    let q = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},
             "some_future_field":{"a":1}}],
            "another_future_field":[1,2,3]}"#,
    )
    .unwrap();
    assert_eq!(q.credentials().len(), 1);
    assert_eq!(
        q.credentials()[0].extension("some_future_field"),
        Some(&json!({"a": 1}))
    );
}

/// §6.1: an `id` "MUST be unique across all Credential Query objects".
/// Without this check the duplicate changes what gets offered, because `credential_sets`
/// resolves a reference to whichever entry came first and the second is answered by nobody.
#[test]
fn duplicate_credential_ids_are_rejected() {
    let err = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}},
                           {"id":"pid","format":"dc+sd-jwt","meta":{}}]}"#,
    )
    .expect_err("a duplicated credential id is not usable");
    assert!(
        matches!(&err, QueryError::DuplicateCredentialId(id) if id == "pid"),
        "got {err:?}"
    );
}

/// §6.3: a claims `id` must be "unique within the particular claims
/// array". Same defect one level down — `claim_sets` refers to claims by
/// id, so a duplicate makes an option ambiguous.
#[test]
fn duplicate_claim_ids_are_rejected() {
    let err = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},"claims":[
             {"id":"a","path":["ns","given_name"]},
             {"id":"a","path":["ns","family_name"]}],
             "claim_sets":[["a"]]}]}"#,
    )
    .expect_err("a duplicated claim id is not usable");
    assert!(
        matches!(
            &err,
            QueryError::DuplicateClaimId { credential, claim }
                if credential == "pid" && claim == "a"
        ),
        "got {err:?}"
    );
}

/// Claims without ids are the ordinary case when there are no
/// `claim_sets`, and any number of them is fine — the uniqueness rule is
/// about ids.
#[test]
fn claims_without_ids_do_not_collide() {
    let q = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},"claims":[
             {"path":["ns","given_name"]},
             {"path":["ns","family_name"]}]}]}"#,
    )
    .expect("unidentified claims are not duplicates");
    assert_eq!(q.credentials()[0].claims().len(), 2);
}

/// §6.1: an `id` is "a non-empty string consisting of alphanumeric,
/// underscore (_), or hyphen (-) characters". One rule per row.
#[test]
fn credential_ids_follow_section_6_1() {
    let cases = [
        ("pid_1-a", Ok(())),
        ("", Err(QueryIdError::Empty)),
        ("eu.europa.ec.eudi.pid.1", Err(QueryIdError::Character('.'))),
        ("pïd", Err(QueryIdError::Character('ï'))),
    ];
    for (id, outcome) in cases {
        assert_eq!(QueryId::parse(id).map(drop), outcome, "{id:?}");
        let json =
            format!(r#"{{"credentials":[{{"id":"{id}","format":"mso_mdoc","meta":{{}}}}]}}"#);
        let parsed = parsed(&json).map(drop).map_err(|e| match e {
            QueryError::Id(e) => Some(e),
            _ => None,
        });
        assert_eq!(parsed, outcome.map_err(Some), "{id:?}");
    }
}

/// A `Form` refusal of `member` for `fault`.
fn form(member: Member, fault: FormFault) -> QueryError {
    QueryError::Form { member, fault }
}

/// The structural rules of §6, §6.1, §6.2, §6.3, §6.4.1, §7 and §7.2.1. One rule per row.
#[test]
fn the_parse_refuses_what_section_6_forbids() {
    let first = Position::new(0);
    let credential = |field| Member::CredentialMember(first, field);
    let claim = |field| Member::ClaimMember(first, first, field);
    let cases: [(&str, QueryError); 20] = [
        (
            r#"{"credentials":[]}"#,
            form(Member::Credentials, FormFault::Empty),
        ),
        (
            r#"{"credentials":[["pid"]]}"#,
            form(Member::Credential(first), FormFault::WrongType),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":"mso_mdoc"}]}"#,
            form(credential(CredentialMember::Meta), FormFault::WrongType),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":"given_name"}]}"#,
            form(credential(CredentialMember::Claims), FormFault::WrongType),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},
                "require_cryptographic_holder_binding":"yes"}]}"#,
            form(
                credential(CredentialMember::HolderBinding),
                FormFault::WrongType,
            ),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],"credential_sets":null}"#,
            form(Member::CredentialSets, FormFault::WrongType),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}]}"#,
            form(credential(CredentialMember::Meta), FormFault::Absent),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[]}]}"#,
            form(credential(CredentialMember::Claims), FormFault::Empty),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
                "claims":[{"id":"a","path":["given_name"]}],"claim_sets":[]}]}"#,
            form(credential(CredentialMember::ClaimSets), FormFault::Empty),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
                "claims":[{"path":["given_name"]}],"claim_sets":[["a"]]}]}"#,
            form(claim(ClaimMember::Id), FormFault::Absent),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
                "claims":[{"path":["given_name"],"values":[]}]}]}"#,
            form(claim(ClaimMember::Values), FormFault::Empty),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
                "claims":[{"path":["age"],"values":[18,1.5]}]}]}"#,
            form(
                claim(ClaimMember::Values),
                FormFault::Entry(Position::new(1)),
            ),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],"credential_sets":[]}"#,
            form(Member::CredentialSets, FormFault::Empty),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
                "credential_sets":[{"options":[]}]}"#,
            form(
                Member::CredentialSetMember(first, SetMember::Options),
                FormFault::Empty,
            ),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
                "credential_sets":[{"options":[[]]}]}"#,
            form(
                Member::CredentialSetMember(first, SetMember::Options),
                FormFault::Entry(first),
            ),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},
                "claims":[{"id":"a","path":["given_name"]}],"claim_sets":[["a"],["b"]]}]}"#,
            QueryError::UnknownClaimId {
                credential: QueryId::parse("pid").unwrap(),
                claim: ClaimId::parse("b").unwrap(),
            },
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
                "credential_sets":[{"options":[["pid"],["nonexistent"]]}]}"#,
            QueryError::UnknownCredentialId(QueryId::parse("nonexistent").unwrap()),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claim_sets":[[]]}]}"#,
            QueryError::ClaimSetsWithoutClaims(QueryId::parse("pid").unwrap()),
        ),
        (
            r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"path":[]}]}]}"#,
            QueryError::ClaimPath {
                credential: QueryId::parse("pid").unwrap(),
                claim: first,
                error: ClaimPathError::Empty,
            },
        ),
        (
            r#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{},
                "claims":[{"path":["org.iso.18013.5.1","given_name"]},{"path":["org.iso.18013.5.1.given_name"]}]}]}"#,
            QueryError::MdocPath {
                credential: QueryId::parse("mdl").unwrap(),
                claim: Position::new(1),
            },
        ),
    ];
    for (json, refused) in cases {
        assert_eq!(parsed(json).expect_err(json), refused, "{json}");
    }
}

/// `purpose` is why the verifier wants a combination, and the wallet's
/// only chance to tell the user. §6.2 allows a string, an integer or an
/// object, so all three have to survive parsing.
#[test]
fn purpose_is_kept_in_all_three_shapes() {
    let q = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
            "credential_sets":[
              {"options":[["pid"]],"purpose":"Proving your age"},
              {"options":[["pid"]],"purpose":1},
              {"options":[["pid"]],"purpose":{"id":1,"name":"Age check"}}]}"#,
    )
    .expect("valid DCQL");
    let sets = q.credential_sets().expect("sets");
    assert_eq!(
        sets[0].purpose(),
        Some(&Value::String("Proving your age".into()))
    );
    assert_eq!(sets[1].purpose(), Some(&Value::from(1)));
    assert_eq!(
        sets[2].purpose().and_then(|p| p.get("name")),
        Some(&Value::String("Age check".into()))
    );
    assert_eq!(
        serde_json::to_string(&sets[0]).expect("serialize"),
        r#"{"options":[["pid"]],"required":true,"purpose":"Proving your age"}"#,
        "purpose round-trips; a wallet passing the query on must not drop it"
    );
}

/// An absent `purpose` stays absent rather than serialising as null — a
/// verifier reading a re-encoded query should not see a field it never
/// sent.
#[test]
fn an_absent_purpose_is_not_serialised() {
    let q = parsed(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["pid"]]}]}"#,
    )
    .expect("valid DCQL");
    let sets = q.credential_sets().expect("sets");
    assert!(sets[0].purpose().is_none());
    assert_eq!(
        serde_json::to_string(&sets[0]).expect("serialize"),
        r#"{"options":[["pid"]],"required":true}"#
    );
}

/// A full query round-trips, including mdoc paths and value filters.
#[test]
fn realistic_query_round_trips() {
    let json = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
        "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
        "claims":[{"id":"a","path":["org.iso.18013.5.1","age_over_18"],"values":[true]}],
        "claim_sets":[["a"]],"_profile":{"a":[1]}}]}"#;
    let q = parsed(json).unwrap();
    let c = &q.credentials()[0];
    assert_eq!(c.claims()[0].values().unwrap()[0], Value::Bool(true));
    assert_eq!(
        c.claim_sets().unwrap()[0].ids().collect::<Vec<_>>(),
        vec!["a"]
    );
    assert_eq!(c.claim("a").unwrap().path().components().len(), 2);

    let back: DcqlQuery = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
    assert_eq!(back, q);
}

/// §6.1.1: `trusted_authorities` is a non-empty array of objects, each with a string `type` and
/// a non-empty array of string `values`. One rule per row; `null` is a member of the wrong type.
#[test]
fn trusted_authorities_follow_section_6_1_1() {
    let cases = [
        (
            json!([{"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]}]),
            None,
        ),
        (Value::Null, Some(TrustedAuthorityError::NotArray)),
        (
            json!({"type": "aki"}),
            Some(TrustedAuthorityError::NotArray),
        ),
        (json!([]), Some(TrustedAuthorityError::Empty)),
        (json!(["aki"]), Some(TrustedAuthorityError::EntryNotObject)),
        (
            json!([{"values": ["a"]}]),
            Some(TrustedAuthorityError::TypeAbsent),
        ),
        (
            json!([{"type": 1, "values": ["a"]}]),
            Some(TrustedAuthorityError::TypeNotString),
        ),
        (
            json!([{"type": "aki"}]),
            Some(TrustedAuthorityError::ValuesAbsent),
        ),
        (
            json!([{"type": "aki", "values": "a"}]),
            Some(TrustedAuthorityError::ValuesNotArray),
        ),
        (
            json!([{"type": "aki", "values": []}]),
            Some(TrustedAuthorityError::ValuesEmpty),
        ),
        (
            json!([{"type": "aki", "values": ["a", 1]}]),
            Some(TrustedAuthorityError::ValueNotString(Position::new(1))),
        ),
    ];
    for (authorities, expected) in cases {
        let query = json!({"credentials": [{"id": "pid", "format": "mso_mdoc", "meta": {},
            "trusted_authorities": authorities}]});
        let got = DcqlQuery::parse(&query).map(drop).map_err(|e| match e {
            QueryError::TrustedAuthorities { credential, error } if credential == "pid" => {
                Some(error)
            }
            _ => None,
        });
        assert_eq!(
            got,
            expected.map_or(Ok(()), |e| Err(Some(e))),
            "{authorities}"
        );
    }
}
