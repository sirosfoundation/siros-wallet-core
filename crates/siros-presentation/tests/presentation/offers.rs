//! A3 and A1: the offers of credential sets, and no query other than `zkp_req` reaches a
//! nym_auth attestation's undisclosable attributes.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_dcql::Dropped;
use siros_dcql::QueryId;
use siros_oid4vp::{ErrorCode, Submission};
use siros_presentation::{
    AdditionIndex, Failure, OfferIndex, Pick, PickError, PresentationError, Selection, SubsetError,
    WalletDisplay, MAX_ADDITIONS, MAX_EXAMINED, MAX_OFFERS,
};
use siros_wallet_state::CredentialId;
use siros_zkp_req_nym_auth::testing::Spec;

use crate::verifier::{dc_api_unsigned, redirect_unsigned, NONCE, STATE};
use crate::wallet::{mdoc, nym_auth, ready, respond_to, sd_jwt, Held, Wallet, MDL, MDL_NS, VCT};

fn request(dcql: Value) -> siros_oid4vp::VerifiedRequest {
    redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": NONCE,
        "state": STATE,
        "dcql_query": dcql
    }))
}

#[test]
fn all_optional_sets_offer_each_option() {
    let wallet = Wallet::new(vec![
        Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        ),
        Held::new(
            2,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
        ),
    ]);
    let request = request(json!({
        "credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL}}
        ],
        "credential_sets": [
            {"options": [["pid"]], "required": false, "purpose": "Identify"},
            {"options": [["mdl"]], "required": false, "purpose": "Drive"}
        ]
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    // (purpose, the queries of the members, the queries of each addition)
    type Shape<'v> = (Option<&'v str>, Vec<&'v str>, Vec<Vec<&'v str>>);
    let offers: Vec<Shape<'_>> = planned
        .view()
        .offers()
        .iter()
        .map(|offer| {
            let queries = offer
                .members()
                .iter()
                .map(|m| m.query_id().as_str())
                .collect();
            let additions = offer
                .additions()
                .iter()
                .map(|a| a.members().iter().map(|m| m.query_id().as_str()).collect())
                .collect();
            (offer.purpose(), queries, additions)
        })
        .collect();
    assert_eq!(
        offers,
        [
            (Some("Identify"), vec!["pid"], vec![vec!["mdl"]]),
            (Some("Drive"), vec!["mdl"], vec![vec!["pid"]]),
        ]
    );
}

#[test]
fn no_query_but_zkp_req_reaches_a_nym_auth_attestation() {
    let (data, auxiliary) = nym_auth(&Spec::default());
    let mut nym = Held::new(1, "mso_mdoc", data);
    nym.metadata = Some(auxiliary);
    let wallet = Wallet::new(vec![nym]);
    let ns = "eu.europa.ec.eudi.nym_auth.1";
    let queries = [
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns},
            "claims": [{"path": [ns, "birth_date"]}]}),
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns},
            "claims": [{"path": [ns, "ssc"]}]}),
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns}}),
        json!({"id": "q", "format": "jwt_vc_json", "meta": {"type_values": [[ns]]},
            "claims": [{"path": ["credentialSubject", "birth_date"]}]}),
    ];
    for query in queries {
        let request = request(json!({"credentials": [query.clone()]}));
        let refused = ready(&wallet.input(&request)).err().unwrap();
        assert_eq!(
            refused,
            PresentationError::NoOffer(Failure::Unsatisfied),
            "{query}"
        );
        assert_eq!(refused.error_code(), ErrorCode::AccessDenied, "{query}");
    }
}

/// What the view shows of an offer: the queries of its members with their number of
/// credentials, and the queries of each addition.
type Shape = (Vec<(String, usize)>, Vec<Vec<String>>);

fn shape(offer: &siros_presentation::OfferView) -> Shape {
    let members = offer
        .members()
        .iter()
        .map(|m| (m.query_id().as_str().to_owned(), m.credentials().len()))
        .collect();
    let additions = offer
        .additions()
        .iter()
        .map(|a| {
            a.members()
                .iter()
                .map(|m| m.query_id().as_str().to_owned())
                .collect()
        })
        .collect();
    (members, additions)
}

/// The request of `dcql` in `direct_post`.
fn asked(dcql: Value) -> siros_oid4vp::VerifiedRequest {
    request(dcql)
}

fn mdl(id: u64) -> Held {
    Held::new(
        id,
        "mso_mdoc",
        mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
    )
}

fn mdl_query(multiple: bool) -> Value {
    json!({"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL}, "multiple": multiple,
        "claims": [{"path": [MDL_NS, "family_name"]}]})
}

fn pid_query() -> Value {
    json!({"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}})
}

fn photo(id: u64) -> Held {
    Held::new(
        id,
        "mso_mdoc",
        mdoc(
            "org.example.photo.1",
            "org.example.photo",
            &[("photo", Cbor::Bytes(vec![1]))],
        ),
    )
}

fn photo_query() -> Value {
    json!({"id": "photo", "format": "mso_mdoc", "meta": {"doctype_value": "org.example.photo.1"}})
}

/// K3: the picked credential picker entries make the selection of the offer they name, with the
/// additions that answer exactly the picked queries the offer leaves; each pick the plan does
/// not hold is refused.
#[test]
fn picks_select_against_the_plan() {
    let pid = Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt(VCT, &[("given_name", json!("Erika"))]),
    );
    let wallet = Wallet::new(vec![pid, mdl(2), photo(3)]);
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false), photo_query()],
        "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["mdl"], ["mdl", "photo"]], "required": false}
        ]
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    let digest = *planned.view().digest();
    let id = |query: &str| QueryId::parse(query).unwrap();
    let pick = |offer, query: &str, credential| {
        Pick::new(
            OfferIndex::new(offer),
            id(query),
            CredentialId::new(credential),
        )
    };
    let selection = |additions: Vec<usize>| {
        let additions = additions.into_iter().map(AdditionIndex::new).collect();
        Ok(Selection::new(
            digest,
            OfferIndex::new(0),
            additions,
            Vec::new(),
        ))
    };
    let refused = |error| Err(PresentationError::Pick(error));
    let unheld = |why| refused(PickError::Unmatched(vec![(OfferIndex::new(0), why)]));
    // (case, picks, outcome)
    let cases: [(&str, Vec<Pick>, Result<Selection, PresentationError>); 11] = [
        ("the offer", vec![pick(0, "pid", 1)], selection(vec![])),
        (
            "the offer and an addition",
            vec![pick(0, "mdl", 2), pick(0, "pid", 1)],
            selection(vec![0]),
        ),
        (
            "the addition that answers every picked query",
            vec![pick(0, "pid", 1), pick(0, "mdl", 2), pick(0, "photo", 3)],
            selection(vec![1]),
        ),
        ("no pick", vec![], refused(PickError::Empty)),
        (
            "two offers",
            vec![pick(0, "pid", 1), pick(1, "pid", 1)],
            refused(PickError::Offers(OfferIndex::new(0), OfferIndex::new(1))),
        ),
        (
            "a pick twice",
            vec![pick(0, "pid", 1), pick(0, "pid", 1)],
            refused(PickError::Repeated {
                query: id("pid"),
                credential: CredentialId::new(1),
            }),
        ),
        (
            "an offer the picker numbers apart from the plan",
            vec![pick(1, "pid", 1)],
            selection(vec![]),
        ),
        (
            "a query the request lacks",
            vec![pick(0, "pid", 1), pick(0, "card", 1)],
            refused(PickError::Query(id("card"))),
        ),
        (
            "a credential the offer does not hold",
            vec![pick(0, "pid", 2)],
            unheld(PickError::Credential {
                query: id("pid"),
                credential: CredentialId::new(2),
            }),
        ),
        (
            "an offer member without a pick",
            vec![pick(0, "mdl", 2)],
            unheld(PickError::Missing(id("pid"))),
        ),
        (
            "a part of an addition",
            vec![pick(0, "pid", 1), pick(0, "photo", 3)],
            unheld(PickError::Additions),
        ),
    ];
    for (case, picks, outcome) in cases {
        assert_eq!(planned.picked(&picks), outcome, "{case}");
    }
}

/// K3: of two offers that hold the picks, one through an addition, the one whose members alone
/// hold them is selected: the offer the picker shows.
#[test]
fn picks_select_the_offer_whose_members_hold_them() {
    let pid = Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt(VCT, &[("given_name", json!("Erika"))]),
    );
    let wallet = Wallet::new(vec![pid, mdl(2)]);
    // The offers {pid} with the addition {mdl}, and {pid, mdl}.
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false)],
        "credential_sets": [
            {"options": [["pid"], ["pid", "mdl"]]},
            {"options": [["mdl"]], "required": false}
        ]
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    let pick = |query: &str, credential| {
        Pick::new(
            OfferIndex::new(0),
            QueryId::parse(query).unwrap(),
            CredentialId::new(credential),
        )
    };
    let selection = planned
        .picked(&[pick("pid", 1), pick("mdl", 2)])
        .expect("a selection");
    let offer = &planned.view().offers()[selection.offer().value()];
    let members = vec![("pid".to_owned(), 1), ("mdl".to_owned(), 1)];
    assert_eq!(shape(offer), (members, vec![]));
}

/// A3: required and optional sets, additions, `multiple` members, and the limits.
#[test]
fn offers_of_credential_sets() {
    let pid = |id| {
        Held::new(
            id,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        )
    };

    // An optional option that shares a query with the offer is no addition.
    let wallet = Wallet::new(vec![pid(1), mdl(2)]);
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false)],
        "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["pid", "mdl"]], "required": false},
            {"options": [["mdl"]], "required": false}
        ]
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    let offers: Vec<Shape> = planned.view().offers().iter().map(shape).collect();
    let addition = vec![vec!["mdl".to_owned()]];
    assert_eq!(offers, [(vec![("pid".to_owned(), 1)], addition)]);

    // A `multiple` member holds every candidate; the selection chooses a non-empty subset.
    let wallet = Wallet::new(vec![mdl(1), mdl(2), mdl(3)]);
    let request = dc_api_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "dc_api", "nonce": NONCE,
        "dcql_query": {"credentials": [mdl_query(true)]}
    }));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let [offer] = planned.view().offers() else {
        panic!("one offer")
    };
    assert_eq!(shape(offer), (vec![("mdl".to_owned(), 3)], Vec::new()));
    assert_eq!(offer.wallet_display(), WalletDisplay::Needed);
    let response = respond_to(&input, 0, Vec::new(), vec![("mdl".into(), vec![3, 1])]).unwrap();
    let Submission::DcApi(data) = response.submission() else {
        panic!("a DC API response")
    };
    assert_eq!(data.json()["vp_token"]["mdl"].as_array().unwrap().len(), 2);
    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1, 3]));
    let subset = |query: &str, ids: Vec<u64>| (query.to_owned(), ids);
    let id = |query: &str| QueryId::parse(query).unwrap();
    let refusals = [
        (
            vec![subset("mdl", vec![])],
            PresentationError::Subset(SubsetError::Empty),
        ),
        (
            vec![subset("mdl", vec![9])],
            PresentationError::Subset(SubsetError::Unknown(CredentialId::new(9))),
        ),
        (
            vec![subset("mdl", vec![2, 2])],
            PresentationError::Subset(SubsetError::Repeated(CredentialId::new(2))),
        ),
        (
            vec![subset("pid", vec![1])],
            PresentationError::SubsetQuery(id("pid")),
        ),
        (
            vec![subset("mdl", vec![1]), subset("mdl", vec![2])],
            PresentationError::SubsetRepeated(id("mdl")),
        ),
    ];
    for (subsets, refusal) in refusals {
        let response = respond_to(&input, 0, Vec::new(), subsets.clone());
        assert_eq!(response.err(), Some(refusal), "{subsets:?}");
    }

    // At most one option per optional set.
    let wallet = Wallet::new(vec![pid(1), mdl(2), photo(3)]);
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false), photo_query()],
        "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["mdl"], ["photo"]], "required": false}
        ]
    }));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let additions = planned.view().offers()[0].additions();
    assert_eq!(additions.len(), 2);
    let both = respond_to(&input, 0, vec![0, 1], Vec::new());
    let set = additions[0].set();
    assert_eq!(
        both.err(),
        Some(PresentationError::AdditionSetRepeated(set))
    );

    // The limits: 40 candidates give MAX_OFFERS offers and MAX_ADDITIONS additions, and two
    // required sets of one query examine MAX_EXAMINED of the 1600 combinations, 25 of them one.
    let mut held: Vec<Held> = (1..=40).map(mdl).collect();
    held.push(Held::new(
        41,
        "dc+sd-jwt",
        sd_jwt(VCT, &[("given_name", json!("Erika"))]),
    ));
    let wallet = Wallet::new(held);
    let limits = [
        (json!({"credentials": [mdl_query(false)]}), MAX_OFFERS, 0),
        (
            json!({"credentials": [pid_query(), mdl_query(false)], "credential_sets": [
                {"options": [["pid"]]}, {"options": [["mdl"]], "required": false}]}),
            1,
            MAX_ADDITIONS,
        ),
        (
            json!({"credentials": [mdl_query(false)], "credential_sets": [
                {"options": [["mdl"]]}, {"options": [["mdl"]]}]}),
            25,
            0,
        ),
    ];
    let unexamined = [
        (Dropped::Exact(8), Dropped::Exact(0)),
        (Dropped::Exact(0), Dropped::Exact(8)),
        (Dropped::Exact(1600 - MAX_EXAMINED), Dropped::Exact(0)),
    ];
    for ((dcql, offers, additions), (unexamined, additions_unexamined)) in
        limits.into_iter().zip(unexamined)
    {
        let request = asked(dcql.clone());
        let planned = ready(&wallet.input(&request)).unwrap();
        let view = planned.view();
        assert_eq!(view.offers().len(), offers, "{dcql}");
        assert_eq!(view.unexamined(), unexamined, "{dcql}");
        assert_eq!(view.offers()[0].additions().len(), additions, "{dcql}");
        assert_eq!(
            view.offers()[0].unexamined(),
            additions_unexamined,
            "{dcql}"
        );
    }
}
