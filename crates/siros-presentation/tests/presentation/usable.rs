//! C4: the plan presents the credentials usable at its time, and phase 2, which makes the plan
//! again at its own time, refuses a selection of one that became unusable since.

use serde_json::json;
use siros_codec::date::DateTime;
use siros_presentation::{Fulfilment, OfferIndex, PresentationError, Selection};

use crate::verifier::{redirect_unsigned, NONCE, NOW, STATE};
use crate::wallet::{ready, sd_jwt, sd_jwt_with, Held, Wallet, VCT};

#[test]
fn credentials_usable_at_the_plan_time() {
    let claims = [("given_name", json!("Erika"))];
    let expiring = sd_jwt_with(VCT, &claims, json!({"exp": NOW + 60}));
    let wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", expiring),
        Held::new(2, "dc+sd-jwt", sd_jwt(VCT, &claims)),
    ]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }));
    let before = wallet.input(&request);
    let after = siros_presentation::PlanInput {
        now: DateTime::from_unix(NOW + 120).unwrap(),
        ..before
    };

    let planned = ready(&before).unwrap();
    assert_eq!(
        planned.view().offers().len(),
        2,
        "both credentials are usable"
    );
    assert_eq!(
        ready(&after).unwrap().view().offers().len(),
        1,
        "the expired credential is no candidate"
    );

    // The user chose the expiring credential's offer; phase 2 runs after it expired.
    let selection = Selection::new(*planned.view().digest(), OfferIndex::new(0), vec![], vec![]);
    let replanned = ready(&after).unwrap();
    let chosen = replanned.choose(&selection, Fulfilment::WalletUi);
    assert_eq!(chosen.err(), Some(PresentationError::DigestMismatch));
}

#[test]
fn the_urn_spelling_of_the_vct_matches() {
    // The ARF's type identifiers circulate in both spellings: the plain
    // form the issuer puts in the payload vct (`eudi:eucc:1` - Spherity's
    // EUCC SD-JWT metadata) and the URN-qualified form a verifier's
    // `vct_values` names (`urn:eudi:eucc:1` - Accredify's ACRA UAT
    // request). Found on-device 2026-11-16: the query answered "no
    // matching credential" while the wallet held exactly the credential
    // the query asked for.
    let claims = [("legal_representative", json!("Erika Mustermann"))];
    // The issuer's spelling: no urn: prefix.
    let wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt("eudi:eucc:1", &claims),
    )]);
    // The verifier's spelling: urn:-qualified.
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [{"id": "eucc", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:eucc:1"]},
            "claims": [{"path": ["legal_representative"]}]}]}
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    assert_eq!(
        planned.view().offers().len(),
        1,
        "the URN-qualified spelling matches the plain one"
    );
    // And the reverse: a wallet credential whose vct carries the urn:
    // prefix matches a query that names the plain spelling.
    let wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt("urn:eudi:eucc:1", &claims),
    )]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [{"id": "eucc", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["eudi:eucc:1"]},
            "claims": [{"path": ["legal_representative"]}]}]}
    }));
    let planned = ready(&wallet.input(&request)).unwrap();
    assert_eq!(
        planned.view().offers().len(),
        1,
        "the plain spelling matches the URN-qualified one"
    );
}

#[test]
fn the_urn_spelling_shim_is_scoped_to_the_eudi_namespace() {
    // The normalization is an EUDI-ecosystem compat shim, NOT a general
    // rule: SD-JWT VC's `vct` is a case-sensitive identifier and two
    // spellings are formally two types. A `urn:` strip outside the
    // `eudi:` namespace would merge distinctions the spec deliberately
    // draws - so this pair must NOT match, in either direction.
    let claims = [("given_name", json!("Erika"))];
    // A no-match plan surfaces as NoOffer(Unsatisfied) here, not an
    // empty offers list: assert the refusal, not just the count.
    let wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt("foo:bar:1", &claims),
    )]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [{"id": "x", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:foo:bar:1"]},
            "claims": [{"path": ["given_name"]}]}]}
    }));
    assert!(
        ready(&wallet.input(&request)).is_err(),
        "a non-eudi URN spelling does not match the bare one"
    );
    // Case stays significant in both spellings (no folding anywhere).
    let wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt("eudi:Eucc:1", &claims),
    )]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
        "state": STATE,
        "dcql_query": {"credentials": [{"id": "x", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:eucc:1"]},
            "claims": [{"path": ["given_name"]}]}]}
    }));
    assert!(
        ready(&wallet.input(&request)).is_err(),
        "case is significant: Eucc != eucc even inside the eudi namespace"
    );
}
