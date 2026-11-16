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
