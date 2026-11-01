//! C5: per batch, the instance the presentation records name least often, the lowest
//! `instanceId` on a tie.

use serde_json::{json, Value};
use siros_codec::date::DateTime;
use siros_credential::{least_used, Credential, UsableCredential};
use siros_wallet_state::WalletState;

use crate::common::{entry, sd_jwt, state};

/// Credential ids of batch A, beyond 32 bits.
const A: [u64; 3] = [4_294_967_296, 4_294_967_297, 4_294_967_298];
const B: [u64; 2] = [10, 11];
const C: [u64; 2] = [20, 21];

fn record(used: &[u64]) -> Value {
    json!({
        "presentationId": 1,
        "transactionId": 1,
        "data": "",
        "usedCredentialIds": used,
        "presentationTimestampSeconds": 1_750_000_000,
        "audience": "https://verifier.example"
    })
}

#[test]
fn least_used_instance_per_batch() {
    let data = sd_jwt(&json!({"vct": "https://credentials.example/identity"}), &[]);
    let vc = |id, batch, instance| entry(id, batch, instance, "dc+sd-jwt", &data);
    let [a0, a1, a2] = A;
    let [b0, b1] = B;
    let [c0, c1] = C;
    // Batch A: instance 0 named twice, 1 twice, 2 once (by a record that names it twice).
    // Batch B: instance 0 named once, 1 never.
    // Batch C: neither named; instance 3 comes before instance 2.
    let text = state(
        vec![
            vc(a0, 7, 0),
            vc(b0, 9, 0),
            vc(a1, 7, 1),
            vc(c0, 11, 3),
            vc(b1, 9, 1),
            vc(a2, 7, 2),
            vc(c1, 11, 2),
        ],
        vec![
            record(&[a0, b0]),
            record(&[a0]),
            record(&[a1]),
            record(&[a1]),
            record(&[a2, a2]),
        ],
    );
    let state = WalletState::parse(&text).unwrap();
    let credentials: Vec<Credential> = state
        .credentials()
        .iter()
        .map(|e| Credential::parse(e).unwrap())
        .collect();
    let now = DateTime::from_unix(1_750_000_000).unwrap();
    let usable: Vec<UsableCredential<'_>> = credentials
        .iter()
        .map(|c| UsableCredential::at(c, now).unwrap())
        .collect();
    let chosen: Vec<String> = least_used(&usable, state.presentations())
        .into_iter()
        .map(|u| u.credential().entry().credential_id().to_string())
        .collect();
    assert_eq!(chosen, [a2.to_string(), b1.to_string(), c1.to_string()]);
}
