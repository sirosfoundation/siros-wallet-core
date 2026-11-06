//! C5: per batch, the instance the presentation records name least often, the lowest `instanceId`
//! on a tie.

use serde_json::{json, Value};
use siros_wallet_state::WalletState;

/// Credential ids of batch A, beyond 32 bits.
const A: [u64; 3] = [4_294_967_296, 4_294_967_297, 4_294_967_298];
const B: [u64; 2] = [10, 11];
const C: [u64; 2] = [20, 21];

fn entry(id: u64, batch: u64, instance: u64) -> Value {
    json!({"credentialId": id, "format": "dc+sd-jwt", "data": "", "kid": "",
        "instanceId": instance, "batchId": batch, "credentialIssuerIdentifier": "",
        "credentialConfigurationId": ""})
}

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
    let [a0, a1, a2] = A;
    let [b0, b1] = B;
    let [c0, c1] = C;
    // Batch A: instance 0 named twice, 1 twice, 2 once (by a record that names it twice).
    // Batch B: instance 0 named once, 1 never.
    // Batch C: neither named; instance 3 comes before instance 2.
    let state = WalletState::parse(
        &json!({
            "schemaVersion": 4,
            "credentials": [
                entry(a0, 7, 0),
                entry(b0, 9, 0),
                entry(a1, 7, 1),
                entry(c0, 11, 3),
                entry(b1, 9, 1),
                entry(a2, 7, 2),
                entry(c1, 11, 2),
            ],
            "keypairs": [],
            "presentations": [
                record(&[a0, b0]),
                record(&[a0]),
                record(&[a1]),
                record(&[a1]),
                record(&[a2, a2]),
            ],
        })
        .to_string(),
    )
    .unwrap();
    let chosen: Vec<u64> = state
        .least_used(state.credentials())
        .into_iter()
        .map(|entry| entry.credential_id().value())
        .collect();
    assert_eq!(chosen, [a2, b1, c1]);
}
