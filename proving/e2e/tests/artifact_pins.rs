//! A backend loads only the artifact its system rulebook pins (Section 8): bytes of the pinned
//! length with another digest are refused before anything decompresses them.

#![allow(clippy::unwrap_used, clippy::panic)]

use siros_zkp_backend_longfellow::{self as longfellow, LongfellowProver, LongfellowVerifier};
use siros_zkp_backend_vega::{self as vega, VegaNymAuth};
use siros_zkp_req_nym_auth::system::NymAuthSystem;

#[test]
fn an_unpinned_artifact_is_refused() {
    let lf = NymAuthSystem::LongfellowV1.circuit_artifact().compressed;
    let vg = NymAuthSystem::VegaV1.circuit_artifact().compressed;
    for bytes in [vec![0u8; lf.len], Vec::new()] {
        assert!(matches!(
            LongfellowProver::load(&bytes),
            Err(longfellow::ArtifactError::Pin(pin)) if pin == lf
        ));
        assert!(matches!(
            LongfellowVerifier::load(&bytes),
            Err(longfellow::ArtifactError::Pin(pin)) if pin == lf
        ));
    }
    for bytes in [vec![0u8; vg.len], Vec::new()] {
        assert!(matches!(
            VegaNymAuth::load(&bytes),
            Err(vega::ArtifactError::Pin(pin)) if pin == vg
        ));
    }
}
