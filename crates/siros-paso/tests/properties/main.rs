//! The properties check_props.py states of the PaSO profile, over seeded random metadata,
//! payloads, wallet configurations and hosts shaped as its dressing shapes them: each
//! rendering's locale, labels, kinds and coverage (View §2-4); the binding rule (Core §7.4.2);
//! the overlay over the card; phase 2's findings and the fallback they cause; the SCA response
//! members (Core §6) and their risk signals (Risk Signals §4-7). Each property's oracle is
//! computed here from the specification's rule.

mod checks;
#[path = "../common/mod.rs"]
mod common;
mod generate;
#[path = "../host.rs"]
mod paso_host;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
fn every_rendering_binding_and_response_holds_the_stated_properties() {
    let mut rng = ChaCha8Rng::seed_from_u64(29);
    let mut tally = checks::Tally::default();
    for _ in 0..300 {
        let case = generate::Case::new(&mut rng);
        checks::case(&case, &mut tally);
    }
    for (name, count) in &tally.0 {
        println!("{count:>5} {name}");
    }
    // A path no case reaches checks nothing.
    for needed in [
        "rendered",
        "excluded",
        "not compatible",
        "unsupported",
        "full-text rows",
        "bound",
        "excluded View §4",
        "excluded no compatible entry",
        "payment boxes",
        "standard boxes",
        "responses",
        "risk signals encrypted",
        "risk signals plain",
        "phase 2 findings",
        "fallbacks",
    ] {
        assert!(tally.count(needed) > 0, "no case reached {needed}");
    }
}
