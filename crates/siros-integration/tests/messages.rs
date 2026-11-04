//! Section 4.13's identifiers: one identifier names one message across the workspace's crates.

use rustc_hash::FxHashMap;
use siros_explain::{Message, Messages};

#[test]
fn an_identifier_names_one_message_across_the_crates() {
    // Catches two error types, in one crate or two, declaring different messages under one
    // identifier. A transparent variant declares its cause's message again, unchanged.
    let declared = [
        siros_openid4vp::CrateMessages::messages(),
        siros_mdoc::CrateMessages::messages(),
        siros_sdjwt::CrateMessages::messages(),
        siros_paso::CrateMessages::messages(),
        siros_qes::CrateMessages::messages(),
        siros_x509::CrateMessages::messages(),
        siros_testkit::CrateMessages::messages(),
        siros_i18n::CrateMessages::messages(),
    ];
    let mut by_id: FxHashMap<&str, &Message> = FxHashMap::default();
    let mut clashes = Vec::new();
    for message in declared.iter().flatten() {
        match by_id.insert(message.id().as_str(), message) {
            Some(earlier) if earlier != message => clashes.push((earlier, message)),
            _ => {}
        }
    }
    assert!(clashes.is_empty(), "{clashes:#?}");
}
