//! One fixture per rule that keeps an entry from rendering for a credential (Proof Metadata §3
//! and §5, View §2-4, Core §7.1 and §7.4.2, the rulebooks, Risk Signals §3-7), each asserting the
//! rule that decided it; and the rules the PaSO profile adds to the core's on a
//! request, each with its error code.

#[path = "../common/mod.rs"]
mod common;

use common::{CUSTOM, Card, en, entry};
use siros_openid4vp::ids::{CredentialId, FormatId};
use siros_openid4vp::rows::Env;
use siros_openid4vp::wallet::{Credential, Facts, Holder};
use siros_paso::document::{DocumentError, PasoDocument};
use siros_paso::labels::LabelViolation;
use siros_paso::outcome::{Outcome, Unsupported};
use siros_paso::{PasoProfile, Rendered};

/// An entry of a type for a credential whose metadata gives `meta` for it.
fn render_with(
    kind: &str,
    meta: &str,
    payload: &str,
    env: &Env,
    profile: &PasoProfile,
) -> Result<Rendered, Outcome> {
    let card = Card::sd_jwt(&format!(r#"{{"{kind}": {meta}}}"#));
    let entry_json =
        format!(r#"{{"type": "{kind}", "credential_ids": ["q"], "payload": {payload}}}"#);
    profile
        .render(
            &entry(&entry_json),
            siros_openid4vp::routing::ChannelKind::DcApi,
            &card.credential(),
            crate::common::placement(&card.credential().format),
            env,
        )
        .expect("no fault")
}

/// A custom type's entry rendered in English with the default profile.
fn render(meta: &str, payload: &str) -> Result<Rendered, Outcome> {
    render_with(CUSTOM, meta, payload, &en(), &PasoProfile::default())
}

/// Metadata of claims (a JSON array's members).
fn claims(members: &str) -> String {
    format!(r#"{{"claims": [{{"path": ["transaction_id"]}}, {members}]}}"#)
}

fn shown(name: &str) -> String {
    format!(r#"[{{"locale": "en", "name": "{name}"}}]"#)
}

/// Asserts the rule.
macro_rules! decided {
    ($rendered:expr, $pattern:pat) => {{
        let rendered = $rendered;
        assert!(
            matches!(&rendered, Err($pattern)),
            "expected {}, got {rendered:?}",
            stringify!($pattern)
        );
    }};
}

mod payloads;
mod signals_and_adhoc;

#[test]
fn metadata_that_breaks_proof_metadata_section_3_makes_the_type_unsupported() {
    let n = |extra: &str| format!(r#"{{"path": ["n"], "display": {}{extra}}}"#, shown("N"));
    let payload = r#"{"transaction_id": "t", "n": "a"}"#;
    decided!(
        render("{}", payload),
        Outcome::Unsupported(Unsupported::NoClaims)
    );
    decided!(
        render("null", payload),
        Outcome::Unsupported(Unsupported::NoEntry(_))
    );
    let many: Vec<String> = (0..100)
        .map(|k| format!(r#"{{"path": ["k{k}"]}}"#))
        .collect();
    decided!(
        render(&claims(&many.join(", ")), payload),
        Outcome::Unsupported(Unsupported::TooManyClaims(101))
    );
    // 100 claims, the most §3.1 allows.
    assert!(render(&claims(&[n(""), many[..98].join(", ")].join(", ")), payload).is_ok());
    decided!(
        render(&claims(r#"{"path": []}"#), payload),
        Outcome::Unsupported(Unsupported::InvalidPath(1))
    );
    decided!(
        render(&claims(&format!("{}, {}", n(""), n(""))), payload),
        Outcome::Unsupported(Unsupported::PathTwice(_))
    );
    decided!(
        render(
            &claims(r#"{"path": ["n"], "value_type": "iso_date"}"#),
            payload
        ),
        Outcome::Unsupported(Unsupported::ValueTypeWithoutDisplay(_))
    );
    decided!(
        render(&claims(r#"{"path": ["n"], "display": []}"#), payload),
        Outcome::Unsupported(Unsupported::EmptyArray(_))
    );
    decided!(
        render(
            &claims(r#"{"path": ["n"], "display": [{"locale": "en"}]}"#),
            payload
        ),
        Outcome::Unsupported(Unsupported::EntryWithoutText(..))
    );
    decided!(
        render(
            &claims(
                r#"{"path": ["n"], "display": [{"locale": "en", "name": "N", "display_type": "url"}]}"#
            ),
            payload
        ),
        Outcome::Unsupported(Unsupported::LabelType { .. })
    );
    decided!(
        render(
            &claims(r#"{"path": ["n"], "display": [{"locale": null, "name": "N"}]}"#),
            payload
        ),
        Outcome::Unsupported(Unsupported::NullLocale(_))
    );
    decided!(
        render(
            &claims(
                r#"{"path": ["n"], "display": [{"locale": "en", "name": "A"}, {"locale": "EN", "name": "B"}]}"#
            ),
            payload
        ),
        Outcome::Unsupported(Unsupported::LocaleRepeated(..))
    );
    decided!(
        render(
            &claims(r#"{"path": ["n"], "display": [{"name": "A"}, {"name": "B"}]}"#),
            payload
        ),
        Outcome::Unsupported(Unsupported::DefaultTwice(_))
    );
    decided!(
        render(
            &claims(&format!(
                r#"{{"path": ["n"], "display": {}}}"#,
                shown(&"x".repeat(61))
            )),
            payload
        ),
        Outcome::Unsupported(Unsupported::ClaimLabel(
            _,
            LabelViolation::TooLong {
                clusters: 61,
                max: 60
            }
        ))
    );
    decided!(
        render(
            &claims(r#"{"path": ["n"], "display": [{"locale": "en", "name": "a\tb"}]}"#),
            payload
        ),
        Outcome::Unsupported(Unsupported::ClaimLabel(_, LabelViolation::Control('\t')))
    );
    decided!(
        render(
            &claims(&n(r#", "value_type": "label_only", "mandatory": true"#)),
            payload
        ),
        Outcome::Unsupported(Unsupported::MandatoryLabelOnly(_))
    );
    decided!(
        render(
            &format!(
                r#"{{"claims": [{{"path": ["transaction_id"]}}, {}], "ui_labels": []}}"#,
                n("")
            ),
            payload
        ),
        Outcome::Unsupported(Unsupported::UiLabelsNotObject)
    );
    decided!(
        render(
            &format!(
                r#"{{"claims": [{{"path": ["transaction_id"]}}, {}], "ui_labels": {{"transaction_title": [{{"locale": "en", "value": "{}"}}]}}}}"#,
                n(""),
                "t".repeat(101)
            ),
            payload
        ),
        Outcome::Unsupported(Unsupported::UiLabel(
            _,
            LabelViolation::TooLong {
                clusters: 101,
                max: 100
            }
        ))
    );
    decided!(
        render(
            &format!(
                r#"{{"claims": [{{"path": ["transaction_id"]}}, {}], "ui_labels": {{"security_hint": [{{"locale": "en", "value": "Check", "value_type": "mini_markdown"}}]}}}}"#,
                n("")
            ),
            payload
        ),
        Outcome::Unsupported(Unsupported::LabelType {
            member: "value_type",
            ..
        })
    );
    // Proof Metadata §3.2: an identifier the wallet does not recognise is ignored.
    assert!(
        render(
            &format!(
                r#"{{"claims": [{{"path": ["transaction_id"]}}, {}], "ui_labels": {{"x": 5}}}}"#,
                n("")
            ),
            payload
        )
        .is_ok()
    );
}

#[test]
fn a_type_without_metadata_or_outside_its_rulebook_is_unsupported() {
    let payload = r#"{"transaction_id": "t"}"#;
    let tid = claims(r#"{"path": ["n"]}"#);
    decided!(
        render_with(
            "urn:paso:sca:global:generic:Bad:1",
            &tid,
            payload,
            &en(),
            &PasoProfile::default()
        ),
        Outcome::Unsupported(Unsupported::NotGeneric(_))
    );
    decided!(
        render_with(
            "urn:paso:sca:global:mandate:Bad:1",
            "{}",
            payload,
            &en(),
            &PasoProfile::default()
        ),
        Outcome::Unsupported(Unsupported::NotMandate(_))
    );
    let card = Card::sd_jwt("{}");
    let entry_json =
        format!(r#"{{"type": "{CUSTOM}", "credential_ids": ["q"], "payload": {payload}}}"#);
    decided!(
        PasoProfile::default()
            .render(
                &entry(&entry_json),
                siros_openid4vp::routing::ChannelKind::DcApi,
                &card.credential(),
                crate::common::placement(&card.credential().format),
                &en()
            )
            .expect("no fault"),
        Outcome::Unsupported(Unsupported::NotListed(_))
    );
    let bare = Credential::new(
        CredentialId::parse("bare").expect("id"),
        FormatId::parse("dc+sd-jwt").expect("format"),
        b"{}",
        Vec::new(),
        Facts::new(Holder::Bound, Vec::new()).expect("facts"),
    )
    .expect("credential");
    decided!(
        PasoProfile::default()
            .render(
                &entry(&entry_json),
                siros_openid4vp::routing::ChannelKind::DcApi,
                &bare,
                crate::common::placement(&bare.format),
                &en()
            )
            .expect("no fault"),
        Outcome::Unsupported(Unsupported::NoPasoMetadata)
    );
}

/// Core §6.1's `metadata_integrity` is the document's value as W3C SRI §3.3 writes it: an option,
/// an algorithm in any case and an unsupported algorithm's expression beside a supported one.
#[test]
fn a_documents_integrity_is_w3c_sri_metadata_kept_as_written() {
    // Core §6.1's example value.
    let digest = "K3L5x7nMqYdP2fR8vQwJ1bHgT9sUcA4eZpXo6yD0mEk=";
    let document = |integrity: &str| {
        format!(
            r#"{{"integrity": "{integrity}", "type": "t", "issuer": {{"iss": "i", "keys": {{}}}}, "transaction_data_types": {{}}}}"#
        )
    };
    for written in [
        format!("sha256-{digest}"),
        format!("sha256-{digest}?ct=a"),
        format!("SHA256-{digest}"),
        format!("sha256-{digest} md5-AA"),
    ] {
        let text = document(&written);
        let node = PasoDocument::json(text.as_bytes()).expect("JSON");
        let read = PasoDocument::read(&node).expect(&written);
        assert_eq!(read.integrity.as_str(), written);
    }
    for refused in ["", "md5-AA", "sha256-A=A"] {
        let text = document(refused);
        let node = PasoDocument::json(text.as_bytes()).expect("JSON");
        assert!(
            matches!(
                PasoDocument::read(&node),
                Err(DocumentError::Member("integrity"))
            ),
            "{refused}"
        );
    }
}
