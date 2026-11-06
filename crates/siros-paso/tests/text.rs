//! Label text against Proof Metadata §3.3.

use siros_explain::Text;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::rows::{Choice, Env};
use siros_paso::labels::{LabelSlot, LabelText, LabelViolation};
use siros_paso::mandate::MandateLabel;
use siros_paso::rulebook::{Rulebook, Subtype};
use siros_testkit::fixtures::OPTIONS;
use siros_testkit::render::{App, CrateSource, ENGLISH_PASO, GERMAN_PASO};

/// Proof Metadata §3.3 on single labels: the length in clusters, C0 and C1 controls, the
/// embeddings and overrides, an isolate left open; a closed isolate and white space alone pass.
#[test]
fn single_labels_meet_section_3_3_as_it_states() {
    let claim = LabelSlot::ClaimName;
    assert!(LabelText::parse(&"é".repeat(60), claim).is_ok());
    assert!(LabelText::parse(&"e\u{301}".repeat(60), claim).is_ok());
    // U+093F is a SpacingMark: an extended cluster keeps it with its consonant (UAX #29 GB9a).
    assert!(LabelText::parse(&"\u{915}\u{93f}".repeat(60), claim).is_ok());
    assert_eq!(
        LabelText::parse(&"x".repeat(61), claim),
        Err(LabelViolation::TooLong {
            clusters: 61,
            max: 60
        })
    );
    assert_eq!(
        LabelText::parse("a\nb", claim),
        Err(LabelViolation::Control('\n'))
    );
    assert_eq!(
        LabelText::parse("a\u{85}b", claim),
        Err(LabelViolation::Control('\u{85}'))
    );
    assert!(matches!(
        LabelText::parse("a\u{202e}b", claim),
        Err(LabelViolation::Directional(_))
    ));
    assert!(matches!(
        LabelText::parse("a\u{2066}b", claim),
        Err(LabelViolation::Directional(_))
    ));
    assert!(LabelText::parse("a\u{2066}b\u{2069}", claim).is_ok());
    // §3.3 holds no rule on white space.
    assert!(LabelText::parse(" \u{3000}", claim).is_ok());
    assert_eq!(
        LabelText::parse(&"x".repeat(41), LabelSlot::Affirmative),
        Err(LabelViolation::TooLong {
            clusters: 41,
            max: 40
        })
    );
    assert!(LabelText::parse(&"x".repeat(160), LabelSlot::Hint).is_ok());
}

/// The wallet's own strings stand in for metadata labels, so each meets §3.3 for its slot.
#[test]
fn the_wallets_own_labels_meet_section_3_3() {
    let subtypes = [
        Subtype::None,
        Subtype::Named("emandate"),
        Subtype::Named("agentic"),
        Subtype::Named("aisp"),
        Subtype::Named("other"),
    ];
    let rulebooks = [Rulebook::View, Rulebook::Payment]
        .into_iter()
        .chain(subtypes.iter().map(|sub| Rulebook::Generic(*sub)))
        .chain(subtypes.iter().map(|sub| Rulebook::Mandate(*sub)));
    let paso = CrateSource::of::<siros_paso::CrateModule>(ENGLISH_PASO, GERMAN_PASO);
    let app = App::of(&[CrateSource::openid4vp(), paso]).expect("the test app");
    for locale in ["en", "de"] {
        let env = Env::new(
            vec![LocaleTag::parse(locale).expect("a tag")],
            Vec::new(),
            OPTIONS,
            Vec::new(),
            Choice::First,
        )
        .expect("the configuration");
        let meets = |text: Text, slot: LabelSlot| {
            let shown = app.plain(&env, &text).expect("the text renders");
            assert!(
                LabelText::parse(&shown, slot).is_ok(),
                "{shown} in {locale}"
            );
        };
        for rulebook in rulebooks.clone() {
            meets(Text::of(&rulebook.title()), LabelSlot::Title);
            meets(Text::of(&rulebook.confirm()), LabelSlot::Affirmative);
            if let Some(section) = rulebook.section() {
                meets(Text::of(&section), LabelSlot::ClaimName);
            }
        }
        for label in MandateLabel::ALL {
            meets(Text::of(&label), LabelSlot::ClaimName);
        }
    }
}
