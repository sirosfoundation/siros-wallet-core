//! Label text against Proof Metadata §3.3.

use siros_paso::labels::{Directional, LabelLimits, LabelText, LabelViolation};

/// Proof Metadata §3.3 on single labels: the length in clusters, C0 and C1 controls, the
/// embeddings and overrides, an isolate left open; a closed isolate and white space alone pass.
#[test]
fn single_labels_meet_section_3_3_as_it_states() {
    let claim = LabelLimits::PASO.claim_name;
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
        Err(LabelViolation::Directional(
            Directional::UnterminatedIsolate
        ))
    ));
    assert!(LabelText::parse("a\u{2066}b\u{2069}", claim).is_ok());
    // §3.3 holds no rule on white space.
    assert!(LabelText::parse(" \u{3000}", claim).is_ok());
    assert_eq!(
        LabelText::parse(&"x".repeat(41), LabelLimits::PASO.affirmative),
        Err(LabelViolation::TooLong {
            clusters: 41,
            max: 40
        })
    );
    assert!(LabelText::parse(&"x".repeat(160), LabelLimits::PASO.hint).is_ok());
}
