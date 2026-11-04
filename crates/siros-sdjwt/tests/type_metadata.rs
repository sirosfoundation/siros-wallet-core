//! SD-JWT VC Type Metadata that extends another type (§5.4, §7.2, §8.5) against the draft's own
//! example: `data/figure-19-*`, `figure-20-*` and `figure-21-*` are Figures 19 to 21 of
//! draft-ietf-oauth-sd-jwt-vc-14, as the reference model reads them (page furniture removed).

use siros_openid4vp::json::Node;
use siros_sdjwt::type_metadata::{ExtendError, extend};

fn json(text: &str) -> Node<'_> {
    Node::parse(text).expect("json")
}

#[test]
fn the_effective_metadata_follows_section_7_2_and_8_5() {
    let base = json(include_str!("data/figure-19-base-type-metadata.json"));
    let child = json(include_str!("data/figure-20-child-type-metadata.json"));
    let effective = json(include_str!("data/figure-21-effective-claim-metadata.json"));
    // §8.5.2: the child's effective claim metadata is Figure 21.
    let extended = extend(&base, &child).expect("extended");
    assert_eq!(extended.get("claims"), effective.get("claims"));
    // The child's members stay, `extends` goes.
    assert_eq!(extended.get("vct"), child.get("vct"));
    assert_eq!(extended.get("extends"), None);
    // §7.2: a child without display keeps its parent's; one with display replaces it.
    let parent = json(r#"{"vct": "p", "display": [{"locale": "en", "name": "P"}]}"#);
    let display = |child: &'static str| {
        extend(&parent, &json(child))
            .expect("extended")
            .get("display")
            .cloned()
    };
    assert_eq!(display(r#"{"vct": "c"}"#), parent.get("display").cloned());
    assert_eq!(
        display(r#"{"vct": "c", "display": [{"locale": "en", "name": "C"}]}"#),
        Some(json(r#"[{"locale": "en", "name": "C"}]"#))
    );
}

#[test]
fn a_child_tightens_sd_and_mandatory_and_loosens_neither() {
    let base = r#"{"vct": "p", "claims": [
        {"path": ["always"], "sd": "always"}, {"path": ["never"], "sd": "never"},
        {"path": ["allowed"], "sd": "allowed"}, {"path": ["plain"]},
        {"path": ["required"], "mandatory": true}, {"path": ["optional"], "mandatory": false}]}"#;
    let base = json(base);
    let cases: [(&str, Result<(), ExtendError>); 9] = [
        // §8.5.1: allowed or absent may become always or never; optional may become mandatory.
        (r#"{"path": ["allowed"], "sd": "never"}"#, Ok(())),
        (r#"{"path": ["plain"], "sd": "always"}"#, Ok(())),
        (r#"{"path": ["optional"], "mandatory": true}"#, Ok(())),
        (r#"{"path": ["always"], "sd": "always"}"#, Ok(())),
        (r#"{"path": ["required"], "mandatory": true}"#, Ok(())),
        // always and never stay; mandatory stays.
        (
            r#"{"path": ["always"], "sd": "allowed"}"#,
            Err(ExtendError::Sd {
                path: r#"["always"]"#.to_owned(),
                base: "always".to_owned(),
            }),
        ),
        (
            r#"{"path": ["never"], "sd": "always"}"#,
            Err(ExtendError::Sd {
                path: r#"["never"]"#.to_owned(),
                base: "never".to_owned(),
            }),
        ),
        (
            r#"{"path": ["required"], "mandatory": false}"#,
            Err(ExtendError::Mandatory {
                path: r#"["required"]"#.to_owned(),
            }),
        ),
        // A claim without a path cannot be matched to the extended type's.
        (r#"{"sd": "always"}"#, Err(ExtendError::Shape)),
    ];
    for (claim, want) in cases {
        let child = format!(r#"{{"vct": "c", "claims": [{claim}]}}"#);
        assert_eq!(extend(&base, &json(&child)).map(drop), want, "{claim}");
    }
    assert_eq!(
        extend(&json("[]"), &base).map(drop),
        Err(ExtendError::Shape),
        "a document is an object"
    );
}
