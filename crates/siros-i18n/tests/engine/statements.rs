//! A derived statement: its id under the crate's scope, its named fields its arguments under
//! their names, an absent `Option` the empty text, and a skipped field no argument.

use siros_i18n::{Bidi, Context};

/// The fixture's statements.
#[derive(siros_i18n::Message)]
enum Shown {
    #[message(id = "hello")]
    Hello,
    #[message(id = "asks")]
    Asks {
        name: String,
        r#for: Option<&'static str>,
        #[message(skip)]
        #[expect(
            dead_code,
            reason = "a skipped field is no argument, and nothing else reads it"
        )]
        index: usize,
    },
}

#[test]
fn a_statement_gives_its_named_fields() {
    let source = "@locale en\n---\n[fixture]\nhello = Hello\nasks = {$name} asks for {$for}.\n";
    let context = Context::new()
        .bidi(Bidi::None)
        .module(source)
        .expect("the module loads");
    let asks = |r#for| Shown::Asks {
        name: "Ada".to_owned(),
        r#for,
        index: 3,
    };
    let cases = [
        (Shown::Hello, "Hello"),
        (asks(Some("age")), "Ada asks for age."),
        (asks(None), "Ada asks for ."),
    ];
    for (shown, expected) in cases {
        assert_eq!(
            context.resolve(&shown).expect("a text").to_string(),
            expected
        );
    }
    let rows: Vec<_> = siros_i18n::check::rows()
        .filter(|row| row.id.starts_with("fixture."))
        .map(|row| (row.id, row.keys))
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&("fixture.hello", &[][..])));
    assert!(rows.contains(&("fixture.asks", &["name", "for"][..])));
}
