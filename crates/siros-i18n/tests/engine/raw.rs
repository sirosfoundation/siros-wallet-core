//! `Raw` is the last resort. A raw text is shown as written.

use siros_explain::Text;
use siros_i18n::Bidi;

use crate::{BODY, Host, formats, load, package, renderer, source};

#[test]
fn a_raw_text_is_shown_as_written() {
    let module = load(&[&source("en", BODY)]).expect("a module");
    let formats = formats();
    let built = package(&[&module]);
    let renderer = renderer(&built, &[&module], &["en"], &formats, Bidi::Default);
    // MF2 syntax, a backslash, a bidi isolate and a text outside NFC: none of them is read.
    let written = "{$x} \\ {#strong}|\u{2068}D\u{323}\u{307}";
    let alone = renderer
        .formatted(&Text::Raw(written.to_owned()))
        .expect("a text");
    assert_eq!(alone.spans().len(), 1);
    assert_eq!(
        (alone.spans()[0].text(), alone.spans()[0].styles()),
        (written, &[][..])
    );
    let argument = renderer
        .plain(&Text::of(&Host::Asks {
            name: written.to_owned(),
        }))
        .expect("a text");
    assert_eq!(argument, format!("\u{2068}{written}\u{2069} asks"));
}
