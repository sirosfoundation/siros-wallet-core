//! The strict JSON reader reports the first fault in document order: a member name that repeats
//! one before it, or a fault of a value, whichever the document writes first.

use siros_codec::json::{Json, JsonFault, ReadFault};

#[test]
fn the_first_fault_in_document_order_is_reported() {
    let rows: [(&str, JsonFault); 2] = [
        (
            r#"{"a": 1, "a": 2, "b": 1e400}"#,
            JsonFault::RepeatedMember("a".to_owned()),
        ),
        (
            r#"{"a": 1e400, "b": 1, "b": 2}"#,
            JsonFault::Read(ReadFault::NumberUnrepresentable),
        ),
    ];
    for (text, fault) in rows {
        assert_eq!(Json::parse_unique(text.as_bytes()), Err(fault), "{text}");
    }
}
