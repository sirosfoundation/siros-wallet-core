//! The consent screen's purpose line, as one table (OpenID4VP 1.0, Section 6.2 `purpose`).

use serde_json::{json, Value};
use siros_display::purpose;

#[test]
fn the_line_joins_the_string_purposes_and_is_absent_without_one() {
    // (case, purposes, line); a blank line made Pixel show a warning triangle (v0.6.1).
    let table: [(&str, Vec<Value>, Option<&str>); 4] = [
        ("blank", vec![json!("   ")], None),
        ("an object", vec![json!({"id": 7})], None),
        (
            "a text",
            vec![json!("Age verification")],
            Some("Age verification"),
        ),
        (
            "two texts, trimmed",
            vec![json!(" Age verification "), json!("Account opening")],
            Some("Age verification · Account opening"),
        ),
    ];
    for (case, purposes, line) in table {
        assert_eq!(purpose::line(&purposes).as_deref(), line, "{case}");
    }
}
