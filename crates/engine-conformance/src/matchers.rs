//! The expectation matchers: JSON members by presence and value, `*`
//! wildcards (bound by name for later steps), `re:` regular expressions
//! over URLs, and numbers by value (the runner contract's comparison
//! rules).
//!
//! Bindings: a `*` (or `prefix-*`) wildcard that matched is bound by its
//! JSON path within the expectation — a later expectation names the
//! binding as `"$<path>"` to assert the same value recurred.

use rustc_hash::FxHashMap;
use serde_json::Value;

/// The wildcard bindings a run has collected, by expectation path.
#[derive(Debug, Default)]
pub struct Bindings {
    bound: FxHashMap<String, Value>,
}

impl Bindings {
    /// Records a binding.
    pub fn bind(&mut self, path: &str, value: Value) {
        self.bound.insert(path.to_owned(), value);
    }

    /// A recorded binding.
    pub fn get(&self, path: &str) -> Option<&Value> {
        self.bound.get(path)
    }
}

/// Why an expectation did not match.
pub struct Mismatch {
    /// The expectation path that failed.
    pub path: String,
    /// What the expectation wanted.
    pub expected: Value,
    /// What the engine produced.
    pub actual: Value,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: expected {}, found {}",
            self.path, self.expected, self.actual
        )
    }
}

/// Matches an expectation against an actual value: every member the
/// expectation names must be present and equal, with the wildcard and
/// binding rules; members the expectation does not name are free (the
/// contract: "an object may carry more members than the expectation
/// names").
pub fn matches(expect: &Value, actual: &Value, bindings: &mut Bindings) -> Result<(), Mismatch> {
    match_expectation(expect, actual, bindings, "")
}

fn match_expectation(
    expect: &Value,
    actual: &Value,
    bindings: &mut Bindings,
    path: &str,
) -> Result<(), Mismatch> {
    // A binding reference: "$<path>" asserts the value the earlier
    // wildcard captured.
    if let Some(reference) = expect.as_str().and_then(|s| s.strip_prefix('$')) {
        if let Some(bound) = bindings.get(reference) {
            if bound == actual {
                return Ok(());
            }
            return Err(Mismatch {
                path: path.to_owned(),
                expected: expect.clone(),
                actual: actual.clone(),
            });
        }
        // Not a binding reference after all: fall through to the string
        // comparison (a literal "$..." is legitimate).
    }

    // The JWE header form: an expectation object of one member
    // `$jwe_header` matches a compact-serialization string by decoding
    // its first part and matching the header object — the only way to
    // assert what an engine encrypted (the ciphertext cannot be
    // predicted, and only the recipient can read it).
    let single = expect
        .as_object()
        .and_then(|o| o.iter().collect::<Vec<_>>().into_iter().next())
        .filter(|_| expect.as_object().is_some_and(|o| o.len() == 1));
    if let Some((name, header_expect)) = single {
        if name == "$jwe_header" {
            let Some(compact) = actual.as_str() else {
                return Err(Mismatch {
                    path: path.to_owned(),
                    expected: expect.clone(),
                    actual: actual.clone(),
                });
            };
            let first = compact.split('.').next().unwrap_or_default();
            let decoded = crate::world::decode_b64url(first);
            let header: Value = serde_json::from_slice(&decoded).unwrap_or(Value::Null);
            return match_expectation(
                header_expect,
                &header,
                bindings,
                &format!("{path}.jwe_header"),
            );
        }
    }

    match (expect, actual) {
        (Value::Object(expect_obj), Value::Object(actual_obj)) => {
            for (name, expected_member) in expect_obj {
                let member_path = format!("{path}.{name}");
                let Some(actual_member) = actual_obj.get(name) else {
                    return Err(Mismatch {
                        path: member_path,
                        expected: expected_member.clone(),
                        actual: Value::Null,
                    });
                };
                match_expectation(expected_member, actual_member, bindings, &member_path)?;
            }
            Ok(())
        }
        (Value::Array(expect_arr), Value::Array(actual_arr)) => {
            // Arrays compare element-wise in order; the expectation may
            // name fewer elements than the actual carries.
            for (index, expected_member) in expect_arr.iter().enumerate() {
                let member_path = format!("{path}[{index}]");
                match_expectation(
                    expected_member,
                    actual_arr.get(index).unwrap_or(&Value::Null),
                    bindings,
                    &member_path,
                )?;
            }
            Ok(())
        }
        (Value::String(expected), _) => match_wildcard(expected, actual, bindings, path),
        // Numbers compare by value: 1 and 1.0 are equal (serde_json's
        // Value equality already does this).
        _ => {
            if expect == actual {
                Ok(())
            } else {
                Err(Mismatch {
                    path: path.to_owned(),
                    expected: expect.clone(),
                    actual: actual.clone(),
                })
            }
        }
    }
}

/// The string rules: `*` matches anything (bound), `prefix-*` matches
/// and binds the suffixed part, anything else is exact equality.
fn match_wildcard(
    expected: &str,
    actual: &Value,
    bindings: &mut Bindings,
    path: &str,
) -> Result<(), Mismatch> {
    if expected == "*" {
        bindings.bind(path, actual.clone());
        return Ok(());
    }
    if let Some(prefix) = expected.strip_suffix('*') {
        if let Some(text) = actual.as_str() {
            if let Some(suffix) = text.strip_prefix(prefix) {
                bindings.bind(path, Value::String(suffix.to_owned()));
                return Ok(());
            }
        }
        return Err(Mismatch {
            path: path.to_owned(),
            expected: Value::String(expected.to_owned()),
            actual: actual.clone(),
        });
    }
    if Value::String(expected.to_owned()) == *actual {
        Ok(())
    } else {
        Err(Mismatch {
            path: path.to_owned(),
            expected: Value::String(expected.to_owned()),
            actual: actual.clone(),
        })
    }
}

/// Matches a URL expectation: exact, `*` wildcards, or a `re:` regular
/// expression over the whole URL.
pub fn match_url(
    expected: &str,
    actual: &str,
    bindings: &mut Bindings,
    path: &str,
) -> Result<(), Mismatch> {
    if let Some(pattern) = expected.strip_prefix("re:") {
        let matched = regex::Regex::new(pattern).map(|re| re.is_match(actual));
        if matched.unwrap_or(false) {
            return Ok(());
        }
        return Err(Mismatch {
            path: path.to_owned(),
            expected: Value::String(expected.to_owned()),
            actual: Value::String(actual.to_owned()),
        });
    }
    if expected == actual {
        return Ok(());
    }
    // Segment wildcards: https://*.example/x matches any single host.
    if expected.contains('*') {
        let re_pattern = format!("^{}$", regex::escape(expected).replace("\\*", "[^/]*"));
        let matched = regex::Regex::new(&re_pattern).map(|re| re.is_match(actual));
        if matched.unwrap_or(false) {
            bindings.bind(path, Value::String(actual.to_owned()));
            return Ok(());
        }
    }
    Err(Mismatch {
        path: path.to_owned(),
        expected: Value::String(expected.to_owned()),
        actual: Value::String(actual.to_owned()),
    })
}

/// Parses a form body into a JSON object: `a=1&b=2` to
/// `{"a":"1","b":"2"}`, with percent-decoding.
pub fn parse_form(body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    let mut object = serde_json::Map::new();
    for pair in text.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        object.insert(percent_decode(name), Value::String(percent_decode(value)));
    }
    Value::Object(object)
}

/// Minimal percent-decoding for form members.
fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            let byte = if c == '+' { b' ' } else { 0 };
            if c == '+' {
                out.push(byte);
            } else {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            continue;
        }
        let mut hex = String::with_capacity(2);
        for _ in 0..2 {
            if let Some(h) = chars.next() {
                hex.push(h);
            }
        }
        match u8::from_str_radix(&hex, 16) {
            Ok(byte) if hex.len() == 2 => out.push(byte),
            _ => {
                out.push(b'%');
                out.extend(hex.as_bytes());
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
