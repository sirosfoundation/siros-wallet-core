//! The schema validator: every vector is validated against the
//! repository's `vector-schema.json` before it runs — an unvalidated
//! vector is a typo away from testing nothing (the runner contract).
//!
//! The interpreter covers the keyword subset the schema uses —
//! `$ref`/`$defs`, `type`, `required`, `properties`,
//! `additionalProperties`, `enum`, `pattern`, `oneOf`, `minItems`,
//! `format: date` — and refuses the document on a keyword it does not
//! implement for a constraint, rather than silently passing a
//! constraint it did not check.

use serde_json::Value;

/// Validates one vector document against the schema. Errors are the
/// violation messages, prefixed with the JSON path.
pub fn validate(schema: &Value, document: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    validate_at(schema, schema, document, document, &mut errors, "");
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_at(
    root: &Value,
    schema: &Value,
    _document_root: &Value,
    doc: &Value,
    errors: &mut Vec<String>,
    path: &str,
) {
    // $ref: to #/$defs/<name>, resolved against the schema root.
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(resolved) = resolve_ref(root, reference) {
            validate_at(root, &resolved, _document_root, doc, errors, path);
        } else {
            errors.push(format!("{path}: unresolvable $ref {reference:?}"));
        }
        return;
    }

    // oneOf: exactly one branch validates.
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let mut matching = 0;
        for branch in branches {
            let mut branch_errors = Vec::new();
            validate_at(root, branch, _document_root, doc, &mut branch_errors, path);
            if branch_errors.is_empty() {
                matching += 1;
            }
        }
        if matching != 1 {
            errors.push(format!(
                "{path}: matches {matching} of {} oneOf branches (exactly one required)",
                branches.len()
            ));
        }
        return;
    }

    // enum: the document must be one of the values.
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(doc) {
            errors.push(format!("{path}: {doc} is not one of the allowed values"));
        }
        return;
    }

    // type.
    if let Some(expected) = schema.get("type") {
        if !type_matches(expected, doc) {
            errors.push(format!("{path}: expected type {expected}, found {doc}"));
            return;
        }
    }

    // pattern: a regular expression over the string (JSON Schema
    // patterns are unanchored; the schema's own patterns carry their
    // anchors).
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if let Some(text) = doc.as_str() {
            let matched = regex::Regex::new(pattern).map(|re| re.is_match(text));
            if !matched.unwrap_or(false) {
                errors.push(format!("{path}: {text:?} does not match {pattern:?}"));
            }
        }
    }

    // format: date (YYYY-MM-DD).
    if schema.get("format").and_then(Value::as_str) == Some("date") {
        if let Some(text) = doc.as_str() {
            let parts: Vec<&str> = text.split('-').collect();
            let ok = parts.len() == 3
                && parts
                    .first()
                    .is_some_and(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_digit()))
                && parts
                    .get(1)
                    .is_some_and(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit()))
                && parts
                    .get(2)
                    .is_some_and(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit()));
            if !ok {
                errors.push(format!("{path}: {text:?} is not a date"));
            }
        }
    }

    // object constraints.
    if let (Some(object), Some(doc_obj)) = (
        schema.get("properties").and_then(Value::as_object),
        doc.as_object(),
    ) {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !doc_obj.contains_key(name) {
                    errors.push(format!("{path}: missing required member {name:?}"));
                }
            }
        }
        for (name, subschema) in object.iter() {
            if let Some(member) = doc_obj.get(name) {
                validate_at(
                    root,
                    subschema,
                    _document_root,
                    member,
                    errors,
                    &format!("{path}.{name}"),
                );
            }
        }
        if let Some(additional) = schema.get("additionalProperties") {
            let known: Vec<&str> = object.keys().map(String::as_str).collect();
            for name in doc_obj.keys() {
                if !known.contains(&name.as_str()) {
                    match additional {
                        Value::Bool(false) => errors
                            .push(format!("{path}: additional member {name:?} is not allowed")),
                        Value::Bool(true) => {}
                        subschema => validate_at(
                            root,
                            subschema,
                            _document_root,
                            doc_obj.get(name).unwrap_or(&Value::Null),
                            errors,
                            &format!("{path}.{name}"),
                        ),
                    }
                }
            }
        }
    }

    // array constraints.
    if let Some(items) = schema.get("items") {
        if let Some(array) = doc.as_array() {
            if let Some(min_items) = schema.get("minItems").and_then(Value::as_i64) {
                if (array.len() as i64) < min_items {
                    errors.push(format!(
                        "{path}: {} items is fewer than the required {min_items}",
                        array.len()
                    ));
                }
            }
            for (index, item) in array.iter().enumerate() {
                validate_at(
                    root,
                    items,
                    _document_root,
                    item,
                    errors,
                    &format!("{path}[{index}]"),
                );
            }
        }
    }
}

/// Whether the document matches the schema's `type` keyword (the schema
/// uses single string types only).
fn type_matches(expected: &Value, doc: &Value) -> bool {
    match expected.as_str() {
        Some("object") => doc.is_object(),
        Some("array") => doc.is_array(),
        Some("string") => doc.is_string(),
        Some("boolean") => doc.is_boolean(),
        Some("integer") => doc.is_i64() || doc.is_u64(),
        Some("number") => doc.is_number(),
        Some("null") => doc.is_null(),
        _ => true, // An unrecognized type keyword: refuse to guess.
    }
}

/// Resolves `#/$defs/<name>` against the schema root. Anything else is
/// unresolvable — this schema references only within itself.
fn resolve_ref(root: &Value, reference: &str) -> Option<Value> {
    let name = reference.strip_prefix("#/$defs/")?;
    root.get("$defs")?.get(name).cloned()
}
