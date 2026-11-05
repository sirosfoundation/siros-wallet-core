//! Transaction data validation: the base64url array, the type allow-list,
//! and the JSON null rejection — per the P0.6-verified behaviour.

use super::types::{TransactionData, TransactionDataError, KNOWN_TRANSACTION_DATA_TYPES};

/// Validates the `transaction_data` entries against the DCQL query.
///
/// The P0.6-verified behaviour:
/// - JSON `null` is a type error (the fail-closed rule), not an absent
///   value.
/// - Each entry is a base64url-encoded JSON object with a `type` and
///   `credential_ids`.
/// - The `credential_ids` must reference credentials in the DCQL query.
/// - The type must be in the allow-list; an unsupported entry is refused
///   with the allow-listed `UNSUPPORTED_TRANSACTION_DATA` code.
/// - The engine checks structure only — type support is the client's
///   judgement (the P0.6 nuance).
pub fn validate_transaction_data(
    raw: &[String],
    dcql_query: &Option<serde_json::Value>,
) -> Result<Vec<TransactionData>, TransactionDataError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::with_capacity(raw.len());
    for (index, encoded) in raw.iter().enumerate() {
        // Decode the base64url.
        let decoded =
            decode_base64url(encoded).ok_or(TransactionDataError::InvalidEncoding { index })?;

        // Parse the JSON.
        let value: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|_| TransactionDataError::InvalidJson { index })?;

        // Extract the type.
        let ty = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        if ty.is_empty() {
            return Err(TransactionDataError::InvalidJson { index });
        }

        // Check the type against the allow-list.
        if !KNOWN_TRANSACTION_DATA_TYPES.contains(&ty.as_str()) {
            return Err(TransactionDataError::UnsupportedType { index, ty });
        }

        // Extract the credential_ids.
        let credential_ids: Vec<String> = value
            .get("credential_ids")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        // Check the credential_ids against the DCQL query's credentials.
        if let Some(query) = dcql_query {
            if let Some(credentials) = query.get("credentials").and_then(|v| v.as_array()) {
                let known: Vec<String> = credentials
                    .iter()
                    .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(str::to_owned))
                    .collect();
                for id in &credential_ids {
                    if !known.contains(id) {
                        return Err(TransactionDataError::InvalidJson { index });
                    }
                }
            }
        }

        let payload = value.get("payload").cloned();
        entries.push(TransactionData {
            transaction_type: ty,
            credential_ids,
            payload,
        });
    }

    Ok(entries)
}

/// Validates the raw JSON (before parsing) to reject `null`.
pub fn reject_null(raw: &serde_json::Value) -> Result<(), TransactionDataError> {
    if raw.is_null() {
        return Err(TransactionDataError::Null);
    }
    Ok(())
}

/// Minimal base64url decoding.
fn decode_base64url(encoded: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let v = value(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}
