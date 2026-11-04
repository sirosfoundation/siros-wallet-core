//! The data the device key signs (ISO/IEC 18013-5, 9.1.3).

use siros_openid4vp::cbor::{self, CborError, Value};

use super::names::DocType;
use super::signature::{SessionTranscript, SigStructure};

/// The protected header of an ES256 `COSE_Sign1`: `{1: -7}`.
pub(crate) const PROTECTED_ES256: [u8; 3] = [0xa1, 0x01, 0x26];

/// `DeviceNameSpacesBytes = #6.24(bstr .cbor {* NameSpace => {+ DataElementIdentifier =>
/// DataElementValue}})`, encoded once for the signing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNameSpaces {
    encoded: Vec<u8>,
}

impl DeviceNameSpaces {
    /// No element: `#6.24(bstr .cbor {})`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            encoded: vec![0xd8, 0x18, 0x41, 0xa0],
        }
    }

    /// The encoding.
    pub(crate) fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }
}

/// The `Sig_structure` the device key signs for `DeviceAuthentication` (ISO/IEC 18013-5,
/// 9.1.3.4): `["Signature1", {1: -7}, h'', #6.24(bstr .cbor ["DeviceAuthentication",
/// SessionTranscript, DocType, DeviceNameSpacesBytes])]`.
///
/// # Errors
///
/// ciborium cannot write a text or a byte string.
pub fn device_signing_input(
    session_transcript: &SessionTranscript,
    doc_type: &DocType,
    name_spaces: &DeviceNameSpaces,
) -> Result<SigStructure, CborError> {
    let mut authentication = vec![0x84];
    authentication.extend(cbor::encode_deterministic(&Value::Text(
        "DeviceAuthentication".to_owned(),
    ))?);
    authentication.extend_from_slice(session_transcript.as_bytes());
    authentication.extend(cbor::encode_deterministic(&Value::Text(
        doc_type.as_str().to_owned(),
    ))?);
    authentication.extend_from_slice(name_spaces.as_cbor());
    let bytes = cbor::encode_deterministic(&cbor::embedded(authentication))?;
    cbor::encode_deterministic(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(PROTECTED_ES256.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(bytes),
    ]))
    .map(SigStructure::new)
}
