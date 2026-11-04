//! What the device signs and authenticates (ISO/IEC 18013-5 §8.3.2.1.2.2, §9.1.3.4):
//! DeviceNameSpacesBytes and DeviceAuthenticationBytes.

use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError, Item, Value, embedded};
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::plugins::MemberValue;
use crate::transcript::SessionTranscript;

/// A device-signed data element: its identifier and its value.
pub(crate) struct Element<'a> {
    /// The data element identifier.
    pub(crate) name: &'a str,
    /// The value.
    pub(crate) value: ElementValue<'a>,
}

/// A data element's value as a CBOR data item.
pub(crate) enum ElementValue<'a> {
    /// A text string.
    Text(&'a str),
    /// A byte string.
    Bytes(&'a [u8]),
    /// A JSON value, converted by RFC 8949 §6.2.
    Json(Node<'static>),
    /// A CBOR data item as a profile or a host module encoded it.
    Cbor(Value),
}

/// Why a member's value is no data element value.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "mdoc.value")]
pub(crate) enum ValueError {
    /// The JSON text does not parse.
    #[error("a JSON member")]
    Json(#[source] #[explain(name = "cause")] JsonError),
    /// The CBOR item does not decode.
    #[error("a CBOR member")]
    Cbor(#[source] #[explain(name = "cause")] CborError),
}

impl<'a> ElementValue<'a> {
    /// The value of a member.
    pub(crate) fn of(value: &'a MemberValue) -> Result<Self, ValueError> {
        Ok(match value {
            MemberValue::Text(text) => Self::Text(text),
            MemberValue::Bytes(bytes) => Self::Bytes(bytes),
            MemberValue::Json(json) => {
                Self::Json(Node::parse(json.as_str()).map_err(ValueError::Json)?.into_owned())
            }
            MemberValue::Cbor(item) => {
                Self::Cbor(cbor::decode(item.as_bytes()).map_err(ValueError::Cbor)?)
            }
        })
    }

    /// The data item.
    fn item(&self) -> Result<Value, CborError> {
        Ok(match self {
            Self::Text(text) => Value::Text((*text).to_owned()),
            Self::Bytes(bytes) => Value::Bytes(bytes.to_vec()),
            Self::Json(node) => cbor::of_json(node)?,
            Self::Cbor(item) => item.clone(),
        })
    }
}

/// DeviceNameSpacesBytes: `#6.24(bstr .cbor DeviceNameSpaces)`, its bytes kept as written so the
/// Verifier rebuilds DeviceAuthentication over them.
pub(crate) struct DeviceNameSpacesBytes(Item);

impl DeviceNameSpacesBytes {
    /// `{ * NameSpace => { + DataElementIdentifier => DataElementValue } }`, each name space with
    /// its elements in the order given; refused when a name space, an element or a key at any
    /// depth comes twice, which `Item::parse` of the encoding finds.
    pub(crate) fn of(namespaces: &[(&str, Vec<Element<'_>>)]) -> Result<Self, CborError> {
        let map = namespaces
            .iter()
            .map(|(namespace, elements)| {
                let items = elements
                    .iter()
                    .map(|element| Ok((Value::Text(element.name.to_owned()), element.value.item()?)))
                    .collect::<Result<Vec<_>, CborError>>()?;
                Ok((Value::Text((*namespace).to_owned()), Value::Map(items)))
            })
            .collect::<Result<Vec<_>, CborError>>()?;
        Item::parse(cbor::encode(&Value::Map(map))?).map(Self)
    }

    /// The tagged byte string DeviceSigned and DeviceAuthentication hold.
    pub(crate) fn tagged(&self) -> Value {
        embedded(self.0.as_bytes().to_vec())
    }
}

/// DeviceAuthenticationBytes: `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
/// DocType, DeviceNameSpacesBytes])`, the detached payload of DeviceSignature and DeviceMac.
pub(crate) fn device_authentication_bytes(
    transcript: &SessionTranscript,
    doctype: &str,
    namespaces: &DeviceNameSpacesBytes,
) -> Result<Vec<u8>, CborError> {
    // A four-item array (RFC 8949 §3.1, major type 4) holding the transcript's own encoding.
    let mut authentication = vec![0x84];
    authentication.extend(cbor::encode(&Value::Text("DeviceAuthentication".to_owned()))?);
    authentication.extend_from_slice(transcript.as_bytes());
    authentication.extend(cbor::encode(&Value::Text(doctype.to_owned()))?);
    authentication.extend(cbor::encode(&namespaces.tagged())?);
    cbor::encode(&embedded(authentication))
}
