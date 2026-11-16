//! Selected items and `DeviceSigned` elements, and the `DeviceResponse` that carries them
//! (ISO/IEC 18013-5, 8.3.2.1.2.2).

use rustc_hash::FxHashSet;
use siros_codec::cbor::Value;

use crate::device::{device_signing_input, DeviceNameSpaces, DeviceSignedElement, PROTECTED_ES256};
use crate::error::DisclosureError;
use crate::mdoc::{IssuerNameSpace, IssuerSignedItem, Mdoc};
use siros_codec::signature::Es256Signature;

use crate::signature::{SessionTranscript, SigStructure};

/// A data element to look up: its namespace and its identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementId<'a> {
    /// The namespace.
    pub name_space: &'a str,
    /// The element identifier.
    pub identifier: &'a str,
}

/// The items one mdoc discloses and the `DeviceSigned` elements its device key signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure<'m> {
    mdoc: &'m Mdoc,
    name_spaces: Vec<(&'m IssuerNameSpace, Vec<&'m IssuerSignedItem>)>,
    device_name_spaces: DeviceNameSpaces,
}

impl Mdoc {
    /// The disclosure of the items `elements` names, and of `device_signed` in `DeviceSigned`.
    ///
    /// # Errors
    ///
    /// [`DisclosureError`]: an element that is no item or is named twice, or a `DeviceSigned`
    /// element the MSO's `KeyAuthorizations` do not authorize or that is given twice.
    pub fn disclose(
        &self,
        elements: &[ElementId<'_>],
        device_signed: Vec<DeviceSignedElement>,
    ) -> Result<Disclosure<'_>, DisclosureError> {
        let mut selected = FxHashSet::default();
        for element in elements {
            if !selected.insert(*element) {
                return Err(DisclosureError::RepeatedSelection);
            }
        }
        let name_spaces: Vec<(&IssuerNameSpace, Vec<&IssuerSignedItem>)> = self
            .name_spaces()
            .iter()
            .filter_map(|name_space| {
                let items: Vec<&IssuerSignedItem> = name_space
                    .items()
                    .iter()
                    .filter(|item| {
                        selected.contains(&ElementId {
                            name_space: name_space.name().as_str(),
                            identifier: item.identifier().as_str(),
                        })
                    })
                    .collect();
                (!items.is_empty()).then_some((name_space, items))
            })
            .collect();
        // Each element identifier occurs once per namespace: every selected element that is
        // an item is counted once.
        let disclosed: usize = name_spaces.iter().map(|(_, items)| items.len()).sum();
        if disclosed != selected.len() {
            return Err(DisclosureError::UnknownElement);
        }
        let device_name_spaces =
            DeviceNameSpaces::authorized(self.mso().key_authorizations(), device_signed)?;
        Ok(Disclosure {
            mdoc: self,
            name_spaces,
            device_name_spaces,
        })
    }
}

impl Disclosure<'_> {
    /// The data the device key signs with ES256 in the session of `session_transcript`.
    #[must_use]
    pub fn signing_input(&self, session_transcript: &SessionTranscript) -> SigStructure {
        device_signing_input(
            session_transcript,
            self.mdoc.doc_type(),
            &self.device_name_spaces,
        )
    }

    /// The encoded `DeviceResponse` of this document, with `signature`, the device key's ES256
    /// signature `r ‖ s` of the signing input.
    ///
    /// `issuerSigned` holds the selected items as issued, in the issuer's order, and
    /// `issuerAuth` as issued. `deviceSigned` holds the `DeviceSigned` elements and
    /// `deviceSignature`, a `COSE_Sign1` with the protected header `{1: -7}` and a detached
    /// payload.
    #[must_use]
    pub fn device_response(&self, signature: &Es256Signature) -> Vec<u8> {
        let text = Value::text;
        let mut issuer_signed = vec![(
            text("issuerAuth"),
            Value::Encoded(self.mdoc.issuer_auth().as_cbor().to_vec()),
        )];
        if !self.name_spaces.is_empty() {
            let name_spaces = self
                .name_spaces
                .iter()
                .map(|(name_space, items)| {
                    let items = items
                        .iter()
                        .map(|item| Value::Encoded(item.bytes().to_vec()))
                        .collect();
                    (text(name_space.name().as_str()), Value::Array(items))
                })
                .collect();
            issuer_signed.push((text("nameSpaces"), Value::Map(name_spaces)));
        }
        let device_signature = Value::Array(vec![
            Value::Bytes(PROTECTED_ES256.to_vec()),
            Value::Map(Vec::new()),
            Value::Null,
            Value::Bytes(signature.as_bytes().to_vec()),
        ]);
        let device_signed = Value::Map(vec![
            (
                text("nameSpaces"),
                Value::Encoded(self.device_name_spaces.as_cbor().to_vec()),
            ),
            (
                text("deviceAuth"),
                Value::Map(vec![(text("deviceSignature"), device_signature)]),
            ),
        ]);
        let document = Value::Map(vec![
            (text("docType"), text(self.mdoc.doc_type().as_str())),
            (text("issuerSigned"), Value::Map(issuer_signed)),
            (text("deviceSigned"), device_signed),
        ]);
        Value::Map(vec![
            (text("version"), text("1.0")),
            (text("documents"), Value::Array(vec![document])),
            (text("status"), Value::Unsigned(0)),
        ])
        .encode()
    }
}
