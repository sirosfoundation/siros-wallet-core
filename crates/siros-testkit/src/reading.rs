//! A Verifier's reading of the port's mdoc presentation, projected into the reference model's
//! JSON shape (fmt_mdoc.py's `as_json`) in the model's member order, so each comparison of a
//! presentation stays a comparison of texts. A byte string becomes `{"bstr": hex}`, an embedded
//! item its content, IssuerSignedItems `{elementIdentifier: elementValue}`, a tagged
//! COSE_Encrypt the model's stand-in dict, and DeviceSignature or DeviceMac the stand-in's text.
//! IssuerAuth leaves the shape: the reading checks it apart.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::cose::coset::{
    self, AsCborValue, CoseEncrypt, CoseMac0, CoseSign1, Header, MacContext,
    RegisteredLabelWithPrivate, mac_structure_data,
};
use siros_openid4vp::cbor::{self, CborError, Value, embedded};
use siros_openid4vp::json::{JsonError, Node, Number};

use crate::cose::jose_names;
use crate::host::digest_prefix;

/// What the model's `Session.handover` held: the Origin, the nonce, the thumbprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelHandover {
    /// The Origin, without `origin:`.
    pub origin: String,
    /// The nonce.
    pub nonce: String,
    /// The response encryption key's thumbprint; `None` for `dc_api`.
    pub thumbprint: Option<[u8; 32]>,
}

/// Why a presentation is no DeviceResponse as the port writes one.
#[derive(Debug, thiserror::Error, Explain)]
pub enum ReadError {
    /// The presentation is no JSON string.
    #[error("a presentation that is no JSON string")]
    #[explain(id = "read.not_text")]
    NotText,
    /// The presentation's text is no base64url without padding.
    #[error("a presentation of no base64url")]
    #[explain(id = "read.base64")]
    Base64(#[source] base64::DecodeError),
    /// The CBOR is unreadable.
    #[error("the DeviceResponse's CBOR")]
    #[explain(id = "read.cbor")]
    Cbor(#[from] CborError),
    /// A projected object repeats a name.
    #[error("the projected JSON")]
    #[explain(id = "read.json")]
    Json(#[from] JsonError),
    /// Another shape than the port writes.
    #[error("{detail}")]
    #[explain(id = "read.shape")]
    Shape {
        /// What breaks the shape.
        detail: String,
    },
    /// coset's refusal.
    #[error("coset refuses a COSE structure")]
    #[explain(id = "read.cose")]
    Cose(#[from] coset::CoseError),
    /// The device authentication covers other bytes than the rebuilt DeviceAuthentication.
    #[error("deviceAuth {found} covers other bytes than {expected}")]
    #[explain(id = "read.uncovered")]
    Uncovered {
        /// The stand-in text over the rebuilt bytes.
        expected: String,
        /// The text the port wrote.
        found: String,
    },
}

fn shape(what: impl Into<String>) -> ReadError {
    ReadError::Shape {
        detail: what.into(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text(value: impl Into<String>) -> Node<'static> {
    Node::String(Cow::Owned(value.into()))
}

fn object(members: Vec<(&str, Node<'static>)>) -> Result<Node<'static>, ReadError> {
    Ok(Node::object(members.into_iter().map(|(name, value)| {
        (Cow::Owned(name.to_owned()), value)
    }))?)
}

/// B.2.6.2's SessionTranscript of the model's handover, written here apart from the core's so the
/// reading checks the port's.
///
/// # Errors
///
/// ciborium cannot write the handover information.
pub fn transcript(handover: &ModelHandover) -> Result<Value, CborError> {
    let info = Value::Array(vec![
        Value::Text(handover.origin.clone()),
        Value::Text(handover.nonce.clone()),
        handover
            .thumbprint
            .map_or(Value::Null, |key| Value::Bytes(key.to_vec())),
    ]);
    Ok(Value::Array(vec![
        Value::Null,
        Value::Null,
        Value::Array(vec![
            Value::Text("OpenID4VPDCAPIHandover".to_owned()),
            Value::Bytes(Sha256::digest(cbor::encode(&info)?).to_vec()),
        ]),
    ]))
}

fn members(value: Value, what: &str) -> Result<Vec<(String, Value)>, ReadError> {
    let Value::Map(pairs) = value else {
        return Err(shape(format!("{what} is no map")));
    };
    pairs
        .into_iter()
        .map(|(key, item)| match key {
            Value::Text(name) => Ok((name, item)),
            _ => Err(shape(format!("{what} has a key that is no text"))),
        })
        .collect()
}

fn take(pairs: &mut Vec<(String, Value)>, name: &str) -> Option<Value> {
    pairs
        .extract_if(.., |(key, _)| key == name)
        .next()
        .map(|(_, value)| value)
}

fn unembedded(value: Value, what: &str) -> Result<(Vec<u8>, Value), ReadError> {
    let Value::Tag(24, inner) = value else {
        return Err(shape(format!("{what} is no tag 24")));
    };
    let Value::Bytes(bytes) = *inner else {
        return Err(shape(format!("{what} holds no byte string")));
    };
    let item = cbor::decode(&bytes)?;
    Ok((bytes, item))
}

/// An element value in the model's shape, maps in their order.
///
/// # Errors
///
/// The value holds a double JSON cannot write, a map key that is no text, or a kind the model's
/// shape lacks.
pub fn model_value(value: &Value) -> Result<Node<'static>, ReadError> {
    Ok(match value {
        Value::Integer(integer) => Node::integer(i128::from(*integer)),
        Value::Float(float) => Node::Number(
            Number::of_double(*float).ok_or_else(|| shape("a double JSON cannot write"))?,
        ),
        Value::Text(value) => text(value.clone()),
        Value::Bool(value) => Node::Bool(*value),
        Value::Null => Node::Null,
        Value::Bytes(bytes) => object(vec![("bstr", text(hex(bytes)))])?,
        Value::Array(items) => {
            Node::Array(items.iter().map(model_value).collect::<Result<_, _>>()?)
        }
        Value::Map(pairs) => Node::object(
            pairs
                .iter()
                .map(|(key, item)| match key {
                    Value::Text(name) => Ok((Cow::Owned(name.clone()), model_value(item)?)),
                    _ => Err(shape("a map key that is no text")),
                })
                .collect::<Result<Vec<_>, ReadError>>()?,
        )?,
        Value::Tag(96, inner) => cose_encrypt_shape(inner)?,
        other => return Err(shape(format!("a value the model's shape lacks: {other:?}"))),
    })
}

fn algorithm(header: &Header) -> Option<i64> {
    match &header.alg {
        Some(RegisteredLabelWithPrivate::Assigned(alg)) => Some(alg.to_i64()),
        Some(RegisteredLabelWithPrivate::PrivateUse(alg)) => Some(*alg),
        _ => None,
    }
}

/// The model's stand-in `{"COSE_Encrypt": {"protected": {"alg", "enc", "kid"}, "ciphertext"}}`
/// of a COSE_Encrypt the testkit wrote.
fn cose_encrypt_shape(inner: &Value) -> Result<Node<'static>, ReadError> {
    let sealed = CoseEncrypt::from_cbor_value(inner.clone())?;
    let [recipient] = sealed.recipients.as_slice() else {
        return Err(shape("a COSE_Encrypt with other than one recipient"));
    };
    let (alg, enc) = algorithm(&recipient.protected.header)
        .zip(algorithm(&sealed.protected.header))
        .and_then(|(recipient, content)| jose_names(recipient, content))
        .ok_or_else(|| shape("a COSE_Encrypt of algorithms the stand-in does not write"))?;
    let kid = String::from_utf8(recipient.unprotected.key_id.clone())
        .map_err(|_| shape("a kid that is no UTF-8"))?;
    let ciphertext = sealed
        .ciphertext
        .ok_or_else(|| shape("a detached ciphertext"))?;
    let protected = object(vec![
        ("alg", text(alg)),
        ("enc", text(enc)),
        ("kid", text(kid)),
    ])?;
    let sealed = object(vec![
        ("protected", protected),
        (
            "ciphertext",
            object(vec![("bstr", text(hex(&ciphertext)))])?,
        ),
    ])?;
    object(vec![("COSE_Encrypt", sealed)])
}

/// What a reading checks the device authentication against: the model's handover, the
/// credential, and the device key's algorithm the view states.
#[derive(Debug, Clone, Copy)]
pub struct Rebuild<'r> {
    /// The model's handover.
    pub handover: &'r ModelHandover,
    /// The credential's id.
    pub credential: &'r str,
    /// The view's `device_alg`.
    pub device_alg: i64,
}

/// The port's presentation in the model's shape and member order. With `rebuild`,
/// DeviceAuthentication is rebuilt from the model's handover, the docType and the
/// DeviceNameSpacesBytes as received; the stand-in's digest must cover it, and becomes `covered`.
///
/// # Errors
///
/// The presentation is no DeviceResponse as the port writes one, or its device authentication
/// covers other bytes than the rebuild.
pub fn model_shape(
    presentation: &Node<'_>,
    rebuild: Option<Rebuild<'_>>,
) -> Result<Node<'static>, ReadError> {
    let encoded = presentation.as_str().ok_or(ReadError::NotText)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(ReadError::Base64)?;
    let mut response = members(cbor::decode(&bytes)?, "the DeviceResponse")?;
    let version = take(&mut response, "version").ok_or_else(|| shape("no version"))?;
    let status = take(&mut response, "status").ok_or_else(|| shape("no status"))?;
    let Some(Value::Array(documents)) = take(&mut response, "documents") else {
        return Err(shape("no documents"));
    };
    if !response.is_empty() {
        return Err(shape("a DeviceResponse member the port does not write"));
    }
    let [document] =
        <[Value; 1]>::try_from(documents).map_err(|_| shape("other than one document"))?;
    let mut document = members(document, "the Document")?;
    let Some(Value::Text(doctype)) = take(&mut document, "docType") else {
        return Err(shape("no docType"));
    };
    let issuer_signed =
        take(&mut document, "issuerSigned").ok_or_else(|| shape("no issuerSigned"))?;
    let mut issuer_signed = members(issuer_signed, "issuerSigned")?;
    let device_signed =
        take(&mut document, "deviceSigned").ok_or_else(|| shape("no deviceSigned"))?;
    let mut device_signed = members(device_signed, "deviceSigned")?;
    if !document.is_empty() {
        return Err(shape("a Document member the port does not write"));
    }
    // IssuerSigned: the items as {elementIdentifier: elementValue}; IssuerAuth a COSE_Sign1.
    let mut issuer = Vec::new();
    if let Some(spaces) = take(&mut issuer_signed, "nameSpaces") {
        for (namespace, items) in members(spaces, "IssuerNameSpaces")? {
            let Value::Array(items) = items else {
                return Err(shape("IssuerSignedItems that are no array"));
            };
            let mut elements = Vec::new();
            for tagged in items {
                let (_, item) = unembedded(tagged, "an IssuerSignedItemBytes")?;
                let mut item = members(item, "an IssuerSignedItem")?;
                let Some(Value::Text(identifier)) = take(&mut item, "elementIdentifier") else {
                    return Err(shape("an item without elementIdentifier"));
                };
                let value = take(&mut item, "elementValue")
                    .ok_or_else(|| shape("an item without elementValue"))?;
                elements.push((Cow::Owned(identifier), model_value(&value)?));
            }
            issuer.push((Cow::Owned(namespace), Node::object(elements)?));
        }
    }
    let issuer_auth =
        take(&mut issuer_signed, "issuerAuth").ok_or_else(|| shape("no issuerAuth"))?;
    if CoseSign1::from_cbor_value(issuer_auth)?.payload.is_none() {
        return Err(shape("an IssuerAuth without its MobileSecurityObjectBytes"));
    }
    if !issuer_signed.is_empty() {
        return Err(shape("an IssuerSigned member the port does not write"));
    }
    // DeviceSigned: the name spaces as received, then the authentication over them.
    let device_spaces =
        take(&mut device_signed, "nameSpaces").ok_or_else(|| shape("no device nameSpaces"))?;
    let (namespace_bytes, namespaces) = unembedded(device_spaces, "DeviceNameSpacesBytes")?;
    let device = model_value(&namespaces)?;
    let auth = take(&mut device_signed, "deviceAuth").ok_or_else(|| shape("no deviceAuth"))?;
    let auth = members(auth, "deviceAuth")?;
    if !device_signed.is_empty() {
        return Err(shape("a DeviceSigned member the port does not write"));
    }
    let [(mode, structure)] = <[(String, Value); 1]>::try_from(auth)
        .map_err(|_| shape("other than one device authentication"))?;
    let detached = |handover: &ModelHandover| -> Result<Vec<u8>, ReadError> {
        let authentication = Value::Array(vec![
            Value::Text("DeviceAuthentication".to_owned()),
            transcript(handover)?,
            Value::Text(doctype.clone()),
            embedded(namespace_bytes.clone()),
        ]);
        Ok(cbor::encode(&embedded(cbor::encode(&authentication)?))?)
    };
    let proof = match mode.as_str() {
        "deviceSignature" => {
            let signed = CoseSign1::from_cbor_value(structure)?;
            if signed.payload.is_some() || signed.unprotected != Header::default() {
                return Err(shape(
                    "a DeviceSignature with a payload or an unprotected header",
                ));
            }
            let found = String::from_utf8(signed.signature.clone())
                .map_err(|_| shape("a signature that is no stand-in text"))?;
            match rebuild {
                None => found,
                Some(rebuild) => {
                    if algorithm(&signed.protected.header) != Some(rebuild.device_alg) {
                        return Err(shape(
                            "a DeviceSignature of another alg than the device key's",
                        ));
                    }
                    let to_be_signed = signed.tbs_detached_data(&detached(rebuild.handover)?, b"");
                    let expected = format!(
                        "sig:{}:{}",
                        rebuild.credential,
                        digest_prefix(&to_be_signed)
                    );
                    if found != expected {
                        return Err(ReadError::Uncovered { expected, found });
                    }
                    format!("sig:{}:covered", rebuild.credential)
                }
            }
        }
        "deviceMac" => {
            let maced = CoseMac0::from_cbor_value(structure)?;
            if maced.payload.is_some()
                || maced.unprotected != Header::default()
                || algorithm(&maced.protected.header)
                    != Some(iana::Algorithm::HMAC_256_256.to_i64())
            {
                return Err(shape(
                    "a DeviceMac with a payload, an unprotected header, or another alg",
                ));
            }
            let found = String::from_utf8(maced.tag.clone())
                .map_err(|_| shape("a tag that is no stand-in text"))?;
            match rebuild {
                None => found,
                Some(rebuild) => {
                    let kid = found
                        .split(':')
                        .nth(2)
                        .ok_or_else(|| shape("a MAC stand-in without a kid"))?
                        .to_owned();
                    let salt =
                        cbor::encode(&embedded(cbor::encode(&transcript(rebuild.handover)?)?))?;
                    let to_be_maced = mac_structure_data(
                        MacContext::CoseMac0,
                        maced.protected.clone(),
                        b"",
                        &detached(rebuild.handover)?,
                    );
                    let expected = format!(
                        "mac:{}:{kid}:{}",
                        rebuild.credential,
                        digest_prefix(&[salt, to_be_maced].concat())
                    );
                    if found != expected {
                        return Err(ReadError::Uncovered { expected, found });
                    }
                    format!("mac:{}:{kid}:covered", rebuild.credential)
                }
            }
        }
        other => return Err(shape(format!("a device authentication {other}"))),
    };
    let device_signed = object(vec![
        ("nameSpaces", device),
        ("deviceAuth", object(vec![(mode.as_str(), text(proof))])?),
    ])?;
    let document = object(vec![
        ("docType", text(doctype)),
        (
            "issuerSigned",
            object(vec![("nameSpaces", Node::object(issuer)?)])?,
        ),
        ("deviceSigned", device_signed),
    ])?;
    object(vec![
        ("version", model_value(&version)?),
        ("status", model_value(&status)?),
        ("documents", Node::Array(vec![document])),
    ])
}

/// The model's presentation with its device authentication's digest replaced by `covered`: the
/// model's digest covers Python's `repr`, the port's the CBOR, so the two compare by what each
/// covers.
///
/// # Errors
///
/// The model's device authentication is no stand-in text ending in 16 hexadecimal digits.
pub fn covered(model: &Node<'_>) -> Result<Node<'static>, ReadError> {
    let proof = |value: &Node<'_>| -> Result<Node<'static>, ReadError> {
        let written = value
            .as_str()
            .ok_or_else(|| shape("a model proof that is no text"))?;
        let (head, digest) = written
            .rsplit_once(':')
            .ok_or_else(|| shape("a model proof without a digest"))?;
        if digest.len() != 16 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(shape(
                "a model proof whose digest is no 16 hexadecimal digits",
            ));
        }
        Ok(text(format!("{head}:covered")))
    };
    rewrite(
        model,
        &["documents", "0", "deviceSigned", "deviceAuth", "*"],
        &proof,
    )
}

/// The value with the nodes at a path (`*` any member, a number an array index) rewritten.
fn rewrite(
    node: &Node<'_>,
    path: &[&str],
    f: &dyn Fn(&Node<'_>) -> Result<Node<'static>, ReadError>,
) -> Result<Node<'static>, ReadError> {
    let Some((step, rest)) = path.split_first() else {
        return f(node);
    };
    Ok(match node {
        Node::Object(members) => Node::object(
            members
                .members()
                .iter()
                .map(|member| {
                    let value = if *step == "*" || member.name == *step {
                        rewrite(&member.value, rest, f)?
                    } else {
                        member.value.clone().into_owned()
                    };
                    Ok((Cow::Owned(member.name.to_string()), value))
                })
                .collect::<Result<Vec<_>, ReadError>>()?,
        )?,
        Node::Array(items) => Node::Array(
            items
                .iter()
                .enumerate()
                .map(|(k, item)| {
                    if *step == "*" || step.parse() == Ok(k) {
                        rewrite(item, rest, f)
                    } else {
                        Ok(item.clone().into_owned())
                    }
                })
                .collect::<Result<_, _>>()?,
        ),
        _ => return Err(shape(format!("no {step} to rewrite"))),
    })
}
