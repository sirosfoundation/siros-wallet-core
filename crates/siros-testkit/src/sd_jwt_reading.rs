//! A Verifier's reading of an SD-JWT presentation (RFC 9901 §7.2, §7.1), written apart from the
//! plug-in: the compact form split at `~`, `sd_hash` checked over the bytes as sent, the disclosures
//! processed into the claims. [`Read::shape`] gives the parts as one JSON object, so a test reads a
//! Key Binding JWT's claims by name. Only `sha-256` is read.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::json::{JsonError, Node};

/// Why a text is no SD-JWT presentation a Verifier takes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.read_sd_jwt")]
pub enum SdJwtReadError {
    /// A segment is no base64url of UTF-8 JSON, or a part is no compact JWS.
    #[error("a part of the compact form")]
    Compact,
    /// A JSON value is unreadable.
    #[error(transparent)]
    Json(#[from] JsonError),
    /// `sd_hash` is no hash of what precedes the Key Binding JWT (§7.3 step 4).
    #[error("sd_hash is no hash of the SD-JWT as sent")]
    SdHash,
    /// No digest of the payload or another disclosure references this disclosure (§7.1 step 5).
    #[error("disclosure {0} is unreferenced")]
    Unreferenced(#[explain(name = "disclosure")] String),
    /// The payload names an algorithm other than `sha-256`.
    #[error("an _sd_alg other than sha-256")]
    SdAlg,
}

/// A Key Binding JWT as sent.
#[derive(Debug, Clone)]
pub struct KeyBindingJwt {
    /// The decoded header.
    pub header: Node<'static>,
    /// The decoded payload.
    pub payload: Node<'static>,
    /// The signature's bytes.
    pub signature: Vec<u8>,
    /// What the signature covers: the header and payload segments, joined by `.`.
    pub signing_input: String,
}

/// A disclosure as sent.
#[derive(Debug, Clone, PartialEq)]
pub struct SentDisclosure {
    /// The base64url text.
    pub encoded: String,
    /// The salt.
    pub salt: String,
    /// The claim name; `None` for an array element.
    pub name: Option<String>,
    /// The value, as the disclosure holds it.
    pub value: Node<'static>,
}

/// A presentation as a Verifier reads it.
#[derive(Debug, Clone)]
pub struct Read {
    /// The Issuer-signed JWT.
    pub issuer_jwt: String,
    /// The text through the last `~`.
    pub sent: String,
    /// The Issuer-signed JWT's decoded header.
    pub header: Node<'static>,
    /// The Issuer-signed JWT's decoded payload.
    pub payload: Node<'static>,
    /// The disclosures, in the order sent.
    pub disclosures: Vec<SentDisclosure>,
    /// The Key Binding JWT.
    pub key_binding: Option<KeyBindingJwt>,
    /// The processed payload without `_sd_alg`; an array digest without a disclosure stays
    /// `{"...": digest}`.
    pub claims: Node<'static>,
}

impl Read {
    /// `{"sd_jwt", "kb_jwt": {"header", "payload", "signature"}}`: the signature as text, `kb_jwt`
    /// absent without a Key Binding JWT.
    ///
    /// # Errors
    ///
    /// The signature is no UTF-8 text.
    pub fn shape(&self) -> Result<Node<'static>, SdJwtReadError> {
        let mut members = vec![(
            Cow::Borrowed("sd_jwt"),
            Node::String(Cow::Owned(self.sent.clone())),
        )];
        if let Some(kb) = &self.key_binding {
            let signature =
                String::from_utf8(kb.signature.clone()).map_err(|_| SdJwtReadError::Compact)?;
            let parts = Node::object([
                (Cow::Borrowed("header"), kb.header.clone()),
                (Cow::Borrowed("payload"), kb.payload.clone()),
                (
                    Cow::Borrowed("signature"),
                    Node::String(Cow::Owned(signature)),
                ),
            ])?;
            members.push((Cow::Borrowed("kb_jwt"), parts));
        }
        Ok(Node::object(members)?)
    }
}

fn decoded(segment: &str) -> Result<Node<'static>, SdJwtReadError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| SdJwtReadError::Compact)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SdJwtReadError::Compact)?;
    Ok(Node::parse(text)?.into_owned())
}

fn hash(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(text))
}

/// The presentation `text`.
///
/// # Errors
///
/// [`SdJwtReadError`]: what a Verifier refuses.
pub fn read(text: &str) -> Result<Read, SdJwtReadError> {
    let (head, kb) = text.rsplit_once('~').ok_or(SdJwtReadError::Compact)?;
    let sent = format!("{head}~");
    let mut parts = head.split('~');
    let issuer_jwt = parts.next().ok_or(SdJwtReadError::Compact)?;
    let segments: Vec<&str> = issuer_jwt.split('.').collect();
    let [header, payload, _] = segments.as_slice() else {
        return Err(SdJwtReadError::Compact);
    };
    let (header, payload) = (decoded(header)?, decoded(payload)?);
    if payload
        .get("_sd_alg")
        .is_some_and(|alg| alg.as_str() != Some("sha-256"))
    {
        return Err(SdJwtReadError::SdAlg);
    }
    let disclosures = parts
        .filter(|part| !part.is_empty())
        .map(disclosure)
        .collect::<Result<Vec<_>, _>>()?;
    let key_binding = (!kb.is_empty())
        .then(|| key_binding(kb, &sent))
        .transpose()?;
    let mut pending: FxHashMap<String, &SentDisclosure> =
        disclosures.iter().map(|d| (hash(&d.encoded), d)).collect();
    let claims = processed(&payload, &mut pending)?;
    if let Some(left) = pending.values().next() {
        return Err(SdJwtReadError::Unreferenced(left.encoded.clone()));
    }
    Ok(Read {
        issuer_jwt: issuer_jwt.to_owned(),
        sent,
        header,
        payload,
        disclosures,
        key_binding,
        claims,
    })
}

fn disclosure(encoded: &str) -> Result<SentDisclosure, SdJwtReadError> {
    let array = decoded(encoded)?;
    let (salt, name, value) = match array.as_array().ok_or(SdJwtReadError::Compact)? {
        [salt, value] => (salt, None, value),
        [salt, name, value] => (
            salt,
            Some(name.as_str().ok_or(SdJwtReadError::Compact)?),
            value,
        ),
        _ => return Err(SdJwtReadError::Compact),
    };
    Ok(SentDisclosure {
        encoded: encoded.to_owned(),
        salt: salt.as_str().ok_or(SdJwtReadError::Compact)?.to_owned(),
        name: name.map(str::to_owned),
        value: value.clone(),
    })
}

fn key_binding(compact: &str, sent: &str) -> Result<KeyBindingJwt, SdJwtReadError> {
    let segments: Vec<&str> = compact.split('.').collect();
    let [header, payload, signature] = segments.as_slice() else {
        return Err(SdJwtReadError::Compact);
    };
    let signing_input = format!("{header}.{payload}");
    let (header, payload) = (decoded(header)?, decoded(payload)?);
    if payload.get("sd_hash").and_then(Node::as_str) != Some(hash(sent).as_str()) {
        return Err(SdJwtReadError::SdHash);
    }
    Ok(KeyBindingJwt {
        header,
        payload,
        signature: URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SdJwtReadError::Compact)?,
        signing_input,
    })
}

/// `node` with its digests replaced by what the disclosures of `pending` reveal.
fn processed(
    node: &Node<'_>,
    pending: &mut FxHashMap<String, &SentDisclosure>,
) -> Result<Node<'static>, SdJwtReadError> {
    match node {
        Node::Object(object) => {
            let mut members = Vec::new();
            for member in object.members() {
                match member.name.as_ref() {
                    "_sd_alg" => {}
                    "_sd" => {
                        for digest in member.value.as_array().unwrap_or(&[]) {
                            let found = digest.as_str().and_then(|digest| pending.remove(digest));
                            if let Some(disclosed) = found {
                                let name = disclosed.name.clone().ok_or(SdJwtReadError::Compact)?;
                                members.push((
                                    Cow::Owned(name),
                                    processed(&disclosed.value, pending)?,
                                ));
                            }
                        }
                    }
                    name => members.push((
                        Cow::Owned(name.to_owned()),
                        processed(&member.value, pending)?,
                    )),
                }
            }
            Ok(Node::object(members)?)
        }
        Node::Array(items) => Ok(Node::Array(
            items
                .iter()
                .map(|item| {
                    let digest = item.get("...").and_then(Node::as_str);
                    match digest.and_then(|digest| pending.remove(digest)) {
                        Some(disclosed) => processed(&disclosed.value, pending),
                        None if digest.is_some() => Ok(item.clone().into_owned()),
                        None => processed(item, pending),
                    }
                })
                .collect::<Result<_, _>>()?,
        )),
        scalar => Ok((*scalar).clone().into_owned()),
    }
}
