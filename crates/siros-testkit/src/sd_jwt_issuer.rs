//! The SD-JWT issuer stand-in (RFC 9901 §4): the compact SD-JWT of a credential view the reference
//! model wrote, which a registration holds as its `dc+sd-jwt` document. Every object member and
//! array element of `values` is selectively disclosable, recursively (§6.3); `vct`, `iss`, `nbf`,
//! `exp` and `cnf` are permanent (SD-JWT VC §3.2.2).

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_openid4vp::json::Node;

use crate::host::digest_prefix;
use crate::issuer::IssueError;

/// The document key under which a registration holds its SD-JWT.
pub const DOCUMENT: &str = "dc+sd-jwt";

/// The names RFC 9901 §4 reserves.
const RESERVED: [&str; 3] = ["_sd", "...", "_sd_alg"];

type Members = Vec<(Cow<'static, str>, Node<'static>)>;

fn text(value: &str) -> Node<'static> {
    Node::String(Cow::Owned(value.to_owned()))
}

fn encoded_json(node: &Node<'_>) -> String {
    URL_SAFE_NO_PAD.encode(node.written_compact())
}

fn hash(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

fn member<'v>(view: &'v Node<'_>, name: &'static str) -> Result<&'v str, IssueError> {
    view.get(name)
        .and_then(Node::as_str)
        .ok_or(IssueError::View(name))
}

/// The holder key's curve: `key_curve`, else the one `key_alg` fixes (RFC 7518 §3.4).
fn key_curve<'v>(view: &'v Node<'_>, alg: &'v str) -> Result<&'v str, IssueError> {
    match view.get("key_curve").and_then(Node::as_str) {
        Some(curve) => Ok(curve),
        None => match alg {
            "ES256" => Ok("P-256"),
            "ES384" => Ok("P-384"),
            "ES512" => Ok("P-521"),
            "EdDSA" => Ok("Ed25519"),
            _ => Err(IssueError::View("key_curve")),
        },
    }
}

/// The holder key as a `cnf.jwk` (RFC 7800 §3.2), its coordinates zero.
fn confirmation(view: &Node<'_>) -> Result<Option<Node<'static>>, IssueError> {
    let Some(alg) = view.get("key_alg") else {
        return Ok(None);
    };
    let alg = alg.as_str().ok_or(IssueError::View("key_alg"))?;
    let curve = key_curve(view, alg)?;
    let zero = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let mut jwk: Members = vec![("crv".into(), text(curve)), ("alg".into(), text(alg))];
    if curve.starts_with("P-") {
        jwk.extend([
            ("kty".into(), text("EC")),
            ("x".into(), text(&zero)),
            ("y".into(), text(&zero)),
        ]);
    } else {
        jwk.extend([("kty".into(), text("OKP")), ("x".into(), text(&zero))]);
    }
    let jwk = Node::object(jwk)?;
    Ok(Some(Node::object([(Cow::Borrowed("jwk"), jwk)])?))
}

/// The claims the issuer keeps permanent, in the order the payload holds them.
fn permanent(view: &Node<'_>) -> Result<Members, IssueError> {
    let mut claims: Members = vec![("vct".into(), text(member(view, "type")?))];
    if let Some(iss) = view.get("issuer").and_then(Node::as_str) {
        claims.push(("iss".into(), text(iss)));
    }
    let validity = view.get("validity");
    for (claim, name) in [("nbf", "not_before"), ("exp", "not_after")] {
        if let Some(date) = validity.and_then(|validity| validity.get(name)) {
            claims.push((claim.into(), date.clone().into_owned()));
        }
    }
    if let Some(confirmation) = confirmation(view)? {
        claims.push(("cnf".into(), confirmation));
    }
    Ok(claims)
}

/// The issuer's state: every disclosure so far, in digest order of first reference.
#[derive(Default)]
struct Issuing {
    disclosures: Vec<String>,
}

impl Issuing {
    /// The disclosure of `content` at `path`, with its digest. The salt is SHA-256 of the path.
    fn disclose(&mut self, path: &str, content: Vec<Node<'static>>) -> String {
        let salt = hash(&format!("salt:{path}"));
        let mut array = vec![text(&salt)];
        array.extend(content);
        let encoded = encoded_json(&Node::Array(array));
        let digest = hash(&encoded);
        self.disclosures.push(encoded);
        digest
    }

    /// The value as the payload or a disclosure holds it: each member of an object behind an `_sd`
    /// digest, each array element behind `{"...": digest}`.
    fn concealed(&mut self, path: &str, value: &Node<'_>) -> Result<Node<'static>, IssueError> {
        match value {
            Node::Object(object) => {
                let mut digests = Vec::new();
                for member in object.members() {
                    if RESERVED.contains(&member.name.as_ref()) {
                        return Err(IssueError::View("values"));
                    }
                    let at = format!("{path}/{}", member.name);
                    let inner = self.concealed(&at, &member.value)?;
                    let digest = self.disclose(&at, vec![text(&member.name), inner]);
                    digests.push(text(&digest));
                }
                Ok(Node::object([(
                    Cow::Borrowed("_sd"),
                    Node::Array(digests),
                )])?)
            }
            Node::Array(items) => Ok(Node::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(at, item)| {
                        let at = format!("{path}/{at}");
                        let inner = self.concealed(&at, item)?;
                        let digest = self.disclose(&at, vec![inner]);
                        Ok(Node::object([(Cow::Borrowed("..."), text(&digest))])?)
                    })
                    .collect::<Result<_, IssueError>>()?,
            )),
            scalar => Ok((*scalar).clone().into_owned()),
        }
    }
}

/// The compact SD-JWT of a view: the header `{"alg", "typ"}`, the permanent claims, `_sd_alg` and
/// `_sd`, a stand-in signature, then the disclosures.
///
/// # Errors
///
/// The view lacks `type`, `alg` or an object `values`, or a claim name of `values` is reserved or
/// permanent.
pub fn issue(view: &Node<'_>) -> Result<String, IssueError> {
    let values = view
        .get("values")
        .filter(|values| values.as_object().is_some())
        .ok_or(IssueError::View("values"))?;
    let mut issuing = Issuing::default();
    let concealed = issuing.concealed("", values)?;
    let digests = concealed
        .get("_sd")
        .ok_or(IssueError::View("values"))?
        .clone();
    let mut payload = permanent(view)?;
    let collides = |name: &str| payload.iter().any(|(permanent, _)| permanent == name);
    if values
        .as_object()
        .is_some_and(|values| values.names().any(collides))
    {
        return Err(IssueError::View("values"));
    }
    payload.push(("_sd_alg".into(), text("sha-256")));
    payload.push(("_sd".into(), digests));
    let header = Node::object([
        (Cow::Borrowed("alg"), text(member(view, "alg")?)),
        (Cow::Borrowed("typ"), text(DOCUMENT)),
    ])?;
    let input = format!(
        "{}.{}",
        encoded_json(&header),
        encoded_json(&Node::object(payload)?)
    );
    let signature = format!("issuer-sig:{}", digest_prefix(input.as_bytes()));
    let mut compact = format!("{input}.{}~", URL_SAFE_NO_PAD.encode(signature));
    for disclosure in issuing.disclosures {
        compact.push_str(&disclosure);
        compact.push('~');
    }
    Ok(compact)
}

/// The view a registration of [`issue`]'s SD-JWT makes: the written view's members, `values` with
/// the permanent claims, and without `jwt` or a null `issuer`.
///
/// # Errors
///
/// As [`issue`].
pub fn registered_view(view: &Node<'_>) -> Result<Node<'static>, IssueError> {
    let values = view
        .get("values")
        .and_then(Node::as_object)
        .ok_or(IssueError::View("values"))?;
    let mut merged = permanent(view)?;
    merged.extend(values.members().iter().map(|member| {
        (
            member.name.clone().into_owned().into(),
            member.value.clone().into_owned(),
        )
    }));
    let mut members: Members = vec![("values".into(), Node::object(merged)?)];
    for name in [
        "type",
        "metadata",
        "issuer",
        "alg",
        "curve",
        "key_alg",
        "key_curve",
        "extends",
        "validity",
    ] {
        match view.get(name) {
            None | Some(Node::Null) => {}
            Some(value) => members.push((name.into(), value.clone().into_owned())),
        }
    }
    if view.get("key_alg").is_some() && view.get("key_curve").is_none() {
        let alg = member(view, "key_alg")?;
        members.push(("key_curve".into(), text(key_curve(view, alg)?)));
    }
    Ok(Node::object(members)?)
}
