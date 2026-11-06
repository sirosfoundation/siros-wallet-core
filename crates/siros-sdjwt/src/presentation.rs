//! The presentation (OpenID4VP 1.0 B.3.6, RFC 9901 §4): the SD-JWT with the disclosures of the
//! option's elements, then a Key Binding JWT whenever the credential is bound to a key, whether
//! the query requires holder binding or waives it (B.3 makes the Key Binding JWT optional only
//! then). The Key Binding JWT has `typ` `kb+jwt` and the holder key's `alg`; its payload holds its
//! own claims (`iat`, the session's `aud` and `nonce`, `sd_hash` over the SD-JWT before it), then
//! the transaction's response members. The presentation keeps the Key Binding JWT's parts
//! unserialised: `{"sd_jwt", "kb_jwt": {"header", "payload", "signature"}}`.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use siros_openid4vp::claims::kit::Presenting;
use siros_openid4vp::claims::{Concrete, ConcretePath};
use siros_openid4vp::detail;
use siros_openid4vp::host::{Haip, Has, Host, Platform, PresentError, Presentation};
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::plugins::{Fault, Member, MemberValue};
use siros_openid4vp::refusal::Quoted;
use siros_openid4vp::wallet::{Credential, Holder};

use crate::FAULT;
use crate::view::SdJwtMembers;

/// The presentation of what the option discloses, with the transaction's members as Key Binding
/// JWT claims.
pub(crate) fn present<H: Has<dyn Haip> + Has<dyn Platform>>(
    presenting: Presenting<'_>,
    host: &H,
) -> Result<Presentation, PresentError> {
    let view = presenting.view;
    let credential = view.credential();
    let members = SdJwtMembers::of(view);
    let mut sd_jwt = format!("{}~", issuer_jwt(credential, &members)?);
    for (path, value) in presenting.disclosed {
        sd_jwt.push_str(&disclosure(path, value)?);
        sd_jwt.push('~');
    }
    let id = || credential.id.to_string();
    let fault =
        |e: JsonError| Fault::caused(FAULT, detail!("{id}: the presentation", id = id()), e);
    let presentation = match credential.facts.holder {
        Holder::Unbound => {
            if let Some(member) = presenting.members.names().next() {
                return Err(Fault::new(
                    FAULT,
                    detail!(
                        "{id}: the member {member} needs a Key Binding JWT, and the credential has no key (B.3.3)",
                        id = id(),
                        member = member.clone()
                    ),
                )
                .into());
            }
            Node::object(vec![("sd_jwt".into(), text(sd_jwt))]).map_err(fault)?
        }
        Holder::Bound => {
            let header = Node::object(vec![
                ("typ".into(), text("kb+jwt".to_owned())),
                ("alg".into(), text(members.holder()?.alg.to_owned())),
            ])
            .map_err(fault)?;
            let payload = payload(&presenting, &sd_jwt, host.get::<dyn Platform>())?;
            let signing_input = format!("{}.{}", base64_json(&header), base64_json(&payload));
            // The stand-in KB-JWT writes the signature's bytes as text.
            let signature = String::from_utf8(
                host.get::<dyn Haip>()
                    .sign(&credential.id, signing_input.as_bytes())?
                    .into_bytes(),
            )
            .map_err(|e| {
                Fault::caused(
                    FAULT,
                    detail!("{id}: a signature that is no UTF-8 text", id = id()),
                    e,
                )
            })?;
            let kb_jwt = Node::object(vec![
                ("header".into(), header),
                ("payload".into(), payload),
                ("signature".into(), text(signature)),
            ])
            .map_err(fault)?;
            Node::object(vec![
                ("sd_jwt".into(), text(sd_jwt)),
                ("kb_jwt".into(), kb_jwt),
            ])
            .map_err(fault)?
        }
    };
    Ok(
        Presentation::object(&presentation.python_compact().to_string())
            .map_err(|e| Fault::caused(FAULT, detail!("{id}: the presentation", id = id()), e))?,
    )
}

/// The Key Binding JWT's payload: its own claims, then the members, each name once.
fn payload<'p>(
    presenting: &Presenting<'p>,
    sd_jwt: &str,
    platform: &dyn Platform,
) -> Result<Node<'p>, Fault> {
    let credential = presenting.view.credential();
    let id = || credential.id.to_string();
    let mut claims: Vec<(Cow<'p, str>, Node<'p>)> = vec![
        ("iat".into(), Node::integer(i128::from(platform.now().0))),
        (
            "aud".into(),
            text(presenting.session.audience().as_str().to_owned()),
        ),
        (
            "nonce".into(),
            text(presenting.session.nonce().as_str().to_owned()),
        ),
        (
            "sd_hash".into(),
            text(URL_SAFE_NO_PAD.encode(Sha256::digest(sd_jwt.as_bytes()))),
        ),
    ];
    for (member, value) in presenting.members.iter() {
        let Member::Claim(name) = member else {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "{id}: a Key Binding JWT holds claims, and {member} is a data element",
                    id = id(),
                    member = member.clone()
                ),
            ));
        };
        let value = match value {
            MemberValue::Text(value) => text(value.clone()),
            MemberValue::Json(value) => {
                Node::parse(value.as_str())
                    .map(Node::into_owned)
                    .map_err(|e| {
                        Fault::caused(
                            FAULT,
                            detail!("{id}: the member {name}", id = id(), name = name.clone()),
                            e,
                        )
                    })?
            }
            MemberValue::Bytes(_) | MemberValue::Cbor(_) => {
                return Err(Fault::new(
                    FAULT,
                    detail!(
                        "{id}: a Key Binding JWT claim holds no byte string or CBOR data item ({name})",
                        id = id(),
                        name = name.clone()
                    ),
                ));
            }
        };
        claims.push((name.clone(), value));
    }
    Node::object(claims).map_err(|e| {
        Fault::caused(
            FAULT,
            detail!("{id}: a member is a Key Binding JWT claim", id = id()),
            e,
        )
    })
}

/// The Issuer-signed JWT: a JWS in compact serialization (RFC 7515 §7.1), three base64url parts
/// joined by dots, so the SD-JWT starting with it is ASCII and splits at `~`.
fn issuer_jwt<'a>(
    credential: &Credential<'_>,
    members: &SdJwtMembers<'a, '_>,
) -> Result<&'a str, Fault> {
    let jwt = members.required("jwt")?;
    let parts: Vec<&str> = jwt.split('.').collect();
    let compact = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if compact {
        Ok(jwt)
    } else {
        Err(Fault::new(
            FAULT,
            detail!(
                "{id}: the view's jwt is no JWS in compact serialization",
                id = credential.id.to_string()
            ),
        ))
    }
}

/// The disclosure of an element: base64url over the compact JSON array `[salt, name, value]`,
/// its name the last component of the element's path, its salt the first 22 hexadecimal digits
/// of SHA-256 over the path as Python's `repr` writes the tuple of its components.
fn disclosure(path: &ConcretePath<'_>, value: &Node<'_>) -> Result<String, Fault> {
    let components: Vec<String> = path
        .iter()
        .map(|component| match component {
            Concrete::Key(key) => Quoted(key).to_string(),
            Concrete::Index(at) => at.to_string(),
        })
        .collect();
    let repr = match components.as_slice() {
        [only] => format!("({only},)"),
        all => format!("({})", all.join(", ")),
    };
    let salt: String = Sha256::digest(repr.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(22)
        .collect();
    let name = match path.last() {
        Some(Concrete::Key(key)) => text(key.to_string()),
        Some(Concrete::Index(at)) => Node::integer(at.position() as i128),
        None => {
            return Err(Fault::new(
                FAULT,
                detail!("a disclosed element without a path"),
            ));
        }
    };
    Ok(base64_json(&Node::Array(vec![
        text(salt),
        name,
        value.clone(),
    ])))
}

/// base64url without padding over the compact JSON.
fn base64_json(node: &Node<'_>) -> String {
    URL_SAFE_NO_PAD.encode(node.python_compact().to_string())
}

fn text<'a>(value: String) -> Node<'a> {
    Node::String(Cow::Owned(value))
}
