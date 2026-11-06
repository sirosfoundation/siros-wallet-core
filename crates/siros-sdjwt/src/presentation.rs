//! The presentation (OpenID4VP 1.0 B.3.6, RFC 9901 §4), a string (§8.1) from the [`DOCUMENT`]: the
//! Issuer-signed JWT, the disclosures of the option's elements (S3), then a compact Key Binding JWT
//! (S4) whenever the credential is bound to a key, whether the query requires holder binding or
//! waives it (B.3 makes the Key Binding JWT optional only then). The Key Binding JWT's payload
//! holds its own claims (`iat`, the session's `aud` and `nonce`, `sd_hash` over the SD-JWT before
//! it), then the transaction's response members.

use std::borrow::Cow;

use siros_openid4vp::claims::kit::Presenting;
use siros_openid4vp::claims::{Concrete, ConcretePath};
use siros_openid4vp::detail;
use siros_openid4vp::host::{Haip, Has, Host, Platform, PresentError, Presentation};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, Member, MemberValue};
use siros_openid4vp::wallet::{Credential, Holder};

use crate::FAULT;
use crate::alg::SigningAlg;
use crate::key_binding::{Audience, Binding, KbNonce, NumericDate};
use crate::registration::DOCUMENT;
use crate::sd_jwt::SdJwt;
use crate::view::SdJwtMembers;

/// The presentation of what the option discloses, with the transaction's members as Key Binding
/// JWT claims.
pub(crate) fn present<H: Has<dyn Haip> + Has<dyn Platform>>(
    presenting: Presenting<'_>,
    host: &H,
) -> Result<Presentation, PresentError> {
    let credential = presenting.view.credential();
    let id = || credential.id.to_string();
    let sd_jwt = issued(credential)?;
    let values = sd_jwt
        .values()
        .map_err(|e| Fault::caused(FAULT, detail!("{id}: the document", id = id()), e))?;
    let paths: Vec<ConcretePath<'_>> = presenting
        .disclosed
        .iter()
        .map(|(path, value)| {
            if node_at(&values, path) == Some(*value) {
                Ok(path.clone())
            } else {
                Err(Fault::new(
                    FAULT,
                    detail!(
                        "{id}: the view states a value the document does not hold",
                        id = id()
                    ),
                ))
            }
        })
        .collect::<Result<_, Fault>>()?;
    let selected = sd_jwt
        .select(&paths)
        .map_err(|e| Fault::caused(FAULT, detail!("{id}: the selected paths", id = id()), e))?;
    match credential.facts.holder {
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
            Ok(Presentation::text(selected.as_str()))
        }
        Holder::Bound => {
            let extra = members(&presenting)?;
            let key_alg = SdJwtMembers::of(presenting.view).holder()?.alg;
            let key_alg = SigningAlg::parse(key_alg).ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!(
                        "{id}: the view's key_alg signs with no private key",
                        id = id()
                    ),
                )
            })?;
            let binding = selected
                .key_binding(
                    Binding {
                        alg: &key_alg,
                        iat: NumericDate(host.get::<dyn Platform>().now().0),
                        aud: &Audience::new(&presenting.session.audience()),
                        nonce: &KbNonce::new(presenting.session.nonce().as_str()),
                    },
                    extra,
                )
                .map_err(|e| {
                    Fault::caused(
                        FAULT,
                        detail!("{id}: a member is a Key Binding JWT claim", id = id()),
                        e,
                    )
                })?;
            let signature = host
                .get::<dyn Haip>()
                .sign(&credential.id, binding.signing_input())?;
            Ok(Presentation::text(
                &binding.assemble(&signature.into_bytes()),
            ))
        }
    }
}

/// The issued SD-JWT the registration holds.
fn issued(credential: &Credential<'_>) -> Result<SdJwt, Fault> {
    let id = || credential.id.to_string();
    let document = credential
        .document(DOCUMENT)
        .ok_or_else(|| Fault::new(FAULT, detail!("{id}: no dc+sd-jwt document", id = id())))?;
    let text = std::str::from_utf8(document)
        .map_err(|e| Fault::caused(FAULT, detail!("{id}: the document", id = id()), e))?;
    SdJwt::parse(text)
        .map_err(|e| Fault::caused(FAULT, detail!("{id}: the document", id = id()), e))
}

/// The value at `path` of `values`.
fn node_at<'n>(values: &'n Node<'n>, path: &[Concrete<'_>]) -> Option<&'n Node<'n>> {
    path.iter().try_fold(values, |node, step| match step {
        Concrete::Key(name) => node.get(name),
        Concrete::Index(at) => node.as_array()?.get(*at),
    })
}

/// The transaction's members as Key Binding JWT claims.
fn members<'p>(presenting: &Presenting<'p>) -> Result<Vec<(Cow<'p, str>, Node<'p>)>, Fault> {
    let credential = presenting.view.credential();
    let id = || credential.id.to_string();
    presenting
        .members
        .iter()
        .map(|(member, value)| {
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
                MemberValue::Text(value) => Node::String(Cow::Owned(value.clone())),
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
            Ok((name.clone(), value))
        })
        .collect()
}
