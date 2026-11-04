//! The presentation (OpenID4VP 1.0 B.2.5): the base64url, without padding, of a DeviceResponse's
//! CBOR with one document (ISO/IEC 18013-5 §8.3.2.1.2.2): the issuer-signed items the option
//! discloses as issued, the transaction's members as device-signed data elements, and the device
//! authentication over DeviceAuthenticationBytes (§9.1.3).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::cbor::cose::coset::AsCborValue;
use siros_openid4vp::cbor::cose::coset::iana::{self, EnumI64};
use siros_openid4vp::cbor::{self, Value};
use siros_openid4vp::claims::Concrete;
use siros_openid4vp::claims::kit::{Presenting, Revalidating};
use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::json::Node;
use siros_explain::Explain;
use siros_openid4vp::detail;
use siros_openid4vp::plugins::{Fault, FindingData, Member};
use siros_openid4vp::request::AgreeableKey;
use siros_openid4vp::host::{
    Haip, Has, Host, MayHave, PresentError, Presentation, Signature, Slot,
};

use crate::FAULT;
use crate::cose::{Signer, device_mac, device_signature};
use crate::device_mac::{DeviceMac, Mac};
use crate::device_authentication::{
    DeviceNameSpacesBytes, Element, ElementValue, device_authentication_bytes,
};
use crate::issuer_signed::{DOCUMENT, Disclosed, IssuerSigned};
use crate::reader_key;
use crate::transcript::{Handover, SessionTranscript};
use crate::view::MdocMembers;

/// Why the build makes no device authentication the Verifier accepts: the format's finding at
/// revalidation, before the End-User authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "mdoc.device")]
pub enum DeviceAuthRefused {
    /// The Verifier's `deviceauth_alg_values` (OpenID4VP B.2.4) lists the device MAC (ISO/IEC
    /// 18013-5 §9.1.3.5) and no signature the device key makes, and the build holds no
    /// [`DeviceMac`] module.
    #[error("the Verifier accepts only a device MAC, and the build holds no device MAC module")]
    NoDeviceMac,
}

/// How the device authenticates the document (ISO/IEC 18013-5 §9.1.3); `M` the device MAC
/// module, or what stands for it.
enum DeviceAuth<'k, M> {
    /// `deviceSignature` with the device key's COSE algorithm, an entry of IANA's registry.
    Signature(iana::Algorithm),
    /// `deviceMac` by the module, its key agreed with this Verifier key.
    Mac {
        /// The Verifier key.
        reader: &'k AgreeableKey<'k>,
        /// The build's device MAC module.
        module: M,
    },
}

impl<'k, M> DeviceAuth<'k, M> {
    /// `deviceMac` when the Verifier lists the MAC for the device key's curve, one of its keys
    /// on that curve lets the wallet agree the MAC key, and it lists no signature the device key
    /// makes or the presentation carries no transaction: a MAC leaves the user deniability, and a
    /// transaction's evidence must convince parties beyond the Verifier, and the build holds the
    /// device MAC module (`module`). Refused when the MAC is the only one the Verifier lists and
    /// the build holds no device MAC module. `deviceSignature` otherwise, and when the Verifier
    /// states no `deviceauth_alg_values`; its algorithm is the device key's, which IANA's COSE
    /// registry must hold.
    fn choose(
        device: Signer,
        supported: Option<&Node<'_>>,
        keys: impl IntoIterator<Item = &'k AgreeableKey<'k>>,
        transaction: bool,
        module: Option<M>,
    ) -> Result<Result<Self, DeviceAuthRefused>, Fault> {
        let allowed = match supported.and_then(|supported| supported.get("deviceauth_alg_values")) {
            None => None,
            Some(listed) => Some(listed.as_array().ok_or_else(|| {
                Fault::new(FAULT, detail!("deviceauth_alg_values is no array, which the request rules refuse"))
            })?),
        };
        let lists = |id: i64| allowed.is_some_and(|allowed| allowed.contains(&Node::integer(id.into())));
        let reader = reader_key(device, keys);
        let mac = reader
            .and_then(|reader| crate::cose::mac(reader.curve()))
            .is_some_and(lists);
        let signature = allowed.is_none() || device.identifiers().into_iter().any(lists);
        Ok(Ok(match (reader, module) {
            (Some(reader), Some(module)) if mac && (!signature || !transaction) => {
                Self::Mac { reader, module }
            }
            (Some(_), None) if mac && !signature => {
                return Ok(Err(DeviceAuthRefused::NoDeviceMac));
            }
            _ => Self::Signature(iana::Algorithm::from_i64(device.alg).ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!(
                        "the device key's algorithm {alg} is no entry of IANA's COSE registry",
                        alg = device.alg
                    ),
                )
            })?),
        }))
    }
}

/// Whether the build makes a device authentication the Verifier accepts, the device MAC module's
/// presence read from the host's type: the refusal of [`DeviceAuth::choose`] as the format's
/// finding.
pub(crate) fn revalidate<H: MayHave<dyn DeviceMac>>(
    revalidating: &Revalidating<'_>,
) -> Result<Option<Box<dyn FindingData>>, Fault> {
    let held = <<H as MayHave<dyn DeviceMac>>::Slot as Slot<dyn DeviceMac>>::HELD;
    Ok(DeviceAuth::choose(
        MdocMembers::of(revalidating.view).device_key()?,
        revalidating.query.supported.as_ref(),
        revalidating.session.keys().iter().map(|key| key.key()),
        !revalidating.provided.is_empty(),
        held.then_some(()),
    )?
    .err()
    .map(|refused| Box::new(refused) as Box<dyn FindingData>))
}

/// The values grouped by name space, in the order each name space first comes.
fn grouped<'a, T>(
    pairs: impl IntoIterator<Item = (&'a str, T)>,
) -> Vec<(&'a str, Vec<T>)> {
    let mut out: Vec<(&'a str, Vec<T>)> = Vec::new();
    for (namespace, value) in pairs {
        match out.iter_mut().find(|(known, _)| *known == namespace) {
            Some((_, values)) => values.push(value),
            None => out.push((namespace, vec![value])),
        }
    }
    out
}

/// The fault of a credential's step, caused by the step's error.
fn caused<E: std::error::Error + Send + Sync + 'static>(
    id: &CredentialId<'_>,
    what: &'static str,
) -> impl FnOnce(E) -> Fault {
    let id = id.to_string();
    move |e| Fault::caused(FAULT, detail!("{id}: {what}"), e)
}

/// The presentation of what the option discloses, with the transaction's members as
/// device-signed data elements.
pub(crate) fn present<H: Has<dyn Haip> + MayHave<dyn DeviceMac>>(
    presenting: Presenting<'_>,
    host: &H,
) -> Result<Presentation, PresentError> {
    let view = presenting.view;
    let credential = view.credential();
    let id = &credential.id;
    let document = credential.document(DOCUMENT).ok_or_else(|| {
        Fault::new(
            FAULT,
            detail!(
                "{id}: no {DOCUMENT} document holds its IssuerSigned",
                id = id.to_string()
            ),
        )
    })?;
    let issued = IssuerSigned::read(document).map_err(caused(id, "the stored IssuerSigned"))?;
    let doctype = issued.doctype();
    let disclosed = presenting
        .disclosed
        .iter()
        .map(|(path, shown)| match path.as_slice() {
            [Concrete::Key(namespace), Concrete::Key(element)] => Ok(Disclosed {
                namespace,
                element,
                shown,
            }),
            _ => Err(Fault::new(
                FAULT,
                detail!(
                    "{id}: an issuer-signed element at {path:?}, no [name space, data element identifier]",
                    id = id.to_string(),
                    path = path.iter().map(Concrete::owned).collect::<Vec<_>>()
                ),
            )),
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    let issuer_signed = issued
        .disclose(&disclosed)
        .map_err(caused(id, "the disclosed IssuerSigned"))?;
    let device = grouped(
        presenting
            .members
            .iter()
            .map(|(member, value)| match member {
                Member::Element { namespace, element } => Ok((
                    namespace.as_ref(),
                    Element {
                        name: element,
                        value: ElementValue::of(value).map_err(|e| {
                            Fault::caused(
                                FAULT,
                                detail!(
                                    "{id}: the member {member}",
                                    id = id.to_string(),
                                    member = member.clone()
                                ),
                                e,
                            )
                        })?,
                    },
                )),
                Member::Claim(_) => Err(Fault::new(
                    FAULT,
                    detail!(
                        "{id}: DeviceSigned name spaces hold data elements, and {member} is a claim",
                        id = id.to_string(),
                        member = member.clone()
                    ),
                )),
            })
            .collect::<Result<Vec<_>, Fault>>()?,
    );
    let auth = DeviceAuth::choose(
        MdocMembers::of(view).device_key()?,
        presenting.query.supported.as_ref(),
        presenting.session.keys().iter().map(|key| key.key()),
        !device.is_empty(),
        host.maybe::<dyn DeviceMac>(),
    )?
    .map_err(|refused| {
        Fault::caused(
            FAULT,
            detail!(
                "{id}: a device authentication refused after revalidation passed",
                id = id.to_string()
            ),
            refused,
        )
    })?;
    let namespaces = DeviceNameSpacesBytes::of(&device).map_err(caused(id, "DeviceNameSpaces"))?;
    let transcript = SessionTranscript::of(&Handover::of(presenting.session)?)
        .map_err(caused(id, "SessionTranscript"))?;
    let detached = device_authentication_bytes(&transcript, doctype, &namespaces)
        .map_err(caused(id, "DeviceAuthentication"))?;
    let (mode, structure) = match auth {
        DeviceAuth::Signature(alg) => (
            "deviceSignature",
            device_signature(alg, &detached, |data| {
                host.get::<dyn Haip>().sign(id, data).map(Signature::into_bytes)
            })?
            .to_cbor_value()
            .map_err(caused(id, "DeviceSignature"))?,
        ),
        DeviceAuth::Mac { reader, module } => {
            let salt = transcript
                .tagged_bytes()
                .map_err(caused(id, "SessionTranscriptBytes"))?;
            (
                "deviceMac",
                device_mac(&detached, |data| {
                    module.mac(id, reader, &salt, data).map(Mac::into_bytes)
                })?
                .to_cbor_value()
                .map_err(caused(id, "DeviceMac"))?,
            )
        }
    };
    let text = |name: &str| Value::Text(name.to_owned());
    let document = Value::Map(vec![
        (text("docType"), text(doctype)),
        (text("issuerSigned"), issuer_signed),
        (
            text("deviceSigned"),
            Value::Map(vec![
                (text("nameSpaces"), namespaces.tagged()),
                (text("deviceAuth"), Value::Map(vec![(text(mode), structure)])),
            ]),
        ),
    ]);
    let response = Value::Map(vec![
        (text("version"), text("1.0")),
        (text("documents"), Value::Array(vec![document])),
        (text("status"), Value::Integer(0.into())),
    ]);
    let bytes = cbor::encode(&response).map_err(caused(id, "the DeviceResponse"))?;
    Ok(Presentation::text(&URL_SAFE_NO_PAD.encode(bytes)))
}
