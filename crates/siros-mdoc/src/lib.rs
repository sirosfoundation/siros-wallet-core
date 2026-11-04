//! The mdoc format plug-in (OpenID4VP 1.0 B.2, Credential Format Identifier `mso_mdoc`):
//! `meta.doctype_value` (B.2.3), the card and rows from OpenID4VCI `credential_metadata`
//! display, the Verifier's COSE algorithms (B.2.4), `DeviceSigned` data elements as transaction
//! response members as the MSO's KeyAuthorizations admit them (B.2.1, ISO/IEC 18013-5
//! §9.1.2.4), and the presentation: a DeviceResponse authenticated by a device signature or a
//! device MAC (ISO/IEC 18013-5 §9.1.3), in ISO/IEC 18013-5's CBOR and COSE. The registration
//! holds the credential's IssuerSigned as its `mso_mdoc` document, which phase 2 alone reads.
//!
//! A credential's view is the claims kit's (`type`, `metadata`, `values`, `issuer`) with
//! `issuer_alg` and `issuer_curve`, IssuerAuth's COSE algorithm and key curve; `device_alg` and
//! `device_curve`, the device key's; and `key_authorizations`, `{"namespaces": [...],
//! "elements": {namespace: [...]}}`. Its `values` hold the issuer-signed data elements by name
//! space.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

mod cose;
mod view;

siros_openid4vp::with_resolve! {
    mod device_authentication;
    mod device_mac;
    pub mod issuer_signed;
    mod presentation;
    pub mod stored;
    mod transcript;

    pub use device_mac::{DeviceMac, Mac};
    pub use transcript::{Handover, SessionTranscript, SessionTranscriptBytes, Thumbprint};
    pub use presentation::DeviceAuthRefused;
    #[cfg(feature = "test-util")]
    pub use device_mac::TestDeviceMac;
}

use siros_explain::{AllOf, Explain, Explained, Message, Messages};
use siros_openid4vp::claims::kit::{self, ClaimsFormat, ClaimsPlugin, ClaimsView, Constraint};
use siros_openid4vp::claims::{Claim, ClaimPath, Step};
use siros_openid4vp::ids::{FormatId, InvalidId};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, FaultDomain, Format, FormatQuery, Member};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{AgreeableKey, Query};
use siros_openid4vp::wallet_metadata::Placement;

use cose::Signer;
use view::MdocMembers;

/// The Credential Format Identifier.
const ID: &str = "mso_mdoc";

/// The plug-in's domain, as its fault message.
pub(crate) const FAULT: FaultDomain = siros_explain::checked!(FaultDomain, "mdoc.fault");

/// The rules of an `mso_mdoc` query the kit reports under the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "mdoc.rules")]
pub enum MdocRule {
    /// B.2.3: `meta.doctype_value` is no string.
    #[error("meta.doctype_value is not a string (B.2.3)")]
    Doctype,
    /// §7.2: a claims path pointer is no name space and data element identifier.
    #[error("is not [name space, data element identifier] (OpenID4VP §7.2)")]
    Pointer,
}

siros_openid4vp::with_resolve! {
    /// The messages phase 2's error types declare.
    fn phase_two() -> Vec<Message> {
        [
            issuer_signed::IssuedError::messages(),
            device_authentication::ValueError::messages(),
            presentation::DeviceAuthRefused::messages(),
        ]
        .concat()
    }
}

siros_openid4vp::without_resolve! {
    /// The messages phase 2's error types declare: none without phase 2.
    fn phase_two() -> Vec<Message> {
        Vec::new()
    }
}

/// The plug-in's messages: those its error types and rules declare, and its fault's.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        let declared: &[fn() -> Vec<Message>] = &[MdocRule::messages, phase_two];
        declared
            .iter()
            .flat_map(|messages| messages())
            .chain([FAULT.message()])
            .collect()
    }
}

/// The mdoc format plug-in. A transaction's response members are data elements of the
/// `DeviceSigned` name spaces; its proof writes none itself.
#[derive(Debug, Clone)]
pub struct Mdoc {
    id: FormatId<'static>,
}

impl Mdoc {
    /// The plug-in.
    pub fn new() -> Result<Self, InvalidId> {
        Ok(Self {
            id: FormatId::parse(ID)?,
        })
    }
}

impl Format for Mdoc {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    /// None: `DeviceNameSpaces` holds the transactions' data elements alone.
    fn reserved(&self) -> &[Member] {
        &[]
    }

    /// ES256 (-7) for IssuerAuth and the device signature (B.2.4; HAIP §7).
    fn wallet_formats(&self) -> Result<Node<'static>, Fault> {
        Node::parse(r#"{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]}"#)
            .map_err(|e| Fault::caused(FAULT, siros_openid4vp::detail!("the formats member"), e))
    }

    /// `DeviceSigned` carries a profile's members as elements of its name spaces (ISO/IEC 18013-5
    /// §8.3.2.1.2.2).
    fn placement(&self) -> Option<Placement> {
        Some(Placement::NameSpaces)
    }

    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        kit::query(self, query, &context)
    }
}

impl ClaimsFormat for Mdoc {
    fn id(&self) -> &'static str {
        ID
    }

    /// OpenID4VCI B.2: a claim's display entry holds its `name`.
    fn label_key(&self) -> &'static str {
        "name"
    }

    fn appendix(&self) -> &'static str {
        "B.2"
    }

    /// B.2.4: a COSE algorithm identifier is an integer.
    fn is_algorithm(&self, value: &Node<'_>) -> bool {
        matches!(value, Node::Number(number) if !number.text().contains(['.', 'e', 'E']))
    }

    /// OpenID4VCI B.2: the display entry's `logo.uri`.
    fn logo<'n>(&self, entry: &'n Node<'n>) -> Option<&'n str> {
        entry.get("logo")?.get("uri")?.as_str()
    }

    /// B.2.3: `meta.doctype_value` is a string.
    fn read_meta<'n, 'm>(
        &self,
        meta: Option<&'n Node<'m>>,
    ) -> Result<&'n Node<'m>, Box<dyn Explained>> {
        meta.filter(|meta| meta.get("doctype_value").and_then(Node::as_str).is_some())
            .ok_or_else(|| Box::new(MdocRule::Doctype) as Box<dyn Explained>)
    }

    /// B.2.3: the credential's docType is `doctype_value`.
    fn meta_matches(&self, meta: &Node<'_>, view: &Node<'_>) -> bool {
        meta.get("doctype_value")
            .is_some_and(|doctype| view.get("type") == Some(doctype))
    }

    /// A `DeviceSigned` data element the transaction writes answers a claim naming it, unless the
    /// claim asks for values: the element's value is made at presentation.
    fn written(&self, claim: &Claim<'_>, provided: &[Member]) -> bool {
        let [Step::Key(namespace), Step::Key(element)] = claim.path.steps() else {
            return false;
        };
        claim.values.is_none()
            && provided.iter().any(|member| {
                matches!(member, Member::Element { namespace: n, element: e } if n == namespace && e == element)
            })
    }

    /// §7.2: a claims path pointer into an mdoc is a name space and a data element identifier.
    fn pointer_refusal(&self, path: &ClaimPath<'_>) -> Option<Box<dyn Explained>> {
        (!matches!(path.steps(), [Step::Key(_), Step::Key(_)]))
            .then(|| Box::new(MdocRule::Pointer) as Box<dyn Explained>)
    }
}

impl ClaimsPlugin for Mdoc {
    /// None beyond the kit's.
    fn rules(&self, _query: &Query<'_>, _named: bool) -> Vec<Refusal> {
        Vec::new()
    }

    /// B.2.4: IssuerAuth's algorithm under `issuerauth_alg_values`; the device key's signature
    /// algorithm under `deviceauth_alg_values`, with the device MAC's identifier for the device
    /// key's curve when a Verifier key on that curve lets the wallet agree the MAC key.
    fn algorithms<'v>(
        &self,
        view: &ClaimsView<'v>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<Vec<Constraint<'v>>, Fault> {
        let members = MdocMembers::of(view);
        let device = members.device_key()?;
        let mac = reader_key(device, keys).and_then(|reader| cose::mac(reader.curve()));
        let identifiers =
            |ids: Vec<i64>| ids.into_iter().map(|id| Node::integer(id.into())).collect();
        Ok(vec![
            Constraint {
                member: "issuerauth_alg_values",
                matched: identifiers(members.issuer_auth()?.identifiers()),
            },
            Constraint {
                member: "deviceauth_alg_values",
                matched: identifiers(device.identifiers().into_iter().chain(mac).collect()),
            },
        ])
    }

    /// B.2.1: each member is a data element the MSO's KeyAuthorizations authorize, by its name
    /// space or as an element; an unauthorized one is an unsupported transaction data type.
    fn carries(
        &self,
        _query: &Query<'_>,
        view: &ClaimsView<'_>,
        members: &[Member],
    ) -> Result<bool, Fault> {
        let authorizations = MdocMembers::of(view).key_authorizations()?;
        Ok(members
            .iter()
            .all(|member| authorizations.authorizes(member)))
    }
}

siros_openid4vp::with_resolve! {
    /// Signs with HAIP's keystore, or MACs with the device MAC module when the build holds it.
    impl<H> siros_openid4vp::host::FormatHost<H> for Mdoc
    where
        H: siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip> + siros_openid4vp::host::MayHave<dyn DeviceMac>,
    {
        fn answer<'q>(
            &'q self,
            query: &'q Query<'q>,
            context: siros_openid4vp::host::AnsweredContext<'q>,
        ) -> Result<Box<dyn siros_openid4vp::host::AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
            kit::answer(self, query, context)
        }
    }

    impl<H> kit::ClaimsPresent<H> for Mdoc
    where
        H: siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip> + siros_openid4vp::host::MayHave<dyn DeviceMac>,
    {
        /// ISO/IEC 18013-5 §9.1.3 and OpenID4VP B.2.4: a device authentication the Verifier
        /// accepts, with the device MAC module when the host's type holds it.
        fn revalidate(
            &self,
            revalidating: kit::Revalidating<'_>,
            _host: &H,
        ) -> Result<Option<Box<dyn siros_openid4vp::plugins::FindingData>>, Fault> {
            presentation::revalidate::<H>(&revalidating)
        }

        fn present(
            &self,
            presenting: kit::Presenting<'_>,
            host: &H,
        ) -> Result<siros_openid4vp::host::Presentation, siros_openid4vp::host::PresentError> {
            presentation::present(presenting, host)
        }
    }
}

/// The first Verifier key on the device key's curve: OpenID4VP §5.1 `jwks` holds the keys the
/// wallet needs to make a presentation, here to agree the device MAC key (ISO/IEC 18013-5
/// §9.1.3.5).
fn reader_key<'k>(
    device: Signer,
    keys: impl IntoIterator<Item = &'k AgreeableKey<'k>>,
) -> Option<&'k AgreeableKey<'k>> {
    keys.into_iter()
        .find(|key| key.curve().as_str() == device.curve.name())
}
