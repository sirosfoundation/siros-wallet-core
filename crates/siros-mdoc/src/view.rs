//! The mdoc members of a credential's view: IssuerAuth's signer, the device key's, and the MSO's
//! KeyAuthorizations.

use siros_openid4vp::claims::kit::ClaimsView;
use siros_openid4vp::detail;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, Member};

use crate::FAULT;
use crate::cose::{Curve, Signer};

/// The mdoc members of a credential's view, each read when an operation needs it.
pub(crate) struct MdocMembers<'a, 'v> {
    view: &'a ClaimsView<'v>,
}

impl<'a, 'v> MdocMembers<'a, 'v> {
    /// The members of the view.
    pub(crate) fn of(view: &'a ClaimsView<'v>) -> Self {
        Self { view }
    }

    /// The fault of the view's member `<prefix><what>`.
    fn fault(&self, prefix: &str, what: &'static str) -> Fault {
        Fault::new(
            FAULT,
            detail!(
                "{id}: the view's {prefix}{what}",
                id = self.view.credential().id.to_string(),
                prefix = prefix.to_owned(),
                what = what
            ),
        )
    }

    /// The signer of the members `<prefix>_alg`, a COSE algorithm identifier, and
    /// `<prefix>_curve`, a curve of ISO/IEC 18013-5 Table 22.
    fn signer(&self, prefix: &str) -> Result<Signer, Fault> {
        let view = self.view.json();
        let alg = view
            .get(&format!("{prefix}_alg"))
            .and_then(|alg| match alg {
                Node::Number(number) => number.text().parse::<i64>().ok(),
                _ => None,
            })
            .ok_or_else(|| self.fault(prefix, "_alg is no COSE algorithm identifier"))?;
        let curve = view
            .get(&format!("{prefix}_curve"))
            .and_then(Node::as_str)
            .and_then(Curve::parse)
            .ok_or_else(|| self.fault(prefix, "_curve is no curve of Table 22"))?;
        Ok(Signer { alg, curve })
    }

    /// IssuerAuth's signer: `issuer_alg`, `issuer_curve`.
    pub(crate) fn issuer_auth(&self) -> Result<Signer, Fault> {
        self.signer("issuer")
    }

    /// The device key's signer: `device_alg`, `device_curve`.
    pub(crate) fn device_key(&self) -> Result<Signer, Fault> {
        self.signer("device")
    }

    /// The MSO's KeyAuthorizations (ISO/IEC 18013-5 §9.1.2.4): `key_authorizations`, an object
    /// with `namespaces`, the name spaces authorized whole, and `elements`, per name space the
    /// data elements authorized; none when absent.
    pub(crate) fn key_authorizations(&self) -> Result<KeyAuthorizations<'a>, Fault> {
        let Some(found) = self.view.json().get("key_authorizations") else {
            return Ok(KeyAuthorizations::default());
        };
        let malformed = || {
            self.fault(
                "",
                "key_authorizations is no object of name spaces and data elements",
            )
        };
        let strings = |node: &'a Node<'v>| -> Option<Vec<&'a str>> {
            node.as_array()?.iter().map(Node::as_str).collect()
        };
        let object = found.as_object().ok_or_else(malformed)?;
        let namespaces = match object.get("namespaces") {
            None => Vec::new(),
            Some(listed) => strings(listed).ok_or_else(malformed)?,
        };
        let elements = match object.get("elements") {
            None => Vec::new(),
            Some(listed) => listed
                .as_object()
                .ok_or_else(malformed)?
                .members()
                .iter()
                .map(|member| Some((member.name.as_ref(), strings(&member.value)?)))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(malformed)?,
        };
        Ok(KeyAuthorizations {
            namespaces,
            elements,
        })
    }
}

/// The MSO's KeyAuthorizations: the name spaces the device key may sign whole, and the data
/// elements it may sign per name space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyAuthorizations<'a> {
    namespaces: Vec<&'a str>,
    elements: Vec<(&'a str, Vec<&'a str>)>,
}

impl KeyAuthorizations<'_> {
    /// Whether the device key may sign the member: a data element whose name space, or the
    /// element in its name space, is authorized (B.2.1).
    pub(crate) fn authorizes(&self, member: &Member) -> bool {
        let Member::Element { namespace, element } = member else {
            return false;
        };
        self.namespaces.contains(&namespace.as_ref())
            || self
                .elements
                .iter()
                .any(|(name, listed)| name == namespace && listed.contains(&element.as_ref()))
    }
}
