//! The SD-JWT members of a credential's view: the Issuer-signed JWT, its signer, and the holder
//! key's.

use siros_openid4vp::claims::kit::ClaimsView;
use siros_openid4vp::detail;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Fault;

use crate::FAULT;
use crate::jose::Signer;

/// The SD-JWT members of a credential's view, each read when an operation needs it.
pub(crate) struct SdJwtMembers<'a, 'v> {
    view: &'a ClaimsView<'v>,
}

impl<'a, 'v> SdJwtMembers<'a, 'v> {
    /// The members of the view.
    pub(crate) fn of(view: &'a ClaimsView<'v>) -> Self {
        Self { view }
    }

    /// A string member; `None` when absent.
    fn text(&self, name: &str) -> Result<Option<&'a str>, Fault> {
        match self.view.json().get(name) {
            None => Ok(None),
            Some(Node::String(text)) => Ok(Some(text)),
            Some(_) => Err(self.fault(name)),
        }
    }

    /// A string member the operation needs.
    pub(crate) fn required(&self, name: &str) -> Result<&'a str, Fault> {
        self.text(name)?.ok_or_else(|| self.fault(name))
    }

    /// The view's member is no string.
    fn fault(&self, name: &str) -> Fault {
        Fault::new(
            FAULT,
            detail!(
                "{id}: the view's {name} is no string",
                id = self.view.credential().id.to_string(),
                name = name.to_owned()
            ),
        )
    }

    /// The Issuer-signed JWT's signer: `alg` and `curve`.
    pub(crate) fn issuer(&self) -> Result<Signer<'a>, Fault> {
        Ok(Signer {
            alg: self.required("alg")?,
            curve: self.text("curve")?,
        })
    }

    /// The holder key: `key_alg` and `key_curve`.
    pub(crate) fn holder(&self) -> Result<Signer<'a>, Fault> {
        Ok(Signer {
            alg: self.required("key_alg")?,
            curve: self.text("key_curve")?,
        })
    }
}
