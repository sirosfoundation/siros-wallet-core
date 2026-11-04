//! A form body (`application/x-www-form-urlencoded`, UTF-8; §5.10, §8.2), written by
//! serde_urlencoded's serializer from the core's form structs (feature `uri`).

#[cfg(feature = "uri")]
use crate::plugins::Fault;
#[cfg(feature = "uri")]
use crate::{FAULT, detail};

/// A form body, which serde_urlencoded writes from one of the core's form structs. Only
/// [`FormBody::of`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormBody(String);

/// The members of a form body: the core's form structs alone.
#[cfg(feature = "uri")]
pub trait FormMembers: serde::Serialize + sealed::Form {}

#[cfg(feature = "uri")]
pub(crate) mod sealed {
    /// Sealed: the core's form structs alone.
    pub trait Form {}
}

impl FormBody {
    /// The body of the members (feature `uri`), in their declaration order, a member that is `None` left out:
    /// serde_urlencoded escapes as RFC 6749 Appendix B says.
    ///
    /// # Errors
    ///
    /// serde_urlencoded refuses the members, which no form struct of the core makes it do.
    #[cfg(feature = "uri")]
    pub fn of(members: &impl FormMembers) -> Result<Self, Fault> {
        serde_urlencoded::to_string(members)
            .map(Self)
            .map_err(|e| Fault::caused(FAULT, detail!("a form body"), e))
    }

    /// The body's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "uri")]
impl sealed::Form for crate::wallet_metadata::RequestUriPost<'_> {}
#[cfg(feature = "uri")]
impl FormMembers for crate::wallet_metadata::RequestUriPost<'_> {}
