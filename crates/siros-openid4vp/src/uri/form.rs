//! A form body (`application/x-www-form-urlencoded`, UTF-8; §5.10, §8.2), written by
//! serde_urlencoded's serializer (feature `uri`).

#[cfg(feature = "uri")]
use siros_explain::Explain;

/// A form body, which serde_urlencoded writes from flat members, each name once. Only
/// [`FormBody::of`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormBody(String);

/// Members that make no form body.
#[cfg(feature = "uri")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.form")]
pub enum NotForm {
    /// A nested value, which RFC 6749 Appendix B's format holds no place for, or another
    /// serializer refusal: serde_urlencoded's message.
    #[error("the members make no form body: {0}")]
    Serializer(#[explain(name = "cause")] String),
    /// A member name written twice, which a recipient reads one way or another.
    #[error("the form body names {0} twice")]
    Repeated(#[explain(name = "member")] String),
}

impl FormBody {
    /// The body of the members (feature `uri`), in their order, a member that is `None` left
    /// out: serde_urlencoded escapes as RFC 6749 Appendix B says and refuses a member whose value
    /// is a map, a sequence or a struct; the body read back names each member once.
    ///
    /// # Errors
    ///
    /// serde_urlencoded refuses the members, or a name repeats.
    #[cfg(feature = "uri")]
    pub fn of(members: &impl serde::Serialize) -> Result<Self, NotForm> {
        let text =
            serde_urlencoded::to_string(members).map_err(|e| NotForm::Serializer(e.to_string()))?;
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(&text).map_err(|e| NotForm::Serializer(e.to_string()))?;
        for (k, (name, _)) in pairs.iter().enumerate() {
            if pairs
                .get(..k)
                .is_some_and(|before| before.iter().any(|(other, _)| other == name))
            {
                return Err(NotForm::Repeated(name.clone()));
            }
        }
        Ok(Self(text))
    }

    /// The body's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The body's text, owned.
    #[cfg(feature = "resolve")]
    pub(crate) fn into_string(self) -> String {
        self.0
    }
}
