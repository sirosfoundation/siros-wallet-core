//! The `https` URL of a resource the host resolves.

/// An absolute `https` URL with a non-empty authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl(String);

impl HttpsUrl {
    /// The URL `text`, when its scheme is `https` (any case), an authority follows `//`, and it
    /// holds no ASCII whitespace or control character.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let scheme = text.get(..8)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return None;
        }
        if text
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return None;
        }
        let authority = text.get(8..)?.split(['/', '?', '#']).next()?;
        if authority.is_empty() {
            return None;
        }
        Some(Self(text.to_owned()))
    }

    /// The host of the authority: without user information, port or IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        let authority = self
            .0
            .get(8..)
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .unwrap_or_default();
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        match host_port.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
            None => host_port.split(':').next().unwrap_or_default(),
        }
    }

    /// The URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
