//! The authenticated identity a session is bound to.

/// The authenticated identity a session is bound to.
///
/// It is established by the transport or the embedding application — never
/// taken from client-supplied WMP parameters — and passed explicitly to the
/// calls that need it (Rust has no request context to carry it implicitly).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    /// Identifies the authenticated user or client. Required for the
    /// principal to own anything.
    pub subject: String,
    /// Scopes [`Principal::subject`] in multi-tenant deployments. May be
    /// empty.
    pub tenant: String,
}

impl Principal {
    /// Creates a principal for `subject` in `tenant`.
    pub fn new(subject: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            tenant: tenant.into(),
        }
    }

    /// The stable owner key stored in a session's owner field.
    ///
    /// Tenant and subject are percent-escaped, so distinct principals never
    /// share a key. A principal without a subject has an empty key: it owns
    /// nothing, and [`Principal::is_authenticated`] reports it as anonymous.
    pub fn key(&self) -> String {
        if self.subject.is_empty() {
            return String::new();
        }
        format!(
            "{}/{}",
            path_escape(&self.tenant),
            path_escape(&self.subject)
        )
    }

    /// Whether the principal can own a session: a subject is present, so it
    /// is never mistaken for the anonymous principal.
    pub fn is_authenticated(&self) -> bool {
        !self.subject.is_empty()
    }
}

/// Percent-escapes a path segment: every byte outside RFC 3986's unreserved
/// set becomes `%HH`, upper-case hex.
///
/// go-wmp uses `url.PathEscape`, which leaves a few sub-delims unescaped;
/// this is more conservative. Both are injective and stable, which is all
/// the owner key needs: distinct principals still never share a key.
fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
        }
    }
    out
}

/// The upper-case hex digit for a value below 16.
fn hex_digit(v: u8) -> char {
    if v < 10 {
        (b'0' + v) as char
    } else {
        (b'A' + (v - 10)) as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_escapes_both_parts() {
        let p = Principal::new("user@example.com", "acme");
        assert_eq!(p.key(), "acme/user%40example.com");
    }

    #[test]
    fn empty_tenant_leaves_the_leading_separator() {
        let p = Principal::new("alice", "");
        assert_eq!(p.key(), "/alice");
    }

    #[test]
    fn anonymous_principal_owns_nothing() {
        let p = Principal::default();
        assert_eq!(p.key(), "");
        assert!(!p.is_authenticated());
        assert!(Principal::new("alice", "acme").is_authenticated());
    }

    #[test]
    fn distinct_principals_never_share_a_key() {
        // The escape is injective on each part and the separator cannot occur
        // unescaped, so no two distinct principals collide.
        let a = Principal::new("a/b", "t");
        let b = Principal::new("b", "t/a");
        assert_ne!(a.key(), b.key());
        assert_eq!(a.key(), "t/a%2Fb");
        assert_eq!(b.key(), "t%2Fa/b");
    }
}
