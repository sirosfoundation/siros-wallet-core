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
    /// The token's `jti`: the token's identifier, for revocation and
    /// cut-off checks (#319's `User.AuthInvalidBefore` gate consults it).
    /// Empty when the transport carries no token identity.
    pub jti: String,
    /// The token access control string (the `tac` claim): what the token's
    /// holder may do. Empty when the transport carries no token (or the
    /// token carries no `tac`) — an empty TAC grants what an
    /// unauthenticated-but-identified principal may do, which the
    /// session-access checks decide.
    pub tac: String,
    /// The token's `iat`, unix seconds, when the transport validated a
    /// token: the #319 lifecycle gate compares it against the user's
    /// cut-off. `None` when the transport carries no token (or the token
    /// names no `iat`) — a principal the transport accepted without one
    /// is not stale.
    pub iat: Option<i64>,
    /// The user's token cut-off as the token's AS stamped it
    /// (`auth_invalid_before`, unix seconds), for the stateless half of
    /// the #319 lifecycle gate. `None` when the token carries none.
    pub auth_invalid_before: Option<i64>,
}

impl Principal {
    /// Creates a principal for `subject` in `tenant`.
    pub fn new(subject: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            tenant: tenant.into(),
            ..Self::default()
        }
    }

    /// Creates a principal with the token identity: `subject` in `tenant`,
    /// the token's `jti`, and its `tac`.
    pub fn with_token(
        subject: impl Into<String>,
        tenant: impl Into<String>,
        jti: impl Into<String>,
        tac: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            tenant: tenant.into(),
            jti: jti.into(),
            tac: tac.into(),
            ..Self::default()
        }
    }

    /// Creates a principal with the token identity and its lifecycle
    /// claims: `subject` in `tenant`, the token's `jti` and `tac`, its
    /// `iat`, and the user's cut-off as the AS stamped it
    /// (`auth_invalid_before`) — the #319 gate's stateless inputs.
    #[must_use]
    pub fn with_token_claims(
        subject: impl Into<String>,
        tenant: impl Into<String>,
        jti: impl Into<String>,
        tac: impl Into<String>,
        iat: Option<i64>,
        auth_invalid_before: Option<i64>,
    ) -> Self {
        Self {
            subject: subject.into(),
            tenant: tenant.into(),
            jti: jti.into(),
            tac: tac.into(),
            iat,
            auth_invalid_before,
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

    /// Whether the principal's TAC carries one permission character
    /// (the Go engine's `TAC.Has`): a TAC is a string of permission
    /// characters (`r` read, `i` insert, and the rest of the backend's
    /// set), and carrying one is belonging to it.
    pub fn tac_has(&self, perm: char) -> bool {
        self.tac.contains(perm)
    }

    /// Whether the principal's TAC carries every permission character in
    /// `perms` (the Go engine's `TAC.HasAll`).
    pub fn tac_has_all(&self, perms: &str) -> bool {
        perms.chars().all(|perm| self.tac_has(perm))
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
    fn tac_grants_carry_their_permission_characters() {
        // The Go engine's TAC model: a string of permission characters,
        // Has / HasAll substring semantics.
        let p = Principal::with_token("alice", "acme", "jti-1", "ri");
        assert!(p.tac_has('r'), "carries read");
        assert!(p.tac_has('i'), "carries insert");
        assert!(!p.tac_has('w'), "carries not write");
        assert!(p.tac_has_all("ri"));
        assert!(p.tac_has_all("r"));
        assert!(!p.tac_has_all("rw"), "write missing");
        // The empty TAC grants nothing — but see the flow-start gate:
        // an empty TAC means legacy auth (no TAC concept), not "no
        // permissions", so the gate does not enforce at all.
        let legacy = Principal::new("alice", "acme");
        assert!(!legacy.tac_has('r'));
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
