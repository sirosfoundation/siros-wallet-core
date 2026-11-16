//! The authenticated identity a session is bound to.

/// How a deployment keys session ownership: per user, or per tenant
/// (engine-parity.md §8, W10's tenant-bound remote principal).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalMode {
    /// The session's owner key is `tenant/subject` — the historic shape:
    /// every deployment whose tokens name a stable user subject.
    #[default]
    User,
    /// The session's owner key is the tenant — the privacy-preserving
    /// remote deployment whose tokens carry a **rotating pseudonym**
    /// `sub` (engine-parity.md §8 G1/G3): keying the session by the
    /// subject would strand it at the mint, so the tenant owns the
    /// session and the resumption token (single-use, rotated on every
    /// resume) is the per-session security.
    Tenant,
}

/// The authenticated identity a session is bound to.
///
/// It is established by the transport or the embedding application — never
/// taken from client-supplied WMP parameters — and passed explicitly to the
/// calls that need it (Rust has no request context to carry it implicitly).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    /// Identifies the authenticated user or client. Required for the
    /// principal to own anything. In [`PrincipalMode::Tenant`] this is the
    /// token's pseudonym subject (engine-parity.md §8 G3): authenticated,
    /// but not an ownership key.
    pub subject: String,
    /// Scopes [`Principal::subject`] in multi-tenant deployments. May be
    /// empty. In [`PrincipalMode::Tenant`] this is the ownership key — a
    /// principal without one owns nothing.
    pub tenant: String,
    /// The deployment's ownership mode, stamped by the transport that
    /// built the principal (the adapter server's
    /// `ENGINE_PRINCIPAL_MODE`). Default [`PrincipalMode::User`]: the
    /// historic shape.
    pub mode: PrincipalMode,
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
            mode: PrincipalMode::User,
        }
    }

    /// The stable owner key stored in a session's owner field.
    ///
    /// Tenant and subject are percent-escaped, so distinct principals never
    /// share a key. A principal without a subject has an empty key: it owns
    /// nothing, and [`Principal::is_authenticated`] reports it as anonymous.
    ///
    /// In [`PrincipalMode::Tenant`] (engine-parity.md §8 G1) the key is the
    /// **tenant** alone: the subject is a rotating pseudonym, so keying by
    /// it would strand the session at the token's mint — a different
    /// pseudonym must reach the session the previous one created. The
    /// escaped tenant never collides with a user-mode `tenant/subject` key,
    /// which always carries an unescaped separator.
    pub fn key(&self) -> String {
        match self.mode {
            PrincipalMode::User => {
                if self.subject.is_empty() {
                    return String::new();
                }
                format!(
                    "{}/{}",
                    path_escape(&self.tenant),
                    path_escape(&self.subject)
                )
            }
            PrincipalMode::Tenant => {
                if self.tenant.is_empty() {
                    return String::new();
                }
                path_escape(&self.tenant)
            }
        }
    }

    /// Puts the principal in a deployment's ownership mode
    /// (engine-parity.md §8): the transport stamps it from its
    /// configuration when it builds the principal from the token.
    #[must_use]
    pub fn in_mode(mut self, mode: PrincipalMode) -> Self {
        self.mode = mode;
        self
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
