//! The response: `vp_token` and the DigitalCredential's `data` (OpenID4VP Annex A).

use crate::host::{Presentation, SealedJwe};
use crate::ids::QueryId;
use crate::json::quote;
use crate::request::{AgreeableKey, ContentEncryption};
use crate::routing::VerifierKey;

/// The key and `enc` a route bound: what the core seals to through `Haip::encrypt_jwe` and what
/// the session holds. Only phase 2 makes one, from the mode's [`Encrypting::Jwe`] once it has
/// checked it: the key is one of the request's (`VerifierKey`), its curve and `alg` and the `enc`
/// are ones the sealing module states (`Haip::agreements`), and the `enc` is one the Verifier
/// lists (A128GCM when it lists none, §5.1):
///
/// ```compile_fail,E0451
/// use siros_openid4vp::request::ContentEncryption;
/// use siros_openid4vp::resolve::RouteKey;
/// use siros_openid4vp::routing::VerifierKey;
///
/// fn forged<'k>(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> RouteKey<'k> {
///     RouteKey { key, enc }
/// }
/// ```
///
/// [`Encrypting::Jwe`]: crate::routing::Encrypting::Jwe
#[derive(Debug, Clone, Copy)]
pub struct RouteKey<'k> {
    key: VerifierKey<'k>,
    enc: ContentEncryption<'static>,
}

impl<'k> RouteKey<'k> {
    pub(crate) const fn of(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> Self {
        Self { key, enc }
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &'k AgreeableKey<'k> {
        self.key.key()
    }

    /// The content encryption.
    #[must_use]
    pub const fn enc(&self) -> ContentEncryption<'static> {
        self.enc
    }
}

#[cfg(feature = "test-util")]
impl<'k> RouteKey<'k> {
    /// The key and `enc` a plug-in's tests seal to, as phase 2 binds them once it has checked
    /// them.
    #[must_use]
    pub const fn new(key: VerifierKey<'k>, enc: ContentEncryption<'static>) -> Self {
        Self::of(key, enc)
    }
}

/// `vp_token`: per Credential Query presented, its presentations in selection order; the queries
/// in the order of their first record.
#[derive(Debug, Clone, Default)]
pub struct VpToken(Vec<(String, Vec<Presentation>)>);

impl VpToken {
    pub(crate) fn push(&mut self, query: &QueryId<'_>, presentation: Presentation) {
        match self.0.iter_mut().find(|(id, _)| id == query.as_str()) {
            Some((_, presentations)) => presentations.push(presentation),
            None => self.0.push((query.to_string(), vec![presentation])),
        }
    }

    /// The JSON text, without whitespace.
    #[must_use]
    pub fn json(&self) -> String {
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(query, presentations)| {
                let items: Vec<&str> = presentations.iter().map(Presentation::as_str).collect();
                format!("{}:[{}]", quote(query), items.join(","))
            })
            .collect();
        format!("{{{}}}", members.join(","))
    }

    /// `{"vp_token": ...}`, the response's plaintext.
    pub(crate) fn data(&self) -> String {
        format!("{{\"vp_token\":{}}}", self.json())
    }
}

/// The DigitalCredential's `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseData {
    /// `dc_api`: `{"vp_token": ...}`.
    Plain(String),
    /// `dc_api.jwt`: the JWE whose plaintext is `{"vp_token": ...}`.
    Encrypted(SealedJwe),
}

impl ResponseData {
    /// The JSON text, without whitespace.
    #[must_use]
    pub fn json(&self) -> String {
        match self {
            Self::Plain(text) => text.clone(),
            Self::Encrypted(jwe) => format!("{{\"response\":{}}}", quote(jwe.as_str())),
        }
    }
}

/// The response to a selection.
#[derive(Debug, Clone)]
pub struct Response {
    /// `vp_token`.
    pub vp_token: VpToken,
    /// The DigitalCredential's `data`.
    pub data: ResponseData,
}
