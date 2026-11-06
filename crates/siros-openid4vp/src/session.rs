//! What binds every presentation of a response to its request (§7.1 item 10): the binding facts
//! each format builds its own binding from, as its Appendix B section defines it.

use crate::ids::{ClientId, Nonce, Origin};
use crate::resolve::RouteKey;
use crate::routing::VerifierKeys;
use crate::uri::ResponseUri;

/// What binds a presentation to its channel (B.2.6's inputs): the Origin over the DC API; by URI
/// the full Client Identifier and the `response_uri` as the request names it.
#[derive(Debug, Clone, Copy)]
pub enum SessionBinding<'s> {
    /// The DC API, from this Origin.
    DcApi {
        /// The Origin, without `origin:`.
        origin: &'s Origin<'s>,
    },
    /// A URI.
    Redirect {
        /// The full `client_id`, its Client Identifier Prefix included.
        client_id: &'s ClientId<'s>,
        /// The `response_uri`.
        response_uri: &'s ResponseUri,
    },
}

/// What a presentation binds: the channel's binding, the `nonce`, the key and `enc` the core
/// sealed the answer to, and the Verifier's keys. Only an answering route makes one
/// (`AnswerRoute::session`), so each fact is the authenticated request's:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::ids::Nonce;
/// use siros_openid4vp::routing::VerifierKeys;
/// use siros_openid4vp::session::{Session, SessionBinding};
///
/// fn forged<'s>(
///     binding: SessionBinding<'s>,
///     nonce: &'s Nonce<'s>,
///     keys: &'s VerifierKeys<'s>,
/// ) -> Session<'s> {
///     Session { binding, nonce, encrypted_to: None, keys }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Session<'s> {
    binding: SessionBinding<'s>,
    nonce: &'s Nonce<'s>,
    encrypted_to: Option<RouteKey<'s>>,
    keys: &'s VerifierKeys<'s>,
}

impl<'s> Session<'s> {
    pub(crate) const fn of(
        binding: SessionBinding<'s>,
        nonce: &'s Nonce<'s>,
        encrypted_to: Option<RouteKey<'s>>,
        keys: &'s VerifierKeys<'s>,
    ) -> Self {
        Self {
            binding,
            nonce,
            encrypted_to,
            keys,
        }
    }

    /// The channel's binding.
    #[must_use]
    pub const fn binding(&self) -> SessionBinding<'s> {
        self.binding
    }

    /// The request's `nonce`.
    #[must_use]
    pub const fn nonce(&self) -> &'s Nonce<'s> {
        self.nonce
    }

    /// The key and `enc` the core sealed the answer to; `None` for a route in the clear.
    #[must_use]
    pub const fn encrypted_to(&self) -> Option<&RouteKey<'s>> {
        self.encrypted_to.as_ref()
    }

    /// The Verifier's keys, as `client_metadata.jwks` lists them.
    #[must_use]
    pub const fn keys(&self) -> &'s VerifierKeys<'s> {
        self.keys
    }

    /// The audience (Annex A, B.3.6): the Origin prefixed with `origin:` over the DC API, even for
    /// a signed request; the full Client Identifier by URI.
    #[must_use]
    pub fn audience(&self) -> String {
        match self.binding {
            SessionBinding::DcApi { origin } => format!("origin:{origin}"),
            SessionBinding::Redirect { client_id, .. } => client_id.to_string(),
        }
    }
}
