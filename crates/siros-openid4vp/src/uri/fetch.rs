//! The fetch of a Request Object (§5.10, RFC 9101 §5.2): the GET or the POST the caller performs,
//! and the request it gives once the caller hands back the body.

use std::borrow::Cow;

use siros_explain::Explain;

use super::{AuthorizationUri, FormBody, RequestUri, RequestUriMethod};
use crate::arrival::{FetchFailure, Received, Unreadable};
use crate::host::CoreHost;
#[cfg(feature = "request-decryption")]
use crate::host::EphemeralKey;
use crate::jose::CompactJws;
#[cfg(feature = "request-decryption")]
use crate::jose::{CompactJwe, JwsError};
use crate::plugins::{Build, Fault, Registry};
use crate::recourse::{self, Rejected};
use crate::wallet_metadata::{MetadataRefused, RequestUriPost, WalletMetadata};

/// What the caller fetches, with `Accept: application/oauth-authz-req+jwt` (RFC 9101 §5.2.3,
/// §5.10): a GET of the `request_uri`, or a POST of this form body to it.
#[derive(Debug, Clone, Copy)]
pub enum RequestObjectFetch<'f> {
    /// GET the `request_uri`.
    Get(&'f RequestUri),
    /// POST the `application/x-www-form-urlencoded` body to the `request_uri`.
    Post {
        /// The `request_uri`.
        uri: &'f RequestUri,
        /// The body: `wallet_metadata`.
        body: &'f FormBody,
    },
}

/// What the caller's fetch gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchAnswer<'b> {
    /// The body, UTF-8.
    Body(&'b str),
    /// The fetch failed.
    Failed(FetchFailure),
}

/// Why a URI gives no fetch: the URI breaks a U rule, a `wallet_metadata` contributor broke its
/// declaration, or a module broke its contract.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.fetch")]
pub enum NoFetch {
    /// A U rule.
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
    /// A contributor broke its declaration.
    #[error(transparent)]
    Metadata(#[from] MetadataRefused),
    /// The host's module or a format's member broke its contract.
    #[error(transparent)]
    Fault(#[from] Fault),
}

/// A request by URI whose Request Object the caller fetches. Consumed by [`Fetch::resume`].
#[derive(Debug)]
#[must_use]
pub struct Fetch<'a> {
    uri: AuthorizationUri<'a>,
    method: FetchMethod,
}

/// How the Request Object is fetched: a POST carries `wallet_metadata`, whose `jwks` holds a
/// fresh key when the registry takes encrypted Request Objects; the fetch keeps the key a JWE
/// Request Object is encrypted to.
#[derive(Debug)]
enum FetchMethod {
    Get,
    Post {
        body: FormBody,
        #[cfg(feature = "request-decryption")]
        key: Option<EphemeralKey>,
    },
}

impl<'a> Fetch<'a> {
    /// The request a URI holds: `client_id`, `request_uri` and `request_uri_method`
    /// ([`AuthorizationUri::parse`]). A GET for `get`, and for `post` when the registry takes no
    /// [`RequestPost`](super::RequestPost) (§5.1); else a POST of `wallet_metadata` (§5.10),
    /// whose `jwks` holds a fresh key on a curve the decrypting module states when the registry
    /// takes [`EncryptedRequests`](super::EncryptedRequests) (reading 21), and which lists the
    /// algorithms the prefix's `Haip::verifies` states for the Request Object when the outer
    /// `client_id` names a registered prefix.
    ///
    /// # Errors
    ///
    /// U3 to U8, U18, U19; or the host's module or a format's member broke its contract.
    pub fn of<H: CoreHost>(
        uri: &'a str,
        registry: &Registry<H>,
        host: &H,
    ) -> Result<Self, NoFetch> {
        let uri = AuthorizationUri::parse(uri)?;
        let method = match (uri.method(), registry.post()) {
            (RequestUriMethod::Get, _) | (RequestUriMethod::Post, None) => FetchMethod::Get,
            (RequestUriMethod::Post, Some(post)) => {
                let key = post.ephemeral_key(host)?;
                let metadata = WalletMetadata::of(registry, host, uri.client_id(), key.as_ref())?;
                let body = FormBody::of(&RequestUriPost::of(&metadata))?;
                FetchMethod::Post {
                    body,
                    #[cfg(feature = "request-decryption")]
                    key,
                }
            }
        };
        Ok(Self { uri, method })
    }

    /// What the caller GETs or POSTs.
    pub fn request(&self) -> RequestObjectFetch<'_> {
        match &self.method {
            FetchMethod::Get => RequestObjectFetch::Get(self.uri.request_uri()),
            FetchMethod::Post { body, .. } => RequestObjectFetch::Post {
                uri: self.uri.request_uri(),
                body,
            },
        }
    }

    /// The request with its Request Object: U9 on a failed fetch, which terminates (§5.10.2). A
    /// compact JWE after a POST that posted a key is decrypted with it through the registry's
    /// encrypted Request Objects, the key consumed; any other JWE is refused (U11); the Request
    /// Object is a compact JWS (U10). A U10 body whose payload still decodes to a JSON object
    /// naming an absolute `https` `response_uri` with a host gets an unverified route.
    ///
    /// # Errors
    ///
    /// U9, U10, U11, with the route [`Rejected`] describes.
    pub fn resume<H: CoreHost>(
        self,
        answer: FetchAnswer<'a>,
        registry: &Registry<H>,
        host: &H,
    ) -> Result<Received<'a>, Box<Rejected<'a>>> {
        let Self { uri, method } = self;
        let end_user = |cause| Box::new(Rejected::of(cause, None));
        let body = match answer {
            FetchAnswer::Failed(failure) => return Err(end_user(Unreadable::Fetch(failure))),
            FetchAnswer::Body(body) => body,
        };
        let text: Cow<'a, str> = if body.split('.').count() == 5 {
            Cow::Owned(decrypted(body, method, registry, host).map_err(end_user)?)
        } else {
            Cow::Borrowed(body)
        };
        let route = |cause| recourse::unverified_body(&text, cause);
        match CompactJws::parse(text.clone()) {
            Ok(object) => Ok(Received::uri(uri, object)),
            Err(cause) => {
                let route = route(&cause);
                Err(Box::new(Rejected::of(Unreadable::Jws(cause), route)))
            }
        }
    }
}

/// A compact JWE Request Object's plaintext, after a POST that posted a key: decrypted with it
/// through the registry's encrypted Request Objects, the key consumed. U11 for a JWE after a GET
/// or a POST that posted none, or one that does not decrypt; U10 for a plaintext beyond ASCII,
/// which holds no compact serialization (RFC 7515 §7.1).
#[cfg(feature = "request-decryption")]
fn decrypted<H: Build>(
    body: &str,
    method: FetchMethod,
    registry: &Registry<H>,
    host: &H,
) -> Result<String, Unreadable> {
    let (FetchMethod::Post { key: Some(key), .. }, Some(access)) = (
        method,
        registry
            .post()
            .and_then(crate::plugins::registry::Post::decryption),
    ) else {
        return Err(Unreadable::Encrypted);
    };
    let decryption = access(host);
    let jwe = CompactJwe::parse(body, &decryption.decrypts()).map_err(Unreadable::Jwe)?;
    let plaintext = decryption
        .decrypt(key, &jwe)
        .map_err(|_| Unreadable::Undecryptable)?;
    String::from_utf8(plaintext).map_err(|_| Unreadable::Jws(JwsError::Structure))
}

/// A compact JWE Request Object: U11, as the build registers no encrypted Request Objects and so
/// posts no key.
#[cfg(not(feature = "request-decryption"))]
fn decrypted<H: Build>(
    _body: &str,
    _method: FetchMethod,
    _registry: &Registry<H>,
    _host: &H,
) -> Result<String, Unreadable> {
    Err(Unreadable::Encrypted)
}
