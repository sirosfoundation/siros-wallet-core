//! The fetch of a Request Object (§5.10, RFC 9101 §5.2): the GET or the POST the caller performs,
//! and the request it gives once the caller hands back the body.

use std::borrow::Cow;

use siros_explain::Explain;

use super::{AuthorizationUri, FormBody, RequestUri, RequestUriMethod};
use crate::arrival::{FetchFailure, Received, Unreadable};
use crate::host::{CoreHost, EphemeralKey};
use crate::jose::{CompactJwe, CompactJws, JwsError};
use crate::plugins::{Fault, Registry};
use crate::recourse::{self, Rejected};
use crate::request::Curve;
use crate::wallet_metadata::{RequestUriPost, WalletMetadata};
use crate::{FAULT, detail};

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

/// Why a URI gives no fetch: the URI breaks a U rule, or a module broke its contract.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.fetch")]
pub enum NoFetch {
    /// A U rule.
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
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
                let key = post
                    .decryption
                    .map(|access| {
                        let decryption = access(host);
                        let key = decryption.ephemeral_key()?;
                        let curve = key
                            .public()
                            .member("crv")
                            .and_then(|crv| crv.as_str())
                            .and_then(Curve::new);
                        if curve.is_some_and(|curve| decryption.decrypts().curve(curve)) {
                            Ok(key)
                        } else {
                            Err(Fault::new(
                                FAULT,
                                detail!("the ephemeral key's crv is none the module states"),
                            ))
                        }
                    })
                    .transpose()?;
                let verifies = uri
                    .client_id()
                    .as_str()
                    .split_once(':')
                    .and_then(|(prefix, _)| registry.client_prefix(prefix))
                    .map(|(_, haip)| haip(host).verifies());
                let metadata = WalletMetadata::of(registry, key.as_ref(), verifies, host)?;
                let body = FormBody::of(&RequestUriPost::of(&metadata))?;
                FetchMethod::Post { body, key }
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
            let (FetchMethod::Post { key: Some(key), .. }, Some(access)) =
                (method, registry.post().and_then(|post| post.decryption))
            else {
                return Err(end_user(Unreadable::Encrypted));
            };
            let decryption = access(host);
            let jwe = CompactJwe::parse(body, &decryption.decrypts())
                .map_err(|e| end_user(Unreadable::Jwe(e)))?;
            let plaintext = decryption
                .decrypt(key, &jwe)
                .map_err(|_| end_user(Unreadable::Undecryptable))?;
            // A plaintext beyond ASCII holds no compact serialization (RFC 7515 §7.1).
            Cow::Owned(
                String::from_utf8(plaintext)
                    .map_err(|_| end_user(Unreadable::Jws(JwsError::Structure)))?,
            )
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
