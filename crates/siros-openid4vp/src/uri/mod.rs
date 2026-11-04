//! Requests by URI (OpenID4VP §5, RFC 9101): the Authorization Request URI a link or a QR code
//! holds, its `request_uri`, the fetch the caller performs, and the endpoints answers go to. URIs
//! parse with fluent-uri (RFC 3986), which keeps the text as received; serde_urlencoded reads the
//! query and writes the form bodies.

mod fetch;
mod form;
mod query;

use fluent_uri::Uri;
use fluent_uri::component::{Host, Scheme};
use siros_explain::Explain;

use crate::arrival::{Unreadable, UriError};
use crate::ids::ClientId;

pub use crate::arrival::{FailedStatus, FetchFailure};
pub use fetch::{Fetch, FetchAnswer, NoFetch, RequestObjectFetch};
pub use form::{FormBody, FormMembers};
use query::QueryRead;

/// The `https` scheme, compared without regard to case (RFC 3986 §3.1).
const HTTPS: &Scheme = Scheme::new_or_panic("https");

/// An Authorization Request URI (§9): a URI (RFC 3986 §3) whose query holds the request, and the
/// parameters the core reads from it, each parsed by its type. serde_urlencoded reads the query
/// as `application/x-www-form-urlencoded` (RFC 6749 Appendix B: `+` a space; an escape whose
/// octets are no UTF-8 decoded as U+FFFD); `client_id` is a [`ClientId`] within RFC 6749 Appendix
/// A.1 (U3), `request_uri` a [`RequestUri`] (U7), `request_uri_method` a [`RequestUriMethod`]
/// (U8). Each of the three refuses a value holding U+FFFD; `request` is refused whatever it holds
/// (U6, U19); every other parameter is ignored (§5).
#[derive(Debug, Clone)]
pub struct AuthorizationUri<'a> {
    uri: Uri<&'a str>,
    client_id: ClientId<'a>,
    request_uri: RequestUri,
    method: RequestUriMethod,
}

impl<'a> AuthorizationUri<'a> {
    /// Parses the URI and reads its query; refused per U3 to U8, U18 and U19, in this order: U3
    /// (the URI, its query), U4 while reading, then U5, U3 (`client_id`), U6, U19, U18, U7, U8.
    ///
    /// # Errors
    ///
    /// The U rule the URI breaks.
    pub fn parse(text: &'a str) -> Result<Self, Unreadable> {
        let uri = Uri::parse(text).map_err(|e| Unreadable::Uri(UriError::Syntax(e.to_string())))?;
        let query = uri
            .query()
            .ok_or(Unreadable::Uri(UriError::Query))?
            .as_str();
        let (client_id, request_uri, method, request) = match query::read(query)? {
            QueryRead::Repeated(name) => return Err(Unreadable::Repeated(name.into_owned())),
            QueryRead::Read {
                client_id,
                request_uri,
                method,
                request,
            } => (client_id, request_uri, method, request),
        };
        let client_id = client_id.ok_or(Unreadable::ClientIdAbsent)?;
        let client_id = ClientId::parse(client_id).map_err(|e| Unreadable::ClientId(e.value))?;
        match (request, request_uri) {
            (true, Some(_)) => Err(Unreadable::RequestAndRequestUri),
            (true, None) => Err(Unreadable::RequestByValue),
            (false, None) => Err(Unreadable::ParametersInUri),
            (false, Some(request_uri)) => Ok(Self {
                uri,
                client_id,
                request_uri: RequestUri::parse(request_uri.into_owned())?,
                method: RequestUriMethod::parse(method.as_deref())?,
            }),
        }
    }

    /// The URI as received.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.uri.as_str()
    }

    /// `client_id`, the full Client Identifier.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId<'a> {
        &self.client_id
    }

    /// `request_uri`.
    #[must_use]
    pub const fn request_uri(&self) -> &RequestUri {
        &self.request_uri
    }

    /// `request_uri_method`; `get` when absent.
    #[must_use]
    pub const fn method(&self) -> RequestUriMethod {
        self.method
    }
}

/// Whether a URI is absolute `https` with a non-empty host, which fluent-uri leaves to its user
/// (`https:///r` parses, its host empty).
fn https_with_host(uri: &Uri<String>) -> bool {
    uri.scheme() == HTTPS
        && uri
            .authority()
            .is_some_and(|authority| match authority.host_parsed() {
                Host::RegName(name) => !name.as_str().is_empty(),
                _ => true,
            })
}

/// A `request_uri` (RFC 9101 §5.2): an absolute `https` URI with a host (U7). fluent-uri refuses
/// a character outside RFC 3986, U+FFFD included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUri(Uri<String>);

impl RequestUri {
    /// The URI; refused per U7.
    ///
    /// # Errors
    ///
    /// The text is no absolute `https` URI with a host.
    pub fn parse(text: String) -> Result<Self, Unreadable> {
        match Uri::parse(text) {
            Ok(uri) if https_with_host(&uri) => Ok(Self(uri)),
            Ok(uri) => Err(Unreadable::RequestUri(uri.into_string())),
            Err((_, text)) => Err(Unreadable::RequestUri(text)),
        }
    }

    /// The URI as received.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A URI other than an absolute `https` URI with a host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.uri", id = "not_https")]
#[error("{0:?} is no absolute https URI with a host")]
pub struct NotHttps(#[explain(name = "uri")] pub String);

/// A `response_uri` (§8.2): an absolute `https` URI with a host (A13), and that host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseUri {
    uri: Uri<String>,
    host: String,
}

impl ResponseUri {
    /// The URI; refused when it is no absolute `https` URI with a host.
    ///
    /// # Errors
    ///
    /// The text is no absolute `https` URI with a host.
    pub fn parse(text: String) -> Result<Self, NotHttps> {
        let uri = Uri::parse(text).map_err(|(_, text)| NotHttps(text))?;
        let host = uri
            .authority()
            .map(|authority| authority.host().to_owned())
            .filter(|_| https_with_host(&uri));
        match host {
            Some(host) => Ok(Self { uri, host }),
            None => Err(NotHttps(uri.into_string())),
        }
    }

    /// The URI as received, which the handover and the delivery use unchanged.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.uri.as_str()
    }

    /// The host, as the URI writes it.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// A `redirect_uri` the Response URI returns (§8.2): a URI with a scheme (RFC 3986 §3), a
/// fragment allowed (reading 23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectTarget(Uri<String>);

/// A text that is no URI with a scheme: a relative reference, or no reference at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.uri", id = "not_uri")]
#[error("{0:?} is no URI with a scheme")]
pub struct NotUri(#[explain(name = "uri")] pub String);

impl RedirectTarget {
    /// The URI.
    ///
    /// # Errors
    ///
    /// The text is no URI with a scheme.
    pub fn parse(text: String) -> Result<Self, NotUri> {
        Uri::parse(text).map(Self).map_err(|(_, text)| NotUri(text))
    }

    /// The URI as received.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// `request_uri_method` (§5.1): absent reads `get`; another value is U8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestUriMethod {
    /// `get`.
    Get,
    /// `post`.
    Post,
}

impl RequestUriMethod {
    /// The method a parameter names; `get` when absent.
    fn parse(text: Option<&str>) -> Result<Self, Unreadable> {
        match text {
            None | Some("get") => Ok(Self::Get),
            Some("post") => Ok(Self::Post),
            Some(other) => Err(Unreadable::RequestUriMethod(other.to_owned())),
        }
    }
}
