//! An https URL as the wallet shows and fetches it: an IRI (RFC 3987) over fluent-uri, with its
//! internationalised host in A-label form (UTS #46).

use fluent_uri::Iri;
use fluent_uri::build::{BuildError, Builder};
use fluent_uri::component::{Host, Scheme};
use fluent_uri::pct_enc::EStr;
use fluent_uri::pct_enc::encoder::IRegName;
use siros_explain::Explain;

use crate::text::python_space;

/// The `https` scheme, compared without regard to case (RFC 3986 §3.1).
const HTTPS: &Scheme = Scheme::new_or_panic("https");

/// An https IRI with a host, as written, and its text with an internationalised host in A-label
/// form (UTS #46).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl {
    written: Iri<String>,
    ascii: Iri<String>,
}

/// Why a text is no https URL the wallet shows or fetches.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.https_url")]
pub enum NotHttpsUrl {
    /// No IRI (RFC 3987).
    #[error("no IRI: {0}")]
    Iri(#[explain(skip)] fluent_uri::ParseError),
    /// Whitespace, which RFC 3987's `ucschar` admits and the display could not delimit.
    #[error("whitespace in the URL")]
    Whitespace,
    /// Another scheme.
    #[error("the scheme is not https")]
    Scheme,
    /// No authority, or an empty host (RFC 9110 §4.2.2).
    #[error("no host")]
    Host,
    /// A host without an A-label form.
    #[error("the host has no A-label form: {cause}")]
    ALabel {
        /// The IRI as written.
        #[explain(skip)]
        written: Iri<String>,
        /// Why the host has none.
        #[source]
        cause: NoALabel,
    },
    /// The IRI with the A-label host does not build.
    #[error("the A-label form is no IRI: {0}")]
    Rebuilt(#[explain(skip)] BuildError),
}

/// Why a registered name beyond ASCII has no A-label form.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.a_label")]
pub enum NoALabel {
    /// UTS #46 refuses the name.
    #[error("UTS #46 refuses it: {0}")]
    Uts46(
        #[source]
        #[explain(skip)]
        idna::Errors,
    ),
    /// UTS #46 maps the name to ASCII outside RFC 3987's `ireg-name`, as U+FF5B maps to `{`.
    #[error("UTS #46 maps it to {0:?}, which is no registered name")]
    NotRegName(#[explain(name = "host")] String),
}

/// What the matcher shows of a text: an https URL it shows and fetches, or an https IRI with a
/// host whose A-label form is missing, which it shows and never fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// A URL the wallet shows and fetches.
    Url(HttpsUrl),
    /// An IRI the matcher shows as written.
    Unreachable(UnreachableUrl),
}

/// An https IRI with a host that has no A-label form (UTS #46): the matcher shows it as written,
/// and no fetch reaches it. Only [`HttpsUrl::shown`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableUrl(Iri<String>);

/// A shown URL serializes as written.
impl serde::Serialize for Shown {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.written())
    }
}

impl Shown {
    /// The text as written.
    #[must_use]
    pub fn written(&self) -> &str {
        match self {
            Self::Url(url) => url.written(),
            Self::Unreachable(unreachable) => unreachable.written(),
        }
    }
}

impl UnreachableUrl {
    /// The IRI as written.
    #[must_use]
    pub fn written(&self) -> &str {
        self.0.as_str()
    }
}

impl HttpsUrl {
    /// The text as the matcher shows it: an https URL, or an https IRI with a host whose A-label
    /// form alone is missing.
    ///
    /// # Errors
    ///
    /// The text is no https IRI with a host.
    pub fn shown(text: &str) -> Result<Shown, NotHttpsUrl> {
        match Self::parse(text) {
            Ok(url) => Ok(Shown::Url(url)),
            Err(NotHttpsUrl::ALabel { written, .. }) => {
                Ok(Shown::Unreachable(UnreachableUrl(written)))
            }
            Err(other) => Err(other),
        }
    }

    /// An https IRI without whitespace whose host is non-empty and, when it holds characters
    /// beyond ASCII, has an A-label form.
    ///
    /// # Errors
    ///
    /// The text holds whitespace, is no IRI, names another scheme, has no host, or has a host
    /// without an A-label form.
    pub fn parse(text: &str) -> Result<Self, NotHttpsUrl> {
        if text.chars().any(python_space) {
            return Err(NotHttpsUrl::Whitespace);
        }
        let written = Iri::parse(text).map_err(NotHttpsUrl::Iri)?.to_owned();
        if written.scheme() != HTTPS {
            return Err(NotHttpsUrl::Scheme);
        }
        let authority = written.authority().ok_or(NotHttpsUrl::Host)?;
        let name = match authority.host_parsed() {
            Host::RegName(name) if name.as_str().is_empty() => return Err(NotHttpsUrl::Host),
            Host::RegName(name) if !name.as_str().is_ascii() => name.as_str(),
            _ => {
                let ascii = written.clone();
                return Ok(Self { written, ascii });
            }
        };
        let a_labels = match idna::domain_to_ascii(name) {
            Ok(a_labels) => a_labels,
            Err(cause) => {
                let cause = NoALabel::Uts46(cause);
                return Err(NotHttpsUrl::ALabel { written, cause });
            }
        };
        let Some(host) = EStr::<IRegName>::new(&a_labels) else {
            let cause = NoALabel::NotRegName(a_labels);
            return Err(NotHttpsUrl::ALabel { written, cause });
        };
        let ascii = Iri::builder()
            .scheme(written.scheme())
            .authority_with(|b| {
                b.optional(Builder::userinfo, authority.userinfo())
                    .host(host)
                    .optional(Builder::port, authority.port())
            })
            .path(written.path())
            .optional(Builder::query, written.query())
            .optional(Builder::fragment, written.fragment())
            .build()
            .map_err(NotHttpsUrl::Rebuilt)?;
        Ok(Self { written, ascii })
    }

    /// The URL as written.
    #[must_use]
    pub fn written(&self) -> &str {
        self.written.as_str()
    }

    /// The URL with its host in A-label form: what the wallet shows and fetches.
    #[must_use]
    pub fn ascii(&self) -> &str {
        self.ascii.as_str()
    }
}
