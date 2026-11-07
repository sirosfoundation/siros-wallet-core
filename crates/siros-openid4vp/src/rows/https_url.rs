//! An https URL as the wallet shows and fetches it: an IRI (RFC 3987) over fluent-uri, each
//! label of a host beyond ASCII in Punycode (RFC 3492).

use std::hash::{Hash, Hasher};

use fluent_uri::Iri;
use fluent_uri::build::{BuildError, Builder};
use fluent_uri::component::{Host, Scheme};
use fluent_uri::pct_enc::EStr;
use fluent_uri::pct_enc::encoder::IRegName;
use siros_explain::Explain;

use crate::text::python_space;

/// The `https` scheme, compared without regard to case (RFC 3986 §3.1).
const HTTPS: &Scheme = Scheme::new_or_panic("https");

/// An https IRI with a host, as written, and its one form in ASCII, which every build shows and a
/// caller fetches (PaSO View §3 mitigates homograph confusion with the punycode form). Two texts
/// with one ASCII form are one URL: equality and hash read `ascii`.
#[derive(Debug, Clone)]
pub struct HttpsUrl {
    written: Iri<String>,
    ascii: Iri<String>,
}

impl PartialEq for HttpsUrl {
    fn eq(&self, other: &Self) -> bool {
        self.ascii == other.ascii
    }
}

impl Eq for HttpsUrl {}

impl Hash for HttpsUrl {
    fn hash<S: Hasher>(&self, state: &mut S) {
        self.ascii.hash(state);
    }
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
    /// A host label whose Punycode overflows 32-bit arithmetic (RFC 3492 §6.4).
    #[error("a host label overflows Punycode")]
    LabelOverflow,
    /// The host's ASCII form is no registered name.
    #[error("the host's ASCII form is no registered name")]
    NotRegName,
    /// The IRI with the ASCII host does not build.
    #[error("the IRI with the ASCII host does not build: {0}")]
    Rebuilt(#[explain(skip)] BuildError),
}

/// A label of a host beyond ASCII: in ASCII it is lowercased; beyond it, each character takes the
/// case UTS #46 gives it, and the label is written `xn--` and its Punycode (RFC 3492).
fn ascii_label(label: &str) -> Result<String, NotHttpsUrl> {
    if label.is_ascii() {
        return Ok(label.to_ascii_lowercase());
    }
    let mut folded = String::with_capacity(label.len());
    for c in label.chars() {
        // Cherokee's case folds to its capitals (Unicode's CaseFolding.txt), the one script that
        // folds upward: IdnaMappingTable.txt keeps U+13A0..U+13F5 and maps the small letters to them.
        if matches!(c, '\u{13A0}'..='\u{13FD}' | '\u{AB70}'..='\u{ABBF}') {
            folded.extend(c.to_uppercase());
        } else {
            folded.extend(c.to_lowercase());
        }
    }
    let punycode = idna::punycode::encode_str(&folded).ok_or(NotHttpsUrl::LabelOverflow)?;
    Ok(format!("xn--{punycode}"))
}

impl HttpsUrl {
    /// An https IRI without whitespace whose host is non-empty. A host wholly in ASCII stays as
    /// written; a host beyond ASCII becomes [`ascii`](Self::ascii)'s form label by label, split on
    /// U+002E.
    ///
    /// # Errors
    ///
    /// The text holds whitespace, is no IRI, names another scheme, has no host, or has a host
    /// label past Punycode's arithmetic.
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
        let labels = name
            .split('.')
            .map(ascii_label)
            .collect::<Result<Vec<_>, _>>()?;
        let labels = labels.join(".");
        let host = EStr::<IRegName>::new(&labels).ok_or(NotHttpsUrl::NotRegName)?;
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

    /// The URL with a host beyond ASCII in Punycode: what the wallet shows and fetches.
    #[must_use]
    pub fn ascii(&self) -> &str {
        self.ascii.as_str()
    }
}
