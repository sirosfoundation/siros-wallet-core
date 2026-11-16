//! Logos of display metadata.

use serde_json::{Map, Value};

use crate::error::{DisplayError, LogoFault};
use crate::json;
use crate::text::LabelText;

/// A logo: where to obtain the image, and its alternative text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logo {
    uri: LogoUri,
    integrity: Option<Integrity>,
    alt_text: Option<LabelText>,
}

impl Logo {
    /// The logo of a `logo` object: `uri` and `alt_text` (OpenID4VCI 1.0, Section 12.2.4), and
    /// for type metadata `uri#integrity` (SD-JWT VC, Section 5.5.1.1.1).
    pub(crate) fn parse(logo: &Value) -> Result<Self, DisplayError> {
        let malformed = DisplayError::Logo;
        let logo = logo.as_object().ok_or(malformed(LogoFault::NotObject))?;
        let uri = match logo.get("uri") {
            Some(Value::String(uri)) => LogoUri::parse(uri)?,
            _ => return Err(malformed(LogoFault::Uri)),
        };
        let integrity = match logo.get("uri#integrity") {
            None => None,
            Some(Value::String(integrity)) => Some(Integrity::parse(integrity)?),
            Some(_) => return Err(malformed(LogoFault::Integrity)),
        };
        Ok(Self {
            uri,
            integrity,
            alt_text: json::optional_label(logo, "alt_text", malformed(LogoFault::AltText))?,
        })
    }

    /// Where to obtain the image.
    pub fn uri(&self) -> &LogoUri {
        &self.uri
    }

    /// The integrity metadata the resolved image is to match (SD-JWT VC, Section 6). `None`
    /// when the metadata gives none.
    pub fn integrity(&self) -> Option<&Integrity> {
        self.integrity.as_ref()
    }

    /// The alternative text for the image.
    pub fn alt_text(&self) -> Option<&LabelText> {
        self.alt_text.as_ref()
    }
}

/// `logo`, when `object` has one.
pub(crate) fn optional(object: &Map<String, Value>) -> Result<Option<Logo>, DisplayError> {
    object.get("logo").map(Logo::parse).transpose()
}

/// The `uri` of a logo: an `https://` URL with an authority, or a `data:` URI with its comma
/// (RFC 2397), of visible ASCII characters only (SD-JWT VC, Section 5.5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogoUri(String);

impl LogoUri {
    fn parse(uri: &str) -> Result<Self, DisplayError> {
        let after = |prefix: &str| {
            uri.get(..prefix.len())
                .filter(|scheme| scheme.eq_ignore_ascii_case(prefix))
                .and_then(|_| uri.get(prefix.len()..))
        };
        let https =
            after("https://").is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
        let data = after("data:").is_some_and(|rest| rest.contains(','));
        if (https || data) && uri.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(Self(uri.to_owned()))
        } else {
            Err(DisplayError::Logo(LogoFault::Uri))
        }
    }

    /// The URL or URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Integrity metadata (W3C Subresource Integrity, Section 3): visible ASCII characters and
/// spaces, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integrity(String);

impl Integrity {
    fn parse(text: &str) -> Result<Self, DisplayError> {
        let printable = text.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if !text.is_empty() && printable {
            Ok(Self(text.to_owned()))
        } else {
            Err(DisplayError::Logo(LogoFault::Integrity))
        }
    }

    /// The metadata.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
