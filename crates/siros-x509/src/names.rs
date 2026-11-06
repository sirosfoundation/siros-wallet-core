//! The original Client Identifiers of the X.509 prefixes (§5.9.3): `x509_hash`'s leaf hash and
//! `x509_san_dns`'s DNS name, and how each compares.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_explain::{IntoArg, kind};
use siros_openid4vp::uri::ResponseUri;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::X509Refusal;
use crate::chain::ChainCertificate;

/// A SHA-256 hash of a leaf certificate's DER, as `x509_hash` writes it: base64url without
/// padding of 32 octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafHash {
    octets: [u8; 32],
    text: String,
}

impl LeafHash {
    /// The hash an original Client Identifier writes.
    ///
    /// # Errors
    ///
    /// The text is no base64url without padding of 32 octets.
    pub fn parse(original: &str) -> Result<Self, X509Refusal> {
        URL_SAFE_NO_PAD
            .decode(original)
            .ok()
            .and_then(|octets| <[u8; 32]>::try_from(octets).ok())
            .map(Self::of)
            .ok_or_else(|| X509Refusal::HashSyntax(original.to_owned()))
    }

    pub(crate) fn of(octets: [u8; 32]) -> Self {
        Self {
            octets,
            text: URL_SAFE_NO_PAD.encode(octets),
        }
    }

    /// The digest's octets.
    #[must_use]
    pub const fn octets(&self) -> &[u8; 32] {
        &self.octets
    }

    /// The hash as `x509_hash` writes it.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A hash is named by its text in a message.
impl IntoArg for LeafHash {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.text
    }
}

/// A DNS name in preferred name syntax (RFC 1034 §3.5, RFC 1123 §2.1): dot-separated labels of
/// 1 to 63 letters, digits and hyphens, neither starting nor ending with a hyphen, 253
/// characters at most. A U-label is no such name (reading 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanDnsName(String);

impl SanDnsName {
    /// The DNS name an original Client Identifier writes.
    ///
    /// # Errors
    ///
    /// The text is no DNS name in preferred name syntax.
    pub fn parse(original: &str) -> Result<Self, X509Refusal> {
        let label = |label: &str| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        if original.len() <= 253 && original.split('.').all(label) {
            Ok(Self(original.to_owned()))
        } else {
            Err(X509Refusal::SanSyntax(original.to_owned()))
        }
    }

    /// Whether a dNSName entry of the certificate's subjectAltName names it, compared after
    /// ASCII lowercasing (RFC 5280 §7.2); `false` without the extension.
    ///
    /// # Errors
    ///
    /// The extension is no DER SubjectAltName, or appears twice (RFC 5280 §4.2).
    pub fn names(&self, certificate: &ChainCertificate) -> Result<bool, X509Refusal> {
        let extension = certificate
            .certificate()
            .tbs_certificate()
            .get_extension::<SubjectAltName>()
            .map_err(X509Refusal::SubjectAltName)?;
        Ok(extension.is_some_and(|(_, SubjectAltName(names))| {
            names.iter().any(|name| match name {
                GeneralName::DnsName(dns) => dns.as_str().eq_ignore_ascii_case(&self.0),
                _ => false,
            })
        }))
    }

    /// Whether the `response_uri`'s host is the name, compared the same way.
    #[must_use]
    pub fn hosts(&self, uri: &ResponseUri) -> bool {
        uri.host().eq_ignore_ascii_case(&self.0)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name is named by its text in a message.
impl IntoArg for SanDnsName {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}
