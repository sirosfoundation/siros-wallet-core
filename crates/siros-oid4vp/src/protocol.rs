//! The exchange protocols of OpenID4VP over the Digital Credentials API (OpenID4VP 1.0, A.1).

/// One of the three exchange protocol identifiers of OpenID4VP 1.0, A.1.
///
/// The identifier fixes the shape of the request `data`:
///
/// | Protocol | `data` |
/// |---|---|
/// | `openid4vp-v1-unsigned` | the request parameters (A.3.1) |
/// | `openid4vp-v1-signed` | `{"request": <JWS Compact Serialization>}` (A.3.2.1) |
/// | `openid4vp-v1-multisigned` | a JWS JSON Serialization, under `request` or as `data` (A.3.2.2) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// `openid4vp-v1-unsigned`.
    Unsigned,
    /// `openid4vp-v1-signed`.
    Signed,
    /// `openid4vp-v1-multisigned`.
    Multisigned,
}

impl Protocol {
    /// The protocol a label names; `None` for any label other than the three of A.1.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "openid4vp-v1-unsigned" => Some(Self::Unsigned),
            "openid4vp-v1-signed" => Some(Self::Signed),
            "openid4vp-v1-multisigned" => Some(Self::Multisigned),
            _ => None,
        }
    }

    /// The label of A.1.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsigned => "openid4vp-v1-unsigned",
            Self::Signed => "openid4vp-v1-signed",
            Self::Multisigned => "openid4vp-v1-multisigned",
        }
    }

    /// Whether the request arrives as a JWS. It says how the request arrived: a signature is
    /// verified only by intake.
    #[must_use]
    pub fn is_signed(self) -> bool {
        !matches!(self, Self::Unsigned)
    }
}
