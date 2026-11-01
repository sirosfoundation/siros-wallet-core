//! Client Identifiers and their prefixes (OpenID4VP 1.0, Section 5.9).

/// A Client Identifier Prefix this wallet supports (OpenID4VP 1.0, Section 5.9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientIdPrefix {
    /// `redirect_uri`: the value is the Response URI. Unsigned requests only.
    RedirectUri,
    /// `x509_san_dns`: the value is a dNSName SAN of the leaf certificate in `x5c`.
    X509SanDns,
    /// `x509_hash`: the value is the base64url SHA-256 of the leaf certificate in `x5c`.
    X509Hash,
    /// `decentralized_identifier`: the value is a DID; `kid` names its key.
    DecentralizedIdentifier,
    /// `verifier_attestation`: the value is the `sub` of the Verifier Attestation JWT in `jwt`.
    VerifierAttestation,
    /// `openid_federation`: the value is an OpenID Federation Entity Identifier.
    OpenidFederation,
}

impl ClientIdPrefix {
    /// Every prefix, in the order `client_id_prefixes_supported` lists them.
    pub(crate) const ALL: [Self; 6] = [
        Self::RedirectUri,
        Self::X509SanDns,
        Self::X509Hash,
        Self::DecentralizedIdentifier,
        Self::VerifierAttestation,
        Self::OpenidFederation,
    ];

    /// The prefix as written before the first `:`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RedirectUri => "redirect_uri",
            Self::X509SanDns => "x509_san_dns",
            Self::X509Hash => "x509_hash",
            Self::DecentralizedIdentifier => "decentralized_identifier",
            Self::VerifierAttestation => "verifier_attestation",
            Self::OpenidFederation => "openid_federation",
        }
    }

    fn named(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }
}

/// Why a `client_id` is not one this wallet supports (Section 5.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ClientIdError {
    /// The `client_id` has no `:`: a pre-registered client.
    Unprefixed,
    /// The prefix is not one of [`ClientIdPrefix`].
    PrefixUnsupported,
    /// The value after the prefix is empty.
    ValueEmpty,
    /// A `decentralized_identifier` value is not a DID.
    NotADid,
    /// An `x509_san_dns` value is not ASCII.
    DnsName,
}

impl ClientIdError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unprefixed => "client_id_unprefixed",
            Self::PrefixUnsupported => "client_id_prefix_unsupported",
            Self::ValueEmpty => "client_id_value_empty",
            Self::NotADid => "client_id_not_a_did",
            Self::DnsName => "client_id_dns_name",
        }
    }
}

/// A `client_id` with a supported prefix and a non-empty value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId {
    prefix: ClientIdPrefix,
    full: String,
}

impl ClientId {
    /// Parses a `client_id`: the prefix is the text before the first `:` (Section 5.9.1).
    ///
    /// # Errors
    ///
    /// [`ClientIdError`]: a `client_id` without `:` (a pre-registered client), with another
    /// prefix (`origin` included, Section 5.9.3), with an empty value, a
    /// `decentralized_identifier` value that is not a DID, or an `x509_san_dns` value that is
    /// not an ASCII DNS name (Section 5.9.3: a dNSName is an IA5String).
    pub fn parse(full: &str) -> Result<Self, ClientIdError> {
        let (prefix, value) = full.split_once(':').ok_or(ClientIdError::Unprefixed)?;
        let prefix = ClientIdPrefix::named(prefix).ok_or(ClientIdError::PrefixUnsupported)?;
        if value.is_empty() {
            return Err(ClientIdError::ValueEmpty);
        }
        match prefix {
            ClientIdPrefix::DecentralizedIdentifier if !value.starts_with("did:") => {
                return Err(ClientIdError::NotADid)
            }
            ClientIdPrefix::X509SanDns if !value.is_ascii() => return Err(ClientIdError::DnsName),
            _ => {}
        }
        Ok(Self {
            prefix,
            full: full.to_owned(),
        })
    }

    /// The prefix.
    #[must_use]
    pub fn prefix(&self) -> ClientIdPrefix {
        self.prefix
    }

    /// The original Client Identifier: the part after the prefix and its `:`.
    #[must_use]
    pub fn value(&self) -> &str {
        self.full
            .get(self.prefix.as_str().len() + 1..)
            .unwrap_or_default()
    }

    /// The whole `client_id`, prefix included, as the audience and the redirect `Handover`
    /// use it (Section 14.8).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full
    }
}
