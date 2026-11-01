//! The positions that refusals and errors name.

siros_codec::position!(
    /// The position of a certificate in an issuer chain: 0 for the chain's first certificate.
    pub ChainIndex
);

siros_codec::position!(
    /// The position of an entry in a trust store record.
    pub EntryIndex
);

siros_codec::position!(
    /// The position of a certificate among the `certificates` of a trust store entry.
    pub CertificateIndex
);
