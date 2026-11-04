//! The core's identifiers, owning their texts.

/// A Credential Query identifier (OpenID4VP 1.0, Section 6.1).
pub type QueryId = siros_openid4vp::ids::QueryId<'static>;

/// A Trusted Authorities Query's `type` (OpenID4VP 1.0, Section 6.1.1).
pub type AuthorityType = siros_openid4vp::ids::AuthorityType<'static>;

/// A Trusted Authorities Query's value (OpenID4VP 1.0, Section 6.1.1).
pub type AuthorityValue = siros_openid4vp::ids::AuthorityValue<'static>;
