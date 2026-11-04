//! The core's response modes (§8.2, §8.3, A.2), peers of any extension's: `dc_api` and
//! `dc_api.jwt` over the DC API, `direct_post.jwt` and `direct_post` by URI. The JWE modes share
//! HAIP §5's key rule (§8.3; reading 25) and its refusal, C7; a build registers them with
//! `jwe_mode`, `dc_api` with `mode`, and `direct_post` with `error_mode` alone.

use siros_explain::Explain;

use crate::refusal::{ErrorCode, Refusal, RequestRule};
use crate::request::{Agreements, ClientMetadata, ContentEncryption, Curve, KeyAgreement, Request};
use crate::routing::{ChannelKind, Mode, ModeName, VerifierKey, VerifierMetadata};
#[cfg(feature = "resolve")]
use crate::routing::{Encrypting, ModeHost};
use crate::wallet_metadata::ParameterName;

/// `dc_api` (A.2): the Authorization Response in the clear, as the DigitalCredential's `data`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DcApi;

/// `dc_api.jwt` (A.2, §8.3): the Authorization Response sealed to the Verifier's key.
#[derive(Debug, Clone, Copy, Default)]
pub struct DcApiJwt;

/// `direct_post.jwt` (§8.3.1): the Authorization Response sealed to the Verifier's key, POSTed to
/// the `response_uri`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectPostJwt;

/// `direct_post` (§8.2), which a build registers with `error_mode` alone: C5 refuses a request
/// naming it, and its error goes plain to the `response_uri` (reading 24).
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectPost;

/// C7: a JWE mode's key rule accepts no key, or no `enc` (§8.3, HAIP §5; reading 25). Both keep
/// the text the reference model writes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.modes")]
pub enum KeyRule {
    /// No key of `client_metadata.jwks` the rule accepts.
    #[error("C7 {mode}: client_metadata offers no key and content encryption the wallet supports")]
    #[explain(id = "c7_key")]
    Key {
        /// The mode.
        mode: ModeName,
    },
    /// No `enc` of `encrypted_response_enc_values_supported` the rule accepts.
    #[error("C7 {mode}: client_metadata offers no key and content encryption the wallet supports")]
    #[explain(id = "c7_enc")]
    Enc {
        /// The mode.
        mode: ModeName,
    },
}

impl RequestRule for KeyRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// HAIP §5's key rule (§8.3): ECDH-ES on P-256, A256GCM before A128GCM.
const KEY_RULE: Agreements = Agreements::new(
    &[Curve::P_256],
    &[KeyAgreement::ECDH_ES],
    &[ContentEncryption::A256GCM, ContentEncryption::A128GCM],
);

/// The `wallet_metadata` members `direct_post.jwt` writes (JARM §4's names, as §5.10 uses them).
const JWE_METADATA: &[ParameterName] = &[
    siros_explain::checked!(
        ParameterName,
        "authorization_encryption_alg_values_supported"
    ),
    siros_explain::checked!(
        ParameterName,
        "authorization_encryption_enc_values_supported"
    ),
];

/// The octets of each coordinate of a P-256 point (RFC 7518 §6.2.1.2, §6.2.1.3).
const P_256_OCTETS: usize = 32;

/// HAIP §5's key rule under the sealing statement `sealer`: the first `EC` key whose curve and
/// `alg`, present (§8.3: "The alg parameter MUST be present in the JWKs"), both the rule and
/// `sealer` state, each coordinate 32 octets; then the first `enc` in `sealer`'s order of
/// preference that the rule states and the Verifier lists, or A128GCM when it lists none (§5.1's
/// default). Phase 1, which holds no module, reads the rule as its own sealer.
fn key_rule<'k>(
    mode: ModeName,
    metadata: &'k VerifierMetadata<'k>,
    sealer: &Agreements,
) -> Result<(VerifierKey<'k>, ContentEncryption<'static>), KeyRule> {
    let key = metadata
        .keys()
        .iter()
        .find(|candidate| {
            let key = candidate.key();
            key.kty() == "EC"
                && key.alg().is_some_and(|alg| {
                    KEY_RULE.agrees(key.curve(), alg) && sealer.agrees(key.curve(), alg)
                })
                && key.point().x().len() == P_256_OCTETS
                && key.point().y().is_some_and(|y| y.len() == P_256_OCTETS)
        })
        .ok_or(KeyRule::Key { mode })?;
    let listed = metadata.member("encrypted_response_enc_values_supported");
    let enc = sealer
        .encryptions()
        .iter()
        .copied()
        .filter(|enc| KEY_RULE.encrypts(*enc))
        .find(|enc| match listed {
            Some(listed) => listed.as_array().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(enc.as_str()))
            }),
            None => *enc == ContentEncryption::A128GCM,
        })
        .ok_or(KeyRule::Enc { mode })?;
    Ok((key, enc))
}

/// What HAIP §5's key rule chooses under its own statement, as phase 1 reads it: the key's `kid`
/// and RFC 7638 thumbprint, and the content encryption. Phase 2 chooses under the sealing
/// module's statement, which can narrow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChoice {
    kid: String,
    thumbprint: [u8; 32],
    enc: ContentEncryption<'static>,
}

impl KeyChoice {
    /// The key rule's choice among the request's `client_metadata.jwks`, for a reader that binds
    /// the key before phase 2 (a session transcript).
    ///
    /// # Errors
    ///
    /// C7 under `mode`.
    pub fn of(mode: ModeName, metadata: &ClientMetadata<'_>) -> Result<Self, KeyRule> {
        let metadata = VerifierMetadata::of(metadata);
        key_rule(mode, &metadata, &KEY_RULE).map(|(key, enc)| Self {
            kid: key.key().kid().to_owned(),
            thumbprint: key.key().thumbprint(),
            enc,
        })
    }

    /// The key's `kid`.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The key's JWK SHA-256 Thumbprint (RFC 7638).
    #[must_use]
    pub const fn thumbprint(&self) -> [u8; 32] {
        self.thumbprint
    }

    /// The content encryption.
    #[must_use]
    pub const fn enc(&self) -> ContentEncryption<'static> {
        self.enc
    }
}

/// A JWE mode's C7 in phase 1, under the rule's own statement.
fn c7(mode: ModeName, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
    match key_rule(mode, metadata, &KEY_RULE) {
        Ok(_) => Vec::new(),
        Err(rule) => vec![Refusal::new(rule)],
    }
}

/// A JWE mode's route in phase 2, under the rule and the sealing module's statement.
#[cfg(feature = "resolve")]
fn encrypting<'k>(
    mode: ModeName,
    metadata: &'k VerifierMetadata<'k>,
    sealer: &Agreements,
) -> Result<Encrypting<'k>, Refusal> {
    key_rule(mode, metadata, sealer)
        .map(|(key, enc)| Encrypting::Jwe { key, enc })
        .map_err(Refusal::new)
}

impl Mode for DcApi {
    fn name(&self) -> ModeName {
        siros_explain::checked!(ModeName, "dc_api")
    }

    fn channel(&self) -> ChannelKind {
        ChannelKind::DcApi
    }

    fn rules(&self, _request: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        Vec::new()
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        &[]
    }
}

impl Mode for DcApiJwt {
    fn name(&self) -> ModeName {
        siros_explain::checked!(ModeName, "dc_api.jwt")
    }

    fn channel(&self) -> ChannelKind {
        ChannelKind::DcApi
    }

    fn rules(&self, _request: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        c7(self.name(), metadata)
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        &[]
    }
}

impl Mode for DirectPostJwt {
    fn name(&self) -> ModeName {
        siros_explain::checked!(ModeName, "direct_post.jwt")
    }

    fn channel(&self) -> ChannelKind {
        ChannelKind::Uri
    }

    fn rules(&self, _request: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        c7(self.name(), metadata)
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        JWE_METADATA
    }
}

impl Mode for DirectPost {
    fn name(&self) -> ModeName {
        siros_explain::checked!(ModeName, "direct_post")
    }

    fn channel(&self) -> ChannelKind {
        ChannelKind::Uri
    }

    fn rules(&self, _request: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
        Vec::new()
    }

    fn metadata_names(&self) -> &'static [ParameterName] {
        &[]
    }
}

#[cfg(feature = "resolve")]
impl<H> ModeHost<H> for DcApi {
    fn encryption<'k>(
        &self,
        _metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        Ok(Encrypting::Plain)
    }
}

#[cfg(feature = "resolve")]
impl<H> ModeHost<H> for DcApiJwt {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        encrypting(self.name(), metadata, sealer)
    }
}

#[cfg(feature = "resolve")]
impl<H> ModeHost<H> for DirectPostJwt {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        encrypting(self.name(), metadata, sealer)
    }
}

/// `direct_post` carries errors alone, in the clear.
#[cfg(feature = "resolve")]
impl<H> ModeHost<H> for DirectPost {
    fn encryption<'k>(
        &self,
        _metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        Ok(Encrypting::Plain)
    }
}
