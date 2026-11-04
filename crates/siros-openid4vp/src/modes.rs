//! The core's response modes (§8.2, §8.3, A.2), peers of any extension's: `dc_api` and
//! `dc_api.jwt` over the DC API, `direct_post.jwt` and `direct_post` by URI. The JWE modes share
//! HAIP §5's key rule (§8.3; reading 25) and its refusal, C7; a build registers them with
//! `jwe_mode`, `dc_api` with `mode`, and `direct_post` with `error_mode` alone. The DC API modes
//! compile under the feature `dc-api`, the URI modes under `uri`; the key rule in every build.

use siros_explain::Explain;

#[cfg(feature = "uri")]
use std::borrow::Cow;

#[cfg(feature = "uri")]
use crate::json::Node;
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::plugins::Fault;
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::refusal::Refusal;
use crate::refusal::{ErrorCode, RequestRule};
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::request::Request;
use crate::request::{Agreements, ContentEncryption, Curve, KeyAgreement};
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::routing::{ChannelKind, Mode};
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::routing::{Encrypting, ModeHost};
use crate::routing::{ModeName, VerifierKey, VerifierMetadata};
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::wallet_metadata::MetadataMember;
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::wallet_metadata::ParameterName;

pub use crate::routing::KeyChoice;

#[cfg(feature = "dc-api")]
/// `dc_api` (A.2): the Authorization Response in the clear, as the DigitalCredential's `data`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DcApi;

#[cfg(feature = "dc-api")]
/// `dc_api.jwt` (A.2, §8.3): the Authorization Response sealed to the Verifier's key.
#[derive(Debug, Clone, Copy, Default)]
pub struct DcApiJwt;

#[cfg(feature = "uri")]
/// `direct_post.jwt` (§8.3.1): the Authorization Response sealed to the Verifier's key, POSTed to
/// the `response_uri`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectPostJwt;

#[cfg(feature = "uri")]
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

/// HAIP §5's key rule's statement (§8.3): ECDH-ES on P-256, A256GCM before A128GCM.
pub const KEY_RULE: Agreements = Agreements::new(
    &[Curve::P_256],
    &[KeyAgreement::ECDH_ES],
    &[ContentEncryption::A256GCM, ContentEncryption::A128GCM],
);

#[cfg(feature = "uri")]
/// The `wallet_metadata` members `direct_post.jwt` writes (JARM §4's names, as §5.10 uses them).
const JWE_NAMES: [ParameterName; 2] = [
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
/// default). Phase 1, which holds no module, reads the rule as its own sealer ([`KEY_RULE`]).
///
/// # Errors
///
/// C7 under `mode`: no key, or no `enc`, the rule accepts.
pub fn key_rule<'k>(
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
    let enc = sealer
        .encryptions()
        .iter()
        .copied()
        .filter(|enc| KEY_RULE.encrypts(*enc))
        .find(|enc| metadata.lists(*enc))
        .ok_or(KeyRule::Enc { mode })?;
    Ok((key, enc))
}

#[cfg(any(feature = "dc-api", feature = "uri"))]
/// A JWE mode's C7 in phase 1, under the rule's own statement.
fn c7(mode: ModeName, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
    match key_rule(mode, metadata, &KEY_RULE) {
        Ok(_) => Vec::new(),
        Err(rule) => vec![Refusal::new(rule)],
    }
}

/// A JWE mode's route in phase 2, under the rule and the sealing module's statement.
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
fn encrypting<'k>(
    mode: ModeName,
    metadata: &'k VerifierMetadata<'k>,
    sealer: &Agreements,
) -> Result<Encrypting<'k>, Refusal> {
    key_rule(mode, metadata, sealer)
        .map(|(key, enc)| Encrypting::Jwe { key, enc })
        .map_err(Refusal::new)
}

#[cfg(feature = "dc-api")]
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

#[cfg(feature = "dc-api")]
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

#[cfg(feature = "uri")]
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
        &JWE_NAMES
    }
}

#[cfg(feature = "uri")]
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

#[cfg(all(feature = "resolve", feature = "dc-api"))]
impl<H> ModeHost<H> for DcApi {
    fn encryption<'k>(
        &self,
        _metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        Ok(Encrypting::Plain)
    }

    /// None: a DC API request posts no `wallet_metadata`.
    fn wallet_metadata(
        &self,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        Ok(Vec::new())
    }
}

#[cfg(all(feature = "resolve", feature = "dc-api"))]
impl<H> ModeHost<H> for DcApiJwt {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        encrypting(self.name(), metadata, sealer)
    }

    /// None: a DC API request posts no `wallet_metadata`.
    fn wallet_metadata(
        &self,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "uri")]
impl<H> ModeHost<H> for DirectPostJwt {
    fn encryption<'k>(
        &self,
        metadata: &'k VerifierMetadata<'k>,
        sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        encrypting(self.name(), metadata, sealer)
    }

    /// `authorization_encryption_alg_values_supported` and
    /// `authorization_encryption_enc_values_supported` (JARM §4, as §5.10 uses them): the key
    /// rule's ECDH-ES on P-256 with A128GCM or A256GCM that `sealer` admits, in its order; none
    /// when it admits neither.
    fn wallet_metadata(
        &self,
        sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        let names = |values: Vec<&'static str>| {
            Node::Array(
                values
                    .into_iter()
                    .map(|value| Node::String(Cow::Borrowed(value)))
                    .collect(),
            )
        };
        let encryptions: Vec<&'static str> = sealer
            .encryptions()
            .iter()
            .filter(|enc| KEY_RULE.encryptions().contains(enc))
            .filter(|enc| sealer.admits(Curve::P_256, KeyAgreement::ECDH_ES, **enc))
            .map(|enc| enc.as_str())
            .collect();
        let [alg, enc] = JWE_NAMES;
        Ok(if encryptions.is_empty() {
            Vec::new()
        } else {
            vec![
                MetadataMember::new(alg, names(vec![KeyAgreement::ECDH_ES.as_str()])),
                MetadataMember::new(enc, names(encryptions)),
            ]
        })
    }
}

/// `direct_post` carries errors alone, in the clear.
#[cfg(feature = "uri")]
impl<H> ModeHost<H> for DirectPost {
    fn encryption<'k>(
        &self,
        _metadata: &'k VerifierMetadata<'k>,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Encrypting<'k>, Refusal> {
        Ok(Encrypting::Plain)
    }

    /// None.
    fn wallet_metadata(
        &self,
        _sealer: &Agreements,
        _host: &H,
    ) -> Result<Vec<MetadataMember>, Fault> {
        Ok(Vec::new())
    }
}
