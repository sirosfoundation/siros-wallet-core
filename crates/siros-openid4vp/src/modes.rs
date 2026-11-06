//! The core's response modes (§8.2, §8.3, A.2), peers of any extension's: `dc_api` and
//! `dc_api.jwt` over the DC API, `direct_post.jwt` and `direct_post` by URI. The JWE modes share
//! HAIP §5's key rule (§8.3; reading 25) and its refusal, C7; a build registers them with
//! `jwe_mode`, `dc_api` with `mode`, and `direct_post` with `error_mode` alone. The DC API modes
//! compile under the feature `dc-api`, the URI modes under `uri`; the key rule in every build.

use siros_explain::Explain;

#[cfg(feature = "uri")]
use std::borrow::Cow;

#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::host::SealedJwe;
#[cfg(feature = "uri")]
use crate::json::Node;
#[cfg(all(feature = "resolve", feature = "dc-api"))]
use crate::json::quote;
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::plugins::Fault;
#[cfg(feature = "uri")]
use crate::refusal::ErrorDescription;
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::refusal::Refusal;
use crate::refusal::{ErrorCode, RequestRule};
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::request::Request;
use crate::request::{Agreements, ContentEncryption, Curve, KeyAgreement};
#[cfg(all(feature = "resolve", feature = "dc-api"))]
use crate::resolve::DcApiData;
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::resolve::{AnswerContent, Body, ModeRoute};
#[cfg(feature = "uri")]
use crate::resolve::{ErrorContent, ErrorResponse, PostBody};
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::routing::{ChannelKind, Mode};
#[cfg(feature = "uri")]
use crate::routing::{Echo, ErrorModeHost};
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::routing::{Encrypting, ModeHost};
use crate::routing::{ModeName, VerifierKey, VerifierMetadata};
#[cfg(feature = "uri")]
use crate::uri::FormBody;
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::wallet_metadata::MetadataMember;
#[cfg(any(feature = "dc-api", feature = "uri"))]
use crate::wallet_metadata::ParameterName;
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
use crate::{FAULT, detail};

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

/// `direct_post.jwt`'s form (§8.3.1): `response`, the compact JWE.
#[cfg(all(feature = "uri", feature = "resolve"))]
#[derive(Debug, serde::Serialize)]
pub struct ResponseForm<'a> {
    response: &'a str,
}

#[cfg(all(feature = "uri", feature = "resolve"))]
impl<'a> ResponseForm<'a> {
    /// The form of the JWE.
    #[must_use]
    pub fn of(jwe: &'a SealedJwe) -> Self {
        Self {
            response: jwe.as_str(),
        }
    }
}

/// §8.2's plain error form, in this order: `error`; `error_description` when the error has one;
/// `state` when the request has one, as received (RFC 6749 §4.1.2.1).
#[cfg(all(feature = "uri", feature = "resolve"))]
#[derive(Debug, serde::Serialize)]
pub struct ErrorForm<'a> {
    error: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<&'a ErrorDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a Echo<'a>>,
}

#[cfg(all(feature = "uri", feature = "resolve"))]
impl<'a> ErrorForm<'a> {
    /// The form of the error.
    #[must_use]
    pub const fn of(error: &'a ErrorResponse<'a>) -> Self {
        Self {
            error: error.code(),
            error_description: error.description(),
            state: error.echo(),
        }
    }
}

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
            key.kty().as_str() == "EC"
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

/// The DC API data of a JSON text the mode wrote.
#[cfg(all(feature = "resolve", feature = "dc-api"))]
fn data(text: String) -> Result<Body, Fault> {
    DcApiData::of(text)
        .map(Body::DcApi)
        .map_err(|e| Fault::caused(FAULT, detail!("the DC API data"), e))
}

/// The JWE a JWE mode wraps. A clear answer on its route is a `Fault`.
#[cfg(all(feature = "resolve", any(feature = "dc-api", feature = "uri")))]
fn sealed<'a>(mode: ModeName, content: &AnswerContent<'a>) -> Result<&'a SealedJwe, Fault> {
    match content {
        AnswerContent::Sealed(jwe) => Ok(jwe),
        AnswerContent::Clear(_) => Err(Fault::new(
            FAULT,
            detail!("{name}'s route holds a key", name = mode),
        )),
    }
}

/// The form body of the members. A `NotForm` refusal is a `Fault`.
#[cfg(feature = "uri")]
fn form(members: &impl serde::Serialize) -> Result<PostBody, Fault> {
    FormBody::of(members)
        .map(PostBody::form)
        .map_err(|e| Fault::caused(FAULT, detail!("a mode's form body"), e))
}

#[cfg(feature = "dc-api")]
impl Mode for DcApi {
    fn name(&self) -> ModeName {
        siros_explain::checked!(ModeName, "dc_api")
    }

    fn channel(&self) -> ChannelKind {
        ChannelKind::DcApi
    }

    fn rules(&self, _: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
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

    fn rules(&self, _: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
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

    fn rules(&self, _: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
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

    fn rules(&self, _: &Request<'_>, _metadata: &VerifierMetadata<'_>) -> Vec<Refusal> {
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

    /// The Authorization Response itself as the DigitalCredential's `data` (A.2).
    fn answer(
        &self,
        _route: &ModeRoute<'_>,
        content: &AnswerContent<'_>,
        _host: &H,
    ) -> Result<Body, Fault> {
        match content {
            AnswerContent::Clear(response) => data(response.json()),
            AnswerContent::Sealed(_) => {
                Err(Fault::new(FAULT, detail!("dc_api's route is in the clear")))
            }
        }
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

    /// `{"response": JWE}` (A.2, §8.3).
    fn answer(
        &self,
        _route: &ModeRoute<'_>,
        content: &AnswerContent<'_>,
        _host: &H,
    ) -> Result<Body, Fault> {
        let jwe = sealed(self.name(), content)?;
        data(format!("{{\"response\":{}}}", quote(jwe.as_str())))
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

    /// `response=<JWE>`, POSTed (§8.3.1).
    fn answer(
        &self,
        _route: &ModeRoute<'_>,
        content: &AnswerContent<'_>,
        _host: &H,
    ) -> Result<Body, Fault> {
        let jwe = sealed(self.name(), content)?;
        form(&ResponseForm::of(jwe)).map(Body::Post)
    }
}

/// §8.2's plain form; the core seals nothing on its route.
#[cfg(feature = "uri")]
impl<H> ErrorModeHost<H> for DirectPost {
    fn error(
        &self,
        _route: &ModeRoute<'_>,
        content: &ErrorContent<'_>,
        _host: &H,
    ) -> Result<PostBody, Fault> {
        match content {
            ErrorContent::Clear(error) => form(&ErrorForm::of(error)),
            ErrorContent::Sealed(_) => Err(Fault::new(
                FAULT,
                detail!("direct_post's route is in the clear"),
            )),
        }
    }
}

/// `response=<JWE>` on a route with a key; §8.2's plain form without one (§8.3.1: "it MAY send
/// an error response without encryption").
#[cfg(feature = "uri")]
impl<H> ErrorModeHost<H> for DirectPostJwt {
    fn error(
        &self,
        _route: &ModeRoute<'_>,
        content: &ErrorContent<'_>,
        _host: &H,
    ) -> Result<PostBody, Fault> {
        match content {
            ErrorContent::Sealed(jwe) => form(&ResponseForm::of(jwe)),
            ErrorContent::Clear(error) => form(&ErrorForm::of(error)),
        }
    }
}
