//! The wallet's metadata for one POST to a `request_uri` (OpenID4VP §5.10, §10.1; RFC 8414 §2),
//! and the POST's form.

use std::borrow::Cow;

use crate::host::EphemeralKey;
use crate::json::Node;
use crate::plugins::{Fault, Registry};
use crate::{FAULT, detail};

/// `wallet_metadata`: a JSON object, as the POST carries it. Only [`WalletMetadata::of`] makes
/// one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct WalletMetadata(String);

impl WalletMetadata {
    /// What §5.10 and CS-12 ask, and no more: `vp_formats_supported`, each registered format's
    /// member under its `Format::id` (§10.1: REQUIRED; Appendix B);
    /// `request_object_signing_alg_values_supported` `["ES256"]` when `signed`, the outer
    /// `client_id` naming a registered prefix, each of which signs (§5.10: SHOULD; HAIP §7);
    /// `authorization_encryption_alg_values_supported` `["ECDH-ES"]` and
    /// `authorization_encryption_enc_values_supported` `["A128GCM", "A256GCM"]` (§5.10: SHOULD
    /// for an encrypted response; HAIP §5); `jwks` holding the key with `use` `enc` (§5.10:
    /// SHOULD; CS-12 §7.3 item 9).
    ///
    /// # Errors
    ///
    /// A format's member breaks JSON's rules, a plug-in's bug.
    pub fn of<H>(registry: &Registry<H>, key: &EphemeralKey, signed: bool) -> Result<Self, Fault> {
        let fault = |e| Fault::caused(FAULT, detail!("the wallet metadata"), e);
        let names = |values: &[&'static str]| {
            Node::Array(
                values
                    .iter()
                    .map(|value| Node::String(Cow::Borrowed(*value)))
                    .collect(),
            )
        };
        let formats = registry
            .formats()
            .map(|format| {
                Ok((
                    Cow::Owned(format.id().to_string()),
                    format.wallet_formats()?,
                ))
            })
            .collect::<Result<Vec<_>, Fault>>()?;
        let formats = Node::object(formats).map_err(fault)?;
        let jwks = Node::object([(
            Cow::Borrowed("keys"),
            Node::Array(vec![key.jwk().map_err(fault)?]),
        )])
        .map_err(fault)?;
        let members = [
            Some(("vp_formats_supported", formats)),
            signed.then(|| {
                (
                    "request_object_signing_alg_values_supported",
                    names(&["ES256"]),
                )
            }),
            Some((
                "authorization_encryption_alg_values_supported",
                names(&["ECDH-ES"]),
            )),
            Some((
                "authorization_encryption_enc_values_supported",
                names(&["A128GCM", "A256GCM"]),
            )),
            Some(("jwks", jwks)),
        ];
        let object = Node::object(
            members
                .into_iter()
                .flatten()
                .map(|(name, value)| (Cow::Borrowed(name), value)),
        )
        .map_err(fault)?;
        Ok(Self(object.python_compact().to_string()))
    }

    /// The JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `request_uri` POST's form (§5.10): `wallet_metadata`, a JSON string; §5.10's
/// `wallet_nonce` stays out (decision 12).
#[derive(Debug, serde::Serialize)]
pub struct RequestUriPost<'a> {
    wallet_metadata: &'a WalletMetadata,
}

impl<'a> RequestUriPost<'a> {
    /// The form of the metadata.
    #[must_use]
    pub const fn of(wallet_metadata: &'a WalletMetadata) -> Self {
        Self { wallet_metadata }
    }
}
