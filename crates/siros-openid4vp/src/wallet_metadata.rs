//! The wallet's metadata for one POST to a `request_uri` (OpenID4VP §5.10, §10.1; RFC 8414 §2),
//! and the POST's form.

use std::borrow::Cow;

use crate::host::EphemeralKey;
use crate::jose::JwsAlgorithms;
use crate::json::Node;
use crate::plugins::{Fault, Registry};
use crate::request::{Agreements, ContentEncryption, Curve, KeyAgreement};
use crate::{FAULT, detail};

/// `wallet_metadata`: a JSON object, as the POST carries it. Only [`WalletMetadata::of`] makes
/// one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct WalletMetadata(String);

impl WalletMetadata {
    /// What §5.10 and CS-12 ask, and no more, each list from its one owner:
    /// `vp_formats_supported`, each registered format's member under its `Format::id` (§10.1:
    /// REQUIRED; Appendix B); `request_object_signing_alg_values_supported`, what the verifying
    /// module `verifies`, given when the outer `client_id` names a registered prefix (§5.10:
    /// SHOULD); `authorization_encryption_alg_values_supported` and
    /// `authorization_encryption_enc_values_supported`, the key rule's ECDH-ES on P-256 with
    /// A128GCM or A256GCM that the `agreements` of the `Haip` a registered JWE mode by URI
    /// bounded state, in the module's order (§5.10: SHOULD for an encrypted response), absent
    /// when it states none or no such mode is registered; `jwks` holding the key with `use` `enc`
    /// when there is one (§5.10: SHOULD; CS-12 §7.3 item 9).
    ///
    /// # Errors
    ///
    /// A format's member breaks JSON's rules, or the key's JWK names another `use`: a plug-in's
    /// or a module's bug.
    pub fn of<H>(
        registry: &Registry<H>,
        key: Option<&EphemeralKey>,
        verifies: Option<JwsAlgorithms>,
        host: &H,
    ) -> Result<Self, Fault> {
        let agreements = registry.uri_sealer(host).unwrap_or(Agreements::NONE);
        let fault = |e| Fault::caused(FAULT, detail!("the wallet metadata"), e);
        let names = |values: &mut dyn Iterator<Item = &'static str>| {
            Node::Array(
                values
                    .map(|value| Node::String(Cow::Borrowed(value)))
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
        let jwks = key
            .map(|key| {
                Node::object([(Cow::Borrowed("keys"), Node::Array(vec![jwk(key)?]))]).map_err(fault)
            })
            .transpose()?;
        let encryptions: Vec<&'static str> = agreements
            .encryptions()
            .iter()
            .filter(|enc| KEY_RULE_ENCRYPTIONS.contains(enc))
            .filter(|enc| agreements.admits(Curve::P_256, KeyAgreement::ECDH_ES, **enc))
            .map(|enc| enc.as_str())
            .collect();
        let encrypting = !encryptions.is_empty();
        let members = [
            Some(("vp_formats_supported", formats)),
            verifies.map(|verifies| {
                (
                    "request_object_signing_alg_values_supported",
                    names(&mut verifies.algorithms().iter().map(|alg| alg.as_str())),
                )
            }),
            encrypting.then(|| {
                (
                    "authorization_encryption_alg_values_supported",
                    names(&mut std::iter::once(KeyAgreement::ECDH_ES.as_str())),
                )
            }),
            encrypting.then(|| {
                (
                    "authorization_encryption_enc_values_supported",
                    names(&mut encryptions.into_iter()),
                )
            }),
            jwks.map(|jwks| ("jwks", jwks)),
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

/// The content encryptions of the key rule the JWE modes answer under (§8.3, HAIP §5).
const KEY_RULE_ENCRYPTIONS: [ContentEncryption<'static>; 2] =
    [ContentEncryption::A128GCM, ContentEncryption::A256GCM];

/// The key's public JWK as `jwks` holds it: its members, and `use` `enc`.
fn jwk(key: &EphemeralKey) -> Result<Node<'static>, Fault> {
    let public = key.public().object();
    match public.get("use").map(Node::as_str) {
        None | Some(Some("enc")) => {}
        Some(_) => {
            return Err(Fault::new(
                FAULT,
                detail!("the ephemeral key's JWK names another use than enc"),
            ));
        }
    }
    let mut members: Vec<_> = public
        .members()
        .iter()
        .filter(|member| member.name != "use")
        .map(|member| (member.name.clone(), member.value.clone()))
        .collect();
    members.push((Cow::Borrowed("use"), Node::String(Cow::Borrowed("enc"))));
    Node::object(members).map_err(|e| Fault::caused(FAULT, detail!("the ephemeral key's JWK"), e))
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
