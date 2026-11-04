//! The wallet's metadata for one POST to a `request_uri` (OpenID4VP §5.10, §10.1; RFC 8414 §2),
//! composed from what each registered part contributes, and the POST's form (feature `uri`); the
//! names registered parts declare, which the registry checks when it builds, in every build.

#[cfg(feature = "uri")]
use std::borrow::Cow;
use std::fmt;

#[cfg(feature = "uri")]
use siros_explain::Explain;

#[cfg(feature = "uri")]
use crate::host::{CoreHost, EphemeralKey};
#[cfg(feature = "uri")]
use crate::ids::ClientId;
#[cfg(feature = "resolve")]
use crate::json::Node;
#[cfg(feature = "uri")]
use crate::plugins::{Fault, Registry};
#[cfg(feature = "uri")]
use crate::{FAULT, detail};

/// How a format's proof carries a profile's response members (B.3.3.1, PaSO Core §6.2, §6.3, CSC
/// §7.2.1): claims of a JSON proof (an SD-JWT VC's Key Binding JWT), or elements of a name space
/// (an mdoc's `DeviceSigned`). A profile places its members by it and names no format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Placement {
    /// Members as claims of a JSON proof ([`Member::claim`](crate::plugins::Member::claim)),
    /// their values JSON.
    Claims,
    /// Members as data elements of a CBOR proof's name spaces
    /// ([`Member::element`](crate::plugins::Member::element)), their values CBOR data items.
    NameSpaces,
}

impl Placement {
    /// Whether a proof of this placement holds `member`: a claim under [`Self::Claims`], a
    /// data element under [`Self::NameSpaces`].
    #[must_use]
    pub const fn places(self, member: &crate::plugins::Member) -> bool {
        matches!(
            (self, member),
            (Self::Claims, crate::plugins::Member::Claim(_))
                | (Self::NameSpaces, crate::plugins::Member::Element { .. })
        )
    }
}

/// A parameter or metadata name (RFC 6749 §8.2's `param-name`: one or more of ASCII letters,
/// digits, `-`, `.` and `_`), the names RFC 8414 metadata and OAuth parameters take. A plug-in
/// makes its own with `siros_explain::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParameterName(&'static str);

impl ParameterName {
    /// The name; `None` for an empty text or another character.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        if rest.is_empty() {
            return None;
        }
        while let [byte, tail @ ..] = rest {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')) {
                return None;
            }
            rest = tail;
        }
        Some(Self(name))
    }

    /// The name as written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ParameterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A name is named by its text in a message.
impl siros_explain::IntoArg for ParameterName {
    type Kind = siros_explain::kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// Where a registered name sits, for the name conflicts the registry refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamePlace {
    /// A member of `wallet_metadata` (§10.1).
    WalletMetadata,
    /// A parameter of the `request_uri` POST beside `wallet_metadata` (§5.10).
    PostParameter,
    /// A member of the Response URI's answer (§8.2).
    AnswerMember,
}

/// The `wallet_metadata` members the core writes itself (§5.10, §10.1): `vp_formats_supported`,
/// `client_id_prefixes_supported`, `request_object_signing_alg_values_supported` and `jwks`.
pub const CORE_METADATA: [ParameterName; 4] = [
    siros_explain::checked!(ParameterName, "vp_formats_supported"),
    siros_explain::checked!(ParameterName, "client_id_prefixes_supported"),
    siros_explain::checked!(ParameterName, "request_object_signing_alg_values_supported"),
    siros_explain::checked!(ParameterName, "jwks"),
];

/// The `request_uri` POST's parameters the core owns (§5.10): `wallet_metadata`, which it writes,
/// and `wallet_nonce`, which it leaves out (decision 12).
pub const CORE_PARAMETERS: [ParameterName; 2] = [
    siros_explain::checked!(ParameterName, "wallet_metadata"),
    siros_explain::checked!(ParameterName, "wallet_nonce"),
];

/// The Response URI answer's member the core reads itself (§8.2): `redirect_uri`.
pub const CORE_ANSWER: [ParameterName; 1] =
    [siros_explain::checked!(ParameterName, "redirect_uri")];

#[cfg(feature = "resolve")]
/// One member a contributor writes into `wallet_metadata`: its declared name and its JSON value.
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataMember {
    name: ParameterName,
    value: Node<'static>,
}

#[cfg(feature = "resolve")]
impl MetadataMember {
    /// The member.
    #[must_use]
    pub const fn new(name: ParameterName, value: Node<'static>) -> Self {
        Self { name, value }
    }

    /// Its name.
    #[must_use]
    pub const fn name(&self) -> ParameterName {
        self.name
    }

    /// Its value.
    #[must_use]
    pub const fn value(&self) -> &Node<'static> {
        &self.value
    }
}

#[cfg(feature = "uri")]
/// One parameter of the `request_uri` POST beside `wallet_metadata`: its declared name and its
/// text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostParameter {
    name: ParameterName,
    value: String,
}

#[cfg(feature = "uri")]
impl PostParameter {
    /// The parameter.
    #[must_use]
    pub const fn new(name: ParameterName, value: String) -> Self {
        Self { name, value }
    }

    /// Its name.
    #[must_use]
    pub const fn name(&self) -> ParameterName {
        self.name
    }

    /// Its text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[cfg(feature = "uri")]
/// What a contribution writes into one POST.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PostContent {
    /// Its `wallet_metadata` members.
    pub members: Vec<MetadataMember>,
    /// Its POST parameters.
    pub parameters: Vec<PostParameter>,
}

#[cfg(feature = "uri")]
/// Members of `wallet_metadata` and parameters of the `request_uri` POST a profile or a deployment
/// adds (§10.1: "Additional Wallet metadata parameters MAY be defined and used"; §5.10:
/// "Additional parameters MAY be defined and used in the request to the Request URI Endpoint").
///
/// # Implementing
///
/// `members` and `parameters` are constants: the registry refuses a name another registered part
/// declares (`NameTwice`) and a name the core writes (`NameReserved`): the members
/// [`CORE_METADATA`], the parameters [`CORE_PARAMETERS`]. The phase-2 half
/// [`PostContributionHost`] writes members and parameters of declared names alone; the core
/// refuses another name with [`MetadataRefused::Undeclared`]. `siros-testkit`'s
/// `TestPostContribution` is the double.
pub trait PostContribution: dyn_clone::DynClone + Send + Sync {
    /// The `wallet_metadata` members it writes.
    fn members(&self) -> &'static [ParameterName];
    /// The POST parameters it writes beside `wallet_metadata`.
    fn parameters(&self) -> &'static [ParameterName];
}

#[cfg(feature = "uri")]
/// The phase-2 half of [`PostContribution`] over the build's host: its bounds name the modules
/// it calls.
pub trait PostContributionHost<H>: PostContribution {
    /// What it writes into this POST.
    ///
    /// # Errors
    ///
    /// The contribution cannot write: a module it calls failed, or its bug.
    fn write(&self, host: &H) -> Result<PostContent, Fault>;
}

#[cfg(feature = "uri")]
/// A contribution the registry takes.
pub trait HostedPostContribution<H>: PostContributionHost<H> {}

#[cfg(feature = "uri")]
impl<H, C: PostContributionHost<H>> HostedPostContribution<H> for C {}

#[cfg(feature = "uri")]
dyn_clone::clone_trait_object!(<H> HostedPostContribution<H>);

#[cfg(feature = "uri")]
/// `wallet_metadata`: a JSON object, as the POST carries it, and the POST parameters its
/// contributors wrote in the same pass. Only [`WalletMetadata::of`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMetadata {
    json: String,
    parameters: Vec<PostParameter>,
}

#[cfg(feature = "uri")]
/// Contributions that make no `wallet_metadata`. The registry refused every name conflict when it
/// built, so what remains is a contributor that broke its declaration.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.wallet_metadata")]
pub enum MetadataRefused {
    /// A contributor wrote a name it did not declare.
    #[error("a contributor wrote {0}, which it did not declare")]
    Undeclared(#[explain(name = "member")] ParameterName),
    /// A contribution that is no JSON object where §10.1 asks for one: a format's
    /// `vp_formats_supported` value.
    #[error("the wallet_metadata member {0} is no JSON object")]
    NotObject(#[explain(name = "member")] String),
    /// A contributor broke its contract.
    #[error(transparent)]
    Fault(#[from] Fault),
}

#[cfg(feature = "uri")]
impl WalletMetadata {
    /// Each member from its one contributor: `vp_formats_supported`, each registered format's
    /// `Format::wallet_formats` under its `Format::id` (§10.1: REQUIRED; Appendix B);
    /// `client_id_prefixes_supported`, the registered prefixes' names (§10.1; without it a
    /// Verifier reads `pre-registered`, which A2 refuses), when the build registers one; when
    /// the outer `client_id` names a registered prefix, each of which authenticates signed
    /// Request Objects, `request_object_signing_alg_values_supported`, the algorithms its
    /// registration's `Haip::verifies` states (§5.10: SHOULD); each registered URI mode's members
    /// (`ModeHost::wallet_metadata`: `direct_post.jwt`'s `authorization_encryption_*`, §5.10:
    /// SHOULD for an encrypted response); with `EncryptedRequests`, `jwks` holding `key`'s public
    /// JWK with `use` `enc` (§5.10: SHOULD; CS-12 §7.3 item 9); each registered contribution's
    /// members. Each contribution writes once, its POST parameters kept for [`RequestUriPost`].
    ///
    /// # Errors
    ///
    /// [`MetadataRefused`]: a contributor wrote an undeclared name or a POST parameter twice, a
    /// format's member is no object, or a contributor or the key's JWK broke its contract.
    pub fn of<H: CoreHost>(
        registry: &Registry<H>,
        host: &H,
        client_id: &ClientId<'_>,
        key: Option<&EphemeralKey>,
    ) -> Result<Self, MetadataRefused> {
        let fault = |e| Fault::caused(FAULT, detail!("the wallet metadata"), e);
        let names = |values: &mut dyn Iterator<Item = &'static str>| {
            Node::Array(
                values
                    .map(|value| Node::String(Cow::Borrowed(value)))
                    .collect(),
            )
        };
        let mut members: Vec<(Cow<'static, str>, Node<'static>)> = Vec::new();
        let formats = registry
            .formats()
            .map(|format| {
                let value = format.wallet_formats()?;
                if value.as_object().is_none() {
                    return Err(MetadataRefused::NotObject(format!(
                        "vp_formats_supported.{}",
                        format.id()
                    )));
                }
                Ok((Cow::Owned(format.id().to_string()), value))
            })
            .collect::<Result<Vec<_>, MetadataRefused>>()?;
        members.push((
            Cow::Borrowed("vp_formats_supported"),
            Node::object(formats).map_err(fault)?,
        ));
        let prefixes: Vec<&'static str> =
            registry.prefix_names().map(|name| name.as_str()).collect();
        if !prefixes.is_empty() {
            members.push((
                Cow::Borrowed("client_id_prefixes_supported"),
                names(&mut prefixes.into_iter()),
            ));
        }
        let verifies = client_id
            .prefixed()
            .and_then(|(prefix, _)| registry.client_prefix(prefix))
            .map(|(_, haip)| haip(host).verifies());
        if let Some(verifies) = verifies {
            members.push((
                Cow::Borrowed("request_object_signing_alg_values_supported"),
                names(&mut verifies.algorithms().iter().map(|alg| alg.as_str())),
            ));
        }
        for (declared, written) in registry.mode_metadata(host)? {
            members.extend(declared_members(declared, written)?);
        }
        if let Some(key) = key {
            members.push((
                Cow::Borrowed("jwks"),
                Node::object([(Cow::Borrowed("keys"), Node::Array(vec![jwk(key)?]))])
                    .map_err(fault)?,
            ));
        }
        let mut parameters: Vec<PostParameter> = Vec::new();
        for contribution in registry.contributions() {
            let PostContent {
                members: written,
                parameters: posted,
            } = contribution.write(host)?;
            members.extend(declared_members(contribution.members(), written)?);
            for parameter in posted {
                if !contribution.parameters().contains(&parameter.name) {
                    return Err(MetadataRefused::Undeclared(parameter.name));
                }
                if parameters.iter().any(|known| known.name == parameter.name) {
                    return Err(Fault::new(
                        FAULT,
                        detail!(
                            "a contribution wrote the POST parameter {name} twice",
                            name = parameter.name
                        ),
                    )
                    .into());
                }
                parameters.push(parameter);
            }
        }
        let object = Node::object(members).map_err(fault)?;
        Ok(Self {
            json: object.python_compact().to_string(),
            parameters,
        })
    }

    /// The JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.json
    }
}

#[cfg(feature = "uri")]
/// A contributor's members as `wallet_metadata` holds them, each of a name it declared.
fn declared_members(
    declared: &'static [ParameterName],
    written: Vec<MetadataMember>,
) -> Result<Vec<(Cow<'static, str>, Node<'static>)>, MetadataRefused> {
    written
        .into_iter()
        .map(|MetadataMember { name, value }| {
            if declared.contains(&name) {
                Ok((Cow::Borrowed(name.as_str()), value))
            } else {
                Err(MetadataRefused::Undeclared(name))
            }
        })
        .collect()
}

#[cfg(feature = "uri")]
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

#[cfg(feature = "uri")]
/// The `request_uri` POST's form (§5.10): `wallet_metadata`, a JSON string, then each registered
/// contribution's parameters in registration order; §5.10's `wallet_nonce` stays out (decision
/// 12). It serializes as a map of text members, which `FormBody::of` writes.
#[derive(Debug)]
pub struct RequestUriPost<'a> {
    wallet_metadata: &'a WalletMetadata,
}

#[cfg(feature = "uri")]
impl serde::Serialize for RequestUriPost<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let parameters = &self.wallet_metadata.parameters;
        let mut map = serializer.serialize_map(Some(1 + parameters.len()))?;
        map.serialize_entry("wallet_metadata", &self.wallet_metadata.json)?;
        for parameter in parameters {
            map.serialize_entry(parameter.name.as_str(), &parameter.value)?;
        }
        map.end()
    }
}

#[cfg(feature = "uri")]
impl<'a> RequestUriPost<'a> {
    /// The form of the metadata and its contributors' parameters.
    #[must_use]
    pub const fn of(wallet_metadata: &'a WalletMetadata) -> Self {
        Self { wallet_metadata }
    }
}
