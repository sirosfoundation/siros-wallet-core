//! Proof Metadata §5: the ad-hoc metadata JWT a PaSO entry may carry. The matcher reads it as it
//! reads a signed request, its payload parsed and unverified ([`Carried`]; section 4.14 of the
//! design). The wallet verifies it as §5.3 states before it relies on it: in phase 2, and in the
//! URI flow before it converts it (`Verified`). A JWT that fails a step makes the entry
//! incompatible for the credential, the stored metadata never standing in; the profile knows each
//! failure ([`AdhocRefusal`]).

use siros_explain::Explain;
use siros_openid4vp::envelope::Channel;
use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::jose::{CompactJws, JwsError};
use siros_openid4vp::json::Node;
use siros_openid4vp::request::Request;

use crate::rulebook::PasoType;

/// The `typ` of an ad-hoc metadata JWT (§5.2).
pub const TYP: &str = "adhoc-transaction-metadata+jwt";

/// Why an entry's ad-hoc metadata JWT is not relied on: it does not read (§5.2), or it fails a
/// §5.3 step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.adhoc")]
pub enum AdhocFailure {
    /// No compact JWS (RFC 7515 §7.1).
    #[error(transparent)]
    Jws(#[from] JwsError),
    /// The payload is no JSON object with unique member names.
    #[error("the payload is not a JSON object")]
    NotObject,
    /// §5.2: the payload's `metadata` is no object.
    #[error("the payload holds no metadata object")]
    Metadata,
    /// Step 1: the `typ`.
    #[error("typ {0:?}")]
    Typ(#[explain(name = "typ")] Option<String>),
    /// Step 2: the signature, or an `alg` the verifying module does not verify.
    #[error("the signature does not verify")]
    Signature,
    /// Step 3, x5c-based keys: no `x5c` chain, a `kid`, or a chain without a path to the
    /// wallet's trust store.
    #[error("no x5c chain to the wallet's trust store")]
    Untrusted,
    /// Step 3, key-set keys: no `kid` of the credential issuer's key set, or a chain.
    #[error("signed by no key of the credential issuer's key set")]
    UnknownKey,
    /// Step 4: `iss`.
    #[error("iss is not the credential's issuer")]
    Issuer,
    /// Step 5: `exp` passed, or no integer `exp` (§5.2).
    #[error("expired, or no integer exp")]
    Expired,
    /// Step 6: `sub` and `format`.
    #[error("sub and format are not the credential's type and format")]
    Binding,
    /// Step 6, x5c-based keys: the chain's root or its leaf's subject is not the credential's.
    #[error("the chain's root or leaf subject is not the credential's")]
    ForeignChain,
    /// Step 7: `transaction_data_type`.
    #[error("transaction_data_type is not the entry's type")]
    TransactionType,
    /// A request of the URI flow whose JWT the wallet has not verified for the credential.
    #[error("not verified for the credential")]
    Unverified,
}

/// An ad-hoc metadata JWT as received, read or not: the identity a verification is kept under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdhocJwt(String);

impl AdhocJwt {
    /// The JWT of this text.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An entry's ad-hoc metadata JWT the profile does not rely on for a credential, with the step it
/// fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdhocRefusal {
    /// The JWT.
    pub jwt: AdhocJwt,
    /// The credential.
    pub credential: CredentialId<'static>,
    /// The step it fails.
    pub failure: AdhocFailure,
}

/// An ad-hoc metadata JWT read as the matcher reads a signed request: a compact JWS (RFC 7515
/// §7.1) whose payload is a JSON object holding a `metadata` object, unverified.
#[derive(Debug, Clone)]
pub struct Read<'j> {
    jws: CompactJws<'j>,
    /// The payload, whose claims phase 2 verifies.
    #[cfg(feature = "resolve")]
    payload: Node<'static>,
    metadata: Node<'static>,
}

impl<'j> Read<'j> {
    /// The JWT read.
    ///
    /// # Errors
    ///
    /// [`AdhocFailure::Jws`], [`AdhocFailure::NotObject`] or [`AdhocFailure::Metadata`].
    pub fn parse(text: &'j str) -> Result<Self, AdhocFailure> {
        let jws = CompactJws::parse(text)?;
        let payload = Node::parse(jws.payload())
            .map_err(|_| AdhocFailure::NotObject)?
            .into_owned();
        if payload.as_object().is_none() {
            return Err(AdhocFailure::NotObject);
        }
        let metadata = payload
            .get("metadata")
            .filter(|metadata| metadata.as_object().is_some())
            .cloned()
            .ok_or(AdhocFailure::Metadata)?;
        Ok(Self {
            jws,
            #[cfg(feature = "resolve")]
            payload,
            metadata,
        })
    }

    /// The JWT as received.
    #[must_use]
    pub fn text(&self) -> &str {
        self.jws.text()
    }

    /// The payload's `metadata`, an object.
    #[must_use]
    pub const fn metadata(&self) -> &Node<'static> {
        &self.metadata
    }

    /// A payload member.
    #[cfg(feature = "resolve")]
    fn member(&self, name: &str) -> Option<&Node<'static>> {
        self.payload.get(name)
    }
}

/// The ad-hoc metadata JWT of each entry of a request that carries one, with the entry's type.
type Jwts<'r> = Vec<(PasoType<'r>, Read<'r>)>;

/// Each entry's JWT read as a signed request is read.
fn jwts<'r>(request: &'r Request<'r>) -> Jwts<'r> {
    request
        .entries()
        .iter()
        .filter_map(|entry| {
            let jwt = entry.members().get("metadata").and_then(Node::as_str)?;
            let kind = PasoType::parse(entry.kind().as_str()).ok()?;
            Read::parse(jwt).ok().map(|read| (kind, read))
        })
        .collect()
}

/// The matcher's ad-hoc metadata JWTs of a DC API request: each entry's JWT read as a signed
/// request is read, unverified (section 4.14 of the design). A JWT that does not read is left
/// out, and the profile's binding refuses its entry.
#[derive(Debug, Clone)]
pub struct Carried<'r> {
    read: Jwts<'r>,
}

impl<'r> Carried<'r> {
    /// The JWTs of a DC API request.
    ///
    /// # Errors
    ///
    /// [`UriFlow`]: a request of the URI flow, whose JWTs the wallet verifies before it converts
    /// them (`Verified`).
    pub fn read(request: &'r Request<'r>) -> Result<Self, UriFlow> {
        match request.envelope().channel() {
            Channel::DcApi(_) => Ok(Self {
                read: jwts(request),
            }),
            Channel::Uri => Err(UriFlow),
        }
    }

    /// Each JWT read, with its entry's type.
    pub fn jwts(&self) -> impl Iterator<Item = (&PasoType<'r>, &Read<'r>)> {
        self.read.iter().map(|(kind, read)| (kind, read))
    }
}

/// A request of the URI flow given to the matcher's reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.adhoc_channel")]
#[error("a request of the URI flow: its ad-hoc metadata is verified before it converts")]
pub struct UriFlow;

/// An ad-hoc metadata JWT the wallet verified for a credential (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Relied {
    /// The JWT.
    pub(crate) jwt: AdhocJwt,
    /// The credential.
    pub(crate) credential: CredentialId<'static>,
}

#[cfg(feature = "resolve")]
mod verify {
    use siros_openid4vp::detail;
    use siros_openid4vp::host::{Haip, Platform, Timestamp};
    use siros_openid4vp::ids::FormatId;
    use siros_openid4vp::jose::{PublicJwk, VerificationKey};
    use siros_openid4vp::json::Node;
    use siros_openid4vp::plugins::Fault;
    use siros_openid4vp::request::Request;
    use siros_openid4vp::wallet::Credential;
    use siros_x509::X5c;

    use super::{AdhocFailure, AdhocJwt, AdhocRefusal, Jwts, Read, Relied, TYP, jwts};
    use crate::FAULT;
    use crate::document::{DOCUMENT, Issuer, PasoDocument};
    use crate::modules::IssuerTrust;
    use crate::rulebook::PasoType;

    /// The wallet's modules a JWT verifies through: HAIP's signature verification, the trust
    /// store of credential issuers, and the clock.
    #[derive(Clone, Copy)]
    pub(crate) struct Modules<'m> {
        pub(crate) haip: &'m dyn Haip,
        pub(crate) trust: &'m dyn IssuerTrust,
        pub(crate) now: Timestamp,
    }

    impl<'m> Modules<'m> {
        /// The host's modules.
        pub(crate) fn of<H>(host: &'m H) -> Self
        where
            H: siros_openid4vp::host::Has<dyn Platform>
                + siros_openid4vp::host::Has<dyn Haip>
                + siros_openid4vp::host::Has<dyn IssuerTrust>,
        {
            Self {
                haip: siros_openid4vp::host::Has::<dyn Haip>::module(host),
                trust: siros_openid4vp::host::Has::<dyn IssuerTrust>::module(host),
                now: siros_openid4vp::host::Has::<dyn Platform>::module(host).now(),
            }
        }
    }

    /// What a JWT binds to: the credential's document and format, and the entry's type.
    pub(crate) struct Binding<'b> {
        pub(crate) document: &'b PasoDocument<'b>,
        pub(crate) format: &'b FormatId<'b>,
        pub(crate) kind: &'b PasoType<'b>,
    }

    impl Read<'_> {
        /// §5.3's steps, in order; step 3 finds the key step 2 verifies under, so a key that
        /// fails step 3 is refused before the signature is checked.
        pub(crate) fn verify(
            &self,
            binding: &Binding<'_>,
            modules: Modules<'_>,
        ) -> Result<(), AdhocFailure> {
            let header = self.jws.header();
            if header.typ().map(|typ| typ.as_str()) != Some(TYP) {
                return Err(AdhocFailure::Typ(
                    header.typ().map(|typ| typ.as_str().to_owned()),
                ));
            }
            let x5c = header.member("x5c").is_some();
            let kid = header.kid();
            let (key, chain) = match &binding.document.issuer {
                Issuer::Chain { root, subject, .. } => {
                    if kid.is_some() || !x5c {
                        return Err(AdhocFailure::Untrusted);
                    }
                    let chain = X5c::of(header).map_err(|_| AdhocFailure::Untrusted)?;
                    let anchor = modules
                        .trust
                        .anchor(&chain, modules.now)
                        .ok_or(AdhocFailure::Untrusted)?;
                    let key = chain.leaf().key().map_err(|_| AdhocFailure::Untrusted)?;
                    let leaf = chain
                        .leaf()
                        .subject()
                        .map_err(|_| AdhocFailure::Untrusted)?;
                    let foreign = anchor.der() != root.bytes() || leaf != subject.bytes();
                    (key, Some(foreign))
                }
                Issuer::KeySet { keys, .. } => {
                    let jwk = kid
                        .filter(|_| !x5c)
                        .and_then(|kid| keys.get(kid.as_str()))
                        .ok_or(AdhocFailure::UnknownKey)?;
                    let jwk =
                        PublicJwk::parse(jwk.clone()).map_err(|_| AdhocFailure::UnknownKey)?;
                    (VerificationKey::of(jwk), None)
                }
            };
            let signed = self.jws.signed();
            if !modules.haip.verifies().accepts(header.alg())
                || modules.haip.verify(&key, &signed).is_err()
            {
                return Err(AdhocFailure::Signature);
            }
            let text = |name: &str| self.member(name).and_then(Node::as_str);
            if text("iss") != Some(binding.document.issuer.iss()) {
                return Err(AdhocFailure::Issuer);
            }
            let live = match self.member("exp") {
                Some(Node::Number(exp)) if exp.is_integer() => {
                    exp.as_u64().is_some_and(|exp| modules.now.0 < exp)
                }
                _ => false,
            };
            if !live {
                return Err(AdhocFailure::Expired);
            }
            if text("sub") != Some(binding.document.credential_type)
                || text("format") != Some(binding.format.as_str())
            {
                return Err(AdhocFailure::Binding);
            }
            if chain == Some(true) {
                return Err(AdhocFailure::ForeignChain);
            }
            if text("transaction_data_type") != Some(binding.kind.as_str()) {
                return Err(AdhocFailure::TransactionType);
            }
            Ok(())
        }
    }

    /// The wallet's ad-hoc metadata JWTs of a request, each verified for each credential holding
    /// a PaSO document (§5.3): the JWTs some credential verifies, which convert in the URI flow
    /// (`view::verified`), the credentials each verifies for, and the refusals, each JWT for each
    /// credential it fails for. A profile given them ([`PasoProfile::with_verified`]) relies in
    /// the URI flow on a JWT for the credentials it verified for alone.
    ///
    /// [`PasoProfile::with_verified`]: crate::PasoProfile::with_verified
    #[derive(Debug, Clone)]
    pub struct Verified<'r> {
        read: Jwts<'r>,
        pub(crate) relied: Vec<Relied>,
        refusals: Vec<AdhocRefusal>,
    }

    impl<'r> Verified<'r> {
        /// Each JWT of the request verified for each credential through the host's modules.
        ///
        /// # Errors
        ///
        /// A [`Fault`]: a credential's PaSO document does not read.
        pub fn of<H>(
            request: &'r Request<'r>,
            credentials: &[&Credential<'_>],
            host: &H,
        ) -> Result<Self, Fault>
        where
            H: siros_openid4vp::host::Has<dyn Platform>
                + siros_openid4vp::host::Has<dyn Haip>
                + siros_openid4vp::host::Has<dyn IssuerTrust>,
        {
            let modules = Modules::of(host);
            let mut kept = Vec::new();
            let mut relied = Vec::new();
            let mut refusals = Vec::new();
            for (kind, jwt) in jwts(request) {
                let mut verified = false;
                for credential in credentials {
                    let Some(bytes) = credential.document(DOCUMENT) else {
                        continue;
                    };
                    let node = PasoDocument::json(bytes)
                        .map_err(|e| Fault::caused(FAULT, detail!("the PaSO document"), e))?;
                    let document = PasoDocument::read(&node)
                        .map_err(|e| Fault::caused(FAULT, detail!("the PaSO document"), e))?;
                    let binding = Binding {
                        document: &document,
                        format: &credential.format,
                        kind: &kind,
                    };
                    match jwt.verify(&binding, modules) {
                        Ok(()) => {
                            verified = true;
                            relied.push(Relied {
                                jwt: AdhocJwt::new(jwt.text()),
                                credential: credential.id.clone().into_owned(),
                            });
                        }
                        Err(failure) => refusals.push(AdhocRefusal {
                            jwt: AdhocJwt::new(jwt.text()),
                            credential: credential.id.clone().into_owned(),
                            failure,
                        }),
                    }
                }
                if verified {
                    kept.push((kind, jwt));
                }
            }
            Ok(Self {
                read: kept,
                relied,
                refusals,
            })
        }

        /// Each JWT some credential verifies, with its entry's type.
        pub fn jwts(&self) -> impl Iterator<Item = (&PasoType<'r>, &Read<'r>)> {
            self.read.iter().map(|(kind, read)| (kind, read))
        }

        /// Each JWT for each credential it fails for, with the step.
        #[must_use]
        pub fn refusals(&self) -> &[AdhocRefusal] {
            &self.refusals
        }
    }
}

#[cfg(feature = "resolve")]
pub use verify::Verified;
#[cfg(feature = "resolve")]
pub(crate) use verify::{Binding, Modules};
