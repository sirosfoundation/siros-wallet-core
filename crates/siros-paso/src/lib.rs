//! The PaSO transaction data profile (draft 2) for the SIROS wallet core: every `urn:paso:sca:`
//! type, as a [`Profile`] the core's registry holds under that prefix.
//!
//! - Core §3, §7.1 and §7.4.1: the request rules over PaSO's entries ([`entry`]).
//! - Core §7.4.2: first match, the first entry in array order that renders for a credential.
//! - Proof Metadata §3: a type's metadata, its labels held to §3.3 ([`metadata`], [`labels`]);
//!   §5: ad-hoc metadata JWTs ([`adhoc`]).
//! - View §2-4: the generic renderer, value types, templates and locale selection
//!   ([`render`]), the Payment, Generic and Mandate rulebooks ([`rulebook`], [`mandate`]),
//!   images ([`image`]); what keeps an entry from rendering ([`outcome`]).
//! - Risk Signals §3-7 ([`risk`]) and Core §6, the response members each format carries
#![cfg_attr(
    feature = "resolve",
    doc = "  ([`respond`], with the feature `resolve`), with what phase 2 revalidates."
)]
#![cfg_attr(
    not(feature = "resolve"),
    doc = "  (`respond`, with the feature `resolve`), with what phase 2 revalidates."
)]
//!
//! A credential's registration holds its PaSO document under [`document::DOCUMENT`]: the
//! signed credential metadata the wallet verified at issuance.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

pub mod adhoc;
#[cfg(feature = "resolve")]
pub mod amr;
mod conform;
#[cfg(all(feature = "resolve", feature = "sealed-signals"))]
mod cose;
pub mod document;
pub mod entry;
pub mod frequency;
pub mod image;
pub mod labels;
pub mod locale;
pub mod mandate;
pub mod markdown;
#[cfg(feature = "resolve")]
pub mod measure;
pub mod metadata;
#[cfg(feature = "resolve")]
pub mod modules;
pub mod outcome;
mod path;
pub mod render;
#[cfg(feature = "resolve")]
pub mod respond;

#[cfg(all(feature = "test-util", feature = "sealed-signals"))]
pub use cose::TestCoseEncrypt;
#[cfg(all(feature = "resolve", feature = "sealed-signals"))]
pub use cose::{NotSealedCose, SealedCose};
#[cfg(feature = "test-util")]
pub use measure::{Measured, Signal, TestPaso};
#[cfg(feature = "resolve")]
pub use measure::{Measurement, Paso, Reading, WalletVersion};
#[cfg(feature = "resolve")]
pub use modules::{
    CoseEnc, CoseEncrypt, IssuerTrust, NotRandomId, NotRootCertificate, RandomId, RandomIds,
    RootCertificate,
};
#[cfg(feature = "test-util")]
pub use modules::{TestIssuerTrust, TestRandomIds};
pub mod risk;
pub mod rulebook;
pub mod rules;
pub mod sca;
mod template;
pub mod value;
pub mod view;

pub use conform::{ClaimIndex, Placement};

use std::error::Error;

use siros_explain::Explain;
use siros_i18n::Context;
use siros_openid4vp::consent::{Header, Overlay, TransactionHeader};
use siros_openid4vp::detail;
#[cfg(all(feature = "resolve", feature = "sealed-signals"))]
use siros_openid4vp::host::Slot;
use siros_openid4vp::ids::{InvalidId, LocaleTag, TypePrefix};
use siros_openid4vp::json::Node;
use siros_openid4vp::media::MediaType;
use siros_openid4vp::plugins::{
    Attested, AttestedName, AttestedText, Binding, Bound, BoundEntries, Build, Carriage, Detail,
    Exclude, Fault, HostedProfile, Member, NoCandidate, Profile, ProfileHandle, RegistryBuilder,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Agreements, Entry, EntryIndex, Request};
use siros_openid4vp::routing::ChannelKind;
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::sri::Integrity;
use siros_openid4vp::wallet::Credential;
#[cfg(feature = "resolve")]
use siros_openid4vp::{
    host::{Authentication, AuthenticationNeed, Haip, Has, MayHave, Platform, ProfileHost},
    plugins::{Answered, FetchedRecord, Members},
};

use crate::adhoc::{AdhocFailure, AdhocRefusal, Relied};
use crate::document::{DOCUMENT, PasoDocument};
use crate::entry::PasoEntry;
use crate::image::Resolution;
use crate::labels::LabelLimits;
use crate::outcome::{NotCompatible, Outcome, Unsupported};
use crate::render::{ItemBound, Registered, RowPosition, TransactionView};
use crate::risk::{Catalogue, Effective, Sealing};
use crate::rulebook::{PASO, PasoType};
use crate::rules::BindExcluded;
use siros_openid4vp::wallet_metadata;

siros_explain::scope!("paso");

/// The profile's fault: the wallet's data it cannot read, or a module that broke its contract.
#[derive(Debug, thiserror::Error, Explain)]
#[error("{detail}")]
#[explain(id = "fault")]
struct PasoFault {
    /// What failed, for the log.
    #[explain(skip)]
    detail: Detail,
    /// The error that caused it.
    #[source]
    cause: Option<Box<dyn Error + Send + Sync>>,
}

/// The profile's fault, its log line written by `detail`.
pub(crate) fn fault(detail: Detail) -> Fault {
    Fault::new(PasoFault {
        detail,
        cause: None,
    })
}

/// The profile's fault caused by an error, its log line written by `detail`.
pub(crate) fn caused(detail: Detail, cause: impl Error + Send + Sync + 'static) -> Fault {
    Fault::new(PasoFault {
        detail,
        cause: Some(Box::new(cause)),
    })
}

mod phase2;
pub use phase2::{FailedImage, OptionalModule, PasoFinding};

/// What the wallet knows of an https resource it fetched at registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// Its content and media type.
    Fetched {
        /// The content.
        content: Vec<u8>,
        /// The media type.
        media: MediaType,
    },
    /// Its fetch failed, for this reason.
    Failed(String),
}

/// The metadata that rendered an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The signed credential metadata the wallet stores, by its JWT's integrity value.
    Stored {
        /// The integrity value.
        integrity: Integrity,
    },
    /// The entry's ad-hoc metadata JWT (Proof Metadata §5).
    Adhoc,
}

/// An entry rendered for a credential, with the metadata that rendered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The rendering.
    pub view: TransactionView,
    /// The metadata.
    pub source: Source,
}

/// The PaSO profile, with the wallet data its registration carries: the https resources the
/// wallet fetched, its View §2 item bound, the risk signal profiles it transcribed, the ad-hoc
/// metadata JWTs the wallet does not rely on for a credential (Proof Metadata §5.3), the modules
/// phase 2 found the build lacks, and the statement of the module that seals a JWE when phase 2
/// found it admits none of an issuer's keys.
#[derive(Debug, Clone)]
pub struct PasoProfile {
    resources: Vec<(String, Fetch)>,
    bound: ItemBound,
    catalogue: Catalogue,
    refusals: Vec<AdhocRefusal>,
    relied: Vec<Relied>,
    lacking: Vec<OptionalModule>,
    sealer: Option<Agreements>,
}

impl Default for PasoProfile {
    /// No resource fetched, the bound 200, PaSO's Default profile, no ad-hoc metadata JWT
    /// refused, every optional module held but those the build compiles without (`COSE_Encrypt`
    /// without the feature `sealed-signals`).
    fn default() -> Self {
        Self {
            resources: Vec::new(),
            bound: ItemBound::LEAST,
            catalogue: Catalogue::paso(),
            refusals: Vec::new(),
            relied: Vec::new(),
            lacking: OptionalModule::UNCOMPILED.to_vec(),
            sealer: None,
        }
    }
}

impl PasoProfile {
    /// The profile with what the wallet knows of a resource; the first said of a URL holds.
    #[must_use]
    pub fn with_resource(mut self, url: HttpsUrl, fetch: Fetch) -> Self {
        self.resources.push((url.ascii().to_owned(), fetch));
        self
    }

    /// The profile with another item bound.
    #[must_use]
    pub const fn with_bound(mut self, bound: ItemBound) -> Self {
        self.bound = bound;
        self
    }

    /// The profile with other risk signal profiles.
    #[must_use]
    pub fn with_catalogue(mut self, catalogue: Catalogue) -> Self {
        self.catalogue = catalogue;
        self
    }

    /// The profile knowing the ad-hoc metadata JWTs the wallet does not rely on, each for a
    /// credential (Proof Metadata §5.3), as phase 2 refuses them. First match moves past their
    /// entries for those credentials.
    #[must_use]
    pub fn with_refusals(mut self, refusals: &[AdhocRefusal]) -> Self {
        self.refusals.extend_from_slice(refusals);
        self
    }

    /// The profile knowing the wallet's verification of a request's ad-hoc metadata JWTs
    /// (Proof Metadata §5.3): first match relies in the URI flow on a JWT for the credentials it
    /// verified for alone, and moves past its entries for the others.
    #[cfg(feature = "resolve")]
    #[must_use]
    pub fn with_verified(mut self, verified: &adhoc::Verified<'_>) -> Self {
        self.refusals.extend_from_slice(verified.refusals());
        self.relied.extend_from_slice(&verified.relied);
        self
    }

    /// Registers the profile for every type under `urn:paso:sca:`, in a registry whose host
    /// holds the modules the profile needs:
    ///
    /// ```
    /// use siros_openid4vp::host::{Haip, Platform};
    /// use siros_openid4vp::plugins::Registry;
    /// use siros_paso::{CoseEncrypt, IssuerTrust, Paso, PasoProfile, RandomIds};
    /// use siros_paso::{TestCoseEncrypt, TestIssuerTrust, TestPaso, TestRandomIds};
    /// use siros_testkit::{TestHaip, TestPlatform};
    ///
    /// siros_testkit::test_host! {
    ///     /// The PaSO build's host.
    ///     #[derive(Default)]
    ///     struct Wallet {
    ///         handles {
    ///             platform: TestPlatform => Platform,
    ///             paso: TestPaso => Paso,
    ///             random_ids: TestRandomIds => RandomIds,
    ///             issuer_trust: TestIssuerTrust => IssuerTrust
    ///         }
    ///         zero_sized { TestHaip => Haip }
    ///         optional { TestCoseEncrypt => CoseEncrypt }
    ///         lacks {}
    ///     }
    /// }
    ///
    /// let mut builder = Registry::<Wallet>::builder();
    /// PasoProfile::default().register(&mut builder).expect("registers");
    /// ```
    pub fn register<H>(self, builder: &mut RegistryBuilder<H>) -> Result<ProfileHandle, InvalidId>
    where
        H: Build,
        Self: HostedProfile<H>,
    {
        let prefix = TypePrefix::parse(PASO)?;
        let handle = builder.profile(self);
        builder.prefix(prefix, handle);
        Ok(handle)
    }

    /// What the wallet knows of an https image: the first resource of its URL in ASCII.
    fn resolution(&self, url: &str) -> Resolution<'_> {
        match self.resources.iter().find(|(known, _)| known == url) {
            None => Resolution::Unknown,
            Some((_, Fetch::Fetched { content, media })) => Resolution::Fetched { content, media },
            Some((_, Fetch::Failed(reason))) => Resolution::Failed(reason),
        }
    }

    /// One entry of a request arriving on `channel` rendered for one credential whose proof
    /// places members by `placement`: its metadata, View's rendering, then whether the wallet can
    /// send its risk signals (Risk Signals §7.3, and §7.6 in a build phase 2 found without a
    /// module they need). The metadata is the ad-hoc metadata JWT's unless the profile knows the
    /// wallet refused it for the credential: over the DC API read as a signed request is read, in
    /// the URI flow once the wallet verified it for the credential (Proof Metadata §5.3,
    #[cfg_attr(
        feature = "resolve",
        doc = "[`PasoProfile::with_verified`]); else the credential's stored metadata for the type."
    )]
    #[cfg_attr(
        not(feature = "resolve"),
        doc = "`PasoProfile::with_verified`, with the feature `resolve`); else the credential's stored \
               metadata for the type."
    )]
    /// Every text resolves through `context` (see [`render::Request::render`]). The outer error
    /// is the wallet's own failure: a document or an entry it cannot read, a text its context
    /// does not word.
    pub fn render(
        &self,
        entry: &Entry<'_>,
        channel: ChannelKind,
        credential: &Credential<'_>,
        placement: Option<wallet_metadata::Placement>,
        env: &Env,
        context: &Context,
    ) -> Result<Result<Rendered, Outcome>, Fault> {
        let kind = paso_type(entry)?;
        let Some(bytes) = credential.document(DOCUMENT) else {
            return Ok(Err(Unsupported::NoPasoMetadata.into()));
        };
        let node =
            PasoDocument::json(bytes).map_err(|e| caused(detail!("the PaSO document"), e))?;
        let document =
            PasoDocument::read(&node).map_err(|e| caused(detail!("the PaSO document"), e))?;
        let paso = match PasoEntry::read(entry, kind) {
            Ok(paso) => paso,
            Err(refused) => return Ok(Err(refused.into())),
        };
        let adhoc = match paso
            .metadata
            .map(|jwt| self.relied_on(jwt, channel, credential))
            .transpose()
        {
            Ok(adhoc) => adhoc,
            Err(refused) => return Ok(Err(refused)),
        };
        self.rendered(&paso, adhoc.as_ref(), &document, placement, env, context)
    }

    /// The ad-hoc metadata JWT the profile relies on for the credential: refused when the profile
    /// knows the wallet refused it for the credential, or in the URI flow unless the wallet
    /// verified it for the credential; read as a signed request is read.
    fn relied_on<'j>(
        &self,
        jwt: &'j str,
        channel: ChannelKind,
        credential: &Credential<'_>,
    ) -> Result<adhoc::Read<'j>, Outcome> {
        let id = credential.id.as_str();
        if let Some(refused) = self
            .refusals
            .iter()
            .find(|refused| refused.jwt.as_str() == jwt && refused.credential.as_str() == id)
        {
            return Err(NotCompatible::Adhoc {
                failure: refused.failure.clone(),
            }
            .into());
        }
        if channel == ChannelKind::Uri
            && !self
                .relied
                .iter()
                .any(|relied| relied.jwt.as_str() == jwt && relied.credential.as_str() == id)
        {
            return Err(NotCompatible::Adhoc {
                failure: AdhocFailure::Unverified,
            }
            .into());
        }
        Ok(adhoc::Read::parse(jwt).map_err(NotCompatible::from)?)
    }

    /// The entry rendered with its metadata: View's rules and the risk signals' decide whether
    /// it renders, then its texts resolve.
    fn rendered(
        &self,
        paso: &PasoEntry<'_>,
        adhoc: Option<&adhoc::Read<'_>>,
        document: &PasoDocument<'_>,
        placement: Option<wallet_metadata::Placement>,
        env: &Env,
        context: &Context,
    ) -> Result<Result<Rendered, Outcome>, Fault> {
        let kind = &paso.kind;
        let (given, source) = match adhoc {
            Some(read) => (read.metadata(), Source::Adhoc),
            None => match document.metadata(kind) {
                Some(given) => (
                    given,
                    Source::Stored {
                        integrity: document.integrity.clone(),
                    },
                ),
                None => {
                    return Ok(Err(Unsupported::NotListed {
                        kind: kind.to_owned_type(),
                    }
                    .into()));
                }
            },
        };
        let request = render::Request {
            registered: Registered::of(kind.clone(), given),
            payload: paso.payload,
            env,
            context,
            bound: self.bound,
            limits: LabelLimits::PASO,
            resolve: &|url: &str| self.resolution(url),
        };
        let plan = match request.plan() {
            Ok(plan) => plan,
            Err(outcome) => return Ok(Err(outcome)),
        };
        if let Err(outcome) = self.signals(given, document, placement) {
            return Ok(Err(outcome));
        }
        let view = plan.resolve(&request)?;
        Ok(Ok(Rendered { view, source }))
    }

    /// Whether the wallet can send the type's risk signals: Risk Signals §7.3, and §7.6 in a
    /// build phase 2 found without a module they need.
    fn signals(
        &self,
        given: &Node<'_>,
        document: &PasoDocument<'_>,
        placement: Option<wallet_metadata::Placement>,
    ) -> Result<(), Outcome> {
        let signals = Effective::resolve(given, &self.catalogue)?;
        let sealer = self
            .sealer
            .as_ref()
            .filter(|_| placement == Some(wallet_metadata::Placement::Claims));
        if signals.sealing == Sealing::Encrypted && document.encryption_key(sealer).is_none() {
            return Err(NotCompatible::NoEncryptionKey.into());
        }
        if let Some(module) = OptionalModule::needed(&signals, placement)
            && self.lacking.contains(&module)
        {
            return Err(NotCompatible::Lacks { module }.into());
        }
        Ok(())
    }
}

/// An entry's type identifier, which the profile's registration keeps under `urn:paso:sca:`.
pub(crate) fn paso_type<'e>(entry: &'e Entry<'e>) -> Result<PasoType<'e>, Fault> {
    let kind = entry.kind().as_str();
    PasoType::parse(kind).map_err(|_| {
        fault(detail!(
            "{kind} is no PaSO type identifier",
            kind = kind.to_owned()
        ))
    })
}

/// What the response attests of a rendering: the locale shown (Core §7.2) and the stored
/// metadata's integrity (Core §6.1).
fn attested(locale: &LocaleTag, source: Source) -> Result<Attested, Fault> {
    let mut attested = vec![(
        AttestedName::new("display_locale"),
        AttestedText::new(locale.to_string()),
    )];
    if let Source::Stored { integrity } = source {
        attested.push((
            AttestedName::new("metadata_integrity"),
            AttestedText::new(integrity.as_str().to_owned()),
        ));
    }
    Attested::new(attested).map_err(|e| caused(detail!("the attested display"), e))
}

/// What a rendering gives the core: `entries`, which it authorizes, the header, `attested`, and
/// the overlay: the transaction's rows before the card's, the hint, and for a payment its
/// transaction header, whose payee and amount rows leave the entry's rows.
///
/// # Errors
///
/// The rendering's payment rows name rows it lacks.
pub fn bound(
    view: TransactionView,
    attested: Attested,
    entries: BoundEntries,
) -> Result<Bound, Fault> {
    let payment = view
        .payment_texts()
        .map(|(merchant, amount)| (merchant.clone(), amount.clone()));
    let TransactionView {
        title,
        rows,
        actions,
        payment: payment_rows,
        ..
    } = view;
    let overlay = match (payment_rows, payment) {
        (Some(heads), Some((merchant, amount))) => {
            let at = |position: RowPosition| rows.get(position.get()).map(|row| row.row.clone());
            let header_rows = [at(heads.merchant()), at(heads.amount())]
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| fault(detail!("payment rows the rendering lacks")))?;
            Overlay {
                rows: rows
                    .into_iter()
                    .enumerate()
                    .filter(|(k, _)| *k != heads.merchant().get() && *k != heads.amount().get())
                    .map(|(_, row)| row.row)
                    .collect(),
                header: Some(TransactionHeader {
                    counterparty: merchant,
                    amount,
                    rows: header_rows,
                }),
                hint: actions.hint,
            }
        }
        _ => Overlay {
            rows: rows.into_iter().map(|row| row.row).collect(),
            header: None,
            hint: actions.hint,
        },
    };
    Ok(Bound {
        entries,
        header: Header {
            title,
            confirm: actions.confirm,
            cancel: actions.deny,
        },
        attested,
        overlay,
    })
}

impl Profile for PasoProfile {
    type Finding = PasoFinding;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        entry::refusals(request, entries)
    }

    /// Core §6.2-6.3: the SCA response claims as Key Binding JWT claims, or as device-signed
    /// elements of `urn:paso:sca:1`.
    fn members(&self, placement: wallet_metadata::Placement) -> Option<&[Member]> {
        Some(sca::members(placement))
    }

    /// Core §7.4.2 steps 2-3: the first entry in array order that renders for the credential;
    /// a locale failure excludes the credential (View §4). A presentation that cannot carry the
    /// SCA response claims supports no PaSO type (OpenID4VP B.2).
    /// Every text resolves through `context`.
    fn bind(
        &self,
        binding: Binding<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Bound, NoCandidate> {
        if binding.carriage == Carriage::Uncarried {
            return Err(Exclude::new(BindExcluded::Carriage).into());
        }
        for index in binding.entries {
            let entry = binding
                .request
                .entry(*index)
                .ok_or_else(|| fault(detail!("an offered entry the request lacks")))?;
            let channel = binding.request.envelope().channel().kind();
            match self.render(
                entry,
                channel,
                binding.credential,
                binding.placement,
                env,
                context,
            )? {
                Ok(Rendered { view, source }) => {
                    let attested = attested(&view.locale, source)?;
                    let entries = BoundEntries::select(binding.entries, vec![*index])
                        .map_err(|e| caused(detail!("the bound entry"), e))?;
                    return Ok(bound(view, attested, entries)?);
                }
                Err(Outcome::Excluded(excluded)) => {
                    return Err(Exclude::new(excluded).into());
                }
                Err(Outcome::Unsupported(_) | Outcome::NotCompatible(_)) => {}
            }
        }
        Err(Exclude::new(BindExcluded::NoEntry).into())
    }
}

#[cfg(feature = "resolve")]
/// Requires the PaSO module, the platform, HAIP's signature verification and JWE, and the trust
/// store of credential issuers; seals an mdoc's risk signals with the `COSE_Encrypt` module when
/// the build holds it.
impl<H> ProfileHost<H> for PasoProfile
where
    H: Has<dyn Platform>
        + Has<dyn Haip>
        + Has<dyn Paso>
        + Has<dyn RandomIds>
        + Has<dyn IssuerTrust>
        + MayHave<dyn CoseEncrypt>,
{
    /// View §3: the https images the payload displays that the matcher had not fetched, read
    /// from metadata the wallet relies on: none from an ad-hoc metadata JWT that fails a step of
    /// Proof Metadata §5.3.
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        phase2::wanted(self, &record, adhoc::Modules::of(host))
    }

    /// The profile knowing the failed images as failed fetches, the refused ad-hoc metadata JWTs
    /// as refused and the modules the build lacks as lacking: first match then moves past the
    /// entries they rendered.
    fn informed(&self, findings: &[&PasoFinding]) -> Self {
        let mut informed = self.clone();
        for finding in findings {
            informed
                .resources
                .extend(finding.failed().iter().map(|failed| {
                    (
                        failed.url.clone(),
                        Fetch::Failed(failed.failure.to_string()),
                    )
                }));
            informed.refusals.extend(finding.refused().cloned());
            informed.lacking.extend(finding.lacks());
            if let Some(sealer) = finding.unsealable() {
                informed.sealer = Some(sealer);
            }
        }
        informed
    }

    /// Strong when the type's effective risk signals require `amr` (Risk Signal Registry
    /// §2.8), else presence.
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        phase2::authentication(self, &record)
    }

    /// Risk Signals §7.6, Proof Metadata §5.3 and View §3: the `COSE_Encrypt` module an mdoc's
    /// sealed risk signals need, read from the host's type; the ad-hoc metadata JWT, verified;
    /// the https images the matcher had not fetched, as the caller fetched them.
    fn revalidate(
        &self,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<PasoFinding>, Fault> {
        #[cfg(feature = "sealed-signals")]
        let cose_held = MayHave::<dyn CoseEncrypt>::slot(host)
            .filled()
            .is_some_and(|cose| cose.encryptions().contains(&CoseEnc::A256GCM));
        #[cfg(not(feature = "sealed-signals"))]
        let cose_held = false;
        phase2::revalidate(
            self,
            &record,
            adhoc::Modules::of(host),
            Has::<dyn Haip>::module(host).agreements(),
            cose_held,
        )
    }

    /// Core §6.1: the SCA response claims, the `amr` signal the End-User's authentication
    /// (Risk Signal Registry §2.8).
    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        phase2::respond(
            self,
            &record,
            respond::Modules::of(host),
            adhoc::Modules::of(host),
            authentication,
        )
    }
}
