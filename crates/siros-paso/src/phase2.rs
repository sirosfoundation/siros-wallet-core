//! Phase 2 of a record PaSO bound: what the matcher could not check, checked now (the ad-hoc
//! metadata JWT, verified as Proof Metadata §5.3 states; the https images it had not fetched,
//! which the caller fetches, View §3 and Core §7.4.2 step 3), and the SCA response claims (Core
//! §6).

use siros_openid4vp::request::Agreements;

use crate::adhoc::AdhocRefusal;
use crate::image::ImageFailure;
use crate::risk::{Effective, Sealing};
use siros_openid4vp::wallet_metadata::Placement;

/// A module the build may lack that an entry's response needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionalModule {
    /// The `COSE_Encrypt` module, stating A256GCM, which seals an mdoc's risk signals (Risk
    /// Signals §7.6).
    CoseEncrypt,
}

impl OptionalModule {
    /// The modules the build compiles without: `COSE_Encrypt` without the feature
    /// `sealed-signals`, so that phase 1 refuses an entry needing one (Risk Signals §7.6).
    #[cfg(feature = "sealed-signals")]
    pub(crate) const UNCOMPILED: &[Self] = &[];
    /// The modules the build compiles without: `COSE_Encrypt` without the feature
    /// `sealed-signals`, so that phase 1 refuses an entry needing one (Risk Signals §7.6).
    #[cfg(not(feature = "sealed-signals"))]
    pub(crate) const UNCOMPILED: &[Self] = &[Self::CoseEncrypt];

    /// The module the response of an entry with these signals needs, by how the presentation's
    /// format places the members: `COSE_Encrypt` for encrypted risk signals in a name space
    /// (Risk Signals §7.6).
    pub(crate) fn needed(signals: &Effective, placement: Option<Placement>) -> Option<Self> {
        (signals.sealing == Sealing::Encrypted && placement == Some(Placement::NameSpaces))
            .then_some(Self::CoseEncrypt)
    }

    /// The module's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CoseEncrypt => "COSE_Encrypt",
        }
    }
}

impl std::fmt::Display for OptionalModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// An https image phase 2 fetched and refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedImage {
    /// The image's URL in ASCII.
    pub url: String,
    /// What failed.
    pub failure: ImageFailure,
}

/// What phase 2 found no longer holds for a record, at least one of: the build lacks a module
/// its response needs, the module that seals its risk signals as a JWE states no key the issuer
/// publishes, its ad-hoc metadata JWT fails a step of Proof Metadata §5.3, an https image's fetch
/// or verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasoFinding {
    lacks: Option<OptionalModule>,
    unsealable: Option<Agreements>,
    refused: Option<AdhocRefusal>,
    failed: Vec<FailedImage>,
}

impl PasoFinding {
    /// The finding, when something no longer holds.
    #[must_use]
    pub fn of(
        lacks: Option<OptionalModule>,
        unsealable: Option<Agreements>,
        refused: Option<AdhocRefusal>,
        failed: Vec<FailedImage>,
    ) -> Option<Self> {
        (lacks.is_some() || unsealable.is_some() || refused.is_some() || !failed.is_empty())
            .then_some(Self {
                lacks,
                unsealable,
                refused,
                failed,
            })
    }

    /// The module the build lacks that the response needs.
    #[must_use]
    pub const fn lacks(&self) -> Option<OptionalModule> {
        self.lacks
    }

    /// The statement of the module that seals the risk signals as a JWE (`Haip::agreements`),
    /// when it admits none of the issuer's keys (Risk Signals §7.3).
    #[must_use]
    pub const fn unsealable(&self) -> Option<Agreements> {
        self.unsealable
    }

    /// The ad-hoc metadata JWT, refused for the record's credential with the §5.3 step it
    /// fails.
    #[must_use]
    pub const fn refused(&self) -> Option<&AdhocRefusal> {
        self.refused.as_ref()
    }

    /// The images that failed, in the metadata's claim order.
    #[must_use]
    pub fn failed(&self) -> &[FailedImage] {
        &self.failed
    }
}

#[cfg(feature = "resolve")]
use crate::value::ValueKind;
#[cfg(feature = "resolve")]
use siros_openid4vp::claims::Concrete;
#[cfg(feature = "resolve")]
use siros_openid4vp::detail;
#[cfg(feature = "resolve")]
use siros_openid4vp::effects::Fetch;
#[cfg(feature = "resolve")]
use siros_openid4vp::host::{Authentication, AuthenticationNeed};
#[cfg(feature = "resolve")]
use siros_openid4vp::json::Node;
#[cfg(feature = "resolve")]
use siros_openid4vp::plugins::{Answered, Fault, FetchedRecord, Members};
#[cfg(feature = "resolve")]
use siros_openid4vp::request::Entry;
#[cfg(feature = "resolve")]
use siros_openid4vp::rows::HttpsUrl;

#[cfg(feature = "resolve")]
use crate::adhoc::{self, AdhocJwt, Read as AdhocRead};
#[cfg(feature = "resolve")]
use crate::document::{DOCUMENT, PasoDocument};
#[cfg(feature = "resolve")]
use crate::entry::PasoEntry;
#[cfg(feature = "resolve")]
use crate::image::{self, Resolution};
#[cfg(feature = "resolve")]
use crate::labels::LabelLimits;
#[cfg(feature = "resolve")]
use crate::metadata::ValueType;
#[cfg(feature = "resolve")]
use crate::outcome::NotCompatible;
#[cfg(feature = "resolve")]
use crate::path::{at, select};
#[cfg(feature = "resolve")]
use crate::render::{Registered, integrity_sibling, rulebook_metadata};
#[cfg(feature = "resolve")]
use crate::respond::{Answer, Modules};
#[cfg(feature = "resolve")]
use crate::risk::RiskSignal;
#[cfg(feature = "resolve")]
#[cfg(feature = "resolve")]
use crate::{PasoProfile, caused, fault};

#[cfg(feature = "resolve")]
/// What a record's entry reads: the entry as received and as read, the credential's document, and
/// the metadata that rendered it: the stored metadata, or the ad-hoc metadata JWT's once verified.
struct Read<'r> {
    received: &'r Entry<'r>,
    entry: PasoEntry<'r>,
    document: &'r PasoDocument<'r>,
    given: &'r Node<'r>,
}

#[cfg(feature = "resolve")]
/// How a step of phase 2 relies on the record's ad-hoc metadata JWT (Proof Metadata §5.3).
#[derive(Clone, Copy)]
enum Reliance<'m> {
    /// Verified now through the host's modules.
    Verify(adhoc::Modules<'m>),
    /// Verified by the revalidation that precedes the step in every phase 2.
    Revalidated,
}

#[cfg(feature = "resolve")]
/// Reads the record's one entry and passes it on; its ad-hoc metadata JWT, when it carries one,
/// relied on as `reliance` states, and refused for the record's credential when it fails a step
/// of §5.3.
fn read<T>(
    record: &Answered<'_>,
    reliance: Reliance<'_>,
    then: impl FnOnce(Read<'_>) -> Result<T, Fault>,
) -> Result<Result<T, AdhocRefusal>, Fault> {
    let [index] = record.entries().entries() else {
        return Err(fault(detail!("a PaSO record authorizes one entry")));
    };
    let received = record
        .request()
        .entry(*index)
        .ok_or_else(|| fault(detail!("a record's entry the request lacks")))?;
    let entry = PasoEntry::read(received, crate::paso_type(received)?)
        .map_err(|refused| caused(detail!("a bound PaSO entry"), refused))?;
    let bytes = record
        .credential()
        .document(DOCUMENT)
        .ok_or_else(|| fault(detail!("a bound credential without its PaSO document")))?;
    let node = PasoDocument::json(bytes).map_err(|e| caused(detail!("the PaSO document"), e))?;
    let document =
        PasoDocument::read(&node).map_err(|e| caused(detail!("the PaSO document"), e))?;
    let read = entry
        .metadata
        .map(AdhocRead::parse)
        .transpose()
        .map_err(|e| caused(detail!("a bound entry's ad-hoc metadata"), e))?;
    if let (Some(jwt), Reliance::Verify(modules)) = (&read, reliance) {
        let credential = record.credential();
        let binding = adhoc::Binding {
            document: &document,
            format: &credential.format,
            kind: &entry.kind,
        };
        if let Err(failure) = jwt.verify(&binding, modules) {
            return Ok(Err(AdhocRefusal {
                jwt: AdhocJwt::new(jwt.text()),
                credential: credential.id.clone().into_owned(),
                failure,
            }));
        }
    }
    let given = match &read {
        Some(read) => Some(read.metadata()),
        None => document.metadata(&entry.kind),
    }
    .ok_or_else(|| fault(detail!("a bound entry's metadata is gone")))?;
    then(Read {
        received,
        entry,
        document: &document,
        given,
    })
    .map(Ok)
}

#[cfg(feature = "resolve")]
/// An https image of the payload the record's metadata displays and the matcher did not
/// have: its text as written, its URL, and its `#integrity` sibling.
struct Pending<'r> {
    text: &'r str,
    url: HttpsUrl,
    integrity: Option<&'r Node<'r>>,
}

#[cfg(feature = "resolve")]
/// The images phase 2 resolves for the entry, in the metadata's claim order.
fn pending<'r>(profile: &PasoProfile, read: &Read<'r>) -> Result<Vec<Pending<'r>>, Fault> {
    let registered = Registered::of(read.entry.kind.clone(), read.given);
    let (metadata, _) = rulebook_metadata(&registered, LabelLimits::PASO)
        .map_err(|e| caused(detail!("a bound entry's metadata"), e))?;
    let payload = read.entry.payload.node();
    let mut pending = Vec::new();
    for claim in &metadata.claims {
        let Some(display) = &claim.display else {
            continue;
        };
        if display.value != ValueType::Kind(ValueKind::Image) {
            continue;
        }
        let found = select(payload, &claim.path)
            .map_err(|e| caused(detail!("a bound entry's image"), NotCompatible::from(e)))?;
        for (path, value) in found {
            let (Some(text), Some(Concrete::Key(_))) = (value.as_str(), path.last()) else {
                continue;
            };
            let Ok(url) = HttpsUrl::parse(text) else {
                continue;
            };
            if !matches!(profile.resolution(url.ascii()), Resolution::Unknown) {
                // The matcher had it, verified or failed, and decided with it.
                continue;
            }
            let integrity = match integrity_sibling(&path) {
                Some(sibling) => at(payload, &sibling).map_err(|e| {
                    caused(detail!("a bound entry's image"), NotCompatible::from(e))
                })?,
                None => None,
            };
            pending.push(Pending {
                text,
                url,
                integrity,
            });
        }
    }
    Ok(pending)
}

#[cfg(feature = "resolve")]
/// The URLs of the images phase 2 resolves, in the metadata's claim order; none when the record's
/// ad-hoc metadata JWT fails a step of §5.3 through `modules`,
/// which the revalidation then refuses.
pub(crate) fn wanted(
    profile: &PasoProfile,
    record: &Answered<'_>,
    modules: adhoc::Modules<'_>,
) -> Result<Vec<HttpsUrl>, Fault> {
    Ok(read(record, Reliance::Verify(modules), |read| {
        Ok(pending(profile, &read)?
            .into_iter()
            .map(|image| image.url)
            .collect())
    })?
    .unwrap_or_default())
}

#[cfg(feature = "resolve")]
/// Revalidates a record: its ad-hoc metadata JWT verified through `modules` (Proof Metadata
/// §5.3), the refusal alone when it fails; then whether the build holds the modules its response
/// needs, whether `sealer`, the statement of the module that seals an SD-JWT's risk signals as a
/// JWE, admits a key the issuer publishes, and each https image of the payload its metadata
/// displays and the matcher did not have, with what the caller fetched. `cose_held`: the build holds the `COSE_Encrypt` module,
/// stating §7.6's A256GCM.
pub(crate) fn revalidate(
    profile: &PasoProfile,
    fetched: &FetchedRecord<'_>,
    modules: adhoc::Modules<'_>,
    sealer: Agreements,
    cose_held: bool,
) -> Result<Option<PasoFinding>, Fault> {
    let resources = fetched.resources();
    let record = fetched.record();
    let read = read(&record, Reliance::Verify(modules), |read| {
        let signals = Effective::resolve(read.given, &profile.catalogue)
            .map_err(|e| caused(detail!("a bound entry's risk signals"), e))?;
        let lacks =
            OptionalModule::needed(&signals, record.placement()).filter(|module| match module {
                OptionalModule::CoseEncrypt => !cose_held,
            });
        let unsealable = (signals.sealing == Sealing::Encrypted
            && record.placement() == Some(Placement::Claims)
            && read.document.encryption_key(Some(&sealer)).is_none())
        .then_some(sealer);
        let mut failed = Vec::new();
        for image in pending(profile, &read)? {
            let fetch = resources
                .fetched(&image.url)
                .ok_or_else(|| fault(detail!("an image the profile wanted is unanswered")))?;
            let resolution = |_: &str| match fetch {
                Fetch::Fetched { content, media } => Resolution::Fetched { content, media },
                Fetch::Unfetched => Resolution::Failed("the fetch failed"),
            };
            match image::resolve(image.text, image.integrity, &resolution) {
                Ok(_) => {}
                Err(NotCompatible::Image { failure, .. }) => {
                    failed.push(FailedImage {
                        url: image.url.ascii().to_owned(),
                        failure,
                    });
                }
                Err(other) => return Err(caused(detail!("an image"), other)),
            }
        }
        Ok(PasoFinding::of(lacks, unsealable, None, failed))
    })?;
    Ok(read.unwrap_or_else(|refused| PasoFinding::of(None, None, Some(refused), Vec::new())))
}

#[cfg(feature = "resolve")]
/// The End-User authentication the record's entry needs: strong when the type's effective
/// risk signals require `amr` (Risk Signal Registry §2.8), presence otherwise. Phase 2 asks it
/// once the revalidation verified the record's ad-hoc metadata JWT.
pub(crate) fn authentication(
    profile: &PasoProfile,
    record: &Answered<'_>,
) -> Result<AuthenticationNeed, Fault> {
    read(record, Reliance::Revalidated, |read| {
        let signals = Effective::resolve(read.given, &profile.catalogue)
            .map_err(|e| caused(detail!("a bound entry's risk signals"), e))?;
        Ok(
            if signals
                .required()
                .any(|spec| spec.signal == RiskSignal::AMR)
            {
                AuthenticationNeed::Strong
            } else {
                AuthenticationNeed::Presence
            },
        )
    })?
    .map_err(|refused| caused(detail!("a refused ad-hoc metadata JWT"), refused.failure))
}

#[cfg(feature = "resolve")]
/// The SCA response members for the record's entry, keyed for the presentation's format,
/// with the End-User's authentication for this response; its ad-hoc metadata JWT verified
/// through `verifying`.
pub(crate) fn respond(
    profile: &PasoProfile,
    record: &Answered<'_>,
    modules: Modules<'_>,
    verifying: adhoc::Modules<'_>,
    authentication: &Authentication,
) -> Result<Members, Fault> {
    read(record, Reliance::Verify(verifying), |read| {
        let placement = record.placement().ok_or_else(|| {
            fault(detail!(
                "PaSO binds no presentation whose proof carries no members"
            ))
        })?;
        let signals = Effective::resolve(read.given, &profile.catalogue)
            .map_err(|e| caused(detail!("a bound entry's risk signals"), e))?;
        Answer {
            request: record.request(),
            entry: read.received,
            document: read.document,
            signals,
            attested: record.attested(),
            placement,
            mode: record.mode(),
        }
        .members(modules, authentication)
    })?
    .map_err(|refused| caused(detail!("a refused ad-hoc metadata JWT"), refused.failure))
}
