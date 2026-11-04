//! Phase 2 of a record PaSO bound: what the matcher could not check, checked now (the ad-hoc
//! metadata JWT's `exp`, Proof Metadata §5.3 step 5; the https images it had not fetched, which
//! the caller fetches, View §3 and Core §7.4.2 step 3), and the SCA response claims (Core §6).

use siros_explain::{IntoArg, kind};
use siros_openid4vp::request::Agreements;

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

/// A module names an argument as the code fixes it.
impl IntoArg for OptionalModule {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
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
    /// The image's URL as the payload writes it.
    pub url: String,
    /// What failed.
    pub failure: ImageFailure,
}

/// What phase 2 found no longer holds for a record, at least one of: the build lacks a module
/// its response needs, the module that seals its risk signals as a JWE states no key the issuer
/// publishes, its ad-hoc metadata JWT expired, an https image's fetch or verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasoFinding {
    lacks: Option<OptionalModule>,
    unsealable: Option<Agreements>,
    expired: Option<String>,
    failed: Vec<FailedImage>,
}

impl PasoFinding {
    /// The finding, when something no longer holds.
    #[must_use]
    pub fn of(
        lacks: Option<OptionalModule>,
        unsealable: Option<Agreements>,
        expired: Option<String>,
        failed: Vec<FailedImage>,
    ) -> Option<Self> {
        (lacks.is_some() || unsealable.is_some() || expired.is_some() || !failed.is_empty())
            .then_some(Self {
                lacks,
                unsealable,
                expired,
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

    /// The ad-hoc metadata JWT, expired.
    #[must_use]
    pub fn expired(&self) -> Option<&str> {
        self.expired.as_deref()
    }

    /// The images that failed, in the metadata's claim order.
    #[must_use]
    pub fn failed(&self) -> &[FailedImage] {
        &self.failed
    }
}

siros_openid4vp::with_resolve! {
    use siros_openid4vp::claims::Concrete;
    use siros_openid4vp::json::Node;
    use siros_openid4vp::detail;
    use siros_openid4vp::effects::Fetch;
    use siros_openid4vp::plugins::{Answered, Fault, FetchedRecord, Members};
    use siros_openid4vp::rows::{HttpsUrl, Shown, ValueKind};
    use siros_openid4vp::host::{Authentication, AuthenticationNeed, Platform, Timestamp};

    use crate::{FAULT, PasoProfile};
    use crate::adhoc::Jws;
    use crate::document::{DOCUMENT, PasoDocument};
    use crate::entry::PasoEntry;
    use crate::image::{self, Resolution};
    use crate::metadata::ValueType;
    use crate::outcome::NotCompatible;
    use crate::path::{at, select};
    use crate::render::{integrity_sibling, rulebook_metadata};
    use crate::respond::{Answer, Modules};
    use crate::risk::RiskSignal;
    use crate::rulebook::Family;

    /// What a record's entry reads: the entry, the credential's document, and the metadata that
    /// rendered it with the ad-hoc metadata JWT when that was it.
    struct Read<'r> {
        entry: PasoEntry<'r>,
        document: &'r PasoDocument<'r>,
        given: &'r Node<'r>,
        adhoc: Option<&'r Jws<'r>>,
    }

    /// Reads the record's one entry and passes it on.
    fn read<T>(
        record: &Answered<'_>,
        then: impl FnOnce(Read<'_>) -> Result<T, Fault>,
    ) -> Result<T, Fault> {
        let [index] = record.entries().entries() else {
            return Err(Fault::new(FAULT, detail!("a PaSO record authorizes one entry")));
        };
        let entry = record
            .request()
            .entry(*index)
            .ok_or_else(|| Fault::new(FAULT, detail!("a record's entry the request lacks")))?;
        let entry =
            PasoEntry::read(entry).map_err(|refused| Fault::caused(FAULT, detail!("a bound PaSO entry"), refused))?;
        let bytes = record
            .credential()
            .document(DOCUMENT)
            .ok_or_else(|| Fault::new(FAULT, detail!("a bound credential without its PaSO document")))?;
        let node = PasoDocument::json(bytes).map_err(|e| Fault::caused(FAULT, detail!("the PaSO document"), e))?;
        let document = PasoDocument::read(&node).map_err(|e| Fault::caused(FAULT, detail!("the PaSO document"), e))?;
        let jws = entry
            .metadata
            .map(Jws::parse)
            .transpose()
            .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's ad-hoc metadata"), e))?;
        let given = match &jws {
            Some(jws) => jws.metadata(),
            None => document.metadata(entry.kind.as_str()),
        }
        .ok_or_else(|| Fault::new(FAULT, detail!("a bound entry's metadata is gone")))?;
        then(Read {
            entry,
            document: &document,
            given,
            adhoc: jws.as_ref(),
        })
    }

    /// Whether an `exp` has passed: an integer at or before the instant.
    fn passed(exp: Option<&Node<'_>>, now: Timestamp) -> Result<bool, Fault> {
        match exp {
            Some(Node::Number(exp)) if exp.is_integer() => Ok(match exp.as_u64() {
                Some(seconds) => now.0 >= seconds,
                None => exp.text().starts_with('-'),
            }),
            _ => Err(Fault::new(FAULT, detail!("a verified ad-hoc metadata JWT without an integer exp"))),
        }
    }

    /// An https image of the payload the record's metadata displays and the matcher did not
    /// have: its text as written, the URL a fetch reaches, and its `#integrity` sibling.
    struct Pending<'r> {
        text: &'r str,
        url: Option<HttpsUrl>,
        integrity: Option<&'r Node<'r>>,
    }

    /// The images phase 2 resolves for the entry, in the metadata's claim order.
    fn pending<'r>(profile: &PasoProfile, read: &Read<'r>) -> Result<Vec<Pending<'r>>, Fault> {
        let kind = read.entry.kind.as_str();
        let family = Family::of(kind)
            .ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("{kind} is no PaSO type identifier", kind = kind.to_owned()),
                )
            })?;
        let (metadata, _) = rulebook_metadata(kind, family, read.given)
            .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's metadata"), e))?;
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
                .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's image"), NotCompatible::from(e)))?;
            for (path, value) in found {
                let (Some(text), Some(Concrete::Key(_))) = (value.as_str(), path.last()) else {
                    continue;
                };
                let url = match HttpsUrl::shown(text) {
                    Ok(Shown::Url(url)) => Some(url),
                    // A host without an A-label form names nothing a fetch reaches.
                    Ok(Shown::Unreachable(_)) => None,
                    Err(_) => continue,
                };
                if !matches!(profile.resolution(text), Resolution::Unknown) {
                    // The matcher had it, verified or failed, and decided with it.
                    continue;
                }
                let integrity = match integrity_sibling(&path) {
                    Some(sibling) => at(payload, &sibling).map_err(|e| {
                        Fault::caused(FAULT, detail!("a bound entry's image"), NotCompatible::from(e))
                    })?,
                    None => None,
                };
                pending.push(Pending { text, url, integrity });
            }
        }
        Ok(pending)
    }

    /// The URLs of the images phase 2 resolves that a fetch reaches, in the metadata's claim
    /// order.
    pub(crate) fn wanted(profile: &PasoProfile, record: &Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        read(record, |read| {
            Ok(pending(profile, &read)?
                .into_iter()
                .filter_map(|image| image.url)
                .collect())
        })
    }

    /// Revalidates a record: whether the build holds the modules its response needs, whether
    /// `sealer`, the statement of the module that seals an SD-JWT's risk signals as a JWE, admits
    /// a key the issuer publishes, its ad-hoc metadata JWT's `exp`, then each https image of the
    /// payload its metadata displays and the matcher did not have, with what the caller fetched.
    /// `cose_held`: the build holds the `COSE_Encrypt` module, stating §7.6's A256GCM.
    pub(crate) fn revalidate(
        profile: &PasoProfile,
        fetched: &FetchedRecord<'_>,
        platform: &dyn Platform,
        sealer: Agreements,
        cose_held: bool,
    ) -> Result<Option<PasoFinding>, Fault> {
        let resources = fetched.resources();
        let record = fetched.record();
        read(&record, |read| {
            let signals = Effective::resolve(read.given, &profile.catalogue)
                .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's risk signals"), e))?;
            let lacks = OptionalModule::needed(&signals, record.placement()).filter(|module| match module {
                OptionalModule::CoseEncrypt => !cose_held,
            });
            let unsealable = (signals.sealing == Sealing::Encrypted
                && record.placement() == Some(Placement::Claims)
                && read.document.encryption_key(Some(&sealer)).is_none())
            .then_some(sealer);
            let expired = match read.adhoc {
                Some(jws) if passed(jws.exp(), platform.now())? => Some(jws.text.to_owned()),
                _ => None,
            };
            let mut failed = Vec::new();
            for image in pending(profile, &read)? {
                let fetch = image
                    .url
                    .map(|url| {
                        resources.fetched(&url).ok_or_else(|| {
                            Fault::new(FAULT, detail!("an image the profile wanted is unanswered"))
                        })
                    })
                    .transpose()?;
                let resolution = |_: &str| match fetch {
                    Some(Fetch::Fetched { content, media }) => Resolution::Fetched {
                        content,
                        media: media.essence(),
                    },
                    Some(Fetch::Unfetched) | None => Resolution::Failed("the fetch failed"),
                };
                match image::resolve(image.text, image.integrity, resolution) {
                    Ok(_) => {}
                    Err(NotCompatible::Image { failure, .. }) => {
                        failed.push(FailedImage {
                            url: image.text.to_owned(),
                            failure,
                        });
                    }
                    Err(other) => return Err(Fault::caused(FAULT, detail!("an image"), other)),
                }
            }
            Ok(PasoFinding::of(lacks, unsealable, expired, failed))
        })
    }

    /// The End-User authentication the record's entry needs: strong when the type's effective
    /// risk signals require `amr` (Risk Signal Registry §2.8), presence otherwise.
    pub(crate) fn authentication(
        profile: &PasoProfile,
        record: &Answered<'_>,
    ) -> Result<AuthenticationNeed, Fault> {
        read(record, |read| {
            let signals = Effective::resolve(read.given, &profile.catalogue)
                .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's risk signals"), e))?;
            Ok(if signals.required().any(|spec| spec.signal == RiskSignal::AMR) {
                AuthenticationNeed::Strong
            } else {
                AuthenticationNeed::Presence
            })
        })
    }

    /// The SCA response members for the record's entry, keyed for the presentation's format,
    /// with the End-User's authentication for this response.
    pub(crate) fn respond(
        profile: &PasoProfile,
        record: &Answered<'_>,
        modules: Modules<'_>,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        read(record, |read| {
            let placement = record.placement().ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("PaSO binds no presentation whose proof carries no members"),
                )
            })?;
            let signals = Effective::resolve(read.given, &profile.catalogue)
                .map_err(|e| Fault::caused(FAULT, detail!("a bound entry's risk signals"), e))?;
            Answer {
                request: record.request(),
                entry: read.entry,
                document: read.document,
                signals,
                attested: record.attested(),
                placement,
                mode: record.mode(),
            }
            .members(modules, authentication)
        })
    }
}
