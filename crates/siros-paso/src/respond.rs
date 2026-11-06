//! Core §6.1: the values of the SCA response claims a PaSO presentation carries, among them the
//! risk signal envelopes (Risk Signals §2.2, §4.2-4.3, §5, §7).

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::detail;
use siros_openid4vp::hash::{HashAlgorithm, Sha2};
use siros_openid4vp::host::{Authentication, Haip, Has, MayHave, Platform, Seconds, Timestamp};
use siros_openid4vp::json::{Member as JsonMember, Node, Number, Object};
use siros_openid4vp::plugins::{Attested, Fault, JsonText, MemberValue, Members};
use siros_openid4vp::request::{ContentEncryption, Request};
use siros_openid4vp::routing::ModeName;
use siros_openid4vp::sri;
use siros_openid4vp::wallet_metadata::Placement;

use crate::FAULT;
use crate::amr;
#[cfg(feature = "sealed-signals")]
use crate::cose::SealedCose;
use crate::document::PasoDocument;
use crate::entry::PasoEntry;
use crate::measure::{Paso, Reading};
#[cfg(feature = "sealed-signals")]
use crate::modules::CoseEnc;
use crate::modules::{CoseEncrypt, RandomIds};
use crate::risk::{Effective, RiskSignal, Sealing, SignalSpec};
use crate::sca::{self, Sca};

/// An instant as Risk Signals §2.2's `collected_at` writes it: `YYYY-MM-DDTHH:MM:SSZ` in UTC;
/// `None` past the year 9999.
#[must_use]
pub fn stamp(at: Timestamp) -> Option<String> {
    let days = at.0 / 86_400;
    let seconds = at.0 % 86_400;
    // Days since 1970-01-01 to a civil date (Hinnant), counting eras of 400 years from
    // 0000-03-01.
    let shifted = days.checked_add(719_468)?;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    (year <= 9999).then(|| {
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    })
}

/// A signal's status and value as its envelope reports them (§2.3).
#[derive(Debug, Clone)]
enum Status {
    /// Measured: the value.
    Ok(Node<'static>),
    /// No measurement was obtainable, or the wallet does not implement the signal.
    Unavailable,
    /// The permission was refused.
    Denied,
}

impl Status {
    const fn name(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
        }
    }
}

/// A member of an object the wallet writes.
fn member(name: &'static str, value: Node<'static>) -> JsonMember<'static> {
    JsonMember {
        name: Cow::Borrowed(name),
        value,
    }
}

/// A value with every integer a double: the numeric members of an mdoc's value are CBOR
/// floats (§5.2).
fn floats(node: &Node<'_>) -> Result<Node<'static>, Fault> {
    Ok(match node {
        Node::Number(number) if number.is_integer() => Node::Number(
            number
                .to_double()
                .and_then(Number::of_double)
                .ok_or_else(|| {
                    Fault::new(
                        FAULT,
                        detail!("{number} has no double", number = number.text().to_owned()),
                    )
                })?,
        ),
        Node::Array(items) => Node::Array(items.iter().map(floats).collect::<Result<_, _>>()?),
        Node::Object(object) => Node::Object(
            Object::new(
                object
                    .members()
                    .iter()
                    .map(|member| {
                        Ok(JsonMember {
                            name: Cow::Owned(member.name.to_string()),
                            value: floats(&member.value)?,
                        })
                    })
                    .collect::<Result<Vec<_>, Fault>>()?,
            )
            .map_err(|e| Fault::caused(FAULT, detail!("a measured value"), e))?,
        ),
        other => other.clone().into_owned(),
    })
}

/// The host's modules answering a record reads: the platform's clock and identifiers, the PaSO
/// module's version and measurements, HAIP's JWE, and the `COSE_Encrypt` module when the build
/// holds it.
#[derive(Clone, Copy)]
pub(crate) struct Modules<'h> {
    pub(crate) platform: &'h dyn Platform,
    pub(crate) paso: &'h dyn Paso,
    pub(crate) random_ids: &'h dyn RandomIds,
    pub(crate) haip: &'h dyn Haip,
    #[cfg(feature = "sealed-signals")]
    pub(crate) cose: Option<&'h dyn CoseEncrypt>,
}

impl<'h> Modules<'h> {
    /// The modules of the build's host.
    pub(crate) fn of<H>(host: &'h H) -> Self
    where
        H: Has<dyn Platform>
            + Has<dyn Haip>
            + Has<dyn Paso>
            + Has<dyn RandomIds>
            + MayHave<dyn CoseEncrypt>,
    {
        use siros_openid4vp::host::Host;

        Self {
            platform: host.get::<dyn Platform>(),
            paso: host.get::<dyn Paso>(),
            random_ids: host.get::<dyn RandomIds>(),
            haip: host.get::<dyn Haip>(),
            #[cfg(feature = "sealed-signals")]
            cose: host.maybe::<dyn CoseEncrypt>(),
        }
    }
}

/// What answering a record reads: the request, the entry it authorizes, the credential's
/// document, the signal set of the metadata that rendered the entry, what the record attests,
/// how the proof places the members, and the response mode the answer goes in.
pub(crate) struct Answer<'a> {
    pub(crate) request: &'a Request<'a>,
    pub(crate) entry: PasoEntry<'a>,
    pub(crate) document: &'a PasoDocument<'a>,
    pub(crate) signals: Effective,
    pub(crate) attested: &'a Attested,
    pub(crate) placement: Placement,
    pub(crate) mode: ModeName,
}

impl Answer<'_> {
    /// §6.1 for the entry: a fresh `jti`, the locale the record attests, SHA-256 over the entry
    /// as received, the stored metadata's integrity when the record attests it, the signed
    /// request's integrity, the wallet's version, and the risk signals the metadata requires.
    pub(crate) fn members(
        &self,
        modules: Modules<'_>,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        let placement = self.placement;
        let attested = |name: &str| {
            self.attested.get(name).ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("the record attests no {name}", name = name.to_owned()),
                )
            })
        };
        // Core §6.1: SHA-256 over the entry as received, B.3.3.1's default algorithm.
        let algorithm = Sha2::Sha256;
        let digest = algorithm.digest(self.entry.entry.raw().as_bytes());
        let mut out = vec![
            (
                sca::member(placement, Sca::Jti),
                MemberValue::Text(modules.random_ids.random_id().to_string()),
            ),
            (
                sca::member(placement, Sca::DisplayLocale),
                MemberValue::Text(attested("display_locale")?.as_str().to_owned()),
            ),
            (
                sca::member(placement, Sca::TransactionDataHash),
                match placement {
                    Placement::Claims => MemberValue::Text(URL_SAFE_NO_PAD.encode(&digest)),
                    Placement::NameSpaces => MemberValue::Bytes(digest),
                },
            ),
            (
                sca::member(placement, Sca::TransactionDataHashAlg),
                MemberValue::Text(algorithm.name().as_str().to_owned()),
            ),
        ];
        if let Some(integrity) = self.attested.get("metadata_integrity") {
            out.push((
                sca::member(placement, Sca::MetadataIntegrity),
                MemberValue::Text(integrity.as_str().to_owned()),
            ));
        }
        let request_object = self.request.request_object().ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!("PaSO answers a signed request only (Core §3)"),
            )
        })?;
        out.push((
            sca::member(placement, Sca::RequestIntegrity),
            MemberValue::Text(
                sri::integrity(request_object.as_bytes())
                    .as_str()
                    .to_owned(),
            ),
        ));
        out.push((
            sca::member(placement, Sca::WalletInstanceVersion),
            MemberValue::Text(modules.paso.version().as_str().to_owned()),
        ));
        let envelopes = self.envelopes(modules, authentication)?;
        if !envelopes.is_empty() {
            let array = Node::Array(envelopes);
            let value = match self.signals.sealing {
                Sealing::Plain => MemberValue::Json(JsonText::from(&array)),
                Sealing::Encrypted => self.sealed(&array, modules)?,
            };
            out.push((sca::member(placement, Sca::RiskSignals), value));
        }
        Members::new(out)
            .map_err(|twice| Fault::caused(FAULT, detail!("the SCA response claims"), twice))
    }

    /// Risk Signals §7: the envelopes as `json.dumps` writes them by default, encrypted to the
    /// issuer's key with §7.6's A256GCM: a JWE for an SD-JWT VC, a `COSE_Encrypt` for an mdoc,
    /// which needs the build's `COSE_Encrypt` module.
    fn sealed(&self, envelopes: &Node<'_>, modules: Modules<'_>) -> Result<MemberValue, Fault> {
        let sealer = match self.placement {
            Placement::Claims => Some(modules.haip.agreements()),
            Placement::NameSpaces => None,
        };
        let key = self.document.encryption_key(sealer.as_ref()).ok_or_else(|| {
            Fault::new(FAULT, detail!("the entry rendered and revalidated with a key to encrypt its risk signals to, now without"))
        })?;
        let plaintext = envelopes.python_ascii().to_string();
        Ok(match self.placement {
            Placement::Claims => MemberValue::Text(
                modules
                    .haip
                    .encrypt_jwe(&key, ContentEncryption::A256GCM, plaintext.as_bytes())?
                    .into_string(),
            ),
            #[cfg(not(feature = "sealed-signals"))]
            Placement::NameSpaces => {
                return Err(Fault::new(
                    FAULT,
                    detail!(
                        "an mdoc's sealed risk signals in a build without sealed-signals, which revalidation refuses"
                    ),
                ));
            }
            #[cfg(feature = "sealed-signals")]
            Placement::NameSpaces => {
                let cose = modules.cose.ok_or_else(|| {
                    Fault::new(
                        FAULT,
                        detail!("an mdoc's sealed risk signals without the COSE_Encrypt module revalidation requires"),
                    )
                })?;
                let sealed = cose.encrypt_cose(&key, CoseEnc::A256GCM, plaintext.as_bytes())?;
                let sealed = SealedCose::parse(sealed, cose.encryptions()).map_err(|e| {
                    Fault::caused(FAULT, detail!("the COSE_Encrypt module's ciphertext"), e)
                })?;
                MemberValue::Cbor(
                    sealed
                        .into_item()
                        .map_err(|e| Fault::caused(FAULT, detail!("a sealed COSE_Encrypt"), e))?,
                )
            }
        })
    }

    /// Risk Signals §4.2-4.3: an envelope per required signal in resolution order, the optional
    /// ones left out (§4.2 MAY).
    fn envelopes(
        &self,
        modules: Modules<'_>,
        authentication: &Authentication,
    ) -> Result<Vec<Node<'static>>, Fault> {
        let mut out = Vec::new();
        for spec in self.signals.required() {
            let (collected_at, status) = self.reading(spec, modules, authentication)?;
            let stamped = stamp(collected_at).ok_or_else(|| {
                Fault::new(FAULT, detail!("a measurement collected past the year 9999"))
            })?;
            let mut members = vec![
                member(
                    "type",
                    Node::String(Cow::Owned(spec.signal.as_str().to_owned())),
                ),
                member("collected_at", Node::String(Cow::Owned(stamped))),
                member("status", Node::String(Cow::Borrowed(status.name()))),
            ];
            if let Status::Ok(value) = &status {
                let value = match self.placement {
                    Placement::Claims => value.clone(),
                    Placement::NameSpaces => floats(value)?,
                };
                members.push(member("value", value));
            }
            out.push(Node::Object(
                Object::new(members)
                    .map_err(|e| Fault::caused(FAULT, detail!("an envelope"), e))?,
            ));
        }
        Ok(out)
    }

    /// A required signal's collection time and status. The response mode is the request's, read
    /// as the wallet answers it (Registry §2.7); the authentication methods are the End-User's
    /// authentication for this response, collected when the user completed it, or unavailable
    /// when its biometric factors meet no class (Registry §2.8);
    /// any other signal is the PaSO module's measurement, or unavailable when the wallet does not
    /// implement it. A collection older than the signal's bound is a fault (§4.3).
    fn reading(
        &self,
        spec: &SignalSpec,
        modules: Modules<'_>,
        authentication: &Authentication,
    ) -> Result<(Timestamp, Status), Fault> {
        let now = modules.platform.now();
        if spec.signal == RiskSignal::RESPONSE_MODE {
            let mode = Node::String(Cow::Borrowed(self.mode.as_str()));
            return Ok((now, Status::Ok(mode)));
        }
        let (collected_at, status) = if spec.signal == RiskSignal::AMR {
            let status = amr::methods(authentication).map_or(Status::Unavailable, Status::Ok);
            (authentication.completed_at(), status)
        } else {
            let bound = spec.max_age.map(|age| Seconds(age.0));
            let Some(measurement) = modules.paso.measure(spec.signal.signal(), bound) else {
                return Ok((now, Status::Unavailable));
            };
            let status = match measurement.reading {
                Reading::Ok(raw) => Status::Ok(
                    Node::parse(raw.get())
                        .map_err(|e| Fault::caused(FAULT, detail!("a measured value"), e))?
                        .into_owned(),
                ),
                Reading::Unavailable => Status::Unavailable,
                Reading::Denied => Status::Denied,
            };
            (measurement.collected_at, status)
        };
        let age = now.0.saturating_sub(collected_at.0);
        if spec.max_age.is_some_and(|bound| age > bound.0) {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "{signal} was collected {age} s ago, past its bound",
                    signal = spec.signal.as_str().to_owned()
                ),
            ));
        }
        Ok((collected_at, status))
    }
}
