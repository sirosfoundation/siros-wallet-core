//! The TS12 transaction data profile for the SIROS wallet core: `urn:eudi:sca:payment:1` and
//! `urn:eudi:sca:login_risk_transaction:1`, as a [`Profile`] the core's registry holds under
//! `urn:eudi:sca:`. It reads TS12's wire, writes TS12's Key Binding JWT claims and renders through
//! siros-paso's engine. A clause TS12 defines exactly keeps TS12's behaviour, one it leaves loose
//! takes PaSO's rule, and a mechanism it does not define is unsupported: an issuer's JSON Schema,
//! bracket-path integrity claims, `extends` of transaction data types.
//!
//! - TS12 §4.1: the registration document, composed at issuance ([`document`]).
//! - TS12 §4.3: the typed payloads ([`payload`]).
//! - TS12 §3.3: the display rules, translated into PaSO's metadata ([`translate`], [`view`]).
//! - TS12 §3.6: the `amr` claim ([`mod@amr`]).
//!
//! ```
//! use siros_explain::{AllOf, checked};
//! use siros_openid4vp::hash::Sha2;
//! use siros_openid4vp::host::Platform;
//! use siros_openid4vp::plugins::Registry;
//! use siros_paso::{RandomIds, TestRandomIds};
//! use siros_testkit::TestPlatform;
//! use siros_ts12::{AttestationType, Ts12Profile};
//!
//! siros_testkit::test_host! {
//!     #[derive(Debug, Clone, Default)]
//!     struct Host {
//!         handles { platform: TestPlatform => Platform, random_ids: TestRandomIds => RandomIds }
//!         zero_sized {}
//!         optional {}
//!         lacks {}
//!     }
//! }
//!
//! const IBAN: AttestationType = checked!(AttestationType, "https://example.com/sca-iban");
//! let mut builder = Registry::<Host>::builder();
//! builder.hash(Sha2::Sha256);
//! assert!(Ts12Profile::new(AllOf::one(IBAN)).register(&mut builder).is_ok());
//! assert!(builder.build().is_ok());
//! ```

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

#[cfg(feature = "resolve")]
pub mod amr;
pub mod document;
pub mod field;
pub mod payload;
#[cfg(feature = "resolve")]
mod phase2;
mod rules;
pub mod translate;
pub mod view;

use siros_explain::{AllOf, Message, Messages};
use siros_openid4vp::detail;
use siros_openid4vp::ids::{InvalidId, TypePrefix};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Attested, Binding, Bound, BoundEntries, Build, Carriage, Exclude, Exclusion, Fault,
    FaultDomain, HostedProfile, Member, NoCandidate, Profile, ProfileHandle, RegistryBuilder,
    ViewAdditions,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Entry, EntryIndex, Request};
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::wallet::Credential;
use siros_openid4vp::wallet_metadata::Placement;
use siros_paso::entry::Payload;
use siros_paso::image::Resolution;
use siros_paso::label_limit;
use siros_paso::labels::LabelLimits;
use siros_paso::outcome::Outcome;
use siros_paso::render::{self, ItemBound, Registered};
use siros_paso::{FailedImage, Fetch};

#[cfg(feature = "resolve")]
pub use amr::{AmrCategory, amr};
pub use document::{
    BuiltInEntry, ComposeError, DOCUMENT, SCA_CATEGORY, Ts12Document, Ts12Type, TypeEntry,
};
pub use field::FieldPath;
pub use payload::{
    DataUrl, DateForm, Expected, Integrity, Logo, MaxChars, PayloadRefusal, Ts12Payload,
};
pub use rules::{Ts12Excluded, Ts12Rule};
pub use translate::{Ts12Unsupported, paso_metadata};

use crate::translate::labels_for;

pub(crate) const FAULT: FaultDomain = siros_explain::checked!(FaultDomain, "ts12.fault");

/// The prefix the profile registers under.
pub const PREFIX: &str = "urn:eudi:sca:";

/// TS12 §3.3.3's limits; claim labels under PaSO's (Proof Metadata §3.3).
pub const LIMITS: LabelLimits = LabelLimits {
    claim_name: label_limit!(60),
    title: label_limit!(50),
    affirmative: label_limit!(30),
    denial: label_limit!(30),
    hint: label_limit!(250),
};

/// `jti`, `response_mode`, `amr`, `transaction_data_hashes` and `transaction_data_hashes_alg` as
/// Key Binding JWT claims (TS12 §3.6, §1.2).
pub(crate) static KEY_BINDING: [Member; 5] = [
    Member::claim("jti"),
    Member::claim("response_mode"),
    Member::claim("amr"),
    Member::claim("transaction_data_hashes"),
    Member::claim("transaction_data_hashes_alg"),
];

/// The crate's messages: those its error types declare.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        [
            ComposeError::messages(),
            PayloadRefusal::messages(),
            Ts12Unsupported::messages(),
            Ts12Rule::messages(),
            Ts12Excluded::messages(),
            view::ConvertError::messages(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// An attestation type a credential's `types` may name (a `vct` value): non-empty, fixed by the
/// build with `siros_explain::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationType(&'static str);

impl AttestationType {
    /// The type; `None` for an empty text.
    #[must_use]
    pub const fn new(vct: &'static str) -> Option<Self> {
        if vct.is_empty() {
            None
        } else {
            Some(Self(vct))
        }
    }

    /// The `vct` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// The profile: the attestation types a credential's `types` must name one of, View §2's item
/// bound, and the https logos the wallet holds.
#[derive(Debug, Clone)]
pub struct Ts12Profile {
    attestation_types: AllOf<AttestationType>,
    bound: ItemBound,
    pub(crate) resources: Vec<(String, Fetch)>,
}

/// What phase 2 finds: a displayed https logo whose fetch or verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ts12Finding {
    /// The logo.
    pub failed: FailedImage,
}

/// A TS12 entry's translation for a credential.
pub(crate) struct Translated {
    pub(crate) kind: Ts12Type,
    #[cfg(feature = "resolve")]
    pub(crate) typed: Ts12Payload,
    pub(crate) metadata: Node<'static>,
    pub(crate) payload: Node<'static>,
}

impl Ts12Profile {
    /// The profile, for credentials whose `types` name one of the attestation types (CS-12 §7.1
    /// item 2: the three base types).
    #[must_use]
    pub const fn new(attestation_types: AllOf<AttestationType>) -> Self {
        Self {
            attestation_types,
            bound: ItemBound::LEAST,
            resources: Vec::new(),
        }
    }

    /// The profile under another item bound.
    #[must_use]
    pub const fn with_bound(mut self, bound: ItemBound) -> Self {
        self.bound = bound;
        self
    }

    /// The profile knowing what the wallet fetched for an https logo.
    #[must_use]
    pub fn with_resource(mut self, url: &HttpsUrl, fetch: Fetch) -> Self {
        self.resources.push((url.written().to_owned(), fetch));
        self
    }

    /// Registers the profile under `urn:eudi:sca:`.
    ///
    /// # Errors
    ///
    /// [`InvalidId`]: the prefix is no valid type prefix.
    pub fn register<H>(self, builder: &mut RegistryBuilder<H>) -> Result<ProfileHandle, InvalidId>
    where
        H: Build,
        Self: HostedProfile<H>,
    {
        let prefix = TypePrefix::parse(PREFIX)?;
        let handle = builder.profile(self);
        builder.prefix(prefix, handle);
        Ok(handle)
    }

    /// What the wallet knows of an https logo: the first resource of its URL as written.
    pub(crate) fn resolution(&self, url: &str) -> Resolution<'_> {
        match self.resources.iter().find(|(known, _)| known == url) {
            None => Resolution::Unknown,
            Some((_, Fetch::Fetched { content, media })) => Resolution::Fetched { content, media },
            Some((_, Fetch::Failed(reason))) => Resolution::Failed(reason),
        }
    }

    /// Phase 1's steps 2 to 7 for the entry and a credential.
    fn bound(
        &self,
        binding: &Binding<'_>,
        index: EntryIndex,
        entry: &Entry<'_>,
        env: &Env,
    ) -> Result<Result<Bound, Excluding>, Fault> {
        let translated = match read_document(binding.credential)? {
            None => return Ok(Err(Excluding::from(Ts12Unsupported::NoDocument))),
            Some(node) => match self.supported(&node, binding.additions) {
                Ok(()) => translate(&node, entry)?,
                Err(unsupported) => return Ok(Err(unsupported.into())),
            },
        };
        let translated = match translated {
            Ok(translated) => translated,
            Err(excluded) => return Ok(Err(excluded)),
        };
        let payload = Payload::of(&translated.payload)
            .ok_or_else(|| Fault::new(FAULT, detail!("a payload that is no object")))?;
        let view = render::Request {
            registered: Registered::of(translated.kind.paso_type(), &translated.metadata),
            payload,
            env,
            bound: self.bound,
            limits: LIMITS,
            resolve: |url: &str| self.resolution(url),
        }
        .render();
        let view = match view {
            Ok(view) => view,
            Err(outcome) => return Ok(Err(outcome.into())),
        };
        let attested = Attested::new(Vec::new())
            .map_err(|e| Fault::caused(FAULT, detail!("the attested display"), e))?;
        let entries = BoundEntries::select(binding.entries, vec![index])
            .map_err(|e| Fault::caused(FAULT, detail!("the bound entry"), e))?;
        Ok(Ok(siros_paso::bound(view, attested, entries)?))
    }

    /// Phase 1's step 2.
    fn supported(
        &self,
        document: &Node<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<(), Ts12Unsupported> {
        let read = Ts12Document::read(document).map_err(|_| Ts12Unsupported::NoDocument)?;
        if read.category() != Some(SCA_CATEGORY) {
            return Err(Ts12Unsupported::Category);
        }
        if !self.configured(additions) {
            return Err(Ts12Unsupported::AttestationType);
        }
        Ok(())
    }

    /// A configured attestation type is among the credential's types (reading 26).
    fn configured(&self, additions: &dyn ViewAdditions) -> bool {
        additions.types().iter().any(|kind| {
            self.attestation_types
                .items()
                .iter()
                .any(|configured| configured.as_str() == kind.as_str())
        })
    }
}

/// The document a credential's registration holds; `None` when it holds none.
pub(crate) fn read_document<'c>(credential: &Credential<'c>) -> Result<Option<Node<'c>>, Fault> {
    credential
        .document(DOCUMENT)
        .map(|bytes| {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| Fault::caused(FAULT, detail!("the TS12 document"), e))?;
            Node::parse(text).map_err(|e| Fault::caused(FAULT, detail!("the TS12 document"), e))
        })
        .transpose()
}

/// Phase 1's steps 3 to 6: the entry's type under the document's rules, its typed payload and its
/// translation into PaSO's model.
pub(crate) fn translate(
    document: &Node<'_>,
    entry: &Entry<'_>,
) -> Result<Result<Translated, Excluding>, Fault> {
    let read = Ts12Document::read(document)
        .map_err(|e| Fault::caused(FAULT, detail!("the TS12 document"), e))?;
    let kind = entry.kind().as_str();
    let translated = (|| {
        let listed = read.entry(kind).ok_or_else(|| Ts12Unsupported::NotListed {
            kind: kind.to_owned(),
        })?;
        let built_in = listed.built_in().ok_or_else(|| Ts12Unsupported::Schema {
            schema: listed.schema().unwrap_or_default().to_owned(),
        })?;
        let metadata = paso_metadata(&built_in)?;
        let members = entry.members();
        let payload = members.get("payload").ok_or_else(|| {
            Excluding::from(PayloadRefusal::Required {
                path: field::PAYLOAD,
            })
        })?;
        let typed = Ts12Payload::parse(built_in.kind(), payload)?;
        labels_for(&built_in, payload)?;
        Ok::<_, Excluding>((built_in.kind(), typed, metadata))
    })();
    match translated {
        Err(excluding) => Ok(Err(excluding)),
        Ok((kind, typed, metadata)) => {
            let payload = Node::Object(typed.paso_payload());
            Ok(Ok(Translated {
                kind,
                #[cfg(feature = "resolve")]
                typed,
                metadata,
                payload,
            }))
        }
    }
}

/// What keeps a credential from a TS12 entry: the rule the matcher reports, or View §4's.
pub(crate) enum Excluding {
    /// Phase 1's rules.
    Rule(Ts12Excluded),
    /// View §4: no locale of the wallet's list.
    Locale(siros_paso::outcome::Excluded),
}

impl From<Ts12Unsupported> for Excluding {
    fn from(unsupported: Ts12Unsupported) -> Self {
        Self::Rule(Ts12Excluded::Unsupported(unsupported))
    }
}

impl From<PayloadRefusal> for Excluding {
    fn from(refusal: PayloadRefusal) -> Self {
        Self::Rule(Ts12Excluded::Payload(refusal))
    }
}

impl From<Outcome> for Excluding {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Excluded(excluded) => Self::Locale(excluded),
            other => Self::Rule(Ts12Excluded::Rendering(other)),
        }
    }
}

impl From<Excluding> for NoCandidate {
    fn from(excluding: Excluding) -> Self {
        match excluding {
            Excluding::Rule(rule) => exclude(rule),
            Excluding::Locale(excluded) => exclude(excluded),
        }
    }
}

fn exclude(rule: impl Exclusion + 'static) -> NoCandidate {
    Exclude::new(rule).into()
}

impl Profile for Ts12Profile {
    type Finding = Ts12Finding;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        rules::refusals(request, entries)
    }

    /// TS12 defines its binding as Key Binding JWT claims (TS12 §1.2, §3.6) and none for a name
    /// space.
    fn members(&self, placement: Placement) -> Option<&[Member]> {
        match placement {
            Placement::Claims => Some(&KEY_BINDING),
            Placement::NameSpaces => None,
        }
    }

    /// Phase 1 (TS12 §3.2): the request's one TS12 entry for the credential. T2 leaves one.
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate> {
        if binding.carriage == Carriage::Uncarried {
            return Err(exclude(Ts12Excluded::Carriage));
        }
        let [index] = binding.entries else {
            return Err(Fault::new(FAULT, detail!("offered entries other than one")).into());
        };
        let entry = binding
            .request
            .entry(*index)
            .ok_or_else(|| Fault::new(FAULT, detail!("an offered entry the request lacks")))?;
        match self.bound(&binding, *index, entry, env)? {
            Ok(bound) => Ok(bound),
            Err(excluding) => Err(excluding.into()),
        }
    }

    /// One SCA attestation per request (CS-12 §7.3 item 7; rb-sca-iban §9): the credentials whose
    /// `ts12` document's category is SCA's with a configured type among their types.
    fn reserves(
        &self,
        credential: &Credential<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<bool, Fault> {
        Ok(read_document(credential)?
            .is_some_and(|document| self.supported(&document, additions).is_ok()))
    }
}
