//! The two plug-in kinds and the registry that holds them.
//!
//! A [`Format`] owns a Credential Query's format members and the credentials of its format: which
//! options a credential answers, whether the Verifier's algorithms admit it, the card that shows
//! them, whether its presentation can carry a transaction's response members, and the
//! presentation itself with those members written into its proof beside the format's own.
//!
//! A [`Profile`] owns a family of transaction data types: its request rules, which entries a
//! credential authorizes for a query, and everything the core needs afterwards as data (the
//! header, the attested display facts, the overlay over the format's card), then in phase 2 what
//! it revalidates and the response members each format carries.
//!
//! The core calls them through these traits only, and in phase 2 through their host
//! implementations ([`crate::host::FormatHost`], [`crate::host::ProfileHost`]).

#[cfg(feature = "resolve")]
mod answered;
pub(crate) mod members;
pub(crate) mod registry;

use std::borrow::Cow;
use std::fmt;

use dyn_clone::DynClone;
use siros_explain::{AllOf, Args, Explain, Explained, Message, MessageId, Messages, names};

#[cfg(feature = "resolve")]
pub use answered::{Answered, FetchedRecord};
pub use members::{JsonText, Member, MemberTwice, MemberValue, Members};
#[cfg(feature = "resolve")]
pub use registry::{FindingData, InformError, ProfileFinding};
pub use registry::{
    HostedFormat, HostedMode, HostedProfile, NoHost, ProfileHandle, Registry, RegistryBuilder,
    RegistryError,
};

use crate::consent::{Card, Header, Overlay};
use crate::ids::FormatId;
use crate::json::Node;
use crate::refusal::Refusal;
use crate::request::{AgreeableKey, EntryIndex, Item, ItemSet, Query, Request};
use crate::routing::QueryContext;
use crate::rows::Env;
use crate::wallet::Credential;
use crate::wallet_metadata::Placement;
#[cfg(feature = "resolve")]
use crate::{host::AuthenticationNeed, rows::HttpsUrl};

/// A rule that keeps a credential from answering a query: its message, and the clause that
/// decides it.
pub trait Exclusion: Explained {
    /// The clause that decides it.
    fn clause(&self) -> Cow<'static, str>;
}

/// A credential cannot answer a query: the plug-in's rule, kept as itself until a text is needed.
#[derive(Debug, thiserror::Error)]
#[error("{rule} [{}]", rule.clause())]
pub struct Exclude {
    rule: Box<dyn Exclusion>,
}

impl Exclude {
    /// The exclusion by a rule.
    pub fn new(rule: impl Exclusion) -> Self {
        Self {
            rule: Box::new(rule),
        }
    }

    /// The rule.
    #[must_use]
    pub fn rule(&self) -> &dyn Exclusion {
        &*self.rule
    }

    /// The clause that decides it.
    #[must_use]
    pub fn clause(&self) -> Cow<'static, str> {
        self.rule.clause()
    }
}

/// An exclusion's message is its rule's.
impl Explain for Exclude {
    fn id(&self) -> MessageId {
        self.rule.id()
    }

    fn args(&self) -> Args<'_> {
        self.rule.args()
    }
}

/// An exclusion's rule declares its message, in its own type's [`Messages`].
impl Messages for Exclude {
    fn messages() -> Vec<Message> {
        Vec::new()
    }
}

/// A crate's domain, as its fault message `<domain>.fault`: `checked!(FaultDomain,
/// "openid4vp.fault")` makes one when the crate builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultDomain(MessageId);

impl FaultDomain {
    /// The domain of the message `id`; `None` unless `id` is a message identifier ending in
    /// `.fault`.
    #[must_use]
    pub const fn new(id: &'static str) -> Option<Self> {
        match MessageId::new(id) {
            Some(message) if matches!(id.as_bytes(), [.., b'.', b'f', b'a', b'u', b'l', b't']) => {
                Some(Self(message))
            }
            _ => None,
        }
    }

    /// The fault message's identifier.
    #[must_use]
    pub const fn id(self) -> MessageId {
        self.0
    }

    /// The fault message as its crate's module declares it: no argument.
    #[must_use]
    pub fn message(self) -> Message {
        Message::new(
            self.0,
            Some("a plug-in could not read the wallet's data, or broke its contract"),
            names!(),
            [],
        )
    }
}

/// A fault's detail: a formatter of the format string over the values named after it, each
/// owned by the formatter, which writes when the log line is written.
///
/// ```
/// use siros_explain::checked;
/// use siros_openid4vp::detail;
/// use siros_openid4vp::plugins::{Fault, FaultDomain};
///
/// const FAULT: FaultDomain = checked!(FaultDomain, "example.fault");
///
/// fn view_fault(id: &str) -> Fault {
///     Fault::new(FAULT, detail!("{id}: no view", id = id.to_owned()))
/// }
/// assert_eq!(view_fault("c1").to_string(), "c1: no view");
/// ```
#[macro_export]
macro_rules! detail {
    ($text:literal $(, $name:ident = $value:expr)* $(,)?) => {{
        $(let $name = $value;)*
        move |f: &mut ::core::fmt::Formatter<'_>| ::core::write!(f, $text)
    }};
}

/// Writes a fault's detail when a log line is written: a formatter that owns its values.
type Detail = Box<dyn Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync>;

/// A plug-in could not read the wallet's data, or broke its contract. Its message is its
/// crate's `<domain>.fault`; its detail is the log line's.
pub struct Fault {
    domain: FaultDomain,
    detail: Detail,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Fault {
    /// A fault of a crate, its detail written by `detail`.
    pub fn new(
        domain: FaultDomain,
        detail: impl Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync + 'static,
    ) -> Self {
        Self {
            domain,
            detail: Box::new(detail),
            source: None,
        }
    }

    /// A fault of a crate caused by an error, its detail written by `detail`.
    pub fn caused(
        domain: FaultDomain,
        detail: impl Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync + 'static,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            domain,
            detail: Box::new(detail),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.detail)(f)
    }
}

impl fmt::Debug for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fault")
            .field("domain", &self.domain)
            .field("detail", &self.to_string())
            .field("source", &self.source)
            .finish()
    }
}

impl std::error::Error for Fault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// A fault's message is its crate's `<domain>.fault`, its detail left to the log line.
impl Explain for Fault {
    fn id(&self) -> MessageId {
        self.domain.id()
    }

    fn args(&self) -> Args<'_> {
        Args::none()
    }
}

/// A fault's message is its crate's, which the crate declares with [`FaultDomain::message`].
impl Messages for Fault {
    fn messages() -> Vec<Message> {
        Vec::new()
    }
}

/// Why a credential gives no candidate for a query.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.no_candidate")]
pub enum NoCandidate {
    /// The plug-in excludes it.
    #[error(transparent)]
    Excluded(#[from] Exclude),
    /// The plug-in failed.
    #[error(transparent)]
    Fault(#[from] Fault),
}

/// A Credential Query's option: the items it holds, in the Verifier's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionItems(Vec<Item>);

impl OptionItems {
    /// The option of these items.
    #[must_use]
    pub fn new(items: Vec<Item>) -> Self {
        Self(items)
    }

    /// The items in the Verifier's order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.0
    }

    /// The items as a set.
    #[must_use]
    pub fn set(&self) -> ItemSet {
        ItemSet::of(self.0.iter().copied())
    }
}

/// An option by its position in the query's options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OptionIndex(pub usize);

/// The items a card shows: those in every option the credential answers, then those the chosen
/// option adds.
#[derive(Debug, Clone, Copy)]
pub struct Shown<'i> {
    /// The items in every answerable option.
    pub everyone: &'i [Item],
    /// The items the chosen option adds.
    pub chosen: &'i [Item],
}

/// A format plug-in.
pub trait Format: DynClone + Send + Sync {
    /// The Credential Format Identifier it owns.
    fn id(&self) -> FormatId<'_>;

    /// The response members its proof writes itself; no profile may write one.
    fn reserved(&self) -> &[Member];

    /// Parses a Credential Query of the format, or gives the format's request rules it breaks.
    /// `context`: the request, its mode, whether a `transaction_data` entry names the query, and
    /// the Verifier's `vp_formats_supported` value for the format.
    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>>;

    /// The format's `vp_formats_supported` member, which `WalletMetadata::of` writes under the
    /// format's [`Format::id`] (Appendix B).
    ///
    /// # Errors
    ///
    /// The member is no JSON value with unique member names, a plug-in's bug.
    fn wallet_formats(&self) -> Result<Node<'static>, Fault>;

    /// How its proof carries a profile's members; `None` for a proof that carries none.
    fn placement(&self) -> Option<Placement>;

    /// What the core's registration view gains for one of its credentials: its types, which a
    /// profile reads through [`Binding::additions`] and names no format.
    ///
    /// # Errors
    ///
    /// The credential's view is none the format reads, a fault of the wallet's data.
    fn additions<'c>(
        &self,
        credential: &'c Credential<'c>,
    ) -> Result<Box<dyn ViewAdditions + 'c>, Fault>;
}

/// What the core's registration view gains: a credential's types, which its format writes at
/// registration and a profile reads (reading 26).
pub trait ViewAdditions: fmt::Debug {
    /// The credential's type, then each type its type metadata extends, nearest first, from the
    /// chain the caller resolved at registration (SD-JWT VC §6.4 for `dc+sd-jwt`); empty for a
    /// format whose credentials state no type.
    fn types(&self) -> Vec<&str>;
}

/// A credential's types as its format read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewTypes(Vec<String>);

impl ViewTypes {
    /// The types, the credential's own first, then those it extends, nearest first.
    #[must_use]
    pub const fn new(types: Vec<String>) -> Self {
        Self(types)
    }
}

impl ViewAdditions for ViewTypes {
    fn types(&self) -> Vec<&str> {
        self.0.iter().map(String::as_str).collect()
    }
}

dyn_clone::clone_trait_object!(Format);

/// A Credential Query as its format parsed it.
pub trait FormatQuery {
    /// The options, in the Verifier's order.
    fn options(&self) -> &[OptionItems];

    /// Excludes the credential when the Verifier's `vp_formats_supported` admits no algorithm
    /// its presentation can use; `keys`: the Verifier's keys, which a presentation may need.
    fn admits(
        &self,
        credential: &Credential<'_>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate>;

    /// The options the credential answers, ascending; empty when it does not match the query.
    /// `provided`: the response members the transaction bound to the credential writes, which a
    /// claim may name.
    fn answerable(
        &self,
        credential: &Credential<'_>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault>;

    /// Whether the credential's presentation can carry these transaction response members.
    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<bool, Fault>;

    /// The credential's card showing the items.
    fn draw(&self, credential: &Credential<'_>, shown: Shown<'_>, env: &Env)
    -> Result<Card, Fault>;
}

/// The `transaction_data` entries a credential authorizes for a query: a non-empty ascending
/// subset of the entries offered to the profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundEntries(Vec<EntryIndex>);

/// Bound entries that break their rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp")]
#[error("bound entries {0:?}: not a non-empty ascending subset of the offered entries")]
pub struct NotOffered(#[explain(skip)] pub Vec<EntryIndex>);

impl BoundEntries {
    /// The chosen entries, when they are a non-empty ascending subset of the offered ones.
    pub fn select(offered: &[EntryIndex], chosen: Vec<EntryIndex>) -> Result<Self, NotOffered> {
        let ascending = chosen
            .windows(2)
            .all(|pair| matches!(pair, [a, b] if a < b));
        if chosen.is_empty() || !ascending || !chosen.iter().all(|entry| offered.contains(entry)) {
            return Err(NotOffered(chosen));
        }
        Ok(Self(chosen))
    }

    /// The entries in array order.
    #[must_use]
    pub fn entries(&self) -> &[EntryIndex] {
        &self.0
    }
}

/// What a response attests of the display: (name, text) pairs, each name once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Attested(Vec<(String, String)>);

/// An attested name given twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp")]
#[error("the attested name {0} is given twice")]
pub struct AttestedTwice(#[explain(name = "name")] pub String);

impl Attested {
    /// The pairs, each name once.
    pub fn new(pairs: Vec<(String, String)>) -> Result<Self, AttestedTwice> {
        if let Some((name, _)) = pairs.iter().enumerate().find_map(|(k, (name, text))| {
            pairs.get(..k).and_then(|before| {
                before
                    .iter()
                    .any(|(n, _)| n == name)
                    .then_some((name, text))
            })
        }) {
            return Err(AttestedTwice(name.clone()));
        }
        Ok(Self(pairs))
    }

    /// The pairs in order.
    #[must_use]
    pub fn pairs(&self) -> &[(String, String)] {
        &self.0
    }

    /// The text attested under a name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, text)| text.as_str())
    }
}

/// What a profile's binding gives the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The entries the credential authorizes for the query.
    pub entries: BoundEntries,
    /// The consent header for a selection holding this credential.
    pub header: Header,
    /// What the response attests of the display.
    pub attested: Attested,
    /// What the profile draws over the format's card.
    pub overlay: Overlay,
}

/// Whether the credential's presentation can carry the profile's response members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carriage {
    /// It can.
    Carried,
    /// It cannot, or the profile defines no members for the format.
    Uncarried,
}

/// What a profile binds: a credential against the profile's entries naming a query.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'b> {
    /// The request.
    pub request: &'b Request<'b>,
    /// The query.
    pub query: &'b Query<'b>,
    /// The credential.
    pub credential: &'b Credential<'b>,
    /// The profile's entries naming the query, in array order.
    pub entries: &'b [EntryIndex],
    /// How the query's format places the profile's members; `None` for a proof that carries
    /// none.
    pub placement: Option<Placement>,
    /// What the registration view gains for the credential: its types.
    pub additions: &'b dyn ViewAdditions,
    /// Whether the presentation can carry the profile's members.
    pub carriage: Carriage,
}

/// A transaction data profile.
pub trait Profile: Clone + Send + Sync + 'static {
    /// What phase 2 finds when something the matcher assumed no longer holds.
    type Finding: fmt::Debug + Send + Sync + 'static;

    /// The profile's request rules over its own entries.
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal>;

    /// The response members its transactions write in a proof of this placement, each of the
    /// kind the placement holds ([`Placement::places`]; the registry refuses another); `None`
    /// when it defines no binding for it. A profile names no format.
    fn members(&self, placement: Placement) -> Option<&[Member]>;

    /// The entries of `binding.entries` the credential authorizes, rendered.
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate>;

    /// The https resources the profile revalidates the record with, in the order it reads them;
    /// the caller fetches each distinct URL once. Pure: the record and the profile's own data
    /// decide them.
    #[cfg(feature = "resolve")]
    fn wanted(&self, record: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault>;

    /// The profile with what phase 2 found, for re-running the consent: the matcher then treats
    /// those conditions as known to fail.
    #[cfg(feature = "resolve")]
    #[must_use]
    fn informed(&self, findings: &[&Self::Finding]) -> Self;

    /// The End-User authentication the record needs (CS-12 §5 item 4; TS12 §3.6).
    ///
    /// # Errors
    ///
    /// The profile cannot read the record.
    #[cfg(feature = "resolve")]
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault>;
}
