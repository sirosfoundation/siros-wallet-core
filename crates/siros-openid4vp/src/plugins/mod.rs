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
#![cfg_attr(
    feature = "resolve",
    doc = "implementations ([`crate::host::FormatHost`], [`crate::host::ProfileHost`])."
)]
#![cfg_attr(
    not(feature = "resolve"),
    doc = "implementations (`host::FormatHost`, `host::ProfileHost`, with the feature `resolve`)."
)]

#[cfg(feature = "resolve")]
mod answered;
pub(crate) mod members;
pub(crate) mod registry;

use std::error::Error;
use std::fmt;

use dyn_clone::DynClone;
use siros_explain::{Arg, Explain};
use siros_i18n::Context;
use siros_syntax::AllOf;

#[cfg(feature = "resolve")]
pub use answered::{Answered, FetchedRecord};
pub use members::{JsonText, Member, MemberTwice, MemberValue, Members};
#[cfg(feature = "transaction-data")]
pub use registry::Hashes;
pub use registry::{
    Build, HostedErrorMode, HostedFormat, HostedMode, HostedProfile, HostedResponseParameters,
    JweHost, MemberNames, NoHost, ProfileHandle, Registry, RegistryBuilder, RegistryError,
};
#[cfg(feature = "resolve")]
pub use registry::{FindingData, InformError, ProfileFinding};

use crate::claims::Foreign;
use crate::consent::{Card, Header, Overlay};
use crate::ids::{CredentialType, FormatId};
use crate::json::Node;
use crate::refusal::Refusal;
use crate::request::{AgreeableKey, EntryIndex, Item, ItemSet, Query, Request};
use crate::routing::QueryContext;
use crate::rows::Env;
use crate::wallet::Credential;
use crate::wallet_metadata::Placement;

/// The citation of the clause that decides a rule (`CSC §6.3`): a text its crate's source writes,
/// so no received value becomes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clause(&'static str);

impl Clause {
    /// The clause this citation names.
    #[must_use]
    pub const fn cited(citation: &'static str) -> Self {
        Self(citation)
    }

    /// The citation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Clause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A rule that keeps a credential from answering a query: its message, and the clause that
/// decides it.
pub trait Exclusion: Explain {
    /// The clause that decides it.
    fn clause(&self) -> Clause;
}

/// A credential cannot answer a query: the plug-in's rule, kept as itself until a text is needed.
/// Its id, arguments and source are the rule's; its log line adds the clause.
#[derive(Debug)]
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
    pub fn clause(&self) -> Clause {
        self.rule.clause()
    }
}

impl fmt::Display for Exclude {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.rule, self.rule.clause())
    }
}

impl Error for Exclude {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.rule.source()
    }
}

impl Explain for Exclude {
    fn id(&self) -> &'static str {
        self.rule.id()
    }

    fn arg(&self, key: &str) -> Option<&dyn Arg> {
        self.rule.arg(key)
    }
}

/// A fault's detail: a formatter of the format string over the values named after it, each
/// owned by the formatter, which writes when the log line is written:
/// `detail!("{id}: no view", id = id.to_owned())`.
#[macro_export]
macro_rules! detail {
    ($text:literal $(, $name:ident = $value:expr)* $(,)?) => {{
        $(let $name = $value;)*
        $crate::plugins::Detail::new(
            move |f: &mut ::core::fmt::Formatter<'_>| ::core::write!(f, $text),
        )
    }};
}

/// A fault's log line, written when a log line is written: a formatter that owns its values.
/// [`detail!`](crate::detail) makes one.
pub struct Detail(Box<dyn Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync>);

impl Detail {
    /// The detail `write` writes.
    pub fn new(
        write: impl Fn(&mut fmt::Formatter<'_>) -> fmt::Result + Send + Sync + 'static,
    ) -> Self {
        Self(Box::new(write))
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(f)
    }
}

impl fmt::Debug for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Detail")
            .field(&format_args!("{self}"))
            .finish()
    }
}

/// A plug-in could not read the wallet's data, or broke its contract. Its id and source are the
/// fault error's that its crate wraps.
#[derive(Debug, thiserror::Error, Explain)]
#[error(transparent)]
pub struct Fault(Box<dyn Explain>);

impl Fault {
    /// The fault of a crate's own fault error. Each crate that faults derives one, under its
    /// scope, with its detail for the log line and its cause as the source:
    ///
    /// ```standalone_crate
    /// use std::error::Error;
    ///
    /// use siros_explain::Explain;
    /// use siros_openid4vp::detail;
    /// use siros_openid4vp::plugins::{Detail, Fault};
    ///
    /// siros_explain::scope!("mdoc");
    ///
    /// #[derive(Debug, thiserror::Error, Explain)]
    /// #[error("{detail}")]
    /// #[explain(id = "fault")]
    /// struct MdocFault {
    ///     #[explain(skip)]
    ///     detail: Detail,
    ///     #[source]
    ///     cause: Option<Box<dyn Error + Send + Sync>>,
    /// }
    ///
    /// fn main() {
    ///     let id = "pid-1";
    ///     let fault = Fault::new(MdocFault {
    ///         detail: detail!("{id}: no view", id = id.to_owned()),
    ///         cause: None,
    ///     });
    ///     assert_eq!(fault.id(), "err.mdoc.fault");
    ///     assert_eq!(fault.to_string(), "pid-1: no view");
    /// }
    /// ```
    pub fn new(error: impl Explain) -> Self {
        Self(Box::new(error))
    }
}

/// The core's fault error.
#[cfg(any(feature = "match", feature = "claims"))]
#[derive(Debug, thiserror::Error, Explain)]
#[error("{detail}")]
#[explain(id = "fault")]
struct CoreFault {
    #[explain(skip)]
    detail: Detail,
    #[source]
    cause: Option<Box<dyn Error + Send + Sync>>,
}

/// The core's fault, its log line written by `detail`.
#[cfg(any(feature = "match", feature = "claims"))]
pub(crate) fn fault(detail: Detail) -> Fault {
    Fault::new(CoreFault {
        detail,
        cause: None,
    })
}

/// The core's fault caused by an error, its log line written by `detail`.
#[cfg(any(feature = "match", feature = "claims"))]
pub(crate) fn caused(detail: Detail, cause: impl Error + Send + Sync + 'static) -> Fault {
    Fault::new(CoreFault {
        detail,
        cause: Some(Box::new(cause)),
    })
}

/// Why a credential gives no candidate for a query.
#[derive(Debug, thiserror::Error, Explain)]
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

/// A Credential Query's options, in the Verifier's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options(Vec<OptionItems>);

impl Options {
    /// The options, in the Verifier's order.
    #[must_use]
    pub const fn new(options: Vec<OptionItems>) -> Self {
        Self(options)
    }

    /// Each option, in order.
    pub fn iter(&self) -> impl Iterator<Item = &OptionItems> {
        self.0.iter()
    }

    /// Each option with its index, the only way to an [`OptionIndex`].
    pub fn indexed(&self) -> impl Iterator<Item = (OptionIndex, &OptionItems)> {
        self.0
            .iter()
            .enumerate()
            .map(|(position, items)| (OptionIndex(position), items))
    }

    /// The option at an index; `None` for an index of a longer query's options.
    #[must_use]
    pub fn get(&self, option: OptionIndex) -> Option<&OptionItems> {
        self.0.get(option.0)
    }

    /// The option at an index.
    ///
    /// # Errors
    ///
    /// [`Foreign::Option`]: the index is of a longer query's options.
    pub fn option(&self, option: OptionIndex) -> Result<&OptionItems, Foreign> {
        self.get(option).ok_or(Foreign::Option { option: option.0 })
    }
}

/// An option by its position in a query's options. Only [`Options::indexed`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OptionIndex(usize);

impl OptionIndex {
    /// The position in the query's options.
    #[must_use]
    pub const fn position(self) -> usize {
        self.0
    }
}

/// The items a card shows: those in every option the credential answers, then those the chosen
/// option adds.
#[derive(Debug, Clone, Copy)]
pub struct Shown<'i> {
    /// The items in every answerable option.
    pub everyone: &'i [Item],
    /// The items the chosen option adds.
    pub chosen: &'i [Item],
}

/// A format plug-in: a Credential Format Identifier's queries, credentials and presentations.
///
/// # Implementing
///
/// `id` is a constant; the registry refuses a format identifier registered twice
/// (`RegistryError::FormatTwice`). `query` reads a Credential Query of the format under the
/// core-made `QueryContext`, and refuses with the request rules it breaks, one or more, as an
/// `AllOf<Refusal>`. `wallet_formats` is the JSON object `vp_formats_supported` holds under `id`
/// (§10.1); the core refuses another value (`MetadataRefused::NotObject`). `placement` states how
/// the format's proof carries a profile's members, and the format writes the members a profile
/// gives where that placement says; the registry refuses a profile naming a member the placement
/// does not hold (`MemberPlacement`) or one the format's proof writes itself (`MemberTwice`,
/// through `reserved`). The phase-2 half, `FormatHost`, answers a query as phase 2 reads it, over
/// the host modules its bounds name, with a `Presentation` of §8.1's two forms. siros-mdoc,
/// siros-sdjwt and siros-zkp-req implement it; siros-testkit's `TestFormat` is the double.
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
    fn types(&self) -> &[CredentialType<'static>];
}

/// A credential's types as its format read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewTypes(Vec<CredentialType<'static>>);

impl ViewTypes {
    /// The types, the credential's own first, then those it extends, nearest first.
    #[must_use]
    pub const fn new(types: Vec<CredentialType<'static>>) -> Self {
        Self(types)
    }
}

impl ViewAdditions for ViewTypes {
    fn types(&self) -> &[CredentialType<'static>] {
        &self.0
    }
}

dyn_clone::clone_trait_object!(Format);

/// A Credential Query as its format parsed it.
pub trait FormatQuery {
    /// The options, in the Verifier's order.
    fn options(&self) -> &Options;

    /// Excludes the credential when the Verifier's `vp_formats_supported` admits no algorithm
    /// its presentation can use; `keys`: the Verifier's keys, which a presentation may need.
    fn admits(
        &self,
        credential: &Credential<'_>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate>;

    /// The options of [`FormatQuery::options`] the credential answers, ascending; empty when it
    /// does not match the query. The core faults on a list of another order or of another
    /// query's options.
    /// `provided`: the response members the transaction bound to the credential writes, which a
    /// claim may name.
    fn answerable(
        &self,
        credential: &Credential<'_>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault>;

    /// Whether the credential's presentation can carry these transaction response members.
    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<Carriage, Fault>;

    /// Excludes a credential answering `options` when what the End-User could be shown of it
    /// must not reach them.
    fn displayable(
        &self,
        credential: &Credential<'_>,
        options: &[OptionIndex],
        env: &Env,
    ) -> Result<(), NoCandidate>;

    /// The credential's card showing the items, each text resolved by `context`. A format that
    /// converts metadata into wording loads the converted source into a clone of `context`.
    ///
    /// # Errors
    ///
    /// The format cannot read the credential, or `context` resolves no text for one of the
    /// card's statements: the fault's source is the `siros_i18n::ResolveError`.
    fn draw(
        &self,
        credential: &Credential<'_>,
        shown: Shown<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Card, Fault>;
}

/// The `transaction_data` entries a credential authorizes for a query: a non-empty ascending
/// subset of the entries offered to the profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundEntries(Vec<EntryIndex>);

/// Bound entries that break their rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "not_offered")]
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

/// A name a response attests a text of the display under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestedName(String);

impl AttestedName {
    /// The name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The text of the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A text of the display a response attests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestedText(String);

impl AttestedText {
    /// The text.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a response attests of the display: (name, text) pairs, each name once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Attested(Vec<(AttestedName, AttestedText)>);

/// An attested name given twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "attested_twice")]
#[error("the attested name {name} is given twice")]
pub struct AttestedTwice {
    /// The name.
    pub name: String,
}

impl Attested {
    /// The pairs, each name once.
    pub fn new(pairs: Vec<(AttestedName, AttestedText)>) -> Result<Self, AttestedTwice> {
        if let Some((name, _)) = pairs.iter().enumerate().find_map(|(k, (name, text))| {
            pairs
                .iter()
                .take(k)
                .any(|(n, _)| n == name)
                .then_some((name, text))
        }) {
            return Err(AttestedTwice {
                name: name.as_str().to_owned(),
            });
        }
        Ok(Self(pairs))
    }

    /// The pairs in order.
    #[must_use]
    pub fn pairs(&self) -> &[(AttestedName, AttestedText)] {
        &self.0
    }

    /// The text attested under a name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AttestedText> {
        self.0
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, text)| text)
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

/// A transaction data profile: the rules, binding and response members of the transaction data
/// types it is registered under.
///
/// # Implementing
///
/// The registry keys a profile by exact type and by type prefix, and refuses a type or prefix
/// registered twice (`TypeTwice`), a registration under a handle it does not hold
/// (`UnknownProfile`), and members a format's proof cannot hold (`MemberPlacement`,
/// `MemberTwice`). `refusals` reads the request's entries the profile owns and refuses with its
/// rules' codes. `members` places the profile's members by the format's [`Placement`] and names
/// no format. `bind` reads a core-made [`Binding`] and gives the entries the credential
/// authorizes, with their texts. The phase-2 half, `ProfileHost`, names the resources it revalidates with
/// (`wanted`), the authentication a record needs, its revalidation and its response members over
/// the host modules its bounds name. siros-paso and siros-qes implement it; siros-testkit's
/// `TestProfile` is the double.
pub trait Profile: Clone + Send + Sync + 'static {
    /// What phase 2 finds when something the matcher assumed no longer holds.
    type Finding: fmt::Debug + Send + Sync + 'static;

    /// The profile's request rules over its own entries.
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal>;

    /// The response members its transactions write in a proof of this placement, each of the
    /// kind the placement holds ([`Placement::places`]; the registry refuses another); `None`
    /// when it defines no binding for it. A profile names no format.
    fn members(&self, placement: Placement) -> Option<&[Member]>;

    /// The entries of `binding.entries` the credential authorizes, with the header and overlay
    /// their texts resolved by `context`. A profile that converts the request's metadata into
    /// wording loads the converted source into a clone of `context`.
    ///
    /// # Errors
    ///
    /// The profile excludes the credential, cannot read it, or `context` resolves no text for one
    /// of its statements: that fault's source is the `siros_i18n::ResolveError`.
    fn bind(
        &self,
        binding: Binding<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Bound, NoCandidate>;

    /// Whether the profile keeps the credential for its own transactions: a credential a profile
    /// reserves is a candidate only for a query one of the profile's entries names. `additions`:
    /// what the registration view gains for it, its types.
    ///
    /// # Errors
    ///
    /// The profile cannot read the wallet's data.
    fn reserves(
        &self,
        _credential: &Credential<'_>,
        _additions: &dyn ViewAdditions,
    ) -> Result<bool, Fault> {
        Ok(false)
    }
}
