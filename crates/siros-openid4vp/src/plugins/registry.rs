//! The registry: formats by identifier, transaction data profiles by exact type or type prefix,
//! each plug-in under the bounds of the build's host.

#[cfg(feature = "resolve")]
use std::any::Any;
use std::any::TypeId;
use std::fmt;

use siros_explain::Explain;
use siros_syntax::AllOf;

#[cfg(feature = "resolve")]
use super::{Answered, Fault, FetchedRecord, Members};
#[cfg(feature = "match")]
use super::{Binding, Bound, NoCandidate, ViewAdditions};
use super::{Format, Member, Profile};
#[cfg(feature = "signed")]
use crate::authenticate::{HostedPrefix, ObjectRule};
#[cfg(feature = "request-decryption")]
use crate::detail;
#[cfg(feature = "transaction-data")]
use crate::hash::HashAlgorithm;
use crate::hash::HashName;
#[cfg(feature = "uri")]
use crate::host::EphemeralKey;
#[cfg(feature = "request-decryption")]
use crate::host::RequestDecryption;
#[cfg(feature = "resolve")]
use crate::host::{Authentication, AuthenticationNeed, FormatHost, ProfileHost};
#[cfg(feature = "resolve")]
use crate::host::{Haip, Has, Platform};
use crate::ids::{FormatId, TransactionType, TypePrefix};
#[cfg(feature = "request-decryption")]
use crate::plugins::fault;
#[cfg(feature = "uri")]
use crate::request::Agreements;
#[cfg(feature = "request-decryption")]
use crate::request::Curve;
use crate::routing::{
    Carries, ChannelKind, Mode, ModeHandle, ModeName, ResponseParameters, ResponseType,
    ResponseTypeName, RoutedMode,
};
#[cfg(feature = "resolve")]
use crate::routing::{ErrorModeHost, ModeHost, ResponseParametersHost};
#[cfg(feature = "resolve")]
use crate::rows::HttpsUrl;
#[cfg(feature = "uri")]
use crate::scope::ScopeQuery;
use crate::scope::{ScopeEntry, ScopeValue, Scopes};
#[cfg(feature = "request-decryption")]
use crate::uri::EncryptedRequests;
#[cfg(feature = "uri")]
use crate::uri::{AnswerReader, RequestPost};
#[cfg(feature = "match")]
use crate::wallet::Credential;
use crate::wallet_metadata::{
    CORE_ANSWER, CORE_METADATA, CORE_PARAMETERS, CORE_RESPONSE, NamePlace, ParameterName, Placement,
};
#[cfg(feature = "uri")]
use crate::wallet_metadata::{HostedPostContribution, MetadataMember, PostContribution};
#[cfg(feature = "match")]
use crate::{
    refusal::Refusal,
    request::{EntryIndex, Request},
    rows::Env,
};
#[cfg(feature = "match")]
use siros_i18n::Context;

/// A profile by its registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileHandle(usize);

/// A registry that cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
pub enum RegistryError {
    /// Two formats with one identifier.
    #[error("two formats have the identifier {format}")]
    #[explain(id = "registry.format_twice")]
    FormatTwice {
        /// The format identifier.
        format: String,
    },
    /// A type or prefix registered twice.
    #[error("{registration} is registered twice")]
    #[explain(id = "registry.type_twice")]
    TypeTwice {
        /// The type or type prefix.
        registration: String,
    },
    /// Two Client Identifier Prefix plug-ins with one name.
    #[error("two Client Identifier Prefix plug-ins have the name {prefix}")]
    #[explain(id = "registry.prefix_twice")]
    PrefixTwice {
        /// The prefix.
        prefix: String,
    },
    /// A registration names a profile the builder does not hold.
    #[error("{registration} names a profile the registry does not hold")]
    #[explain(id = "registry.unknown_profile")]
    UnknownProfile {
        /// The type or type prefix.
        registration: String,
    },
    /// Two modes of one name on one channel: two registrations for answers, two for errors, or
    /// an answer and an error registration of modes of different types.
    #[error("the response mode {name} is registered twice on one channel")]
    #[explain(id = "registry.mode_twice")]
    ModeTwice {
        /// The name.
        name: ModeName,
        /// The channel.
        #[explain(skip)]
        channel: ChannelKind,
    },
    /// An error mode on the DC API, whose errors are A.4's and the core's.
    #[error("the response mode {mode} writes DC API errors, which A.4 fixes")]
    #[explain(id = "registry.error_mode_channel")]
    ErrorModeChannel {
        /// The mode.
        mode: ModeName,
    },
    /// Two response types of one name.
    #[error("the response type {response_type} is registered twice")]
    #[explain(id = "registry.response_type_twice")]
    ResponseTypeTwice {
        /// The response type.
        response_type: ResponseTypeName,
    },
    /// `RequestPost` or `EncryptedRequests` registered twice.
    #[error("the request_uri POST is registered twice")]
    #[explain(id = "registry.post_twice")]
    PostTwice,
    /// Two hash algorithms of one name.
    #[error("the hash algorithm {algorithm} is registered twice")]
    #[explain(id = "registry.hash_twice")]
    HashTwice {
        /// The algorithm.
        algorithm: HashName,
    },
    /// A transaction data profile without `sha-256`, B.3.3.1's default.
    #[error("a transaction data profile is registered and sha-256 is not")]
    #[explain(id = "registry.sha256_absent")]
    Sha256Absent,
    /// Two queries of one scope value.
    #[error("the scope value {scope} is registered twice")]
    #[explain(id = "registry.scope_twice")]
    ScopeTwice {
        /// The scope value.
        scope: ScopeValue,
    },
    /// A scope value's query that is no DCQL query the core reads.
    #[error("the scope value {scope} maps to no DCQL query")]
    #[explain(id = "registry.scope_query")]
    ScopeQuery {
        /// The scope value.
        scope: ScopeValue,
    },
    /// A Credential Query or claim id two scope values' queries share (§5.5: "MUST be unique").
    #[error("the scope values {first} and {second} share the id {id}")]
    #[explain(id = "registry.scope_ids")]
    ScopeIds {
        /// The first scope value.
        first: ScopeValue,
        /// The second.
        second: ScopeValue,
        /// The id.
        id: String,
    },
    /// A mode that writes `wallet_metadata` members over the DC API, whose requests post none.
    #[error("the DC API response mode {mode} writes wallet_metadata members")]
    #[explain(id = "registry.metadata_channel")]
    MetadataChannel {
        /// The mode.
        mode: ModeName,
    },
    /// A name two registered parts write.
    #[error("{name} is written by two registered parts")]
    #[explain(id = "registry.name_twice")]
    NameTwice {
        /// Where.
        #[explain(skip)]
        place: NamePlace,
        /// The name.
        name: ParameterName,
    },
    /// A name the core writes itself, which a registered part declares.
    #[error("{name} is the core's to write")]
    #[explain(id = "registry.name_reserved")]
    NameReserved {
        /// Where.
        #[explain(skip)]
        place: NamePlace,
        /// The name.
        name: ParameterName,
    },
    /// `EncryptedRequests` without `RequestPost`.
    #[error("encrypted Request Objects are registered without the request_uri POST")]
    #[explain(id = "registry.decryption_without_post")]
    DecryptionWithoutPost,
    /// A profile would write a member twice into one presentation: one of the format's own, or
    /// one it declares twice.
    #[error(
        "the profile registered for {registration} writes {members} twice in a {format} presentation"
    )]
    #[explain(id = "registry.member_twice")]
    MemberTwice {
        /// A type or prefix the profile is registered under.
        registration: String,
        /// The format.
        format: String,
        /// The members.
        members: MemberNames,
    },
    /// A profile names members of another kind than the format's placement holds: a data
    /// element where the proof holds claims, or a claim where it holds name-space elements.
    #[error(
        "the profile registered for {registration} names {members} in a {format} presentation, whose proof holds no such member"
    )]
    #[explain(id = "registry.member_placement")]
    MemberPlacement {
        /// A type or prefix the profile is registered under.
        registration: String,
        /// The format.
        format: String,
        /// The members.
        members: MemberNames,
    },
}

/// Member names a [`RegistryError`] lists, sorted, each once. Its `Display`, a message's
/// argument, writes them separated by `, `.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberNames(AllOf<String>);

impl MemberNames {
    /// The names sorted, each once; `None` for no name.
    fn of(mut names: Vec<String>) -> Option<Self> {
        names.sort();
        names.dedup();
        AllOf::new(names).map(Self)
    }

    /// The names.
    #[must_use]
    pub fn names(&self) -> &[String] {
        self.0.items()
    }
}

impl fmt::Display for MemberNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.items().join(", "))
    }
}

/// A registered format and the placement it stated when the registry was built, which the
/// registry checked each profile's members against and which matching and phase 2 read.
struct RegisteredFormat<H: Build> {
    format: Box<<H as Plugins>::Format>,
    placement: Option<Placement>,
}

impl<H: Build> Clone for RegisteredFormat<H> {
    fn clone(&self) -> Self {
        Self {
            format: dyn_clone::clone_box(&*self.format),
            placement: self.placement,
        }
    }
}

/// A format of the registry, as phase 1 (`dyn Format`) or phase 2 (`dyn FormatHost<H>`) reads
/// it, with the placement it stated at registration.
#[cfg(feature = "match")]
pub(crate) struct Placed<'r, F: ?Sized> {
    pub(crate) format: &'r F,
    pub(crate) placement: Option<Placement>,
}

/// The matcher's build: a registry of phase 1's plug-ins, without a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoHost;

/// A registry's host, which fixes what the registry takes of each plug-in: [`NoHost`] takes
/// phase 1's [`Format`], [`Profile`] and [`Mode`] in every build; under `resolve`, a host holding
#[cfg_attr(
    feature = "resolve",
    doc = "a [`Platform`](crate::host::Platform) takes a plug-in whose phase 2 runs over it \
           ([`FormatHost`](crate::host::FormatHost), [`ProfileHost`](crate::host::ProfileHost), \
           [`ModeHost`](crate::routing::ModeHost), \
           [`ErrorModeHost`](crate::routing::ErrorModeHost))."
)]
#[cfg_attr(
    not(feature = "resolve"),
    doc = "a `Platform` takes a plug-in whose phase 2 runs over it (`FormatHost`, `ProfileHost`, \
           `ModeHost`, `ErrorModeHost`)."
)]
/// The core implements it for those hosts alone.
pub trait Build: Plugins {}

impl<H: Plugins> Build for H {}

/// What a registry stores of each plug-in for its host: [`Build`]'s sealed part.
mod sealed {
    use super::{ErasedProfile, Format, Mode, ResponseParameters};

    /// The stored plug-ins of a host's registry.
    pub trait Plugins: Sized {
        /// A stored format.
        type Format: ?Sized + Format + Upcast<dyn Format>;
        /// A stored profile.
        type Profile: ?Sized + ErasedProfile + Upcast<dyn ErasedProfile>;
        /// A stored response mode that carries answers.
        type Mode: ?Sized + Mode + Upcast<dyn Mode>;
        /// A stored response mode that carries a URI route's errors.
        type ErrorMode: ?Sized + Mode + Upcast<dyn Mode>;
        /// Stored parameters of the Authorization Response.
        type ResponseParameters: ?Sized + ResponseParameters + Upcast<dyn ResponseParameters>;
        /// How a JWE mode's registration reaches the host's sealing module.
        type Sealing: Copy;
    }

    /// A stored plug-in as phase 1 reads it.
    pub trait Upcast<T: ?Sized> {
        /// The plug-in's phase 1.
        fn upcast(&self) -> &T;
    }
}

use sealed::{Plugins, Upcast};

impl Upcast<dyn Format> for dyn Format {
    fn upcast(&self) -> &(dyn Format + 'static) {
        self
    }
}

impl Upcast<dyn Mode> for dyn Mode {
    fn upcast(&self) -> &(dyn Mode + 'static) {
        self
    }
}

impl Upcast<dyn ErasedProfile> for dyn ErasedProfile {
    fn upcast(&self) -> &(dyn ErasedProfile + 'static) {
        self
    }
}

impl Upcast<dyn ResponseParameters> for dyn ResponseParameters {
    fn upcast(&self) -> &(dyn ResponseParameters + 'static) {
        self
    }
}

impl Plugins for NoHost {
    type Format = dyn Format;
    type Profile = dyn ErasedProfile;
    type Mode = dyn Mode;
    type ErrorMode = dyn Mode;
    type ResponseParameters = dyn ResponseParameters;
    type Sealing = ();
}

#[cfg(feature = "resolve")]
impl<H> Upcast<dyn Format> for dyn FormatHost<H> {
    fn upcast(&self) -> &(dyn Format + 'static) {
        self
    }
}

#[cfg(feature = "resolve")]
impl<H> Upcast<dyn Mode> for dyn ModeHost<H> {
    fn upcast(&self) -> &(dyn Mode + 'static) {
        self
    }
}

#[cfg(feature = "resolve")]
impl<H> Upcast<dyn Mode> for dyn ErrorModeHost<H> {
    fn upcast(&self) -> &(dyn Mode + 'static) {
        self
    }
}

#[cfg(feature = "resolve")]
impl<H> Upcast<dyn ResponseParameters> for dyn ResponseParametersHost<H> {
    fn upcast(&self) -> &(dyn ResponseParameters + 'static) {
        self
    }
}

#[cfg(feature = "resolve")]
impl<H> Upcast<dyn ErasedProfile> for dyn DynProfile<H> {
    fn upcast(&self) -> &(dyn ErasedProfile + 'static) {
        self
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>> Plugins for H {
    type Format = dyn FormatHost<H>;
    type Profile = dyn DynProfile<H>;
    type Mode = dyn ModeHost<H>;
    type ErrorMode = dyn ErrorModeHost<H>;
    type ResponseParameters = dyn ResponseParametersHost<H>;
    type Sealing = HaipAccess<H>;
}

/// A format the registry of the host `H` takes: a [`Format`] for [`NoHost`]; under `resolve`, a
#[cfg_attr(
    feature = "resolve",
    doc = "format whose phase 2 runs over `H` ([`FormatHost`](crate::host::FormatHost))."
)]
#[cfg_attr(
    not(feature = "resolve"),
    doc = "format whose phase 2 runs over `H` (`FormatHost`)."
)]
pub trait HostedFormat<H: Build>: 'static {
    /// The format as the registry stores it.
    #[doc(hidden)]
    fn stored(self) -> Box<<H as Plugins>::Format>;
}

impl<F: Format + 'static> HostedFormat<NoHost> for F {
    fn stored(self) -> Box<dyn Format> {
        Box::new(self)
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>, F: FormatHost<H> + 'static> HostedFormat<H> for F {
    fn stored(self) -> Box<dyn FormatHost<H>> {
        Box::new(self)
    }
}

/// A profile the registry of the host `H` takes: a [`Profile`] for [`NoHost`]; under `resolve`,
#[cfg_attr(
    feature = "resolve",
    doc = "a profile whose phase 2 runs over `H` ([`ProfileHost`](crate::host::ProfileHost))."
)]
#[cfg_attr(
    not(feature = "resolve"),
    doc = "a profile whose phase 2 runs over `H` (`ProfileHost`)."
)]
pub trait HostedProfile<H: Build>: 'static {
    /// The profile as the registry stores it.
    #[doc(hidden)]
    fn stored(self) -> Box<<H as Plugins>::Profile>;
}

impl<P: Profile> HostedProfile<NoHost> for P {
    fn stored(self) -> Box<dyn ErasedProfile> {
        Box::new(self)
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>, P: ProfileHost<H>> HostedProfile<H> for P {
    fn stored(self) -> Box<dyn DynProfile<H>> {
        Box::new(self)
    }
}

/// A response mode the registry of the host `H` takes: a [`Mode`] for [`NoHost`]; under
#[cfg_attr(
    feature = "resolve",
    doc = "`resolve`, a mode whose phase 2 runs over `H` ([`ModeHost`](crate::routing::ModeHost))."
)]
#[cfg_attr(
    not(feature = "resolve"),
    doc = "`resolve`, a mode whose phase 2 runs over `H` (`ModeHost`)."
)]
pub trait HostedMode<H: Build>: 'static {
    /// The mode as the registry stores it.
    #[doc(hidden)]
    fn stored(self) -> Box<<H as Plugins>::Mode>;
}

impl<M: Mode + 'static> HostedMode<NoHost> for M {
    fn stored(self) -> Box<dyn Mode> {
        Box::new(self)
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>, M: ModeHost<H> + 'static> HostedMode<H> for M {
    fn stored(self) -> Box<dyn ModeHost<H>> {
        Box::new(self)
    }
}

/// A response mode the registry of the host `H` takes for a URI route's errors: a [`Mode`] for
/// [`NoHost`]; under `resolve`, a mode whose error responses run over `H`
#[cfg_attr(
    feature = "resolve",
    doc = "([`ErrorModeHost`](crate::routing::ErrorModeHost))."
)]
#[cfg_attr(not(feature = "resolve"), doc = "(`ErrorModeHost`).")]
pub trait HostedErrorMode<H: Build>: 'static {
    /// The mode as the registry stores it.
    #[doc(hidden)]
    fn stored(self) -> Box<<H as Plugins>::ErrorMode>;
}

impl<M: Mode + 'static> HostedErrorMode<NoHost> for M {
    fn stored(self) -> Box<dyn Mode> {
        Box::new(self)
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>, M: ErrorModeHost<H> + 'static> HostedErrorMode<H> for M {
    fn stored(self) -> Box<dyn ErrorModeHost<H>> {
        Box::new(self)
    }
}

/// Parameters of the Authorization Response the registry of the host `H` takes: a
/// [`ResponseParameters`] for [`NoHost`]; under `resolve`, parameters whose members are written
#[cfg_attr(
    feature = "resolve",
    doc = "over `H` ([`ResponseParametersHost`](crate::routing::ResponseParametersHost))."
)]
#[cfg_attr(not(feature = "resolve"), doc = "over `H` (`ResponseParametersHost`).")]
pub trait HostedResponseParameters<H: Build>: 'static {
    /// The parameters as the registry stores them.
    #[doc(hidden)]
    fn stored(self) -> Box<<H as Plugins>::ResponseParameters>;
}

impl<P: ResponseParameters + 'static> HostedResponseParameters<NoHost> for P {
    fn stored(self) -> Box<dyn ResponseParameters> {
        Box::new(self)
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>, P: ResponseParametersHost<H> + 'static> HostedResponseParameters<H>
    for P
{
    fn stored(self) -> Box<dyn ResponseParametersHost<H>> {
        Box::new(self)
    }
}

/// A host whose registry takes a JWE mode: [`NoHost`]; under `resolve`, a host holding the
/// `Haip` that seals the mode's answers.
pub trait JweHost: Build {
    /// How the registration reaches the sealing module.
    #[doc(hidden)]
    fn sealing() -> <Self as Plugins>::Sealing;
}

impl JweHost for NoHost {
    fn sealing() {}
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform> + Has<dyn Haip>> JweHost for H {
    fn sealing() -> HaipAccess<H> {
        |host| Has::<dyn Haip>::module(host)
    }
}

/// The host's `Haip`, as the registration of a JWE mode or a prefix keeps its accessor.
#[cfg(feature = "resolve")]
pub(crate) type HaipAccess<H> = fn(&H) -> &dyn Haip;

/// A mode's registration as the builder collects it, with the type of the mode, which tells one
/// mode's answer and error registrations from two modes of one name.
struct ModeRegistration<H: Build> {
    registered: RegisteredMode<H>,
    kind: TypeId,
}

impl<H: Build> ModeRegistration<H> {
    fn of<M: 'static>(registered: RegisteredMode<H>) -> Self {
        Self {
            registered,
            kind: TypeId::of::<M>(),
        }
    }
}

/// A registered part of the Authorization Response's parameters and the names `build` checked,
/// which bound the members phase 2 takes from it.
pub(crate) struct RegisteredParameters<H: Build> {
    part: Box<<H as Plugins>::ResponseParameters>,
    names: &'static [ParameterName],
}

impl<H: Build> RegisteredParameters<H> {
    /// The part, its names read once.
    fn of(part: Box<<H as Plugins>::ResponseParameters>) -> Self {
        let names = part.upcast().names();
        Self { part, names }
    }

    /// The part.
    #[cfg(feature = "resolve")]
    pub(crate) fn part(&self) -> &<H as Plugins>::ResponseParameters {
        &self.part
    }

    /// The names `build` checked.
    #[cfg(feature = "resolve")]
    pub(crate) const fn names(&self) -> &'static [ParameterName] {
        self.names
    }
}

impl<H: Build> Clone for RegisteredParameters<H> {
    fn clone(&self) -> Self {
        Self {
            part: dyn_clone::clone_box(&*self.part),
            names: self.names,
        }
    }
}

/// A registered mode by its registration: answers in the clear (`mode`), answers the core seals
/// as JWEs through the host's `Haip` (`jwe_mode`), or a URI mode's errors alone (`error_mode`).
pub(crate) enum RegisteredMode<H: Build> {
    /// Answers in the clear.
    Clear(Box<<H as Plugins>::Mode>),
    /// Answers the core seals, and how the registration reaches the sealing module.
    Jwe(Box<<H as Plugins>::Mode>, <H as Plugins>::Sealing),
    /// A URI route's errors.
    Errors(Box<<H as Plugins>::ErrorMode>),
}

impl<H: Build> RegisteredMode<H> {
    /// The mode as phase 1 reads it.
    pub(crate) fn mode(&self) -> &dyn Mode {
        match self {
            Self::Clear(mode) | Self::Jwe(mode, _) => mode.upcast(),
            Self::Errors(mode) => mode.upcast(),
        }
    }

    /// Whether it carries errors alone.
    pub(crate) const fn carries_errors(&self) -> bool {
        matches!(self, Self::Errors(_))
    }
}

impl<H: Build> Clone for RegisteredMode<H> {
    fn clone(&self) -> Self {
        match self {
            Self::Clear(mode) => Self::Clear(dyn_clone::clone_box(&**mode)),
            Self::Jwe(mode, access) => Self::Jwe(dyn_clone::clone_box(&**mode), *access),
            Self::Errors(mode) => Self::Errors(dyn_clone::clone_box(&**mode)),
        }
    }
}

/// The plug-ins: formats by identifier, profiles by exact type identifier and by type prefix.
/// `H` is the registry's host ([`Build`]): [`NoHost`] for the matcher, whose registry takes
/// phase 1's plug-ins; under `resolve`, the wallet's host, whose registry takes plug-ins with
/// their phase 2 over it.
pub struct Registry<H: Build = NoHost> {
    #[cfg(feature = "transaction-data")]
    hashes: Vec<Box<dyn HashAlgorithm>>,
    scopes: Vec<ScopeEntry>,
    response_types: Vec<Box<dyn ResponseType>>,
    #[cfg_attr(
        not(feature = "resolve"),
        expect(dead_code, reason = "phase 2 writes their members")
    )]
    parameters: Vec<RegisteredParameters<H>>,
    modes: Vec<RegisteredMode<H>>,
    formats: Vec<RegisteredFormat<H>>,
    #[cfg_attr(
        not(feature = "match"),
        expect(dead_code, reason = "matching and phase 2 read the profiles")
    )]
    profiles: Vec<Typed<<H as Plugins>::Profile>>,
    #[cfg(feature = "signed")]
    clients: Vec<RegisteredPrefix<H>>,
    #[cfg(feature = "signed")]
    object_rules: Vec<Box<dyn ObjectRule>>,
    #[cfg(feature = "uri")]
    post: Option<Post<H>>,
    #[cfg(feature = "uri")]
    contributions: Vec<Box<dyn HostedPostContribution<H>>>,
    #[cfg(feature = "uri")]
    readers: Vec<Box<dyn AnswerReader>>,
}

/// A profile with the exact type identifiers and the type prefixes registered for it.
struct Typed<P: ?Sized> {
    profile: Box<P>,
    exact: Vec<TransactionType<'static>>,
    prefixes: Vec<TypePrefix<'static>>,
}

impl<P: ?Sized> Typed<P> {
    const fn untyped(profile: Box<P>) -> Self {
        Self {
            profile,
            exact: Vec::new(),
            prefixes: Vec::new(),
        }
    }

    /// Each registration's name: the type, else `the prefix` and the prefix.
    fn registrations(&self) -> impl Iterator<Item = String> + '_ {
        self.exact.iter().map(ToString::to_string).chain(
            self.prefixes
                .iter()
                .map(|prefix| format!("the prefix {prefix}")),
        )
    }
}

impl<H: Build> fmt::Debug for Registry<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field(
                "formats",
                &self
                    .formats
                    .iter()
                    .map(|registered| registered.format.id().to_string())
                    .collect::<Vec<_>>(),
            )
            .field(
                "profiles",
                &self
                    .profiles
                    .iter()
                    .map(|typed| (&typed.exact, &typed.prefixes))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Collects the plug-ins of a [`Registry`].
pub struct RegistryBuilder<H: Build = NoHost> {
    #[cfg(feature = "transaction-data")]
    hashes: Vec<Box<dyn HashAlgorithm>>,
    #[cfg(feature = "uri")]
    scopes: Vec<Box<dyn ScopeQuery>>,
    response_types: Vec<Box<dyn ResponseType>>,
    parameters: Vec<Box<<H as Plugins>::ResponseParameters>>,
    modes: Vec<ModeRegistration<H>>,
    formats: Vec<Box<<H as Plugins>::Format>>,
    profiles: Vec<Box<<H as Plugins>::Profile>>,
    exact: Vec<(TransactionType<'static>, ProfileHandle)>,
    prefixes: Vec<(TypePrefix<'static>, ProfileHandle)>,
    #[cfg(feature = "signed")]
    clients: Vec<RegisteredPrefix<H>>,
    #[cfg(feature = "signed")]
    object_rules: Vec<Box<dyn ObjectRule>>,
    #[cfg(feature = "uri")]
    posts: Vec<RequestPost>,
    #[cfg(feature = "request-decryption")]
    encrypted: Vec<DecryptionAccess<H>>,
    #[cfg(feature = "uri")]
    contributions: Vec<Box<dyn HostedPostContribution<H>>>,
    #[cfg(feature = "uri")]
    readers: Vec<Box<dyn AnswerReader>>,
}

impl<H: Build> Default for RegistryBuilder<H> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "transaction-data")]
            hashes: Vec::new(),
            #[cfg(feature = "uri")]
            scopes: Vec::new(),
            response_types: Vec::new(),
            parameters: Vec::new(),
            modes: Vec::new(),
            formats: Vec::new(),
            profiles: Vec::new(),
            exact: Vec::new(),
            prefixes: Vec::new(),
            #[cfg(feature = "signed")]
            clients: Vec::new(),
            #[cfg(feature = "signed")]
            object_rules: Vec::new(),
            #[cfg(feature = "uri")]
            posts: Vec::new(),
            #[cfg(feature = "request-decryption")]
            encrypted: Vec::new(),
            #[cfg(feature = "uri")]
            contributions: Vec::new(),
            #[cfg(feature = "uri")]
            readers: Vec::new(),
        }
    }
}

impl<H: Build> RegistryBuilder<H> {
    /// A transaction data hash algorithm (B.3.3.1), keyed by its name; `build` refuses a name
    /// registered twice, and a registry with a transaction data profile and without `sha-256`
    /// (feature `transaction-data`).
    #[cfg(feature = "transaction-data")]
    pub fn hash(&mut self, algorithm: impl HashAlgorithm + 'static) {
        self.hashes.push(Box::new(algorithm));
    }

    /// A scope value's DCQL query (§5.5), keyed by its scope value; `build` refuses a value
    /// twice, a query the DCQL reader refuses, and a Credential Query or claim id two queries
    /// share (feature `uri`).
    #[cfg(feature = "uri")]
    pub fn scope(&mut self, query: impl ScopeQuery + 'static) {
        self.scopes.push(Box::new(query));
    }

    /// A response type (RFC 6749 §3.1.1), keyed by its name (P1); `build` refuses a name
    /// registered twice.
    pub fn response_type(&mut self, response_type: impl ResponseType + 'static) {
        self.response_types.push(Box::new(response_type));
    }

    /// Parameters of the Authorization Response beside `vp_token` and `state` (§8.1), keyed by
    /// their names: `build` refuses a name another part declares (`NameTwice`) and one the core
    /// writes, `vp_token`, `state`, `error`, `error_description`, `error_uri` (`NameReserved`).
    pub fn response_parameters(&mut self, parameters: impl HostedResponseParameters<H>) {
        self.parameters.push(parameters.stored());
    }

    /// A response mode whose answers are in the clear, keyed by its name and channel.
    pub fn mode<M: HostedMode<H>>(&mut self, mode: M) {
        let registered = RegisteredMode::Clear(mode.stored());
        self.modes.push(ModeRegistration::of::<M>(registered));
    }

    /// A response mode whose answers the core seals as JWEs (§8.3) through the host's `Haip`,
    /// keyed by its name and channel.
    ///
    /// A host without the module does not compile with it.
    pub fn jwe_mode<M: HostedMode<H>>(&mut self, mode: M)
    where
        H: JweHost,
    {
        let registered = RegisteredMode::Jwe(mode.stored(), H::sealing());
        self.modes.push(ModeRegistration::of::<M>(registered));
    }

    /// A URI response mode's error responses (§8.2, §8.3.1), keyed by its name: a mode
    /// registered here alone carries errors alone (C5 refuses a request naming it). Over the DC
    /// API the core writes A.4's error itself, so `build` refuses a DC API mode registered here.
    /// A mode registered for answers under the name is of the same type (`ModeTwice`).
    pub fn error_mode<M: HostedErrorMode<H>>(&mut self, mode: M) {
        let registered = RegisteredMode::Errors(mode.stored());
        self.modes.push(ModeRegistration::of::<M>(registered));
    }

    /// Adds a format whose phase 2 the build's host can run.
    pub fn format(&mut self, format: impl HostedFormat<H>) {
        self.formats.push(format.stored());
    }

    /// Adds a profile whose phase 2 the build's host can run, to register under types or
    /// prefixes.
    pub fn profile(&mut self, profile: impl HostedProfile<H>) -> ProfileHandle {
        self.profiles.push(profile.stored());
        ProfileHandle(self.profiles.len() - 1)
    }

    /// Registers a profile for an exact type identifier.
    pub fn exact(&mut self, kind: TransactionType<'static>, profile: ProfileHandle) {
        self.exact.push((kind, profile));
    }

    /// Registers a profile for the type identifiers starting with a prefix.
    pub fn prefix(&mut self, prefix: TypePrefix<'static>, profile: ProfileHandle) {
        self.prefixes.push((prefix, profile));
    }

    /// A Client Identifier Prefix (§5.9.3), keyed by its name; the core verifies its requests'
    /// signatures through the host's `Haip`, whose accessor the registration keeps. `build`
    /// refuses a name registered twice.
    ///
    /// A host without the module does not compile with it.
    #[cfg(feature = "signed")]
    pub fn client_prefix(&mut self, prefix: impl HostedPrefix<H> + 'static)
    where
        H: Has<dyn Haip>,
    {
        self.clients.push(RegisteredPrefix {
            prefix: Box::new(prefix),
            haip: |host| Has::<dyn Haip>::module(host),
        });
    }

    /// A rule over an authenticated Request Object's claims (A14), run after A10 in registration
    /// order (feature `signed`).
    #[cfg(feature = "signed")]
    pub fn object_rule(&mut self, rule: impl ObjectRule + 'static) {
        self.object_rules.push(Box::new(rule));
    }

    /// The POST of `wallet_metadata` to the `request_uri` (§5.10): with it, a request whose
    /// `request_uri_method` is `post` is fetched by POST; without it, by GET (§5.1: "Wallets not
    /// supporting the post method will send a GET request"). `build` refuses it twice (feature
    /// `uri`).
    #[cfg(feature = "uri")]
    pub fn request_post(&mut self, post: RequestPost) {
        self.posts.push(post);
    }

    /// Encrypted Request Objects (§5.10): each POST's `jwks` holds a fresh key from the host's
    /// `RequestDecryption`, whose accessor the registration keeps, and a JWE Request Object
    /// decrypts through it. `build` refuses it twice, and without [`Self::request_post`].
    ///
    /// A host without the module does not compile with it.
    #[cfg(feature = "request-decryption")]
    pub fn request_encryption(&mut self, requests: EncryptedRequests)
    where
        H: Has<dyn RequestDecryption>,
    {
        let EncryptedRequests = requests;
        self.encrypted
            .push(|host| Has::<dyn RequestDecryption>::module(host));
    }

    /// Members of `wallet_metadata` and parameters of the `request_uri` POST a profile or a
    /// deployment adds (§10.1, §5.10: "Additional parameters MAY be defined"), keyed by their
    /// names: `build` refuses a name another part declares (`NameTwice`) and a name the core
    /// writes (`NameReserved`) (feature `uri`).
    #[cfg(feature = "uri")]
    pub fn post_contribution(&mut self, contribution: impl HostedPostContribution<H> + 'static) {
        self.contributions.push(Box::new(contribution));
    }

    /// A reader of the Response URI's answer members (§8.2: "Additional parameters MAY be
    /// defined"), keyed by their names: `build` refuses a name another reader declares
    /// (`NameTwice`) and `redirect_uri` (`NameReserved`) (feature `uri`).
    #[cfg(feature = "uri")]
    pub fn answer_reader(&mut self, reader: impl AnswerReader + 'static) {
        self.readers.push(Box::new(reader));
    }

    /// The registry. Refused when a response type is registered twice, a mode twice on one
    /// channel, an error mode twice or on the DC API, two formats share an identifier, a type or
    /// prefix is registered twice, a registration names no profile, a profile would write a
    /// member twice into one presentation, a profile names a member the format's placement does
    /// not hold, the POST or encrypted Request Objects are registered twice or encrypted Request
    /// Objects without the POST, or two parts declare one name or a part declares one the core
    /// writes.
    pub fn build(self) -> Result<Registry<H>, RegistryError> {
        let Self {
            #[cfg(feature = "transaction-data")]
            hashes,
            #[cfg(feature = "uri")]
            scopes,
            response_types,
            parameters,
            modes,
            formats,
            profiles,
            exact,
            prefixes,
            #[cfg(feature = "signed")]
            clients,
            #[cfg(feature = "signed")]
            object_rules,
            #[cfg(feature = "uri")]
            posts,
            #[cfg(feature = "request-decryption")]
            encrypted,
            #[cfg(feature = "uri")]
            contributions,
            #[cfg(feature = "uri")]
            readers,
        } = self;
        #[cfg(feature = "transaction-data")]
        for (k, algorithm) in hashes.iter().enumerate() {
            if hashes
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.name() == algorithm.name()))
            {
                return Err(RegistryError::HashTwice {
                    algorithm: algorithm.name(),
                });
            }
        }
        #[cfg(feature = "uri")]
        let scopes = read_scopes(&scopes)?;
        #[cfg(not(feature = "uri"))]
        let scopes = Vec::new();
        for (k, kind) in response_types.iter().enumerate() {
            if response_types
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.name() == kind.name()))
            {
                return Err(RegistryError::ResponseTypeTwice {
                    response_type: kind.name(),
                });
            }
        }
        for (k, registration) in modes.iter().enumerate() {
            let registered = &registration.registered;
            let (name, channel) = (registered.mode().name(), registered.mode().channel());
            let errors = registered.carries_errors();
            if errors && channel == ChannelKind::DcApi {
                return Err(RegistryError::ErrorModeChannel { mode: name });
            }
            if modes.get(..k).is_some_and(|before| {
                before.iter().any(|other| {
                    other.registered.mode().name() == name
                        && other.registered.mode().channel() == channel
                        && (other.registered.carries_errors() == errors
                            || other.kind != registration.kind)
                })
            }) {
                return Err(RegistryError::ModeTwice { name, channel });
            }
        }
        let modes: Vec<RegisteredMode<H>> = modes
            .into_iter()
            .map(|registration| registration.registered)
            .collect();
        let parameters: Vec<RegisteredParameters<H>> = parameters
            .into_iter()
            .map(RegisteredParameters::of)
            .collect();
        #[cfg(feature = "uri")]
        let declared = Declared {
            responses: parameters
                .iter()
                .flat_map(|registered| registered.names)
                .copied()
                .collect(),
            members: contributions
                .iter()
                .flat_map(|c| PostContribution::members(c.as_ref()))
                .copied()
                .collect(),
            parameters: contributions
                .iter()
                .flat_map(|c| PostContribution::parameters(c.as_ref()))
                .copied()
                .collect(),
            answers: readers
                .iter()
                .flat_map(|reader| reader.names())
                .copied()
                .collect(),
        };
        #[cfg(not(feature = "uri"))]
        let declared = Declared {
            responses: parameters
                .iter()
                .flat_map(|registered| registered.names)
                .copied()
                .collect(),
            ..Declared::default()
        };
        names(&modes, declared)?;
        #[cfg(feature = "signed")]
        if let Some(twice) = clients.iter().enumerate().find_map(|(k, registered)| {
            let name = registered.prefix.name();
            clients
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.prefix.name() == name))
                .then(|| name.to_string())
        }) {
            return Err(RegistryError::PrefixTwice { prefix: twice });
        }
        #[cfg(feature = "request-decryption")]
        let post = Post::of(&posts, encrypted)?;
        #[cfg(all(feature = "uri", not(feature = "request-decryption")))]
        let post = Post::of(&posts)?;
        for (k, format) in formats.iter().enumerate() {
            if formats
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.id() == format.id()))
            {
                return Err(RegistryError::FormatTwice {
                    format: format.id().to_string(),
                });
            }
        }
        let formats: Vec<RegisteredFormat<H>> = formats
            .into_iter()
            .map(|format| RegisteredFormat {
                placement: format.placement(),
                format,
            })
            .collect();
        let mut profiles: Vec<Typed<_>> = profiles.into_iter().map(Typed::untyped).collect();
        #[cfg(feature = "transaction-data")]
        let transacting = !exact.is_empty() || !prefixes.is_empty();
        for (kind, handle) in exact {
            profiles
                .get_mut(handle.0)
                .ok_or_else(|| RegistryError::UnknownProfile {
                    registration: kind.to_string(),
                })?
                .exact
                .push(kind);
        }
        for (prefix, handle) in prefixes {
            profiles
                .get_mut(handle.0)
                .ok_or_else(|| RegistryError::UnknownProfile {
                    registration: format!("the prefix {prefix}"),
                })?
                .prefixes
                .push(prefix);
        }
        let registrations: Vec<(String, &<H as Plugins>::Profile)> = profiles
            .iter()
            .flat_map(|typed| {
                typed
                    .registrations()
                    .map(|name| (name, typed.profile.as_ref()))
            })
            .collect();
        for (k, (name, profile)) in registrations.iter().enumerate() {
            if registrations.iter().take(k).any(|(other, _)| other == name) {
                return Err(RegistryError::TypeTwice {
                    registration: name.clone(),
                });
            }
            for RegisteredFormat { format, placement } in &formats {
                let Some((placement, members)) = placement.and_then(|placement| {
                    profile
                        .members(placement)
                        .map(|members| (placement, members))
                }) else {
                    continue;
                };
                let misplaced: Vec<String> = members
                    .iter()
                    .filter(|member| !placement.places(member))
                    .map(ToString::to_string)
                    .collect();
                if let Some(members) = MemberNames::of(misplaced) {
                    return Err(RegistryError::MemberPlacement {
                        registration: name.clone(),
                        format: format.id().to_string(),
                        members,
                    });
                }
                let twice: Vec<String> = members
                    .iter()
                    .enumerate()
                    .filter(|(j, m)| {
                        members
                            .iter()
                            .enumerate()
                            .any(|(i, other)| i != *j && other == *m)
                            || format.reserved().contains(m)
                    })
                    .map(|(_, m)| m.to_string())
                    .collect();
                if let Some(members) = MemberNames::of(twice) {
                    return Err(RegistryError::MemberTwice {
                        registration: name.clone(),
                        format: format.id().to_string(),
                        members,
                    });
                }
            }
        }
        #[cfg(feature = "transaction-data")]
        if transacting
            && !hashes
                .iter()
                .any(|algorithm| algorithm.name().as_str() == "sha-256")
        {
            return Err(RegistryError::Sha256Absent);
        }
        Ok(Registry {
            #[cfg(feature = "transaction-data")]
            hashes,
            scopes,
            response_types,
            parameters,
            modes,
            formats,
            profiles,
            #[cfg(feature = "signed")]
            clients,
            #[cfg(feature = "signed")]
            object_rules,
            #[cfg(feature = "uri")]
            post,
            #[cfg(feature = "uri")]
            contributions,
            #[cfg(feature = "uri")]
            readers,
        })
    }
}

impl<H: Build> Registry<H> {
    /// A builder.
    #[must_use]
    pub fn builder() -> RegistryBuilder<H> {
        RegistryBuilder::default()
    }

    /// Whether a Client Identifier Prefix of the name is registered (feature `signed`).
    #[cfg(feature = "signed")]
    #[must_use]
    pub fn names_prefix(&self, name: &str) -> bool {
        self.client_prefix(name).is_some()
    }

    /// The Client Identifier Prefix of a name, with the accessor of the `Haip` its registration
    /// bounded.
    #[cfg(feature = "signed")]
    pub(crate) fn client_prefix(
        &self,
        name: &str,
    ) -> Option<(&dyn HostedPrefix<H>, HaipAccess<H>)> {
        self.clients
            .iter()
            .find(|registered| registered.prefix.name().as_str() == name)
            .map(|registered| (registered.prefix.as_ref(), registered.haip))
    }

    /// The registered prefixes' names, in registration order.
    #[cfg(feature = "uri")]
    pub(crate) fn prefix_names(&self) -> impl Iterator<Item = crate::authenticate::PrefixName> {
        self.clients
            .iter()
            .map(|registered| registered.prefix.name())
    }

    /// The registered POST contributions, in registration order.
    #[cfg(feature = "uri")]
    pub(crate) fn contributions(&self) -> impl Iterator<Item = &dyn HostedPostContribution<H>> {
        self.contributions.iter().map(AsRef::as_ref)
    }

    /// The registered readers of the Response URI's answer, in registration order.
    #[cfg(feature = "uri")]
    pub(crate) fn answer_readers(&self) -> &[Box<dyn AnswerReader>] {
        &self.readers
    }

    /// The registered rules over a Request Object's claims, in registration order.
    #[cfg(feature = "signed")]
    pub(crate) fn object_rules(&self) -> &[Box<dyn ObjectRule>] {
        &self.object_rules
    }

    /// The registered POST of `wallet_metadata`, with the decrypting module's accessor when
    /// encrypted Request Objects are registered.
    #[cfg(feature = "uri")]
    pub(crate) const fn post(&self) -> Option<&Post<H>> {
        self.post.as_ref()
    }

    /// The formats, in registration order.
    #[cfg(feature = "uri")]
    pub(crate) fn formats(&self) -> impl Iterator<Item = &dyn Format> {
        self.formats
            .iter()
            .map(|registered| registered.format.upcast())
    }

    fn registered(&self, id: &FormatId<'_>) -> Option<&RegisteredFormat<H>> {
        self.formats
            .iter()
            .find(|registered| registered.format.id() == *id)
    }

    fn plugged(&self, id: &FormatId<'_>) -> Option<&<H as Plugins>::Format> {
        self.registered(id)
            .map(|registered| registered.format.as_ref())
    }

    /// The format with an identifier and the placement it stated at registration.
    #[cfg(feature = "match")]
    pub(crate) fn placed(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn Format>> {
        self.registered(id).map(|registered| {
            let format: &dyn Format = registered.format.upcast();
            Placed {
                format,
                placement: registered.placement,
            }
        })
    }

    /// The format with an identifier.
    #[must_use]
    pub fn format(&self, id: &FormatId<'_>) -> Option<&dyn Format> {
        self.plugged(id).map(Upcast::upcast)
    }

    /// The profile registered for the exact type identifier, else for its longest registered
    /// prefix.
    #[must_use]
    pub fn profile(&self, kind: &TransactionType<'_>) -> Option<ProfileHandle> {
        self.typed(kind).map(|(handle, _)| handle)
    }

    /// The profile registered for the exact type identifier, else for its longest registered
    /// prefix, with its handle.
    fn typed(
        &self,
        kind: &TransactionType<'_>,
    ) -> Option<(ProfileHandle, &Typed<<H as Plugins>::Profile>)> {
        let handled = || {
            self.profiles
                .iter()
                .enumerate()
                .map(|(k, typed)| (ProfileHandle(k), typed))
        };
        handled()
            .find(|(_, typed)| typed.exact.iter().any(|exact| exact == kind))
            .or_else(|| {
                handled()
                    .flat_map(|(handle, typed)| {
                        typed
                            .prefixes
                            .iter()
                            .map(move |prefix| (prefix, handle, typed))
                    })
                    .filter(|(prefix, _, _)| kind.has_prefix(prefix))
                    .max_by_key(|(prefix, _, _)| prefix.as_str().len())
                    .map(|(_, handle, typed)| (handle, typed))
            })
    }
}

#[cfg(feature = "resolve")]
impl<H: Has<dyn Platform>> Registry<H> {
    /// Each registered URI mode's `wallet_metadata` members with the names it declared, in
    /// registration order, each written under what its registration seals with: the `Haip`
    /// statement of a JWE mode, none of a mode in the clear.
    ///
    /// # Errors
    ///
    /// A mode broke its contract.
    #[cfg(feature = "uri")]
    pub(crate) fn mode_metadata(&self, host: &H) -> Result<Vec<ModeMembers>, Fault> {
        self.modes
            .iter()
            .filter(|registered| registered.mode().channel() == ChannelKind::Uri)
            .filter_map(|registered| {
                let (mode, sealer) = match registered {
                    RegisteredMode::Jwe(mode, access) => (mode, access(host).agreements()),
                    RegisteredMode::Clear(mode) => (mode, Agreements::NONE),
                    RegisteredMode::Errors(_) => return None,
                };
                Some(
                    mode.wallet_metadata(&sealer, host)
                        .map(|members| (mode.metadata_names(), members)),
                )
            })
            .collect()
    }

    /// The format with an identifier, with its phase 2 over the build's host, and the placement
    /// it stated at registration.
    pub(crate) fn placed_host(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn FormatHost<H>>> {
        self.registered(id).map(|registered| {
            let format: &dyn FormatHost<H> = registered.format.as_ref();
            Placed {
                format,
                placement: registered.placement,
            }
        })
    }

    /// The format with an identifier, with its phase 2 over the build's host.
    #[must_use]
    pub fn format_host(&self, id: &FormatId<'_>) -> Option<&dyn FormatHost<H>> {
        self.plugged(id)
            .map(|format| -> &dyn FormatHost<H> { format })
    }

    #[cfg(feature = "resolve")]
    pub(crate) fn profile_host(&self, handle: ProfileHandle) -> Option<&dyn DynProfile<H>> {
        self.profiles
            .get(handle.0)
            .map(|typed| typed.profile.as_ref())
    }

    /// The registry with each profile informed of its findings, for the request's re-run of
    /// phase 1 and the phase 2 that follows it. Refused when a finding comes from a profile this
    /// registry does not hold.
    pub fn informed(&self, findings: &[&ProfileFinding]) -> Result<Self, InformError> {
        let mut found: Vec<(&dyn DynProfile<H>, Vec<&dyn FindingData>)> = self
            .profiles
            .iter()
            .map(|typed| (typed.profile.as_ref(), Vec::new()))
            .collect();
        for finding in findings {
            let (_, own) = found.get_mut(finding.profile.0).ok_or(InformError)?;
            own.push(finding.data.as_ref());
        }
        let read = found
            .iter()
            .map(|(profile, own)| profile.read(own))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            #[cfg(feature = "transaction-data")]
            hashes: self.hashes.clone(),
            scopes: self.scopes.clone(),
            response_types: self.response_types.clone(),
            parameters: self.parameters.clone(),
            modes: self.modes.clone(),
            formats: self.formats.clone(),
            profiles: read
                .into_iter()
                .zip(&self.profiles)
                .map(|(informed, typed)| Typed {
                    profile: informed(),
                    exact: typed.exact.clone(),
                    prefixes: typed.prefixes.clone(),
                })
                .collect(),
            #[cfg(feature = "signed")]
            clients: self.clients.clone(),
            #[cfg(feature = "signed")]
            object_rules: self.object_rules.clone(),
            #[cfg(feature = "uri")]
            post: self.post.clone(),
            #[cfg(feature = "uri")]
            contributions: self.contributions.clone(),
            #[cfg(feature = "uri")]
            readers: self.readers.clone(),
        })
    }
}

/// A registered prefix, with the accessor of the host's `Haip` its registration bounded.
#[cfg(feature = "signed")]
pub(crate) struct RegisteredPrefix<H> {
    prefix: Box<dyn HostedPrefix<H>>,
    haip: HaipAccess<H>,
}

#[cfg(feature = "signed")]
impl<H> Clone for RegisteredPrefix<H> {
    fn clone(&self) -> Self {
        Self {
            prefix: self.prefix.clone(),
            haip: self.haip,
        }
    }
}

/// A mode's `wallet_metadata` members, with the names it declared.
#[cfg(feature = "uri")]
pub(crate) type ModeMembers = (&'static [ParameterName], Vec<MetadataMember>);

/// The host's `RequestDecryption`, as the registration of encrypted Request Objects keeps it.
#[cfg(feature = "request-decryption")]
pub(crate) type DecryptionAccess<H> = fn(&H) -> &dyn RequestDecryption;

/// The registered POST of `wallet_metadata`, and the decrypting module's accessor when encrypted
/// Request Objects are registered.
#[cfg(feature = "uri")]
pub(crate) struct Post<H> {
    #[cfg(feature = "request-decryption")]
    decryption: Option<DecryptionAccess<H>>,
    #[cfg(not(feature = "request-decryption"))]
    host: std::marker::PhantomData<fn(&H)>,
}

#[cfg(feature = "uri")]
impl<H> Clone for Post<H> {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "request-decryption")]
            decryption: self.decryption,
            #[cfg(not(feature = "request-decryption"))]
            host: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "request-decryption")]
impl<H> Post<H> {
    /// The POST the registrations make: none without the POST; refused when a part is given
    /// twice, or encrypted Request Objects without the POST.
    fn of(
        posts: &[RequestPost],
        encrypted: Vec<DecryptionAccess<H>>,
    ) -> Result<Option<Self>, RegistryError> {
        let mut encrypted = encrypted.into_iter();
        let decryption = encrypted.next();
        if posts.len() > 1 || encrypted.next().is_some() {
            return Err(RegistryError::PostTwice);
        }
        match (posts, decryption) {
            ([], None) => Ok(None),
            ([], Some(_)) => Err(RegistryError::DecryptionWithoutPost),
            (_, decryption) => Ok(Some(Self { decryption })),
        }
    }

    /// The decrypting module's accessor, when encrypted Request Objects are registered.
    pub(crate) const fn decryption(&self) -> Option<DecryptionAccess<H>> {
        self.decryption
    }

    /// The key a POST's `jwks` holds: a fresh one from the decrypting module, on a curve it
    /// states, when encrypted Request Objects are registered.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    pub(crate) fn ephemeral_key(&self, host: &H) -> Result<Option<EphemeralKey>, Fault> {
        self.decryption
            .map(|access| {
                let decryption = access(host);
                let key = decryption.ephemeral_key()?;
                let curve = key
                    .public()
                    .member("crv")
                    .and_then(|crv| crv.as_str())
                    .and_then(Curve::new);
                if curve.is_some_and(|curve| decryption.decrypts().curve(curve)) {
                    Ok(key)
                } else {
                    Err(fault(detail!(
                        "the ephemeral key's crv is none the module states"
                    )))
                }
            })
            .transpose()
    }
}

#[cfg(all(feature = "uri", not(feature = "request-decryption")))]
impl<H> Post<H> {
    /// The POST the registrations make: none without the POST; refused when it is given twice.
    fn of(posts: &[RequestPost]) -> Result<Option<Self>, RegistryError> {
        match posts {
            [] => Ok(None),
            [_] => Ok(Some(Self {
                host: std::marker::PhantomData,
            })),
            _ => Err(RegistryError::PostTwice),
        }
    }

    /// The key a POST's `jwks` holds: none, as the build registers no encrypted Request Objects.
    ///
    /// # Errors
    ///
    /// None in this build; the signature is the one encrypted Request Objects need.
    pub(crate) const fn ephemeral_key(&self, _host: &H) -> Result<Option<EphemeralKey>, Fault> {
        Ok(None)
    }
}

impl<H: Build> Registry<H> {
    /// The registered mode a handle names, with its role.
    #[cfg(feature = "resolve")]
    pub(crate) fn mode_host(&self, handle: ModeHandle) -> Option<&RegisteredMode<H>> {
        self.modes.get(handle.place())
    }

    /// The registered response parameters, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn response_parameters(&self) -> &[RegisteredParameters<H>] {
        &self.parameters
    }

    /// The URI mode of a name registered for errors (`error_mode`).
    #[cfg(feature = "resolve")]
    pub(crate) fn error_mode(&self, name: ModeName) -> Option<RoutedMode> {
        self.modes
            .iter()
            .enumerate()
            .find(|(_, registered)| {
                let mode = registered.mode();
                registered.carries_errors()
                    && mode.channel() == ChannelKind::Uri
                    && mode.name() == name
            })
            .map(|(place, _)| RoutedMode::of(ModeHandle::at(place), name, Carries::Errors))
    }
}

#[cfg(feature = "transaction-data")]
/// The registered algorithms, in registration order, as the request carries them from the
/// registry its envelope was read with.
#[derive(Clone, Copy)]
pub struct Hashes<'r>(&'r [Box<dyn HashAlgorithm>]);

#[cfg(feature = "transaction-data")]
impl<'r> Hashes<'r> {
    /// The registry's algorithms.
    pub(crate) const fn of(algorithms: &'r [Box<dyn HashAlgorithm>]) -> Self {
        Self(algorithms)
    }

    /// The algorithm of a Hash Name String.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<&'r dyn HashAlgorithm> {
        self.0
            .iter()
            .find(|algorithm| algorithm.name().as_str() == name)
            .map(AsRef::as_ref)
    }
}

#[cfg(feature = "transaction-data")]
impl fmt::Debug for Hashes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|algorithm| algorithm.name()))
            .finish()
    }
}

/// The registry's response types and modes, as the envelope reads them whatever the build's
/// host.
pub(crate) trait Routes {
    /// The registered response type of a name.
    fn response_type(&self, name: &str) -> Option<ResponseTypeName>;
    /// The registered mode of a name on a channel: the mode that carries answers, else the one
    /// that carries errors alone.
    fn routed(&self, channel: ChannelKind, name: &str) -> Option<(RoutedMode, &dyn Mode)>;
    /// The registered hash algorithms.
    #[cfg(feature = "transaction-data")]
    fn hashes(&self) -> Hashes<'_>;
    /// The registered scope queries.
    fn scopes(&self) -> Scopes<'_>;
}

impl<H: Build> Routes for Registry<H> {
    fn response_type(&self, name: &str) -> Option<ResponseTypeName> {
        self.response_types
            .iter()
            .map(|kind| kind.name())
            .find(|kind| kind.as_str() == name)
    }

    fn routed(&self, channel: ChannelKind, name: &str) -> Option<(RoutedMode, &dyn Mode)> {
        let find = |errors: bool| {
            self.modes
                .iter()
                .enumerate()
                .find_map(|(place, registered)| {
                    let mode = registered.mode();
                    (mode.channel() == channel
                        && mode.name().as_str() == name
                        && registered.carries_errors() == errors)
                        .then(|| {
                            let carries = if errors {
                                Carries::Errors
                            } else {
                                Carries::Answers
                            };
                            let routed =
                                RoutedMode::of(ModeHandle::at(place), mode.name(), carries);
                            (routed, mode)
                        })
                })
        };
        find(false).or_else(|| find(true))
    }

    #[cfg(feature = "transaction-data")]
    fn hashes(&self) -> Hashes<'_> {
        Hashes::of(&self.hashes)
    }

    fn scopes(&self) -> Scopes<'_> {
        Scopes::of(&self.scopes)
    }
}

/// The names registered parts declare, by place: the Authorization Response's parameters, the
/// `wallet_metadata` members of the modes that carry answers and of the POST's contributions, the
/// POST's parameters, the Response URI answer's members.
#[derive(Default)]
struct Declared {
    responses: Vec<ParameterName>,
    members: Vec<ParameterName>,
    parameters: Vec<ParameterName>,
    answers: Vec<ParameterName>,
}

/// The names registered parts declare: a DC API mode declares none (`MetadataChannel`); each name
/// once in its place (`NameTwice`), none the core writes there (`NameReserved`):
/// [`CORE_RESPONSE`], [`CORE_METADATA`], [`CORE_PARAMETERS`] and [`CORE_ANSWER`].
fn names<H: Build>(
    modes: &[RegisteredMode<H>],
    mut declared: Declared,
) -> Result<(), RegistryError> {
    let mut members: Vec<ParameterName> = Vec::new();
    for registered in modes {
        if registered.carries_errors() {
            continue;
        }
        let mode = registered.mode();
        let names = mode.metadata_names();
        if mode.channel() == ChannelKind::DcApi && !names.is_empty() {
            return Err(RegistryError::MetadataChannel { mode: mode.name() });
        }
        members.extend_from_slice(names);
    }
    members.append(&mut declared.members);
    let places = [
        (
            NamePlace::ResponseParameter,
            &CORE_RESPONSE[..],
            declared.responses,
        ),
        (NamePlace::WalletMetadata, &CORE_METADATA[..], members),
        (
            NamePlace::PostParameter,
            &CORE_PARAMETERS[..],
            declared.parameters,
        ),
        (NamePlace::AnswerMember, &CORE_ANSWER[..], declared.answers),
    ];
    for (place, reserved, names) in places {
        for (k, name) in names.iter().enumerate() {
            if reserved.contains(name) {
                return Err(RegistryError::NameReserved { place, name: *name });
            }
            if names.get(..k).is_some_and(|before| before.contains(name)) {
                return Err(RegistryError::NameTwice { place, name: *name });
            }
        }
    }
    Ok(())
}

/// The registered scope queries as read: refused per [`RegistryError::ScopeTwice`],
/// [`RegistryError::ScopeQuery`] and [`RegistryError::ScopeIds`].
#[cfg(feature = "uri")]
fn read_scopes(queries: &[Box<dyn ScopeQuery>]) -> Result<Vec<ScopeEntry>, RegistryError> {
    let mut entries: Vec<ScopeEntry> = Vec::new();
    for query in queries {
        let (value, entry) = (query.scope(), ScopeEntry::read(query.as_ref()));
        if entries.iter().any(|entry| entry.value == value) {
            return Err(RegistryError::ScopeTwice { scope: value });
        }
        let entry = entry.ok_or(RegistryError::ScopeQuery { scope: value })?;
        for earlier in &entries {
            if let Some(id) = entry.ids.iter().find(|id| earlier.ids.contains(id)) {
                return Err(RegistryError::ScopeIds {
                    first: earlier.value,
                    second: value,
                    id: id.clone(),
                });
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// The plug-ins as phase 1 reads them, whatever the build's host.
#[cfg(feature = "match")]
pub(crate) trait Catalog {
    fn placed(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn Format>>;
    /// The profile registered for the type, with its handle.
    fn profiled(&self, kind: &TransactionType<'_>) -> Option<(ProfileHandle, &dyn ErasedProfile)>;
    /// The profiles that reserve the credential.
    fn reserving(
        &self,
        credential: &Credential<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<Vec<ProfileHandle>, super::Fault>;
}

#[cfg(feature = "match")]
impl<H: Build> Catalog for Registry<H> {
    fn placed(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn Format>> {
        Self::placed(self, id)
    }

    fn profiled(&self, kind: &TransactionType<'_>) -> Option<(ProfileHandle, &dyn ErasedProfile)> {
        self.typed(kind)
            .map(|(handle, typed)| (handle, typed.profile.upcast()))
    }

    fn reserving(
        &self,
        credential: &Credential<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<Vec<ProfileHandle>, super::Fault> {
        let mut reserving = Vec::new();
        for (position, typed) in self.profiles.iter().enumerate() {
            let profile: &dyn ErasedProfile = typed.profile.upcast();
            if profile.reserves(credential, additions)? {
                reserving.push(ProfileHandle(position));
            }
        }
        Ok(reserving)
    }
}

/// A profile's finding, as the core carries it to the wallet and back.
#[cfg(feature = "resolve")]
pub trait FindingData: Any + fmt::Debug + Send + Sync {}

#[cfg(feature = "resolve")]
impl<T: Any + fmt::Debug + Send + Sync> FindingData for T {}

/// What a profile found in phase 2, with the profile that found it.
#[cfg(feature = "resolve")]
#[derive(Debug)]
pub struct ProfileFinding {
    profile: ProfileHandle,
    data: Box<dyn FindingData>,
}

#[cfg(feature = "resolve")]
impl ProfileFinding {
    /// The finding, when it is of the profile's finding type `T`.
    #[must_use]
    pub fn data<T: 'static>(&self) -> Option<&T> {
        (self.data.as_ref() as &dyn Any).downcast_ref()
    }
}

/// A finding from a profile the registry does not hold.
#[cfg(feature = "resolve")]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "inform_error")]
#[error("a finding comes from a profile the registry does not hold")]
pub struct InformError;

/// A profile informed of its findings, made when called.
#[cfg(feature = "resolve")]
type Informed<'f, H> = Box<dyn FnOnce() -> Box<dyn DynProfile<H>> + 'f>;

/// A [`Profile`] with its finding type erased.
pub trait ErasedProfile: Send + Sync {
    #[cfg(feature = "match")]
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal>;
    fn members(&self, placement: Placement) -> Option<&[Member]>;
    #[cfg(feature = "match")]
    fn bind(
        &self,
        binding: Binding<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Bound, NoCandidate>;
    #[cfg(feature = "match")]
    fn reserves(
        &self,
        credential: &Credential<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<bool, super::Fault>;
}

impl<P: Profile> ErasedProfile for P {
    #[cfg(feature = "match")]
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        Profile::refusals(self, request, entries)
    }

    fn members(&self, placement: Placement) -> Option<&[Member]> {
        Profile::members(self, placement)
    }

    #[cfg(feature = "match")]
    fn bind(
        &self,
        binding: Binding<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Bound, NoCandidate> {
        Profile::bind(self, binding, env, context)
    }

    #[cfg(feature = "match")]
    fn reserves(
        &self,
        credential: &Credential<'_>,
        additions: &dyn ViewAdditions,
    ) -> Result<bool, super::Fault> {
        Profile::reserves(self, credential, additions)
    }
}

/// An [`ErasedProfile`] with phase 2's methods over the build's host `H`.
#[cfg(feature = "resolve")]
pub trait DynProfile<H>: ErasedProfile {
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault>;
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault>;
    fn revalidate(
        &self,
        handle: ProfileHandle,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<ProfileFinding>, Fault>;
    /// Reads the findings as the profile's finding type, refused when one is another type. The
    /// result makes the profile informed of them, or its clone when there are none.
    fn read<'f>(&'f self, findings: &[&'f dyn FindingData])
    -> Result<Informed<'f, H>, InformError>;
    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault>;
}

#[cfg(feature = "resolve")]
impl<H, P: ProfileHost<H>> DynProfile<H> for P {
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        ProfileHost::wanted(self, record, host)
    }

    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        ProfileHost::authentication(self, record)
    }

    fn revalidate(
        &self,
        handle: ProfileHandle,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<ProfileFinding>, Fault> {
        Ok(
            ProfileHost::revalidate(self, record, host)?.map(|finding| ProfileFinding {
                profile: handle,
                data: Box::new(finding),
            }),
        )
    }

    fn read<'f>(
        &'f self,
        findings: &[&'f dyn FindingData],
    ) -> Result<Informed<'f, H>, InformError> {
        let own = findings
            .iter()
            .map(|finding| {
                (*finding as &dyn Any)
                    .downcast_ref::<P::Finding>()
                    .ok_or(InformError)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Box::new(move || -> Box<dyn DynProfile<H>> {
            match own.as_slice() {
                [] => Box::new(self.clone()),
                own => Box::new(ProfileHost::informed(self, own)),
            }
        }))
    }

    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        ProfileHost::respond(self, record, host, authentication)
    }
}
