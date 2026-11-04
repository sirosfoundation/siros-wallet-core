//! The registry: formats by identifier, transaction data profiles by exact type or type prefix,
//! each plug-in under the bounds of the build's host.

#[cfg(feature = "resolve")]
use std::any::Any;
use std::fmt;

use siros_explain::{AllOf, Explain};

#[cfg(feature = "resolve")]
use super::{Answered, Fault, FetchedRecord, Members};
#[cfg(feature = "match")]
use super::{Binding, Bound, NoCandidate};
use super::{Format, Member, Profile};
#[cfg(feature = "resolve")]
use crate::authenticate::{HostedPrefix, ObjectRule};
use crate::hash::{HashName, Hashes, HostedHash};
#[cfg(feature = "resolve")]
use crate::host::{Authentication, AuthenticationNeed, FormatHost, ProfileHost};
#[cfg(feature = "resolve")]
use crate::host::{Haip, Has, RequestDecryption};
use crate::ids::{FormatId, TransactionType, TypePrefix};
#[cfg(feature = "resolve")]
use crate::request::Agreements;
#[cfg(feature = "resolve")]
use crate::routing::ModeHost;
use crate::routing::{
    Carries, ChannelKind, Mode, ModeHandle, ModeName, ResponseType, ResponseTypeName, RoutedMode,
};
#[cfg(feature = "resolve")]
use crate::rows::HttpsUrl;
#[cfg(feature = "resolve")]
use crate::scope::ScopeQuery;
use crate::scope::{ScopeEntry, ScopeValue, Scopes};
#[cfg(feature = "resolve")]
use crate::uri::{AnswerReader, EncryptedRequests, RequestPost};
#[cfg(feature = "resolve")]
use crate::wallet_metadata::{
    CORE_ANSWER, CORE_PARAMETERS, HostedPostContribution, MetadataMember, PostContribution,
};
use crate::wallet_metadata::{CORE_METADATA, NamePlace, ParameterName, Placement};
#[cfg(feature = "match")]
use crate::{
    refusal::Refusal,
    request::{EntryIndex, Request},
    rows::Env,
};

/// A profile by its registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileHandle(usize);

/// A registry that cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.registry")]
pub enum RegistryError {
    /// Two formats with one identifier.
    #[error("two formats have the identifier {0}")]
    FormatTwice(#[explain(name = "format")] String),
    /// A type or prefix registered twice.
    #[error("{0} is registered twice")]
    TypeTwice(#[explain(name = "registration")] String),
    /// Two Client Identifier Prefix plug-ins with one name.
    #[error("two Client Identifier Prefix plug-ins have the name {0}")]
    PrefixTwice(#[explain(name = "prefix")] String),
    /// A registration names a profile the builder does not hold.
    #[error("{0} names a profile the registry does not hold")]
    UnknownProfile(#[explain(name = "registration")] String),
    /// Two modes of one name on one channel, or two error modes of one name.
    #[error("the response mode {name} is registered twice on one channel")]
    ModeTwice {
        /// The name.
        name: ModeName,
        /// The channel.
        #[explain(skip)]
        channel: ChannelKind,
    },
    /// An error mode on the DC API, whose errors are A.4's and the core's.
    #[error("the response mode {0} writes DC API errors, which A.4 fixes")]
    ErrorModeChannel(#[explain(name = "mode")] ModeName),
    /// Two response types of one name.
    #[error("the response type {0} is registered twice")]
    ResponseTypeTwice(#[explain(name = "response_type")] ResponseTypeName),
    /// `RequestPost` or `EncryptedRequests` registered twice.
    #[error("the request_uri POST is registered twice")]
    PostTwice,
    /// Two hash algorithms of one name.
    #[error("the hash algorithm {0} is registered twice")]
    HashTwice(#[explain(name = "algorithm")] HashName),
    /// A transaction data profile without `sha-256`, B.3.3.1's default.
    #[error("a transaction data profile is registered and sha-256 is not")]
    Sha256Absent,
    /// Two queries of one scope value.
    #[error("the scope value {0} is registered twice")]
    ScopeTwice(#[explain(name = "scope")] ScopeValue),
    /// A scope value's query that is no DCQL query the core reads.
    #[error("the scope value {0} maps to no DCQL query")]
    ScopeQuery(#[explain(name = "scope")] ScopeValue),
    /// A Credential Query or claim id two scope values' queries share (§5.5: "MUST be unique").
    #[error("the scope values {first} and {second} share the id {id}")]
    ScopeIds {
        /// The first scope value.
        first: ScopeValue,
        /// The second.
        second: ScopeValue,
        /// The id.
        id: String,
    },
    /// A mode that writes `wallet_metadata` members over the DC API, whose requests post none.
    #[error("the DC API response mode {0} writes wallet_metadata members")]
    MetadataChannel(#[explain(name = "mode")] ModeName),
    /// A name two registered parts write.
    #[error("{name} is written by two registered parts")]
    NameTwice {
        /// Where.
        #[explain(skip)]
        place: NamePlace,
        /// The name.
        name: ParameterName,
    },
    /// A name the core writes itself, which a registered part declares.
    #[error("{name} is the core's to write")]
    NameReserved {
        /// Where.
        #[explain(skip)]
        place: NamePlace,
        /// The name.
        name: ParameterName,
    },
    /// `EncryptedRequests` without `RequestPost`.
    #[error("encrypted Request Objects are registered without the request_uri POST")]
    DecryptionWithoutPost,
    /// A profile would write a member twice into one presentation: one of the format's own, or
    /// one it declares twice.
    #[error("the profile registered for {registration} writes {} twice in a {format} presentation", .members.items().join(", "))]
    MemberTwice {
        /// A type or prefix the profile is registered under.
        registration: String,
        /// The format.
        format: String,
        /// The members.
        members: AllOf<String>,
    },
    /// A profile names members of another kind than the format's placement holds: a data
    /// element where the proof holds claims, or a claim where it holds name-space elements.
    #[error("the profile registered for {registration} names {} in a {format} presentation, whose proof holds no such member", .members.items().join(", "))]
    MemberPlacement {
        /// A type or prefix the profile is registered under.
        registration: String,
        /// The format.
        format: String,
        /// The members.
        members: AllOf<String>,
    },
}

/// A registered format and the placement it stated when the registry was built, which the
/// registry checked each profile's members against and which matching and phase 2 read.
struct RegisteredFormat<H> {
    format: Box<dyn HostedFormat<H>>,
    placement: Option<Placement>,
}

impl<H> Clone for RegisteredFormat<H> {
    fn clone(&self) -> Self {
        Self {
            format: self.format.clone(),
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

/// The matcher's build: a registry without a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoHost;

/// A format of a registry: phase 1's [`Format`] under `match`; under `resolve`, a format whose
/// phase 2 runs over the build's host `H` ([`FormatHost`]).
#[cfg(feature = "resolve")]
pub trait HostedFormat<H>: FormatHost<H> {}

#[cfg(feature = "resolve")]
impl<H, F: FormatHost<H>> HostedFormat<H> for F {}

/// A format of a registry: phase 1's [`Format`] under `match`; under `resolve`, a format whose
/// phase 2 runs over the build's host `H`.
#[cfg(not(feature = "resolve"))]
pub trait HostedFormat<H>: Format {}

#[cfg(not(feature = "resolve"))]
impl<H, F: Format> HostedFormat<H> for F {}

dyn_clone::clone_trait_object!(<H> HostedFormat<H>);

/// A profile of a registry: phase 1's [`Profile`] under `match`; under `resolve`, a profile
/// whose phase 2 runs over the build's host `H` ([`ProfileHost`]).
#[cfg(feature = "resolve")]
pub trait HostedProfile<H>: ProfileHost<H> {}

#[cfg(feature = "resolve")]
impl<H, P: ProfileHost<H>> HostedProfile<H> for P {}

/// A profile of a registry: phase 1's [`Profile`] under `match`; under `resolve`, a profile
/// whose phase 2 runs over the build's host `H`.
#[cfg(not(feature = "resolve"))]
pub trait HostedProfile<H>: Profile {}

#[cfg(not(feature = "resolve"))]
impl<H, P: Profile> HostedProfile<H> for P {}

/// A response mode of a registry: phase 1's [`Mode`] under `match`; under `resolve`, a mode whose
/// phase 2 runs over the build's host `H` ([`ModeHost`]).
#[cfg(feature = "resolve")]
pub trait HostedMode<H>: ModeHost<H> {}

#[cfg(feature = "resolve")]
impl<H, M: ModeHost<H>> HostedMode<H> for M {}

/// A response mode of a registry: phase 1's [`Mode`] under `match`; under `resolve`, a mode whose
/// phase 2 runs over the build's host `H`.
#[cfg(not(feature = "resolve"))]
pub trait HostedMode<H>: Mode {}

#[cfg(not(feature = "resolve"))]
impl<H, M: Mode> HostedMode<H> for M {}

dyn_clone::clone_trait_object!(<H> HostedMode<H>);

/// The host's `Haip`, as the registration of a JWE mode keeps its accessor.
#[cfg(feature = "resolve")]
pub(crate) type HaipAccess<H> = fn(&H) -> &dyn Haip;

/// A JWE mode's registration in the match build, which holds no module.
#[cfg(not(feature = "resolve"))]
pub(crate) type HaipAccess<H> = std::marker::PhantomData<fn(&H)>;

/// What a registered mode carries and how its answers are sealed.
pub(crate) enum Role<H> {
    /// Answers in the clear (`mode`).
    Clear,
    /// Answers the core seals as JWEs through the host's `Haip` (`jwe_mode`).
    Jwe(HaipAccess<H>),
    /// A URI mode's errors alone (`error_mode`).
    Errors,
}

impl<H> Clone for Role<H> {
    fn clone(&self) -> Self {
        match self {
            Self::Clear => Self::Clear,
            Self::Jwe(access) => Self::Jwe(*access),
            Self::Errors => Self::Errors,
        }
    }
}

/// A registered mode with its role.
pub(crate) struct RegisteredMode<H> {
    pub(crate) mode: Box<dyn HostedMode<H>>,
    pub(crate) role: Role<H>,
}

impl<H> Clone for RegisteredMode<H> {
    fn clone(&self) -> Self {
        Self {
            mode: self.mode.clone(),
            role: self.role.clone(),
        }
    }
}

/// The plug-ins: formats by identifier, profiles by exact type identifier and by type prefix.
/// `H` is the build's host: [`NoHost`] in the matcher's build; under `resolve` a format enters
/// only as a [`FormatHost<H>`](crate::host::FormatHost), a profile as a
/// [`ProfileHost<H>`](crate::host::ProfileHost).
pub struct Registry<H = NoHost> {
    hashes: Vec<Box<dyn HostedHash>>,
    scopes: Vec<ScopeEntry>,
    response_types: Vec<Box<dyn ResponseType>>,
    modes: Vec<RegisteredMode<H>>,
    formats: Vec<RegisteredFormat<H>>,
    #[cfg_attr(
        not(feature = "match"),
        expect(dead_code, reason = "matching and phase 2 read the profiles")
    )]
    profiles: Vec<Box<dyn DynProfile<H>>>,
    exact: Vec<(TransactionType<'static>, ProfileHandle)>,
    prefixes: Vec<(TypePrefix<'static>, ProfileHandle)>,
    #[cfg(feature = "resolve")]
    clients: Vec<RegisteredPrefix<H>>,
    #[cfg(feature = "resolve")]
    object_rules: Vec<Box<dyn ObjectRule>>,
    #[cfg(feature = "resolve")]
    post: Option<Post<H>>,
    #[cfg(feature = "resolve")]
    contributions: Vec<Box<dyn HostedPostContribution<H>>>,
    #[cfg(feature = "resolve")]
    readers: Vec<Box<dyn AnswerReader>>,
}

impl<H> fmt::Debug for Registry<H> {
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
            .field("exact", &self.exact)
            .field("prefixes", &self.prefixes)
            .finish_non_exhaustive()
    }
}

/// Collects the plug-ins of a [`Registry`].
pub struct RegistryBuilder<H = NoHost> {
    hashes: Vec<Box<dyn HostedHash>>,
    #[cfg(feature = "resolve")]
    scopes: Vec<Box<dyn ScopeQuery>>,
    response_types: Vec<Box<dyn ResponseType>>,
    modes: Vec<RegisteredMode<H>>,
    formats: Vec<Box<dyn HostedFormat<H>>>,
    profiles: Vec<Box<dyn DynProfile<H>>>,
    exact: Vec<(TransactionType<'static>, ProfileHandle)>,
    prefixes: Vec<(TypePrefix<'static>, ProfileHandle)>,
    #[cfg(feature = "resolve")]
    clients: Vec<RegisteredPrefix<H>>,
    #[cfg(feature = "resolve")]
    object_rules: Vec<Box<dyn ObjectRule>>,
    #[cfg(feature = "resolve")]
    posts: Vec<PostPart<H>>,
    #[cfg(feature = "resolve")]
    contributions: Vec<Box<dyn HostedPostContribution<H>>>,
    #[cfg(feature = "resolve")]
    readers: Vec<Box<dyn AnswerReader>>,
}

impl<H> Default for RegistryBuilder<H> {
    fn default() -> Self {
        Self {
            hashes: Vec::new(),
            #[cfg(feature = "resolve")]
            scopes: Vec::new(),
            response_types: Vec::new(),
            modes: Vec::new(),
            formats: Vec::new(),
            profiles: Vec::new(),
            exact: Vec::new(),
            prefixes: Vec::new(),
            #[cfg(feature = "resolve")]
            clients: Vec::new(),
            #[cfg(feature = "resolve")]
            object_rules: Vec::new(),
            #[cfg(feature = "resolve")]
            posts: Vec::new(),
            #[cfg(feature = "resolve")]
            contributions: Vec::new(),
            #[cfg(feature = "resolve")]
            readers: Vec::new(),
        }
    }
}

impl<H> RegistryBuilder<H> {
    /// A transaction data hash algorithm (B.3.3.1), keyed by its name; `build` refuses a name
    /// registered twice, and a registry with a transaction data profile and without `sha-256`.
    pub fn hash(&mut self, algorithm: impl HostedHash + 'static) {
        self.hashes.push(Box::new(algorithm));
    }

    /// A scope value's DCQL query (§5.5), keyed by its scope value; `build` refuses a value
    /// twice, a query the DCQL reader refuses, and a Credential Query or claim id two queries
    /// share.
    #[cfg(feature = "resolve")]
    pub fn scope(&mut self, query: impl ScopeQuery + 'static) {
        self.scopes.push(Box::new(query));
    }

    /// A response type (RFC 6749 §3.1.1), keyed by its name (P1); `build` refuses a name
    /// registered twice.
    pub fn response_type(&mut self, response_type: impl ResponseType + 'static) {
        self.response_types.push(Box::new(response_type));
    }

    /// A response mode whose answers are in the clear, keyed by its name and channel.
    pub fn mode(&mut self, mode: impl HostedMode<H> + 'static) {
        self.modes.push(RegisteredMode {
            mode: Box::new(mode),
            role: Role::Clear,
        });
    }

    /// A response mode whose answers the core seals as JWEs (§8.3) through the host's `Haip`,
    /// keyed by its name and channel.
    ///
    /// A host without the module does not compile with it:
    ///
    /// ```compile_fail,E0277
    /// use siros_openid4vp::host::Platform;
    /// use siros_openid4vp::plugins::Registry;
    /// use siros_testkit::TestPlatform;
    ///
    /// siros_testkit::test_host! {
    ///     /// A host of the platform alone.
    ///     #[derive(Default)]
    ///     struct Bare {
    ///         handles { platform: TestPlatform => Platform }
    ///         zero_sized {}
    ///         optional {}
    ///         lacks {}
    ///     }
    /// }
    ///
    /// let mut builder = Registry::<Bare>::builder();
    /// builder.jwe_mode(siros_openid4vp::modes::DcApiJwt);
    /// ```
    #[cfg(feature = "resolve")]
    pub fn jwe_mode(&mut self, mode: impl HostedMode<H> + 'static)
    where
        H: Has<dyn Haip>,
    {
        self.modes.push(RegisteredMode {
            mode: Box::new(mode),
            role: Role::Jwe(|host| Has::<dyn Haip>::module(host)),
        });
    }

    /// A response mode whose answers are sealed as JWEs (§8.3), keyed by its name and channel.
    #[cfg(not(feature = "resolve"))]
    pub fn jwe_mode(&mut self, mode: impl HostedMode<H> + 'static) {
        self.modes.push(RegisteredMode {
            mode: Box::new(mode),
            role: Role::Jwe(std::marker::PhantomData),
        });
    }

    /// A URI response mode's error responses (§8.2, §8.3.1), keyed by its name: a mode
    /// registered here alone carries errors alone (C5 refuses a request naming it). Over the DC
    /// API the core writes A.4's error itself, so `build` refuses a DC API mode registered here.
    pub fn error_mode(&mut self, mode: impl HostedMode<H> + 'static) {
        self.modes.push(RegisteredMode {
            mode: Box::new(mode),
            role: Role::Errors,
        });
    }

    /// Adds a format whose phase 2 the build's host can run.
    pub fn format(&mut self, format: impl HostedFormat<H> + 'static) {
        self.formats.push(Box::new(format));
    }

    /// Adds a profile whose phase 2 the build's host can run, to register under types or
    /// prefixes.
    pub fn profile(&mut self, profile: impl HostedProfile<H>) -> ProfileHandle {
        self.profiles.push(Box::new(profile));
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
    /// A host without the module does not compile with it:
    ///
    /// ```compile_fail,E0277
    /// use siros_openid4vp::host::Platform;
    /// use siros_openid4vp::plugins::Registry;
    /// use siros_testkit::TestPlatform;
    ///
    /// siros_testkit::test_host! {
    ///     /// A host of the platform alone.
    ///     #[derive(Default)]
    ///     struct Bare {
    ///         handles { platform: TestPlatform => Platform }
    ///         zero_sized {}
    ///         optional {}
    ///         lacks {}
    ///     }
    /// }
    ///
    /// let mut builder = Registry::<Bare>::builder();
    /// builder.client_prefix(siros_testkit::TestPrefix::Request);
    /// ```
    #[cfg(feature = "resolve")]
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
    /// order.
    #[cfg(feature = "resolve")]
    pub fn object_rule(&mut self, rule: impl ObjectRule + 'static) {
        self.object_rules.push(Box::new(rule));
    }

    /// The POST of `wallet_metadata` to the `request_uri` (§5.10): with it, a request whose
    /// `request_uri_method` is `post` is fetched by POST; without it, by GET (§5.1: "Wallets not
    /// supporting the post method will send a GET request"). `build` refuses it twice.
    #[cfg(feature = "resolve")]
    pub fn request_post(&mut self, post: RequestPost) {
        self.posts.push(PostPart::Post(post));
    }

    /// Encrypted Request Objects (§5.10): each POST's `jwks` holds a fresh key from the host's
    /// `RequestDecryption`, whose accessor the registration keeps, and a JWE Request Object
    /// decrypts through it. `build` refuses it twice, and without [`Self::request_post`].
    ///
    /// A host without the module does not compile with it:
    ///
    /// ```compile_fail,E0277
    /// use siros_openid4vp::host::Platform;
    /// use siros_openid4vp::plugins::Registry;
    /// use siros_testkit::TestPlatform;
    ///
    /// siros_testkit::test_host! {
    ///     /// A host of the platform alone.
    ///     #[derive(Default)]
    ///     struct Bare {
    ///         handles { platform: TestPlatform => Platform }
    ///         zero_sized {}
    ///         optional {}
    ///         lacks {}
    ///     }
    /// }
    ///
    /// let mut builder = Registry::<Bare>::builder();
    /// builder.request_encryption(siros_openid4vp::uri::EncryptedRequests);
    /// ```
    #[cfg(feature = "resolve")]
    pub fn request_encryption(&mut self, requests: EncryptedRequests)
    where
        H: Has<dyn RequestDecryption>,
    {
        self.posts.push(PostPart::Encrypted(requests, |host| {
            Has::<dyn RequestDecryption>::module(host)
        }));
    }

    /// Members of `wallet_metadata` and parameters of the `request_uri` POST a profile or a
    /// deployment adds (§10.1, §5.10: "Additional parameters MAY be defined"), keyed by their
    /// names: `build` refuses a name another part declares (`NameTwice`) and a name the core
    /// writes (`NameReserved`).
    #[cfg(feature = "resolve")]
    pub fn post_contribution(&mut self, contribution: impl HostedPostContribution<H> + 'static) {
        self.contributions.push(Box::new(contribution));
    }

    /// A reader of the Response URI's answer members (§8.2: "Additional parameters MAY be
    /// defined"), keyed by their names: `build` refuses a name another reader declares
    /// (`NameTwice`) and `redirect_uri` (`NameReserved`).
    #[cfg(feature = "resolve")]
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
            hashes,
            #[cfg(feature = "resolve")]
            scopes,
            response_types,
            modes,
            formats,
            profiles,
            exact,
            prefixes,
            #[cfg(feature = "resolve")]
            clients,
            #[cfg(feature = "resolve")]
            object_rules,
            #[cfg(feature = "resolve")]
            posts,
            #[cfg(feature = "resolve")]
            contributions,
            #[cfg(feature = "resolve")]
            readers,
        } = self;
        for (k, algorithm) in hashes.iter().enumerate() {
            if hashes
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.name() == algorithm.name()))
            {
                return Err(RegistryError::HashTwice(algorithm.name()));
            }
        }
        #[cfg(feature = "resolve")]
        let scopes = read_scopes(&scopes)?;
        #[cfg(not(feature = "resolve"))]
        let scopes = Vec::new();
        for (k, kind) in response_types.iter().enumerate() {
            if response_types
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.name() == kind.name()))
            {
                return Err(RegistryError::ResponseTypeTwice(kind.name()));
            }
        }
        for (k, registered) in modes.iter().enumerate() {
            let (name, channel) = (registered.mode.name(), registered.mode.channel());
            let errors = matches!(registered.role, Role::Errors);
            if errors && channel == ChannelKind::DcApi {
                return Err(RegistryError::ErrorModeChannel(name));
            }
            if modes.get(..k).is_some_and(|before| {
                before.iter().any(|other| {
                    other.mode.name() == name
                        && other.mode.channel() == channel
                        && matches!(other.role, Role::Errors) == errors
                })
            }) {
                return Err(RegistryError::ModeTwice { name, channel });
            }
        }
        #[cfg(feature = "resolve")]
        let declared = Declared {
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
        #[cfg(not(feature = "resolve"))]
        let declared = Declared::default();
        names(&modes, declared)?;
        #[cfg(feature = "resolve")]
        if let Some(twice) = clients.iter().enumerate().find_map(|(k, registered)| {
            let name = registered.prefix.name();
            clients
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.prefix.name() == name))
                .then(|| name.to_string())
        }) {
            return Err(RegistryError::PrefixTwice(twice));
        }
        #[cfg(feature = "resolve")]
        let post = Post::of(posts)?;
        for (k, format) in formats.iter().enumerate() {
            if formats
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.id() == format.id()))
            {
                return Err(RegistryError::FormatTwice(format.id().to_string()));
            }
        }
        let formats: Vec<RegisteredFormat<H>> = formats
            .into_iter()
            .map(|format| RegisteredFormat {
                placement: format.placement(),
                format,
            })
            .collect();
        let registrations: Vec<(String, ProfileHandle)> = exact
            .iter()
            .map(|(kind, handle)| (kind.to_string(), *handle))
            .chain(
                prefixes
                    .iter()
                    .map(|(prefix, handle)| (format!("the prefix {prefix}"), *handle)),
            )
            .collect();
        for (k, (name, handle)) in registrations.iter().enumerate() {
            if registrations
                .get(..k)
                .is_some_and(|before| before.iter().any(|(other, _)| other == name))
            {
                return Err(RegistryError::TypeTwice(name.clone()));
            }
            let profile = profiles
                .get(handle.0)
                .ok_or_else(|| RegistryError::UnknownProfile(name.clone()))?;
            for RegisteredFormat { format, placement } in &formats {
                let Some((placement, members)) = placement.and_then(|placement| {
                    profile
                        .members(placement)
                        .map(|members| (placement, members))
                }) else {
                    continue;
                };
                let mut misplaced: Vec<String> = members
                    .iter()
                    .filter(|member| !placement.places(member))
                    .map(ToString::to_string)
                    .collect();
                misplaced.sort();
                misplaced.dedup();
                if let Some(members) = AllOf::new(misplaced) {
                    return Err(RegistryError::MemberPlacement {
                        registration: name.clone(),
                        format: format.id().to_string(),
                        members,
                    });
                }
                let mut twice: Vec<String> = members
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
                twice.sort();
                twice.dedup();
                if let Some(members) = AllOf::new(twice) {
                    return Err(RegistryError::MemberTwice {
                        registration: name.clone(),
                        format: format.id().to_string(),
                        members,
                    });
                }
            }
        }
        let transacting = !exact.is_empty() || !prefixes.is_empty();
        if transacting
            && !hashes
                .iter()
                .any(|algorithm| algorithm.name().as_str() == "sha-256")
        {
            return Err(RegistryError::Sha256Absent);
        }
        Ok(Registry {
            hashes,
            scopes,
            response_types,
            modes,
            formats,
            profiles,
            exact,
            prefixes,
            #[cfg(feature = "resolve")]
            clients,
            #[cfg(feature = "resolve")]
            object_rules,
            #[cfg(feature = "resolve")]
            post,
            #[cfg(feature = "resolve")]
            contributions,
            #[cfg(feature = "resolve")]
            readers,
        })
    }
}

impl<H> Registry<H> {
    /// A builder.
    #[must_use]
    pub fn builder() -> RegistryBuilder<H> {
        RegistryBuilder::default()
    }

    /// Whether a Client Identifier Prefix of the name is registered.
    #[cfg(feature = "resolve")]
    #[must_use]
    pub fn names_prefix(&self, name: &str) -> bool {
        self.client_prefix(name).is_some()
    }

    /// The Client Identifier Prefix of a name, with the accessor of the `Haip` its registration
    /// bounded.
    #[cfg(feature = "resolve")]
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
    #[cfg(feature = "resolve")]
    pub(crate) fn prefix_names(&self) -> impl Iterator<Item = crate::authenticate::PrefixName> {
        self.clients
            .iter()
            .map(|registered| registered.prefix.name())
    }

    /// Each registered URI mode's `wallet_metadata` members with the names it declared, in
    /// registration order, each written under what its registration seals with: the `Haip`
    /// statement of a JWE mode, none of a mode in the clear.
    ///
    /// # Errors
    ///
    /// A mode broke its contract.
    #[cfg(feature = "resolve")]
    pub(crate) fn mode_metadata(&self, host: &H) -> Result<Vec<ModeMembers>, Fault> {
        self.modes
            .iter()
            .filter(|registered| registered.mode.channel() == ChannelKind::Uri)
            .filter_map(|registered| {
                let sealer = match registered.role {
                    Role::Jwe(access) => access(host).agreements(),
                    Role::Clear => Agreements::NONE,
                    Role::Errors => return None,
                };
                Some(
                    registered
                        .mode
                        .wallet_metadata(&sealer, host)
                        .map(|members| (registered.mode.metadata_names(), members)),
                )
            })
            .collect()
    }

    /// The registered POST contributions, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn contributions(&self) -> impl Iterator<Item = &dyn HostedPostContribution<H>> {
        self.contributions.iter().map(AsRef::as_ref)
    }

    /// The registered readers of the Response URI's answer, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn answer_readers(&self) -> &[Box<dyn AnswerReader>] {
        &self.readers
    }

    /// The registered rules over a Request Object's claims, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn object_rules(&self) -> &[Box<dyn ObjectRule>] {
        &self.object_rules
    }

    /// The registered POST of `wallet_metadata`, with the decrypting module's accessor when
    /// encrypted Request Objects are registered.
    #[cfg(feature = "resolve")]
    pub(crate) const fn post(&self) -> Option<&Post<H>> {
        self.post.as_ref()
    }

    /// The formats, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn formats(&self) -> impl Iterator<Item = &dyn Format> {
        self.formats
            .iter()
            .map(|registered| -> &dyn Format { registered.format.as_ref() })
    }

    fn registered(&self, id: &FormatId<'_>) -> Option<&RegisteredFormat<H>> {
        self.formats
            .iter()
            .find(|registered| registered.format.id() == *id)
    }

    fn plugged(&self, id: &FormatId<'_>) -> Option<&dyn HostedFormat<H>> {
        self.registered(id)
            .map(|registered| registered.format.as_ref())
    }

    /// The format with an identifier and the placement it stated at registration.
    #[cfg(feature = "match")]
    pub(crate) fn placed(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn Format>> {
        self.registered(id).map(|registered| {
            let format: &dyn Format = registered.format.as_ref();
            Placed {
                format,
                placement: registered.placement,
            }
        })
    }

    /// The format with an identifier, with its phase 2 over the build's host, and the placement
    /// it stated at registration.
    #[cfg(feature = "resolve")]
    pub(crate) fn placed_host(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn FormatHost<H>>> {
        self.registered(id).map(|registered| {
            let format: &dyn FormatHost<H> = registered.format.as_ref();
            Placed {
                format,
                placement: registered.placement,
            }
        })
    }

    /// The format with an identifier.
    #[must_use]
    pub fn format(&self, id: &FormatId<'_>) -> Option<&dyn Format> {
        self.plugged(id).map(|format| -> &dyn Format { format })
    }

    /// The format with an identifier, with its phase 2 over the build's host.
    #[cfg(feature = "resolve")]
    #[must_use]
    pub fn format_host(&self, id: &FormatId<'_>) -> Option<&dyn FormatHost<H>> {
        self.plugged(id)
            .map(|format| -> &dyn FormatHost<H> { format })
    }

    /// The profile registered for the exact type identifier, else for its longest registered
    /// prefix.
    #[must_use]
    pub fn profile(&self, kind: &TransactionType<'_>) -> Option<ProfileHandle> {
        self.exact
            .iter()
            .find(|(exact, _)| exact == kind)
            .map(|(_, handle)| *handle)
            .or_else(|| {
                self.prefixes
                    .iter()
                    .filter(|(prefix, _)| kind.has_prefix(prefix))
                    .max_by_key(|(prefix, _)| prefix.as_str().len())
                    .map(|(_, handle)| *handle)
            })
    }

    #[cfg(feature = "match")]
    pub(crate) fn profile_ref(&self, handle: ProfileHandle) -> Option<&dyn ErasedProfile> {
        self.profiles
            .get(handle.0)
            .map(|profile| -> &dyn ErasedProfile { profile.as_ref() })
    }

    #[cfg(feature = "resolve")]
    pub(crate) fn profile_host(&self, handle: ProfileHandle) -> Option<&dyn DynProfile<H>> {
        self.profiles.get(handle.0).map(AsRef::as_ref)
    }

    /// The registry with each profile informed of its findings, for the request's re-run of
    /// phase 1 and the phase 2 that follows it. Refused when a finding comes from a profile this
    /// registry does not hold.
    #[cfg(feature = "resolve")]
    pub fn informed(&self, findings: &[&ProfileFinding]) -> Result<Self, InformError> {
        let mut found: Vec<(&dyn DynProfile<H>, Vec<&dyn FindingData>)> = self
            .profiles
            .iter()
            .map(|profile| (profile.as_ref(), Vec::new()))
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
            hashes: self.hashes.clone(),
            scopes: self.scopes.clone(),
            response_types: self.response_types.clone(),
            modes: self.modes.clone(),
            formats: self.formats.clone(),
            profiles: read.into_iter().map(|informed| informed()).collect(),
            exact: self.exact.clone(),
            prefixes: self.prefixes.clone(),
            clients: self.clients.clone(),
            object_rules: self.object_rules.clone(),
            post: self.post.clone(),
            contributions: self.contributions.clone(),
            readers: self.readers.clone(),
        })
    }
}

/// A registered prefix, with the accessor of the host's `Haip` its registration bounded.
#[cfg(feature = "resolve")]
pub(crate) struct RegisteredPrefix<H> {
    prefix: Box<dyn HostedPrefix<H>>,
    haip: HaipAccess<H>,
}

#[cfg(feature = "resolve")]
impl<H> Clone for RegisteredPrefix<H> {
    fn clone(&self) -> Self {
        Self {
            prefix: self.prefix.clone(),
            haip: self.haip,
        }
    }
}

/// A mode's `wallet_metadata` members, with the names it declared.
#[cfg(feature = "resolve")]
pub(crate) type ModeMembers = (&'static [ParameterName], Vec<MetadataMember>);

/// The host's `RequestDecryption`, as the registration of encrypted Request Objects keeps it.
#[cfg(feature = "resolve")]
pub(crate) type DecryptionAccess<H> = fn(&H) -> &dyn RequestDecryption;

/// A part of the `request_uri` POST as registered.
#[cfg(feature = "resolve")]
enum PostPart<H> {
    Post(RequestPost),
    Encrypted(EncryptedRequests, DecryptionAccess<H>),
}

/// The registered POST of `wallet_metadata`, and the decrypting module's accessor when encrypted
/// Request Objects are registered.
#[cfg(feature = "resolve")]
pub(crate) struct Post<H> {
    pub(crate) decryption: Option<DecryptionAccess<H>>,
}

#[cfg(feature = "resolve")]
impl<H> Clone for Post<H> {
    fn clone(&self) -> Self {
        Self {
            decryption: self.decryption,
        }
    }
}

#[cfg(feature = "resolve")]
impl<H> Post<H> {
    /// The POST the parts make: none without parts; refused when a part is given twice, or
    /// encrypted Request Objects without the POST.
    fn of(parts: Vec<PostPart<H>>) -> Result<Option<Self>, RegistryError> {
        let mut post = None;
        let mut decryption = None;
        for part in parts {
            match part {
                PostPart::Post(RequestPost) => {
                    if post.replace(()).is_some() {
                        return Err(RegistryError::PostTwice);
                    }
                }
                PostPart::Encrypted(EncryptedRequests, access) => {
                    if decryption.replace(access).is_some() {
                        return Err(RegistryError::PostTwice);
                    }
                }
            }
        }
        match (post, decryption) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(RegistryError::DecryptionWithoutPost),
            (Some(()), decryption) => Ok(Some(Self { decryption })),
        }
    }
}

impl<H> Registry<H> {
    /// The registered mode a handle names, with its role.
    #[cfg(feature = "resolve")]
    pub(crate) fn mode_host(&self, handle: ModeHandle) -> Option<&RegisteredMode<H>> {
        self.modes.get(handle.place())
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
    fn hashes(&self) -> Hashes<'_>;
    /// The registered scope queries.
    fn scopes(&self) -> Scopes<'_>;
}

impl<H> Routes for Registry<H> {
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
                    let mode = &registered.mode;
                    (mode.channel() == channel
                        && mode.name().as_str() == name
                        && matches!(registered.role, Role::Errors) == errors)
                        .then(|| {
                            let carries = if errors {
                                Carries::Errors
                            } else {
                                Carries::Answers
                            };
                            let routed =
                                RoutedMode::of(ModeHandle::at(place), mode.name(), carries);
                            let mode: &dyn Mode = mode.as_ref();
                            (routed, mode)
                        })
                })
        };
        find(false).or_else(|| find(true))
    }

    fn hashes(&self) -> Hashes<'_> {
        Hashes::of(&self.hashes)
    }

    fn scopes(&self) -> Scopes<'_> {
        Scopes::of(&self.scopes)
    }
}

/// The names registered parts declare, by place: the `wallet_metadata` members of the modes that
/// carry answers and of the POST's contributions, the POST's parameters, the Response URI
/// answer's members.
#[derive(Default)]
struct Declared {
    members: Vec<ParameterName>,
    parameters: Vec<ParameterName>,
    answers: Vec<ParameterName>,
}

/// The names registered parts declare: a DC API mode declares none (`MetadataChannel`); each name
/// once in its place (`NameTwice`), none the core writes there (`NameReserved`):
/// [`CORE_METADATA`], and under `resolve` the POST's `wallet_metadata` and `wallet_nonce` and the
/// answer's `redirect_uri`.
fn names<H>(modes: &[RegisteredMode<H>], mut declared: Declared) -> Result<(), RegistryError> {
    let mut members: Vec<ParameterName> = Vec::new();
    for registered in modes {
        if matches!(registered.role, Role::Errors) {
            continue;
        }
        let names = registered.mode.metadata_names();
        if registered.mode.channel() == ChannelKind::DcApi && !names.is_empty() {
            return Err(RegistryError::MetadataChannel(registered.mode.name()));
        }
        members.extend_from_slice(names);
    }
    members.append(&mut declared.members);
    #[cfg(feature = "resolve")]
    let (parameters, answers): (&[ParameterName], &[ParameterName]) =
        (&CORE_PARAMETERS, &CORE_ANSWER);
    #[cfg(not(feature = "resolve"))]
    let (parameters, answers): (&[ParameterName], &[ParameterName]) = (&[], &[]);
    let places = [
        (NamePlace::WalletMetadata, &CORE_METADATA[..], members),
        (NamePlace::PostParameter, parameters, declared.parameters),
        (NamePlace::AnswerMember, answers, declared.answers),
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
#[cfg(feature = "resolve")]
fn read_scopes(queries: &[Box<dyn ScopeQuery>]) -> Result<Vec<ScopeEntry>, RegistryError> {
    let mut entries: Vec<ScopeEntry> = Vec::new();
    for query in queries {
        let (value, entry) = (query.scope(), ScopeEntry::read(query.as_ref()));
        if entries.iter().any(|entry| entry.value == value) {
            return Err(RegistryError::ScopeTwice(value));
        }
        let entry = entry.ok_or(RegistryError::ScopeQuery(value))?;
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
    fn profile(&self, kind: &TransactionType<'_>) -> Option<ProfileHandle>;
    fn profile_ref(&self, handle: ProfileHandle) -> Option<&dyn ErasedProfile>;
}

#[cfg(feature = "match")]
impl<H> Catalog for Registry<H> {
    fn placed(&self, id: &FormatId<'_>) -> Option<Placed<'_, dyn Format>> {
        Self::placed(self, id)
    }

    fn profile(&self, kind: &TransactionType<'_>) -> Option<ProfileHandle> {
        Self::profile(self, kind)
    }

    fn profile_ref(&self, handle: ProfileHandle) -> Option<&dyn ErasedProfile> {
        Self::profile_ref(self, handle)
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
#[explain(domain = "openid4vp")]
#[error("a finding comes from a profile the registry does not hold")]
pub struct InformError;

/// A profile informed of its findings, made when called.
#[cfg(feature = "resolve")]
type Informed<'f, H> = Box<dyn FnOnce() -> Box<dyn DynProfile<H>> + 'f>;

/// A [`Profile`] with its finding type erased: phase 1's methods, and phase 2's that read no
/// host.
pub(crate) trait ErasedProfile: Send + Sync {
    #[cfg(feature = "match")]
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal>;
    fn members(&self, placement: Placement) -> Option<&[Member]>;
    #[cfg(feature = "match")]
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate>;
    #[cfg(feature = "resolve")]
    fn wanted(&self, record: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault>;
    #[cfg(feature = "resolve")]
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault>;
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
    fn bind(&self, binding: Binding<'_>, env: &Env) -> Result<Bound, NoCandidate> {
        Profile::bind(self, binding, env)
    }

    #[cfg(feature = "resolve")]
    fn wanted(&self, record: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        Profile::wanted(self, record)
    }

    #[cfg(feature = "resolve")]
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Profile::authentication(self, record)
    }
}

/// An [`ErasedProfile`] with phase 2's methods over the build's host `H`.
pub(crate) trait DynProfile<H>: ErasedProfile {
    #[cfg(feature = "resolve")]
    fn revalidate(
        &self,
        handle: ProfileHandle,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<ProfileFinding>, Fault>;
    /// Reads the findings as the profile's finding type, refused when one is another type. The
    /// result makes the profile informed of them, or its clone when there are none.
    #[cfg(feature = "resolve")]
    fn read<'f>(&'f self, findings: &[&'f dyn FindingData])
    -> Result<Informed<'f, H>, InformError>;
    #[cfg(feature = "resolve")]
    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault>;
}

#[cfg(not(feature = "resolve"))]
impl<H, P: Profile> DynProfile<H> for P {}

#[cfg(feature = "resolve")]
impl<H, P: ProfileHost<H>> DynProfile<H> for P {
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
                own => Box::new(Profile::informed(self, own)),
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
