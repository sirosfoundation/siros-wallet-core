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
use crate::authenticate::ClientPrefix;
#[cfg(feature = "resolve")]
use crate::host::{Authentication, AuthenticationNeed, FormatHost, ProfileHost};
use crate::ids::{FormatId, TransactionType, TypePrefix};
#[cfg(feature = "resolve")]
use crate::rows::HttpsUrl;
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

/// The plug-ins: formats by identifier, profiles by exact type identifier and by type prefix.
/// `H` is the build's host: [`NoHost`] in the matcher's build; under `resolve` a format enters
/// only as a [`FormatHost<H>`](crate::host::FormatHost), a profile as a
/// [`ProfileHost<H>`](crate::host::ProfileHost).
pub struct Registry<H = NoHost> {
    formats: Vec<Box<dyn HostedFormat<H>>>,
    #[cfg_attr(
        not(feature = "match"),
        expect(dead_code, reason = "matching and phase 2 read the profiles")
    )]
    profiles: Vec<Box<dyn DynProfile<H>>>,
    exact: Vec<(TransactionType<'static>, ProfileHandle)>,
    prefixes: Vec<(TypePrefix<'static>, ProfileHandle)>,
    #[cfg(feature = "resolve")]
    clients: Vec<Box<dyn ClientPrefix>>,
}

impl<H> fmt::Debug for Registry<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field(
                "formats",
                &self
                    .formats
                    .iter()
                    .map(|format| format.id().to_string())
                    .collect::<Vec<_>>(),
            )
            .field("exact", &self.exact)
            .field("prefixes", &self.prefixes)
            .finish_non_exhaustive()
    }
}

/// Collects the plug-ins of a [`Registry`].
pub struct RegistryBuilder<H = NoHost> {
    formats: Vec<Box<dyn HostedFormat<H>>>,
    profiles: Vec<Box<dyn DynProfile<H>>>,
    exact: Vec<(TransactionType<'static>, ProfileHandle)>,
    prefixes: Vec<(TypePrefix<'static>, ProfileHandle)>,
    #[cfg(feature = "resolve")]
    clients: Vec<Box<dyn ClientPrefix>>,
}

impl<H> Default for RegistryBuilder<H> {
    fn default() -> Self {
        Self {
            formats: Vec::new(),
            profiles: Vec::new(),
            exact: Vec::new(),
            prefixes: Vec::new(),
            #[cfg(feature = "resolve")]
            clients: Vec::new(),
        }
    }
}

impl<H> RegistryBuilder<H> {
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

    /// Registers a Client Identifier Prefix plug-in; `build` refuses a prefix registered twice.
    #[cfg(feature = "resolve")]
    pub fn client_prefix(&mut self, prefix: impl ClientPrefix + 'static) {
        self.clients.push(Box::new(prefix));
    }

    /// The registry. Refused when two formats share an identifier, a type or prefix is
    /// registered twice, a registration names no profile, or a profile would write a member
    /// twice into one presentation.
    pub fn build(self) -> Result<Registry<H>, RegistryError> {
        let Self {
            formats,
            profiles,
            exact,
            prefixes,
            #[cfg(feature = "resolve")]
            clients,
        } = self;
        #[cfg(feature = "resolve")]
        if let Some(twice) = clients.iter().enumerate().find_map(|(k, prefix)| {
            clients
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.name() == prefix.name()))
                .then(|| prefix.name().to_string())
        }) {
            return Err(RegistryError::PrefixTwice(twice));
        }
        for (k, format) in formats.iter().enumerate() {
            if formats
                .get(..k)
                .is_some_and(|before| before.iter().any(|other| other.id() == format.id()))
            {
                return Err(RegistryError::FormatTwice(format.id().to_string()));
            }
        }
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
            for format in &formats {
                let Some(members) = profile.members(&format.id()) else {
                    continue;
                };
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
        Ok(Registry {
            formats,
            profiles,
            exact,
            prefixes,
            #[cfg(feature = "resolve")]
            clients,
        })
    }
}

impl<H> Registry<H> {
    /// A builder.
    #[must_use]
    pub fn builder() -> RegistryBuilder<H> {
        RegistryBuilder::default()
    }

    /// The Client Identifier Prefix plug-in of a name.
    #[cfg(feature = "resolve")]
    #[must_use]
    pub fn client_prefix(&self, name: &str) -> Option<&dyn ClientPrefix> {
        self.clients
            .iter()
            .find(|prefix| prefix.name().as_str() == name)
            .map(AsRef::as_ref)
    }

    /// The formats, in registration order.
    #[cfg(feature = "resolve")]
    pub(crate) fn formats(&self) -> impl Iterator<Item = &dyn Format> {
        self.formats
            .iter()
            .map(|format| -> &dyn Format { format.as_ref() })
    }

    fn plugged(&self, id: &FormatId<'_>) -> Option<&dyn HostedFormat<H>> {
        self.formats
            .iter()
            .find(|format| format.id() == *id)
            .map(AsRef::as_ref)
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
            formats: self.formats.clone(),
            profiles: read.into_iter().map(|informed| informed()).collect(),
            exact: self.exact.clone(),
            prefixes: self.prefixes.clone(),
            clients: self.clients.clone(),
        })
    }
}

/// The plug-ins as phase 1 reads them, whatever the build's host.
#[cfg(feature = "match")]
pub(crate) trait Catalog {
    fn format(&self, id: &FormatId<'_>) -> Option<&dyn Format>;
    fn profile(&self, kind: &TransactionType<'_>) -> Option<ProfileHandle>;
    fn profile_ref(&self, handle: ProfileHandle) -> Option<&dyn ErasedProfile>;
}

#[cfg(feature = "match")]
impl<H> Catalog for Registry<H> {
    fn format(&self, id: &FormatId<'_>) -> Option<&dyn Format> {
        Self::format(self, id)
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
    fn members(&self, format: &FormatId<'_>) -> Option<&[Member]>;
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

    fn members(&self, format: &FormatId<'_>) -> Option<&[Member]> {
        Profile::members(self, format)
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
