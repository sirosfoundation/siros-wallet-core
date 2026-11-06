//! A claims format as a format plug-in: the kit answers the core for it.

use siros_explain::AllOf;

#[cfg(feature = "resolve")]
use super::super::ConcretePath;
use super::super::PathError;
use super::{ClaimsFormat, ClaimsQuery, ClaimsView, Constraint};
use crate::consent::Card;
use crate::ids::CredentialType;
use crate::json::Node;
use crate::plugins::{
    Carriage, Fault, FormatQuery, Member, NoCandidate, OptionIndex, Options, Shown, ViewAdditions,
    ViewTypes,
};
use crate::refusal::Refusal;
use crate::request::{AgreeableKey, Query};
use crate::routing::{EntryNaming, QueryContext};
use crate::rows::Env;
use crate::wallet::Credential;
use crate::{FAULT, detail};
#[cfg(feature = "resolve")]
use crate::{
    host::{AnsweredContext, AnsweredOption, AnsweredQuery, PresentError, Presentation, Usable},
    plugins::{FindingData, Members},
    session::Session,
};

/// A claims format as a format plug-in: what it adds to the kit, which parses its Credential
/// Queries, matches, admits, draws and discloses its credentials.
pub trait ClaimsPlugin: ClaimsFormat + Send + Sync {
    /// The request rules the format adds to the kit's for a query.
    fn rules(&self, query: &Query<'_>, naming: EntryNaming) -> Vec<Refusal>;

    /// Per `vp_formats_supported` member constraining the credential's presentation, the
    /// identifiers the presentation can match; `keys`: the Verifier's keys.
    fn algorithms<'v>(
        &self,
        view: &ClaimsView<'v>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<Vec<Constraint<'v>>, Fault>;

    /// Whether the credential's presentation for the query can carry these response members.
    fn carries(
        &self,
        query: &Query<'_>,
        view: &ClaimsView<'_>,
        members: &[Member],
    ) -> Result<Carriage, Fault>;
}

/// A claims format's presentation over the build's host `H`; its bounds name the modules it
/// calls.
#[cfg(feature = "resolve")]
pub trait ClaimsPresent<H>: ClaimsPlugin {
    /// What phase 1 assumed of the credential and the option and could not check, checked over
    /// the build's host before the End-User authenticates; the format's finding when it no
    /// longer holds.
    ///
    /// # Errors
    ///
    /// The format's fault.
    fn revalidate(
        &self,
        revalidating: Revalidating<'_>,
        host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault>;

    /// The presentation of what the option discloses, its proof holding the members beside the
    /// format's own.
    ///
    /// # Errors
    ///
    /// The format's contract broken, or a step that failed with its reason.
    fn present(&self, presenting: Presenting<'_>, host: &H) -> Result<Presentation, PresentError>;
}

/// What a claims format presents: the query, the credential's view, the elements the chosen
/// option discloses with their concrete paths (each once, in claim order), the transaction's
/// response members, and what binds the presentation to the request. Only the kit makes one,
/// for a credential the platform found usable.
#[cfg(feature = "resolve")]
#[non_exhaustive]
pub struct Presenting<'p> {
    /// The query.
    pub query: &'p ClaimsQuery<'p>,
    /// The credential and its view.
    pub view: &'p ClaimsView<'p>,
    /// The elements disclosed.
    pub disclosed: &'p [(ConcretePath<'p>, &'p Node<'p>)],
    /// The response members.
    pub members: &'p Members,
    /// The session.
    pub session: &'p Session<'p>,
}

/// What a claims format revalidates: the query, the credential's view, the response members the
/// transaction bound to the credential writes, and what binds the presentation to the request.
/// Only the kit makes one, for a credential the platform found usable.
#[cfg(feature = "resolve")]
#[non_exhaustive]
pub struct Revalidating<'r> {
    /// The query.
    pub query: &'r ClaimsQuery<'r>,
    /// The credential and its view.
    pub view: &'r ClaimsView<'r>,
    /// The response members the transaction writes.
    pub provided: &'r [Member],
    /// The session.
    pub session: &'r Session<'r>,
}

/// `Format::query` of a claims format: the query parsed by the kit, or the kit's request rules
/// it breaks followed by the format's.
pub fn query<'q, P: ClaimsPlugin>(
    plugin: &'q P,
    query: &'q Query<'q>,
    context: &QueryContext<'q>,
) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
    Ok(Box::new(PluginQuery::parse(
        plugin,
        query,
        context.naming(),
        context.supported().cloned(),
    )?))
}

/// `Format::additions` of a claims format: the types the format reads in the credential's view.
///
/// # Errors
///
/// The view is no claims view, or the format cannot read its types.
pub fn additions<'c>(
    format: &impl ClaimsFormat,
    credential: &'c Credential<'c>,
) -> Result<Box<dyn ViewAdditions + 'c>, Fault> {
    let view = ClaimsView::read(credential)?;
    let types = format.types(view.json())?;
    Ok(Box::new(ViewTypes::new(
        types.into_iter().map(CredentialType::into_owned).collect(),
    )))
}

/// `FormatHost::answer` of a claims format: the query parsed as [`query`] parses it, with its
/// phase 2 over the build's host.
#[cfg(feature = "resolve")]
pub fn answer<'q, H, P: ClaimsPresent<H>>(
    plugin: &'q P,
    query: &'q Query<'q>,
    context: AnsweredContext<'q>,
) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
    let context = context.context();
    Ok(Box::new(PluginQuery::parse(
        plugin,
        query,
        context.naming(),
        context.supported().cloned(),
    )?))
}

/// A Credential Query of a claims format, answering the core for its plug-in.
struct PluginQuery<'q, P> {
    plugin: &'q P,
    query: &'q Query<'q>,
    claims: ClaimsQuery<'q>,
}

impl<'q, P: ClaimsPlugin> PluginQuery<'q, P> {
    /// The query parsed by the kit, or the kit's request rules it breaks followed by the
    /// format's.
    fn parse(
        plugin: &'q P,
        query: &'q Query<'q>,
        naming: EntryNaming,
        supported: Option<Node<'q>>,
    ) -> Result<Self, AllOf<Refusal>> {
        let own = AllOf::new(plugin.rules(query, naming));
        match (ClaimsQuery::parse(plugin, query, supported), own) {
            (Ok(claims), None) => Ok(Self {
                plugin,
                query,
                claims,
            }),
            (Ok(_), Some(own)) => Err(own),
            (Err(refusals), None) => Err(refusals),
            (Err(refusals), Some(own)) => Err(refusals.and(own)),
        }
    }

    fn path_fault(credential: &Credential<'_>, error: PathError) -> Fault {
        Fault::caused(
            FAULT,
            detail!("{id}: values", id = credential.id.to_string()),
            error,
        )
    }
}

impl<P: ClaimsPlugin> FormatQuery for PluginQuery<'_, P> {
    fn options(&self) -> &Options {
        self.claims.claims().options()
    }

    /// The kit's rule over the identifiers the format gives; nothing to check when the Verifier
    /// states no `vp_formats_supported` value for the format.
    fn admits(
        &self,
        credential: &Credential<'_>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        if self.claims.supported().is_none() {
            return Ok(());
        }
        let view = ClaimsView::read(credential)?;
        let constraints = self.plugin.algorithms(&view, keys)?;
        Ok(self.claims.admits(self.plugin, &constraints)?)
    }

    fn answerable(
        &self,
        credential: &Credential<'_>,
        _env: &Env,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        let view = ClaimsView::read(credential)?;
        self.claims.answerable(self.plugin, view.json(), provided)
    }

    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<Carriage, Fault> {
        let view = ClaimsView::read(credential)?;
        self.plugin.carries(self.query, &view, members)
    }

    fn draw(
        &self,
        credential: &Credential<'_>,
        shown: Shown<'_>,
        env: &Env,
    ) -> Result<Card, Fault> {
        let view = ClaimsView::read(credential)?;
        self.claims
            .card(self.plugin, view.json(), shown, env)
            .map_err(|e| Self::path_fault(credential, e))
    }
}

#[cfg(feature = "resolve")]
impl<H, P: ClaimsPresent<H>> AnsweredQuery<H> for PluginQuery<'_, P> {
    fn choose<'a>(
        &'a self,
        credential: Usable<'a>,
        _env: &Env,
        provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault> {
        let view = ClaimsView::read(credential.credential())?;
        Ok(self
            .claims
            .answerable(self.plugin, view.json(), provided)?
            .into_iter()
            .map(|option| {
                Box::new(PluginOption {
                    query: self,
                    credential,
                    option,
                    provided: provided.to_vec(),
                }) as Box<dyn AnsweredOption<H> + 'a>
            })
            .collect())
    }
}

/// An answerable option of a claims format's query, for a usable credential, with the response
/// members the transaction bound to the credential writes.
#[cfg(feature = "resolve")]
struct PluginOption<'a, 'q, P> {
    query: &'a PluginQuery<'q, P>,
    credential: Usable<'a>,
    option: OptionIndex,
    provided: Vec<Member>,
}

#[cfg(feature = "resolve")]
impl<H, P: ClaimsPresent<H>> AnsweredOption<H> for PluginOption<'_, '_, P> {
    fn option(&self) -> OptionIndex {
        self.option
    }

    /// The format's revalidation. The kit's matching needs none: it reads the credential's view
    /// alone, which phase 2 derived again.
    fn revalidate(
        &self,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault> {
        let view = ClaimsView::read(self.credential.credential())?;
        self.query.plugin.revalidate(
            Revalidating {
                query: &self.query.claims,
                view: &view,
                provided: &self.provided,
                session,
            },
            host,
        )
    }

    fn present(
        &self,
        members: &Members,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Presentation, PresentError> {
        let credential = self.credential.credential();
        let view = ClaimsView::read(credential)?;
        let provided: Vec<Member> = members.names().cloned().collect();
        let disclosed = self
            .query
            .claims
            .disclosed(self.query.plugin, self.option, view.json(), &provided)
            .map_err(|e| PluginQuery::<P>::path_fault(credential, e))?;
        self.query.plugin.present(
            Presenting {
                query: &self.query.claims,
                view: &view,
                disclosed: &disclosed,
                members,
                session,
            },
            host,
        )
    }
}
