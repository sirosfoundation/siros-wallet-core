//! Phase 2's steps: the selection prepared with the resources its profiles want, then the
//! response built over the build's host once the caller has fetched them.

use std::ops::Range;

use siros_explain::AllOf;

use super::route::Route;
use super::selection::{check, derived};
use super::{
    AuthorizationResponse, Built, Finding, Outcome, ParameterBreach, RecordIndex, Rejection,
    ResponseMember, VpToken,
};
use crate::authenticate::Authenticated;
use crate::effects::{Fetch, Filled, Resource, Resources, Slots};
use crate::host::{
    AnsweredOption, AnsweredQuery, Authentication, AuthenticationNeed, Categories, CoreHost, Host,
    Platform, PresentError, Usable,
};
use crate::matching::{Accepted, EntryView, Match, ReturnedRecord, TransactionBinding, Views};
use crate::plugins::registry::{DynProfile, Placed};
use crate::plugins::{
    Answered, Attested, BoundEntries, Fault, FetchedRecord, Member, Members, OptionIndex,
    ProfileHandle, Registry,
};
use crate::refusal::Refused;
use crate::rendering::Rendering;
use crate::request::{ClientMetadata, Query, QueryIndex, Request};
use crate::routing::{AnsweredContext, Carries, EntryNaming, ModeName, QueryContext, Routing};
use crate::rows::Env;
use crate::session::Session;
use crate::wallet::{Credential, Wallet};
use crate::wallet_metadata::Placement;
use crate::{FAULT, detail};

/// A selection read from an authenticated request, its records derived and checked, each
/// record's query read for phase 2, and one slot per distinct resource each record's profile
/// revalidates with. Only [`Prepared::prepare`] makes one; [`Prepared::respond`] consumes it.
#[must_use]
pub struct Prepared<'p, H: CoreHost> {
    authenticated: &'p Authenticated<'p>,
    registry: &'p Registry<H>,
    env: &'p Env,
    request: Request<'p>,
    records: Vec<Picked<'p, H>>,
    resources: Slots<Resource>,
}

/// A derived record: its query, its option, the wallet's credential, and the transaction it
/// authorizes.
struct Picked<'p, H> {
    query: QueryIndex,
    option: OptionIndex,
    credential: &'p Credential<'p>,
    transacted: Option<Transacted<'p, H>>,
}

/// A record phase 2 answers: its query as its format read it for phase 2 under the accepted
/// mode, its option, the wallet's credential, and the transaction it authorizes.
struct Chosen<'r, 'p, H: CoreHost> {
    query: &'r Query<'r>,
    answered: Box<dyn AnsweredQuery<H> + 'r>,
    picked: &'r Picked<'p, H>,
}

/// A record's transaction: its profile with the profile's handle, the entries and display facts
/// the profile bound, how the presentation's format places the profile's members, and the slots
/// of the resources the profile wanted.
struct Transacted<'p, H> {
    handle: ProfileHandle,
    profile: &'p dyn DynProfile<H>,
    entries: BoundEntries,
    attested: Attested,
    placement: Option<Placement>,
    slots: Range<usize>,
}

impl<H> Transacted<'_, H> {
    /// The record as its profile reads it.
    fn answered<'a>(
        &'a self,
        request: &'a Request<'a>,
        credential: &'a Credential<'a>,
        mode: ModeName,
    ) -> Answered<'a> {
        Answered::of(
            request,
            credential,
            &self.entries,
            &self.attested,
            self.placement,
            mode,
        )
    }
}

/// A record its credential can still present, with the option its format answers it with.
struct Presenting<'a, 'r, 'p, H: CoreHost> {
    record: &'a Chosen<'r, 'p, H>,
    option: Box<dyn AnsweredOption<H> + 'a>,
}

impl<'p, H: CoreHost> Prepared<'p, H> {
    /// Phase 2's first step, from the ids the End-User chose, none when the request's every
    /// credential set is optional (§6.4.2): the request read from the authenticated envelope
    /// with its routing, its rules run again; every record derived with the matcher's code and
    /// checked as a selection; each record's query read through its format's
    /// [`FormatHost::answer`] under the accepted response mode; each record's profile names the
    /// resources it revalidates with over the host's modules, one slot each, in record order.
    /// `registry` is the one the envelope was read with; `rendering` the package of the wallet's
    /// live modules.
    ///
    /// # Errors
    ///
    /// The request refused, the ids no selection it allows, a record the wallet does not derive
    /// (Fallback), or a plug-in's fault.
    ///
    /// [`FormatHost::answer`]: crate::host::FormatHost::answer
    pub fn prepare(
        authenticated: &'p Authenticated<'p>,
        ids: &[&str],
        wallet: &'p Wallet<'p>,
        registry: &'p Registry<H>,
        env: &'p Env,
        rendering: &Rendering<'_>,
        host: &H,
    ) -> Result<Self, Outcome> {
        let request = Request::parse(authenticated.envelope())?;
        let mut questions = Vec::new();
        let records = {
            let accepted = Accepted::new(&request, registry)?;
            let returned = ids
                .iter()
                .map(|id| ReturnedRecord::parse(id))
                .collect::<Result<Vec<_>, _>>()
                .map_err(Rejection::from)?;
            let matched = Match::run(&accepted, wallet, env, rendering)?;
            let views = Views::of(&matched, env)?;
            let views = derived(&views, &returned)?;
            check(&accepted, &views)?;
            let read = Read::of(&request, registry, accepted.mode().name())?;
            let mut records = Vec::new();
            for view in views {
                let picked = picked(
                    &accepted,
                    registry,
                    &matched,
                    wallet,
                    view,
                    &mut questions,
                    host,
                )?;
                drop(read.chosen(&picked)?);
                records.push(picked);
            }
            records
        };
        Ok(Self {
            authenticated,
            registry,
            env,
            request,
            records,
            resources: Slots::of(questions),
        })
    }

    /// The resources the caller fetches, one per slot, in order.
    #[must_use]
    pub fn questions(&self) -> &[Resource] {
        self.resources.questions()
    }

    /// Phase 2's last step, in order: each record's query read again through its format's
    /// [`FormatHost::answer`]; `fetch` answers every resource of [`Prepared::questions`], once,
    /// in order; the route of the authenticated request ([`Route::new`]), whose answering mode's
    /// refusal (C7, or C6 for `client_metadata`) ends the step; under the route's session each
    /// credential checked usable, each record's profile revalidating with its own resources and
    /// each record's option with its format; the End-User authenticating at least as strongly as
    /// the strongest need of the records' profiles; the presentations bound to the session, the
    /// registered response parameters' members after `vp_token` and `state`, and the delivery
    /// through [`AnswerRoute::answer`](super::AnswerRoute::answer).
    ///
    /// # Errors
    ///
    /// The answering mode's refusal (C7, or C6), a finding (Fallback), the End-User
    /// unauthenticated or authenticated too weakly, a presentation that failed, or a plug-in's
    /// fault.
    ///
    /// [`FormatHost::answer`]: crate::host::FormatHost::answer
    pub fn respond(
        self,
        fetch: impl FnMut(&Resource) -> Fetch,
        host: &H,
    ) -> Result<Built<'p>, Outcome> {
        let Self {
            authenticated,
            registry,
            env,
            request,
            records,
            resources,
        } = self;
        let routing = authenticated.envelope().routing();
        let mode = routing
            .mode()
            .filter(|mode| mode.carries() == Carries::Answers)
            .ok_or_else(|| Fault::new(FAULT, detail!("an accepted request without its mode")))?
            .name();
        let read = Read::of(&request, registry, mode)?;
        let chosen = records
            .iter()
            .map(|picked| read.chosen(picked))
            .collect::<Result<Vec<_>, _>>()?;
        let filled = resources.fill(fetch);
        let (route, refusal) = Route::read(authenticated, registry, host)?;
        if let Some(refusal) = refusal {
            return Err(Outcome::Refused(Refused::one(refusal)));
        }
        let answering = route.answering().ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!("the route of an accepted request answers nothing"),
            )
        })?;
        let session = answering.session();
        let phase = Phase {
            request: &request,
            env,
            host,
            mode,
        };
        let presenting = phase.revalidate(&chosen, &filled, &session)?;
        let authentication = phase.authenticate(&chosen)?;
        let mut vp_token = VpToken::default();
        for Presenting { record, option } in &presenting {
            let members = phase.members(record, &authentication)?;
            let presentation =
                option
                    .present(&members, &session, host)
                    .map_err(|failed| match failed {
                        PresentError::Fault(fault) => Outcome::Fault(fault),
                        PresentError::Failed { reason } => Outcome::NotPresented(reason),
                    })?;
            vp_token.push(&record.query.id, presentation);
        }
        let members = parameters(registry, routing, &session, host)?;
        let response = AuthorizationResponse::of(vp_token, routing.state(), members);
        let delivery = answering.answer(&response, host)?;
        Ok(Built::of(response, delivery))
    }
}

/// The registered response parameters' members, in registration order, each of a name the
/// registry checked for its part, each name once.
fn parameters<H: CoreHost>(
    registry: &Registry<H>,
    routing: &Routing<'_>,
    session: &Session<'_>,
    host: &H,
) -> Result<Vec<ResponseMember>, Fault> {
    let response_type = routing
        .response_type()
        .ok_or_else(|| Fault::new(FAULT, detail!("an accepted request without its type")))?;
    let mut members: Vec<ResponseMember> = Vec::new();
    for registered in registry.response_parameters() {
        for member in registered.part().members(response_type, session, host)? {
            let name = member.name();
            let breach = if !registered.names().contains(&name) {
                Some(ParameterBreach::Undeclared)
            } else if members.iter().any(|written| written.name() == name) {
                Some(ParameterBreach::Twice)
            } else {
                None
            };
            if let Some(breach) = breach {
                return Err(Fault::caused(
                    FAULT,
                    detail!("the response parameter {name}"),
                    breach,
                ));
            }
            members.push(member);
        }
    }
    Ok(members)
}

/// What reading a record's query for phase 2 takes: the request, its metadata, the registry and
/// the accepted mode.
struct Read<'r, 'p, H: CoreHost> {
    request: &'r Request<'r>,
    metadata: &'r ClientMetadata<'r>,
    registry: &'p Registry<H>,
    mode: ModeName,
}

impl<'r, 'p: 'r, H: CoreHost> Read<'r, 'p, H> {
    fn of(
        request: &'r Request<'r>,
        registry: &'p Registry<H>,
        mode: ModeName,
    ) -> Result<Self, Fault> {
        let metadata = request.envelope().client_metadata().map_err(|e| {
            Fault::caused(
                FAULT,
                detail!("an accepted request's client_metadata"),
                e.clone(),
            )
        })?;
        Ok(Self {
            request,
            metadata,
            registry,
            mode,
        })
    }

    /// The record with its query read through its format's phase 2 under the accepted mode.
    fn chosen<'a>(&self, picked: &'a Picked<'p, H>) -> Result<Chosen<'a, 'p, H>, Outcome>
    where
        'r: 'a,
    {
        let request = self.request;
        let query = request
            .query(picked.query)
            .ok_or_else(|| Fault::new(FAULT, detail!("a record names no query")))?;
        let Placed { format, .. } = self
            .registry
            .placed_host(&query.format)
            .ok_or_else(|| Fault::new(FAULT, detail!("a record's query has no format")))?;
        let context = AnsweredContext::of(
            QueryContext::of(
                request,
                Some(self.mode),
                EntryNaming::of(request.entry_named(), picked.query),
                self.metadata.vp_formats(&query.format).cloned(),
            ),
            self.mode,
        );
        let answered = format
            .answer(query, context)
            .map_err(|refusals| Outcome::Refused(Refused::all(refusals)))?;
        Ok(Chosen {
            query,
            answered,
            picked,
        })
    }
}

/// A derived record as phase 2 answers it: the wallet's credential, its query and option, and
/// for a transaction its profile's binding with the resources the profile wants over the host's
/// modules, one per distinct URL, appended to `questions`.
fn picked<'p, H: CoreHost>(
    accepted: &Accepted<'_>,
    registry: &'p Registry<H>,
    matched: &Match<'_>,
    wallet: &'p Wallet<'p>,
    view: &EntryView<'_>,
    questions: &mut Vec<Resource>,
    host: &H,
) -> Result<Picked<'p, H>, Outcome> {
    let request = accepted.request();
    let candidate = matched
        .candidate(view.pick.query, view.pick.candidate)
        .ok_or_else(|| Fault::new(FAULT, detail!("a record names no candidate")))?;
    let credential = wallet
        .credentials()
        .iter()
        .find(|credential| credential.id == candidate.credential.id)
        .ok_or_else(|| Fault::new(FAULT, detail!("a candidate the wallet does not hold")))?;
    let query = request
        .query(view.pick.query)
        .ok_or_else(|| Fault::new(FAULT, detail!("a record names no query")))?;
    let Placed { placement, .. } = registry
        .placed_host(&query.format)
        .ok_or_else(|| Fault::new(FAULT, detail!("a record's query has no format")))?;
    let transacted = match &candidate.bound {
        Some(TransactionBinding { transaction, bound }) => {
            let profile = registry
                .profile_host(transaction.profile)
                .ok_or_else(|| Fault::new(FAULT, detail!("a transaction has no profile")))?;
            let wanted = profile.wanted(
                Answered::of(
                    request,
                    credential,
                    &bound.entries,
                    &bound.attested,
                    placement,
                    accepted.mode().name(),
                ),
                host,
            )?;
            let start = questions.len();
            questions.extend(Resource::distinct(wanted));
            Some(Transacted {
                handle: transaction.profile,
                profile,
                entries: bound.entries.clone(),
                attested: bound.attested.clone(),
                placement,
                slots: start..questions.len(),
            })
        }
        None => None,
    };
    Ok(Picked {
        query: view.pick.query,
        option: view.pick.option,
        credential,
        transacted,
    })
}

/// What `respond`'s steps read: the request, the configuration, the host and the accepted mode.
struct Phase<'a, 'r, H> {
    request: &'r Request<'r>,
    env: &'a Env,
    host: &'a H,
    mode: ModeName,
}

impl<'a, 'r: 'a, H: CoreHost> Phase<'a, 'r, H> {
    /// What the matcher could not check, checked now: each credential can still be presented,
    /// each record's profile revalidates what it assumed with the resources it wanted, and each
    /// record's option what its format assumed. Fallback with every finding.
    fn revalidate<'p: 'a>(
        &self,
        records: &'a [Chosen<'r, 'p, H>],
        filled: &Filled<Resource>,
        session: &Session<'_>,
    ) -> Result<Vec<Presenting<'a, 'r, 'p, H>>, Outcome> {
        let mut findings = Vec::new();
        let mut presenting = Vec::new();
        for (position, record) in records.iter().enumerate() {
            let position = RecordIndex(position);
            let credential = record.picked.credential;
            let Some(credential) = self.host.get::<dyn Platform>().usable(credential) else {
                findings.push(Finding::Unusable { record: position });
                continue;
            };
            if let Some(finding) = self.profile_finding(record.picked, filled, position)? {
                findings.push(finding);
            }
            let option = self.option(record, credential)?;
            if let Some(finding) = option.revalidate(session, self.host)? {
                findings.push(Finding::Format {
                    record: position,
                    finding,
                });
            }
            presenting.push(Presenting { record, option });
        }
        AllOf::new(findings).map_or(Ok(presenting), |findings| Err(Outcome::Fallback(findings)))
    }

    /// The record's profile's finding with the resources it wanted; none without a transaction.
    fn profile_finding(
        &self,
        picked: &Picked<'_, H>,
        filled: &Filled<Resource>,
        position: RecordIndex,
    ) -> Result<Option<Finding>, Fault> {
        let Some(transacted) = &picked.transacted else {
            return Ok(None);
        };
        let own = filled
            .replies()
            .get(transacted.slots.clone())
            .ok_or_else(|| Fault::new(FAULT, detail!("a record's slots the step lacks")))?;
        let fetched = FetchedRecord::of(
            transacted.answered(self.request, picked.credential, self.mode),
            Resources::of(own),
        );
        Ok(transacted
            .profile
            .revalidate(transacted.handle, fetched, self.host)?
            .map(|finding| Finding::Revalidation {
                record: position,
                finding,
            }))
    }

    /// The record's option as its format answers it for the usable credential.
    fn option<'p>(
        &self,
        record: &'a Chosen<'r, 'p, H>,
        credential: Usable<'a>,
    ) -> Result<Box<dyn AnsweredOption<H> + 'a>, Fault> {
        let provided: Vec<Member> = match &record.picked.transacted {
            Some(transacted) => transacted
                .placement
                .and_then(|placement| transacted.profile.members(placement))
                .unwrap_or(&[])
                .to_vec(),
            None => Vec::new(),
        };
        record
            .answered
            .choose(credential, self.env, &provided)?
            .into_iter()
            .find(|option| option.option() == record.picked.option)
            .ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("a record's option its format no longer answers"),
                )
            })
    }

    /// The End-User's authentication, at least as strong as the strongest need of the records'
    /// profiles; refused when the platform's is weaker.
    fn authenticate(&self, records: &[Chosen<'r, '_, H>]) -> Result<Authentication, Outcome> {
        let need = records
            .iter()
            .filter_map(|record| {
                record
                    .picked
                    .transacted
                    .as_ref()
                    .map(|transacted| (record.picked, transacted))
            })
            .map(|(picked, transacted)| {
                transacted.profile.authentication(transacted.answered(
                    self.request,
                    picked.credential,
                    self.mode,
                ))
            })
            .try_fold(AuthenticationNeed::Presence, |strongest, need| {
                need.map(|need| strongest.max(need))
            })?;
        let authentication = self
            .host
            .get::<dyn Platform>()
            .authenticate(need)
            .ok_or(Outcome::UserUnauthenticated)?;
        let covered = Categories::of(&authentication);
        if need.met_by(covered) {
            Ok(authentication)
        } else {
            Err(Outcome::AuthenticationTooWeak { need, covered })
        }
    }

    /// The response members the record's profile writes, each one the profile declares for the
    /// format; none without a transaction.
    fn members(
        &self,
        record: &Chosen<'r, '_, H>,
        authentication: &Authentication,
    ) -> Result<Members, Outcome> {
        let Some(transacted) = &record.picked.transacted else {
            return Ok(Members::none());
        };
        let profile = transacted.profile;
        let members = profile.respond(
            transacted.answered(self.request, record.picked.credential, self.mode),
            self.host,
            authentication,
        )?;
        let declared = transacted
            .placement
            .and_then(|placement| profile.members(placement))
            .unwrap_or(&[]);
        if let Some(extra) = members.names().find(|member| !declared.contains(member)) {
            return Err(Fault::caused(
                FAULT,
                detail!(
                    "a profile wrote {extra}, which it does not declare",
                    extra = extra.clone()
                ),
                ParameterBreach::Undeclared,
            )
            .into());
        }
        Ok(members)
    }
}
