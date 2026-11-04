//! Phase 2's steps: the selection prepared with the resources its profiles want, then the
//! response built over the build's host once the caller has fetched them.

use std::ops::Range;

use siros_explain::AllOf;

use super::selection::{check, derived};
use super::{Finding, Outcome, Rejection, Response, ResponseData, RouteKey, VpToken};
use crate::effects::{Fetch, Filled, Resource, Resources, Slots};
use crate::envelope::Channel;
use crate::host::{
    AnsweredOption, AnsweredQuery, Authentication, AuthenticationNeed, Categories, CoreHost, Haip,
    Host, Platform, PresentError, Usable,
};
use crate::matching::{Accepted, EntryView, Match, ReturnedRecord, Views};
use crate::plugins::registry::{DynProfile, Placed, Role};
use crate::plugins::{
    Answered, Attested, BoundEntries, Fault, FetchedRecord, Member, Members, OptionIndex,
    ProfileHandle, Registry,
};
use crate::refusal::Refused;
use crate::request::{Agreements, Query, Request};
use crate::routing::{AnsweredContext, Encrypting, ModeName, QueryContext, VerifierMetadata};
use crate::rows::Env;
use crate::session::{Session, SessionBinding};
use crate::wallet::{Credential, Wallet};
use crate::wallet_metadata::Placement;
use crate::{FAULT, detail};

/// A selection read, its records derived and checked, each record's query read for phase 2,
/// and one slot per distinct resource each record's profile revalidates with. Only
/// [`Prepared::prepare`] makes one; [`Prepared::respond`] consumes it.
#[must_use]
pub struct Prepared<'p, H> {
    accepted: Accepted<'p>,
    registry: &'p Registry<H>,
    env: &'p Env,
    records: Vec<Chosen<'p, H>>,
    resources: Slots<Resource>,
}

/// A record phase 2 answers: its query as its format read it for phase 2, its option, the
/// wallet's credential, and the transaction it authorizes.
struct Chosen<'p, H> {
    query: &'p Query<'p>,
    answered: Box<dyn AnsweredQuery<H> + 'p>,
    option: OptionIndex,
    credential: &'p Credential<'p>,
    transacted: Option<Transacted<'p, H>>,
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
struct Presenting<'a, 'p, H> {
    record: &'a Chosen<'p, H>,
    option: Box<dyn AnsweredOption<H> + 'a>,
}

impl<'p, H: CoreHost> Prepared<'p, H> {
    /// Phase 2's first step, from the ids the platform returned; `wallet`, `registry` and
    /// `env` the data and configuration the wallet registered. The request's rules run again;
    /// every record is derived with the matcher's code and checked as a selection; each
    /// record's query is read through its format's [`FormatHost::answer`] under the accepted
    /// response mode; each record's profile names the resources it revalidates with, one slot
    /// each, in record order.
    ///
    /// # Errors
    ///
    /// The request refused, the ids no selection it allows, a record the wallet does not derive
    /// (Fallback), or a plug-in's fault.
    ///
    /// [`FormatHost::answer`]: crate::host::FormatHost::answer
    pub fn prepare(
        request: &'p Request<'p>,
        ids: &[&str],
        wallet: &'p Wallet<'p>,
        registry: &'p Registry<H>,
        env: &'p Env,
    ) -> Result<Self, Outcome> {
        let accepted = Accepted::new(request, registry)?;
        let returned = ids
            .iter()
            .map(|id| ReturnedRecord::parse(id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Rejection::from)?;
        let mut questions = Vec::new();
        let records = {
            let matched = Match::run(&accepted, wallet, env)?;
            let views = Views::of(&matched, env)?;
            let views = derived(&views, &returned)?;
            check(&accepted, &views)?;
            views
                .iter()
                .map(|view| chosen(&accepted, registry, &matched, wallet, view, &mut questions))
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(Self {
            accepted,
            registry,
            env,
            records,
            resources: Slots::of(questions),
        })
    }

    /// The resources the caller fetches, one per slot, in order.
    #[must_use]
    pub fn questions(&self) -> &[Resource] {
        self.resources.questions()
    }

    /// Phase 2's last step: `fetch` answers every resource of [`Prepared::questions`], once, in
    /// order; each credential is checked usable, each record's profile revalidates with its own
    /// resources and each record's option with its format; the End-User authenticates at least
    /// as strongly as the strongest need of the records' profiles; the presentations are made
    /// and the response encrypted under the request's mode.
    ///
    /// # Errors
    ///
    /// A finding (Fallback), the End-User unauthenticated or authenticated too weakly, a
    /// presentation that failed, or a plug-in's fault.
    pub fn respond(
        self,
        fetch: impl FnMut(&Resource) -> Fetch,
        host: &H,
    ) -> Result<Response, Outcome> {
        let Self {
            accepted,
            registry,
            env,
            records,
            resources,
        } = self;
        let request = accepted.request();
        let metadata = VerifierMetadata::of(accepted.metadata());
        let mode = accepted.mode().name();
        let sealing = seal(registry, &accepted, &metadata, host)?;
        let filled = resources.fill(fetch);
        let binding = match request.envelope().channel() {
            Channel::DcApi(origin) => SessionBinding::DcApi { origin },
            Channel::Uri => {
                return Err(Fault::new(
                    FAULT,
                    detail!("a URI request reaches phase 2 through its route, which the response side builds"),
                )
                .into());
            }
        };
        let session = Session::of(
            binding,
            request.nonce(),
            sealing.as_ref().map(|sealing| sealing.key),
            metadata.keys(),
        );
        let phase = Phase {
            request,
            env,
            host,
            mode,
        };
        let presenting = phase.revalidate(&records, &filled, &session)?;
        let authentication = phase.authenticate(&records)?;
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
        let plaintext = vp_token.data();
        let data = match sealing {
            None => ResponseData::Plain(plaintext),
            Some(Sealing { haip, key }) => ResponseData::Encrypted(haip.encrypt_jwe(
                key.key(),
                key.enc(),
                plaintext.as_bytes(),
            )?),
        };
        Ok(Response { vp_token, data })
    }
}

/// What a JWE mode's route seals the answer with: the host's `Haip`, and the key the mode chose
/// among the request's with the content encryption, as the core checked them.
struct Sealing<'k, 'h> {
    haip: &'h dyn Haip,
    key: RouteKey<'k>,
}

/// The route of the mode the request's routing accepted, as its registration seals it: `None`
/// in the clear; for a JWE mode, the key and `enc` the mode's key rule chooses under the host's
/// `Haip::agreements`, refused with the mode's rule when the statement admits none. A route
/// that breaks its registration (a key in the clear, no key for a JWE mode, a key or `enc` the
/// statement does not admit, an error mode routing an answer) is a `Fault`.
fn seal<'k, 'h, H>(
    registry: &Registry<H>,
    accepted: &Accepted<'_>,
    metadata: &'k VerifierMetadata<'k>,
    host: &'h H,
) -> Result<Option<Sealing<'k, 'h>>, Outcome> {
    let routed = accepted.mode();
    let registered = registry
        .mode_host(routed.handle())
        .filter(|registered| registered.mode.name() == routed.name())
        .ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!("the request's mode is none the registry holds"),
            )
        })?;
    let (sealer, haip) = match &registered.role {
        Role::Clear => (Agreements::NONE, None),
        Role::Jwe(access) => {
            let haip = access(host);
            (haip.agreements(), Some(haip))
        }
        Role::Errors => {
            return Err(Fault::new(
                FAULT,
                detail!("a mode that carries errors routed an answer"),
            )
            .into());
        }
    };
    let encrypting = registered
        .mode
        .encryption(metadata, &sealer, host)
        .map_err(|refusal| Outcome::Refused(Refused::one(refusal)))?;
    match (encrypting, haip) {
        (Encrypting::Plain, None) => Ok(None),
        (Encrypting::Jwe { key, enc }, Some(haip)) => {
            let stated = key
                .key()
                .alg()
                .is_some_and(|alg| sealer.admits(key.key().curve(), alg, enc));
            if stated && metadata.lists(enc) {
                Ok(Some(Sealing {
                    haip,
                    key: RouteKey::of(key, enc),
                }))
            } else {
                Err(Fault::new(
                    FAULT,
                    detail!("a mode chose a key or an enc the sealing module does not state, or an enc the Verifier does not list"),
                )
                .into())
            }
        }
        (Encrypting::Jwe { .. }, None) => {
            Err(Fault::new(FAULT, detail!("a mode in the clear chose a key")).into())
        }
        (Encrypting::Plain, Some(_)) => {
            Err(Fault::new(FAULT, detail!("a JWE mode chose no key")).into())
        }
    }
}

/// A derived record as phase 2 answers it: the wallet's credential, its query read for phase 2,
/// and for a transaction its profile's binding with the resources the profile wants, one per
/// distinct URL, appended to `questions`.
fn chosen<'p, H>(
    accepted: &Accepted<'p>,
    registry: &'p Registry<H>,
    matched: &Match<'_>,
    wallet: &'p Wallet<'p>,
    view: &EntryView<'_>,
    questions: &mut Vec<Resource>,
) -> Result<Chosen<'p, H>, Outcome> {
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
    let Placed { format, placement } = registry
        .placed_host(&query.format)
        .ok_or_else(|| Fault::new(FAULT, detail!("a record's query has no format")))?;
    let context = AnsweredContext::of(
        QueryContext::of(
            request,
            Some(accepted.mode().name()),
            request.entry_named().contains(view.pick.query),
            accepted.metadata().vp_formats(&query.format).cloned(),
        ),
        accepted.mode().name(),
    );
    let answered = format
        .answer(query, context)
        .map_err(|refusals| Outcome::Refused(Refused::all(refusals)))?;
    let transacted = match (&candidate.bound, accepted.transaction(view.pick.query)) {
        (Some(bound), Some(transaction)) => {
            let profile = registry
                .profile_host(transaction.profile)
                .ok_or_else(|| Fault::new(FAULT, detail!("a transaction has no profile")))?;
            let wanted = profile.wanted(Answered::of(
                request,
                credential,
                &bound.entries,
                &bound.attested,
                placement,
                accepted.mode().name(),
            ))?;
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
        _ => None,
    };
    Ok(Chosen {
        query,
        answered,
        option: view.pick.option,
        credential,
        transacted,
    })
}

/// What `respond`'s steps read: the request, the configuration, the host and the accepted mode.
struct Phase<'a, 'p, H> {
    request: &'p Request<'p>,
    env: &'p Env,
    host: &'a H,
    mode: ModeName,
}

impl<'a, 'p: 'a, H: CoreHost> Phase<'a, 'p, H> {
    /// What the matcher could not check, checked now: each credential can still be presented,
    /// each record's profile revalidates what it assumed with the resources it wanted, and each
    /// record's option what its format assumed. Fallback with every finding.
    fn revalidate(
        &self,
        records: &'a [Chosen<'p, H>],
        filled: &Filled<Resource>,
        session: &Session<'_>,
    ) -> Result<Vec<Presenting<'a, 'p, H>>, Outcome> {
        let mut findings = Vec::new();
        let mut presenting = Vec::new();
        for (position, record) in records.iter().enumerate() {
            let Some(credential) = self.host.get::<dyn Platform>().usable(record.credential) else {
                findings.push(Finding::Unusable { record: position });
                continue;
            };
            if let Some(finding) = self.profile_finding(record, filled, position)? {
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
        record: &Chosen<'p, H>,
        filled: &Filled<Resource>,
        position: usize,
    ) -> Result<Option<Finding>, Fault> {
        let Some(transacted) = &record.transacted else {
            return Ok(None);
        };
        let own = filled
            .replies()
            .get(transacted.slots.clone())
            .ok_or_else(|| Fault::new(FAULT, detail!("a record's slots the step lacks")))?;
        let fetched = FetchedRecord::of(
            transacted.answered(self.request, record.credential, self.mode),
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
    fn option(
        &self,
        record: &'a Chosen<'p, H>,
        credential: Usable<'a>,
    ) -> Result<Box<dyn AnsweredOption<H> + 'a>, Fault> {
        let provided: Vec<Member> = match &record.transacted {
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
            .find(|option| option.option() == record.option)
            .ok_or_else(|| {
                Fault::new(
                    FAULT,
                    detail!("a record's option its format no longer answers"),
                )
            })
    }

    /// The End-User's authentication, at least as strong as the strongest need of the records'
    /// profiles; refused when the platform's is weaker.
    fn authenticate(&self, records: &[Chosen<'p, H>]) -> Result<Authentication, Outcome> {
        let need = records
            .iter()
            .filter_map(|record| {
                record
                    .transacted
                    .as_ref()
                    .map(|transacted| (record, transacted))
            })
            .map(|(record, transacted)| {
                transacted.profile.authentication(transacted.answered(
                    self.request,
                    record.credential,
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
        record: &Chosen<'p, H>,
        authentication: &Authentication,
    ) -> Result<Members, Outcome> {
        let Some(transacted) = &record.transacted else {
            return Ok(Members::none());
        };
        let profile = transacted.profile;
        let members = profile.respond(
            transacted.answered(self.request, record.credential, self.mode),
            self.host,
            authentication,
        )?;
        let declared = transacted
            .placement
            .and_then(|placement| profile.members(placement))
            .unwrap_or(&[]);
        if let Some(extra) = members.names().find(|member| !declared.contains(member)) {
            return Err(Fault::new(
                FAULT,
                detail!(
                    "a profile wrote {extra}, which it does not declare",
                    extra = extra.clone()
                ),
            )
            .into());
        }
        Ok(members)
    }
}
