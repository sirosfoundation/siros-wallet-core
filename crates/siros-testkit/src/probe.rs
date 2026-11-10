//! Probes: a [`Format`] ([`ProbeFormat`]) and a [`Profile`] ([`ProfileProbe`]) registered with the
//! core alongside the doubles, each handing a test's closure what the core's flow gives a plug-in
//! and stopping the flow there: [`read_query`] a query's [`QueryContext`], [`read_phase_two`] a
//! query's [`AnsweredContext`] with the route's [`Session`], [`read_record`] a record's
//! [`FetchedRecord`]. [`read_parsed`] hands the closure a format's reading of a query.
//! [`read_session`] and [`read_redirect_session`] run the route alone; [`dc_api`] and
//! [`sealed_to_b26`] make what a route takes.
//!
//! A plug-in the registry stores is `'static`, so a closure owns what it reads. Each runs on the
//! calling thread, the one that makes the core's call.

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use siros_i18n::Context;
use siros_openid4vp::arrival::Received;
use siros_openid4vp::consent::Card;
use siros_openid4vp::detail;
use siros_openid4vp::effects::{Fetch, Resource};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::host::{
    AnsweredContext, AnsweredOption, AnsweredQuery, Authentication, AuthenticationNeed, CoreHost,
    FormatHost, Haip, Has, PresentError, Presentation, ProfileHost, Usable,
};
use siros_openid4vp::ids::{FormatId, InvalidId};
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::matching::Accepted;
use siros_openid4vp::plugins::{
    Answered, Binding, Bound, Build, Carriage, Fault, FetchedRecord, FindingData, Format,
    FormatQuery, HostedErrorMode, HostedMode, Member, Members, NoCandidate, NoHost, OptionIndex,
    OptionItems, Options, Profile, Registry, RegistryBuilder, Shown, ViewAdditions, ViewTypes,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{AgreeableKey, ContentEncryption, EntryIndex, Query, Request};
use siros_openid4vp::resolve::{Prepared, Route};
use siros_openid4vp::routing::{ChannelKind, ModeName, QueryContext, VpToken};
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::session::Session;
use siros_openid4vp::uri::{Fetch as UriFetch, FetchAnswer};
use siros_openid4vp::wallet::{Credential, Wallet};
use siros_openid4vp::wallet_metadata::Placement;
use siros_syntax::AllOf;

use crate::fixtures::{
    FixtureError, Held, REQUEST_OBJECT_HEADER, authenticate, env, first_selection,
};
use crate::format::{DoubleText, resolve};
use crate::jose::{VERIFIER_SECRET, compact_jws};
use crate::prefix::{NamedPrefix, TestPrefix};
use crate::render::Language;
use crate::{TestChoice, TestHost, TestMode, fault};

thread_local! {
    /// The closure the probes run next.
    static READ: Cell<Option<Box<dyn Any>>> = const { Cell::new(None) };
}

/// The armed closure, which a flow that ends without reaching its probe leaves for no other.
struct Armed;

impl Armed {
    fn with(read: impl Any) -> Self {
        arm(read);
        Self
    }
}

/// Makes `read` the closure the probes run next.
fn arm(read: impl Any) {
    READ.set(Some(Box::new(read)));
}

impl Drop for Armed {
    fn drop(&mut self) {
        drop(READ.take());
    }
}

/// The closure of the stage `T` when one is armed.
fn armed<T: Any>() -> Option<T> {
    let held = READ.take()?;
    match held.downcast::<T>() {
        Ok(read) => Some(*read),
        Err(other) => {
            READ.set(Some(other));
            None
        }
    }
}

/// The fault that stops a flow at its probe.
fn stopped() -> Fault {
    fault(detail!("the flow stopped at its probe"))
}

/// What a closure returned, or why the flow never reached it.
fn result<R>(
    out: &Rc<Cell<Option<R>>>,
    reached: impl FnOnce() -> String,
) -> Result<R, FixtureError> {
    out.take().ok_or_else(|| FixtureError::Rejected(reached()))
}

/// A closure over a query and its context.
type ReadsQuery = dyn for<'q> FnOnce(&'q Query<'q>, QueryContext<'q>);

/// A closure over what phase 2 gives a format.
type ReadsPhaseTwo<H> = dyn for<'a> FnOnce(PhaseTwo<'a, H>);

/// A closure over a record phase 2 revalidates.
type ReadsRecord<H> = dyn for<'a> FnOnce(FetchedRecord<'a>, &'a H);

/// [`read_query`]'s closure and the query it reads.
struct QueryRead {
    query: String,
    read: Box<ReadsQuery>,
}

/// [`read_phase_two`]'s closure.
struct PhaseTwoRead<H: 'static>(Box<ReadsPhaseTwo<H>>);

/// [`read_record`]'s closure.
struct RecordRead<H: 'static>(Box<ReadsRecord<H>>);

/// What phase 2 gives a format: a query with the context the core read it in, and the session
/// and host its option revalidates under.
pub struct PhaseTwo<'a, H> {
    /// The query.
    pub query: &'a Query<'a>,
    /// The context the core read it in.
    pub context: AnsweredContext<'a>,
    /// The session the route binds.
    pub session: &'a Session<'a>,
    /// The host the flow runs over.
    pub host: &'a H,
}

/// A format of the identifier and placement given: a query of it has one option of no item, which
/// every credential answers, and its card holds no row.
#[derive(Debug, Clone)]
pub struct ProbeFormat {
    id: FormatId<'static>,
    placement: Option<Placement>,
}

impl ProbeFormat {
    /// The format.
    ///
    /// # Errors
    ///
    /// `id` is no format identifier.
    pub fn new(id: &str, placement: Option<Placement>) -> Result<Self, InvalidId> {
        Ok(Self {
            id: FormatId::parse(id.to_owned())?,
            placement,
        })
    }
}

impl Format for ProbeFormat {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    fn reserved(&self) -> &[Member] {
        &[]
    }

    fn wallet_formats(&self) -> Result<Node<'static>, Fault> {
        Ok(Node::Object(Object::default()))
    }

    fn placement(&self) -> Option<Placement> {
        self.placement
    }

    fn additions<'c>(
        &self,
        _credential: &'c Credential<'c>,
    ) -> Result<Box<dyn ViewAdditions + 'c>, Fault> {
        Ok(Box::new(ViewTypes::new(Vec::new())))
    }

    /// Runs [`read_query`]'s closure when `query` is the one it reads.
    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        if let Some(armed) = armed::<QueryRead>() {
            if armed.query == query.id().as_str() {
                (armed.read)(query, context);
            } else {
                arm(armed);
            }
        }
        Ok(Box::new(ProbeQuery::new()))
    }
}

impl<H: 'static> FormatHost<H> for ProbeFormat {
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        Ok(Box::new(Answering {
            reading: ProbeQuery::new(),
            query,
            context,
        }))
    }
}

/// A query of [`ProbeFormat`].
struct ProbeQuery {
    options: Options,
}

impl ProbeQuery {
    fn new() -> Self {
        Self {
            options: Options::new(vec![OptionItems::new(Vec::new())]),
        }
    }
}

impl FormatQuery for ProbeQuery {
    fn options(&self) -> &Options {
        &self.options
    }

    fn admits(
        &self,
        _credential: &Credential<'_>,
        _keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        Ok(())
    }

    fn answerable(
        &self,
        _credential: &Credential<'_>,
        _env: &Env,
        _provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        Ok(self.options.indexed().map(|(index, _)| index).collect())
    }

    fn carries(
        &self,
        _credential: &Credential<'_>,
        _members: &[Member],
    ) -> Result<Carriage, Fault> {
        Ok(Carriage::Carried)
    }

    fn displayable(
        &self,
        _credential: &Credential<'_>,
        _options: &[OptionIndex],
        _env: &Env,
    ) -> Result<(), NoCandidate> {
        Ok(())
    }

    /// The credential's id as the title.
    fn draw(
        &self,
        credential: &Credential<'_>,
        _shown: Shown<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Card, Fault> {
        Ok(Card {
            icon: env.icon(None).clone(),
            title: resolve(context, &DoubleText::written(credential.id.as_str()))?,
            subtitle: None,
            rows: Vec::new(),
        })
    }
}

/// A query of [`ProbeFormat`] as phase 2 reads it.
struct Answering<'q> {
    reading: ProbeQuery,
    query: &'q Query<'q>,
    context: AnsweredContext<'q>,
}

impl FormatQuery for Answering<'_> {
    fn options(&self) -> &Options {
        self.reading.options()
    }

    fn admits(
        &self,
        credential: &Credential<'_>,
        keys: &[AgreeableKey<'_>],
    ) -> Result<(), NoCandidate> {
        self.reading.admits(credential, keys)
    }

    fn answerable(
        &self,
        credential: &Credential<'_>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<OptionIndex>, Fault> {
        self.reading.answerable(credential, env, provided)
    }

    fn carries(&self, credential: &Credential<'_>, members: &[Member]) -> Result<Carriage, Fault> {
        self.reading.carries(credential, members)
    }

    fn displayable(
        &self,
        credential: &Credential<'_>,
        options: &[OptionIndex],
        env: &Env,
    ) -> Result<(), NoCandidate> {
        self.reading.displayable(credential, options, env)
    }

    fn draw(
        &self,
        credential: &Credential<'_>,
        shown: Shown<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Card, Fault> {
        self.reading.draw(credential, shown, env, context)
    }
}

impl<H: 'static> AnsweredQuery<H> for Answering<'_> {
    fn choose<'a>(
        &'a self,
        _credential: Usable<'a>,
        _env: &Env,
        _provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault> {
        Ok(self
            .reading
            .options
            .indexed()
            .map(|(option, _)| {
                Box::new(AnsweringOption {
                    option,
                    query: self.query,
                    context: &self.context,
                }) as Box<dyn AnsweredOption<H> + 'a>
            })
            .collect())
    }
}

/// The option of an [`Answering`] query.
struct AnsweringOption<'a, 'q> {
    option: OptionIndex,
    query: &'q Query<'q>,
    context: &'a AnsweredContext<'q>,
}

impl<H: 'static> AnsweredOption<H> for AnsweringOption<'_, '_> {
    fn option(&self) -> OptionIndex {
        self.option
    }

    /// Runs [`read_phase_two`]'s closure, the flow's last step.
    fn revalidate(
        &self,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault> {
        let PhaseTwoRead(read) = armed::<PhaseTwoRead<H>>()
            .ok_or_else(|| fault(detail!("a probe's phase 2 without a closure")))?;
        read(PhaseTwo {
            query: self.query,
            context: self.context.clone(),
            session,
            host,
        });
        Err(stopped())
    }

    fn present(
        &self,
        _members: &Members,
        _session: &Session<'_>,
        _host: &H,
    ) -> Result<Presentation, PresentError> {
        Err(stopped().into())
    }
}

/// A profile as `P`, whose revalidation hands the record to [`read_record`]'s closure when one is
/// armed.
#[derive(Debug, Clone)]
pub struct ProfileProbe<P>(pub P);

impl<P: Profile> Profile for ProfileProbe<P> {
    type Finding = P::Finding;

    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        self.0.refusals(request, entries)
    }

    fn members(&self, placement: Placement) -> Option<&[Member]> {
        self.0.members(placement)
    }

    fn bind(
        &self,
        binding: Binding<'_>,
        env: &Env,
        context: &Context,
    ) -> Result<Bound, NoCandidate> {
        self.0.bind(binding, env, context)
    }
}

impl<H: 'static, P: ProfileHost<H>> ProfileHost<H> for ProfileProbe<P> {
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        self.0.wanted(record, host)
    }

    fn informed(&self, findings: &[&Self::Finding]) -> Self {
        Self(self.0.informed(findings))
    }

    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        self.0.authentication(record)
    }

    fn revalidate(
        &self,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<Self::Finding>, Fault> {
        match armed::<RecordRead<H>>() {
            Some(RecordRead(read)) => {
                read(record, host);
                Err(stopped())
            }
            None => self.0.revalidate(record, host),
        }
    }

    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault> {
        self.0.respond(record, host, authentication)
    }
}

/// The closure's result over the context `Accepted::new` reads `query` of `request` in.
///
/// # Errors
///
/// The core made no context: the request's `client_metadata` breaks C6.
pub fn read_query<R: 'static>(
    request: &Request<'_>,
    query: &Query<'_>,
    read: impl for<'q> FnOnce(&'q Query<'q>, QueryContext<'q>) -> R + 'static,
) -> Result<R, FixtureError> {
    let mut builder = Registry::<NoHost>::builder();
    builder.format(ProbeFormat::new(query.format().as_str(), None)?);
    let registry = builder.build()?;
    let out = Rc::new(Cell::new(None));
    let sink = Rc::clone(&out);
    let armed = Armed::with(QueryRead {
        query: query.id().to_string(),
        read: Box::new(move |query, context| {
            sink.set(Some(read(query, context)));
        }),
    });
    let accepted = Accepted::new(request, &registry).map(drop);
    drop(armed);
    result(&out, || format!("{accepted:?}"))
}

/// The closure's result over `format`'s reading of `query` of `request`, in the context
/// `Accepted::new` reads it in.
///
/// # Errors
///
/// The core made no context, or the format refuses the query.
pub fn read_parsed<F, R>(
    request: &Request<'_>,
    query: &Query<'_>,
    format: F,
    read: impl FnOnce(&dyn FormatQuery) -> R + 'static,
) -> Result<R, FixtureError>
where
    F: Format + 'static,
    R: 'static,
{
    read_query(request, query, move |query, context| {
        let parsed = format.query(query, context)?;
        Ok(read(&*parsed))
    })?
    .map_err(|refusals: AllOf<Refusal>| FixtureError::Rejected(format!("{refusals:?}")))
}

/// Registers `mode` as its choice has it: in the clear for [`TestChoice::Plain`], else sealed, and
/// by URI for its errors too.
fn register_mode<H>(builder: &mut RegistryBuilder<H>, mode: TestMode)
where
    H: CoreHost + Has<dyn Haip>,
    TestMode: HostedMode<H> + HostedErrorMode<H>,
{
    builder.response_type(VpToken);
    if mode.channel == ChannelKind::Uri {
        builder.error_mode(mode.clone());
    }
    if mode.choice == TestChoice::Plain {
        builder.mode(mode);
    } else {
        builder.jwe_mode(mode);
    }
}

/// The closure's result over what phase 2 gives a format of `format` for the first query of a
/// request arriving as `received`, routed by `mode`: the request's envelope authenticated, a
/// stand-in credential selected, the selection prepared over `host`, the route chosen.
///
/// # Errors
///
/// The flow ended before the format's revalidation: a rule the request breaks, a mode's choice the
/// core refuses.
pub fn read_phase_two<H, R>(
    received: &Received<'_>,
    format: &str,
    mode: TestMode,
    host: &H,
    read: impl for<'a> FnOnce(PhaseTwo<'a, H>) -> R + 'static,
) -> Result<R, FixtureError>
where
    H: CoreHost + Has<dyn Haip> + 'static,
    R: 'static,
{
    let mut builder = Registry::<H>::builder();
    register_mode(&mut builder, mode);
    builder.format(ProbeFormat::new(format, None)?);
    let registry = builder.build()?;
    let envelope = Envelope::parse(received, &registry)?;
    let request = Request::parse(&envelope)?;
    let held = Held::new("probe", format, "{}");
    let wallet = Wallet::new(vec![held.credential()?]).map_err(FixtureError::Registration)?;
    let env = env(&["en"], Vec::new())?;
    let context = Language::English.shared()?;
    let ids = first_selection(&request, &wallet, &registry, &env, context)
        .map_err(FixtureError::Rejected)?;
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let authenticated = authenticate(&envelope, &registry, context, host)?;
    let out = Rc::new(Cell::new(None));
    let sink = Rc::clone(&out);
    let armed = Armed::with(PhaseTwoRead::<H>(Box::new(move |phase_two| {
        sink.set(Some(read(phase_two)));
    })));
    let flow = Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        &registry,
        &env,
        context,
        host,
    )
    .and_then(|prepared| prepared.respond(|_: &Resource| Fetch::Unfetched, host))
    .map(drop);
    drop(armed);
    result(&out, || match flow {
        Ok(()) => "the flow answered without revalidating".to_owned(),
        Err(outcome) => outcome.to_string(),
    })
}

/// What the consent's first selection is made from: a request, the wallet, the registry, its
/// configuration and the context its texts resolve in.
pub struct Selection<'a, H: Build> {
    /// The request, its envelope read over a registry of `registry`'s modes.
    pub request: &'a Request<'a>,
    /// The wallet.
    pub wallet: &'a Wallet<'a>,
    /// The registry.
    pub registry: &'a Registry<H>,
    /// The configuration.
    pub env: &'a Env,
    /// The context the texts resolve in.
    pub context: &'a Context,
}

/// The closure's result over the [`FetchedRecord`] phase 2 revalidates for the first selection the
/// consent offers, the resources fetched by `fetch`. `registry` holds a [`ProfileProbe`] for the
/// record's type.
///
/// # Errors
///
/// The flow ended before the revalidation: the request or the selection refused, a record without
/// a transaction, a credential the host calls unusable.
pub fn read_record<H, R>(
    flow: Selection<'_, H>,
    fetch: impl FnMut(&Resource) -> Fetch,
    host: &H,
    read: impl for<'a> FnOnce(FetchedRecord<'a>, &'a H) -> R + 'static,
) -> Result<R, FixtureError>
where
    H: CoreHost + 'static,
    R: 'static,
{
    let Selection {
        request,
        wallet,
        registry,
        env,
        context,
    } = flow;
    let ids =
        first_selection(request, wallet, registry, env, context).map_err(FixtureError::Rejected)?;
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let authenticated = authenticate(request.envelope(), registry, context, host)?;
    let out = Rc::new(Cell::new(None));
    let sink = Rc::clone(&out);
    let armed = Armed::with(RecordRead::<H>(Box::new(move |record, host| {
        sink.set(Some(read(record, host)));
    })));
    let flow = Prepared::prepare(&authenticated, &ids, wallet, registry, env, context, host)
        .and_then(|prepared| prepared.respond(fetch, host))
        .map(drop);
    drop(armed);
    result(&out, || match flow {
        Ok(()) => "the flow answered without revalidating a record".to_owned(),
        Err(outcome) => outcome.to_string(),
    })
}

/// The closure's result over the session the answering route of `mode` binds for a request
/// arriving as `received`.
///
/// # Errors
///
/// The route refuses: a rule the request breaks, a mode's choice the core refuses.
pub fn read_session<R>(
    received: &Received<'_>,
    mode: TestMode,
    read: impl FnOnce(&Session<'_>) -> R,
) -> Result<R, FixtureError> {
    let host = TestHost::default();
    let mut builder = Registry::<TestHost>::builder();
    register_mode(&mut builder, mode);
    let registry = builder.build()?;
    routed(received, &registry, &host, read)
}

/// The session of an authenticated request's answering route.
fn routed<R, H: CoreHost>(
    received: &Received<'_>,
    registry: &Registry<H>,
    host: &H,
    read: impl FnOnce(&Session<'_>) -> R,
) -> Result<R, FixtureError> {
    let envelope = Envelope::parse(received, registry)?;
    let authenticated = authenticate(&envelope, registry, Language::English.shared()?, host)?;
    let route = Route::new(&authenticated, registry, host)
        .map_err(|outcome| FixtureError::Rejected(outcome.to_string()))?;
    let answering = route
        .answering()
        .ok_or_else(|| FixtureError::Rejected("the route answers nothing".to_owned()))?;
    Ok(read(&answering.session()))
}

/// A request by URI: what it names, for [`read_redirect_session`].
#[derive(Debug, Clone, Copy)]
pub struct Redirect<'r> {
    /// The full `client_id`, of a prefix `prefix` names.
    pub client_id: &'r str,
    /// The `response_uri`.
    pub response_uri: &'r str,
    /// The `nonce`.
    pub nonce: &'r str,
    /// `client_metadata`, JSON.
    pub client_metadata: &'r str,
}

/// The closure's result over the session of a Request Object of `redirect` fetched from a link,
/// signed by the test Verifier, routed by a test mode on the URI channel under `choice`.
///
/// # Errors
///
/// The request is rejected, or the core refuses the mode's choice.
pub fn read_redirect_session<R>(
    redirect: Redirect<'_>,
    prefix: siros_openid4vp::authenticate::PrefixName,
    choice: TestChoice,
    read: impl FnOnce(&Session<'_>) -> R,
) -> Result<R, FixtureError> {
    const MODE: ModeName = siros_syntax::checked!(ModeName, "direct_post.test");
    let Redirect {
        client_id,
        response_uri,
        nonce,
        client_metadata,
    } = redirect;
    let host = TestHost::default();
    let mut builder = Registry::<TestHost>::builder();
    register_mode(
        &mut builder,
        TestMode {
            choice,
            ..TestMode::new(MODE, ChannelKind::Uri)
        },
    );
    builder.client_prefix(NamedPrefix {
        name: prefix,
        prefix: TestPrefix::Request,
    });
    let registry = builder.build()?;
    let link = format!(
        "openid4vp://?client_id={client_id}&request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
    );
    let payload = format!(
        r#"{{"client_id":"{client_id}","response_type":"vp_token","response_mode":"{MODE}","response_uri":"{response_uri}","nonce":"{nonce}","client_metadata":{client_metadata},"dcql_query":{{"credentials":[{{"id":"q","format":"test"}}]}}}}"#
    );
    let jws = compact_jws(&VERIFIER_SECRET, REQUEST_OBJECT_HEADER, &payload)?;
    let fetch = UriFetch::of(&link, &registry, &host)
        .map_err(|refused| FixtureError::Rejected(refused.to_string()))?;
    let received = fetch
        .resume(FetchAnswer::Body(&jws), &registry, &host)
        .map_err(|rejected| FixtureError::Rejected(rejected.failure().to_string()))?;
    routed(&received, &registry, &host, read)
}

/// A test mode named `dc_api` on the DC API channel under `choice`, as [`read_phase_two`] and
/// [`read_session`] route a request of [`crate::fixtures::parameters`].
#[must_use]
pub const fn dc_api(choice: TestChoice) -> TestMode {
    let mut mode = TestMode::new(
        siros_syntax::checked!(ModeName, "dc_api"),
        ChannelKind::DcApi,
    );
    mode.choice = choice;
    mode
}

/// `client_metadata` holding `metadata`'s members with [`crate::fixtures::B26_KEY`] after its keys,
/// and the choice of that key under A128GCM.
///
/// # Errors
///
/// `metadata` is no JSON object, or breaks a rule of its reading.
pub fn sealed_to_b26(metadata: &str) -> Result<(String, TestChoice), FixtureError> {
    let invalid = |e: &dyn std::fmt::Display| FixtureError::Rejected(e.to_string());
    let mut value: serde_json::Value = serde_json::from_str(metadata).map_err(|e| invalid(&e))?;
    let key: serde_json::Value =
        serde_json::from_str(crate::fixtures::B26_KEY).map_err(|e| invalid(&e))?;
    value
        .as_object_mut()
        .ok_or_else(|| FixtureError::Rejected("metadata that is no object".to_owned()))?
        .entry("jwks")
        .or_insert_with(|| serde_json::json!({"keys": []}))
        .get_mut("keys")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| FixtureError::Rejected("jwks without keys".to_owned()))?
        .push(key);
    let text = value.to_string();
    let raw = serde_json::value::RawValue::from_string(text.clone()).map_err(|e| invalid(&e))?;
    let parsed =
        siros_openid4vp::request::ClientMetadata::parse(Some(&raw)).map_err(|e| invalid(&e))?;
    let place = parsed.agreeable_keys().len().saturating_sub(1);
    Ok((
        text,
        TestChoice::Key {
            place,
            enc: ContentEncryption::A128GCM,
        },
    ))
}
