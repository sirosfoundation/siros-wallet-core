//! What the format plug-ins' tests share: requests over the DC API as the model writes them, the
//! wallet's configuration, and credentials as the wallet registers them.

use std::borrow::Cow;
use std::num::NonZeroU32;

use siros_explain::Explain;
use siros_openid4vp::arrival::{DcApiProtocol, DcApiProtocols, Received, Unreadable};
use siros_openid4vp::envelope::Envelope;
use siros_openid4vp::ids::{
    AuthorityType, AuthorityValue, CredentialId, DocumentKey, FormatId, InvalidId, LocaleTag,
    Origin,
};
use siros_openid4vp::json::quote;
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::refusal::Refused;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Amounts, Choice, Env, EnvError, Icon, IconMedia};
use siros_openid4vp::wallet::{
    Credential, Document, Facts, HeldAuthority, Holder, RegistrationError,
};

use crate::issuer::{DOCUMENT, IssueError, issue};

/// The Origin of the model's requests.
pub const ORIGIN: &str = "https://verifier.example";

/// The `nonce` of the model's requests.
pub const NONCE: &str = "n-0S6_WzA2Mj";

/// The Client Identifier of the test Verifier's signed requests: the test prefix's.
pub const CLIENT_ID: &str = "test:verifier";

/// The protected header of the test Verifier's Request Objects.
pub const REQUEST_OBJECT_HEADER: &str = r#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#;

/// A fixture that cannot exist.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "testkit.fixture")]
pub enum FixtureError {
    /// An identifier breaks its rule.
    #[error(transparent)]
    Id(#[from] InvalidId),
    /// The configuration breaks its rule.
    #[error(transparent)]
    Env(#[from] EnvError),
    /// The registration breaks its rule.
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    /// The view is no JSON.
    #[error("the view")]
    View(
        #[from]
        #[explain(name = "cause")]
        JsonError,
    ),
    /// The view cannot be issued.
    #[error("the issued IssuerSigned")]
    Issue(
        #[from]
        #[explain(name = "cause")]
        IssueError,
    ),
    /// The request cannot be read.
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
    /// The request breaks a rule.
    #[error(transparent)]
    Refused(#[from] Refused),
    /// A double failed.
    #[error(transparent)]
    Fault(#[from] Fault),
}

/// Request parameters: `dc_api`, the model's nonce, the DCQL query, then `extra` members.
#[must_use]
pub fn parameters(dcql: &str, extra: &str) -> String {
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(",{extra}")
    };
    format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"{NONCE}","dcql_query":{dcql}{extra}}}"#
    )
}

/// An unsigned DC API request of the parameters, from the model's Origin.
///
/// # Errors
///
/// The parameters are no JSON object with unique member names (U3).
pub fn unsigned(parameters: &str) -> Result<Received<'_>, FixtureError> {
    received(DcApiProtocol::Unsigned, parameters)
}

/// The parameters with the test Verifier's `client_id` as their first member: a signed request's
/// payload.
#[must_use]
pub fn signed_parameters(parameters: &str) -> String {
    let rest = parameters.strip_prefix('{').unwrap_or(parameters);
    let separator = if rest.trim_start().starts_with('}') {
        ""
    } else {
        ","
    };
    format!(r#"{{"client_id":{}{separator}{rest}"#, quote(CLIENT_ID))
}

/// The `data` of a signed DC API request (A.3.2.1): `request`, a compact JWS the test Verifier
/// signs with ES256 over the parameters and its `client_id`.
///
/// # Errors
///
/// The test Verifier's key is no P-256 scalar, a bug of the kit.
pub fn signed_data(parameters: &str) -> Result<String, Fault> {
    let jws = crate::jose::compact_jws(
        &crate::jose::VERIFIER_SECRET,
        REQUEST_OBJECT_HEADER,
        &signed_parameters(parameters),
    )?;
    Ok(format!(r#"{{"request":{}}}"#, quote(&jws)))
}

/// A signed DC API request of its `data`, from the model's Origin.
///
/// # Errors
///
/// The data breaks a U rule.
pub fn signed(data: &str) -> Result<Received<'_>, FixtureError> {
    received(DcApiProtocol::Signed, data)
}

/// A DC API request in a protocol, from the model's Origin, every protocol registered.
///
/// # Errors
///
/// The data breaks a U rule.
pub fn received(protocol: DcApiProtocol, data: &str) -> Result<Received<'_>, FixtureError> {
    Ok(Received::dc_api(
        protocol.as_str(),
        data,
        Origin::parse(ORIGIN)?,
        &DcApiProtocols::ALL,
    )?)
}

/// The DC API protocol and `data` of an exported request: its parameters, or `{"request": JWS}`
/// for its Request Object.
#[must_use]
pub fn data_of<'a>(
    parameters: &'a str,
    request_object: Option<&str>,
) -> (DcApiProtocol, Cow<'a, str>) {
    match request_object {
        None => (DcApiProtocol::Unsigned, Cow::Borrowed(parameters)),
        Some(jws) => (
            DcApiProtocol::Signed,
            Cow::Owned(format!(r#"{{"request":{}}}"#, quote(jws))),
        ),
    }
}

/// The request a DC API arrival's envelope holds.
///
/// # Errors
///
/// The envelope breaks a U rule, or the request a rule of its parsing.
pub fn request_of<'r>(received: &'r Received<'r>) -> Result<Request<'r>, FixtureError> {
    let envelope = Envelope::parse(received)?;
    Ok(Request::parse(&envelope)?)
}

/// A PNG icon of a logo URI, of `size` bytes.
pub fn icon(uri: &str, size: u32) -> Option<(String, Icon)> {
    Some((
        uri.to_owned(),
        Icon {
            reference: uri.to_owned().into(),
            media: IconMedia::Png,
            size: NonZeroU32::new(size)?,
        },
    ))
}

/// The wallet's configuration: its priority list, its icons by logo URI, amounts formatted,
/// each slot's default preselected.
pub fn env(locales: &[&'static str], icons: Vec<(String, Icon)>) -> Result<Env, FixtureError> {
    let tags = locales
        .iter()
        .map(|tag| LocaleTag::parse(*tag))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Env::new(tags, icons, Amounts::Formatted, Choice::First)?)
}

/// A credential's registration: its id, format and view, its documents by key, whether it is
/// bound to a key, and its Trusted Authorities values by type.
#[derive(Debug, Clone)]
pub struct Held {
    /// The id.
    pub id: String,
    /// The Credential Format Identifier.
    pub format: String,
    /// The view, JSON.
    pub view: String,
    /// The documents, (key, content).
    pub documents: Vec<(String, Vec<u8>)>,
    /// Whether it is bound to a key the wallet holds.
    pub holder: Holder,
    /// The Trusted Authorities values, by type.
    pub authorities: Vec<(String, Vec<String>)>,
}

impl Held {
    /// A credential of a format with a view, bound to a key, without documents or authorities.
    pub fn new(id: &str, format: &str, view: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            format: format.to_owned(),
            view: view.into(),
            documents: Vec::new(),
            holder: Holder::Bound,
            authorities: Vec::new(),
        }
    }

    /// The credential with its view's IssuerSigned as its `mso_mdoc` document.
    ///
    /// # Errors
    ///
    /// The view is no JSON, or the issuer stand-in cannot issue it.
    pub fn with_issued(mut self) -> Result<Self, FixtureError> {
        let issued = issue(&Node::parse(&self.view)?)?;
        self.documents.push((DOCUMENT.to_owned(), issued));
        Ok(self)
    }

    /// The credential as the registration holds it.
    pub fn credential(&self) -> Result<Credential<'_>, FixtureError> {
        let documents = self
            .documents
            .iter()
            .map(|(key, content)| {
                Ok(Document {
                    key: DocumentKey::parse(key.as_str())?,
                    content: content.as_slice(),
                })
            })
            .collect::<Result<Vec<_>, FixtureError>>()?;
        let authorities = self
            .authorities
            .iter()
            .map(|(kind, values)| {
                Ok(HeldAuthority {
                    kind: AuthorityType::parse(kind.as_str())?,
                    values: values
                        .iter()
                        .map(|value| AuthorityValue::parse(value.as_str()))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, FixtureError>>()?;
        Ok(Credential::new(
            CredentialId::parse(self.id.as_str())?,
            FormatId::parse(self.format.as_str())?,
            self.view.as_bytes(),
            documents,
            Facts::new(self.holder, authorities)?,
        )?)
    }
}

/// The ids of the first selection the consent offers, each slot's first entry chosen (the slot's
/// default); the refusals, the unmet request or the fault otherwise.
pub fn first_selection<H>(
    request: &Request<'_>,
    wallet: &siros_openid4vp::wallet::Wallet<'_>,
    registry: &siros_openid4vp::plugins::Registry<H>,
    env: &Env,
) -> Result<Vec<String>, String> {
    use siros_openid4vp::matching::{
        Accepted, Choice as Offer, Consent, Match, Views, display, offer,
    };
    let accepted = Accepted::new(request, registry).map_err(|e| e.to_string())?;
    let matched = Match::run(&accepted, wallet, env).map_err(|e| e.to_string())?;
    let consent = Consent::of(&matched).ok_or("the wallet cannot meet the request")?;
    let views = Views::of(&matched, env).map_err(|e| e.to_string())?;
    let sets = offer(&matched, &consent, env.choice());
    let shown = display(&sets, &views, &[]).map_err(|e| e.to_string())?;
    let first = shown.sets().first().ok_or("no set")?;
    let ids: Vec<&str> = first
        .iter()
        .map(|slot| slot.first().map(Offer::id).ok_or("an empty slot"))
        .collect::<Result<_, _>>()?;
    let chosen = shown.select(0, &ids).map_err(|e| e.to_string())?;
    Ok(chosen.ids().into_iter().map(str::to_owned).collect())
}

/// The response to [`first_selection`], nothing published for phase 2's fetches; the refusals,
/// the unmet request, the fault or the phase 2 outcome otherwise.
pub fn answer_first<H: siros_openid4vp::host::CoreHost>(
    request: &Request<'_>,
    wallet: &siros_openid4vp::wallet::Wallet<'_>,
    registry: &siros_openid4vp::plugins::Registry<H>,
    env: &Env,
    host: &H,
) -> Result<siros_openid4vp::resolve::Response, String> {
    let ids = first_selection(request, wallet, registry, env)?;
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let published = crate::Published::default();
    siros_openid4vp::resolve::Prepared::prepare(request, &ids, wallet, registry, env)
        .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
        .map_err(|e| e.to_string())
}

/// The presentation of a query's option for a credential, as phase 2 makes it: the option among
/// those the query's [`AnsweredQuery::choose`] gives, presented over the host.
///
/// # Errors
///
/// The format faults, the credential does not answer the option (a fault of the test doubles'
/// domain), or the presentation fails.
///
/// [`AnsweredQuery::choose`]: siros_openid4vp::host::AnsweredQuery::choose
pub fn present_option<H>(
    query: &dyn siros_openid4vp::host::AnsweredQuery<H>,
    credential: siros_openid4vp::host::Usable<'_>,
    option: siros_openid4vp::plugins::OptionIndex,
    members: &siros_openid4vp::plugins::Members,
    session: &siros_openid4vp::session::Session<'_>,
    host: &H,
) -> Result<siros_openid4vp::host::Presentation, siros_openid4vp::host::PresentError> {
    use siros_openid4vp::plugins::Fault;

    let env = env(&["en"], Vec::new()).map_err(|e| {
        Fault::caused(
            crate::FAULT,
            siros_openid4vp::detail!("the fixture's env"),
            e,
        )
    })?;
    let provided: Vec<siros_openid4vp::plugins::Member> = members.names().cloned().collect();
    let answered = query
        .choose(credential, &env, &provided)?
        .into_iter()
        .find(|answered| answered.option() == option)
        .ok_or_else(|| {
            Fault::new(
                crate::FAULT,
                siros_openid4vp::detail!("an option the credential does not answer"),
            )
        })?;
    answered.present(members, session, host)
}

/// The context phase 2 reads a query of the request with under `dc_api`, no entry naming it,
/// and the Verifier's `vp_formats_supported` value for its format.
#[must_use]
pub fn dc_api_context<'q>(
    request: &'q Request<'q>,
    supported: Option<siros_openid4vp::json::Node<'q>>,
) -> siros_openid4vp::host::AnsweredContext<'q> {
    siros_openid4vp::host::AnsweredContext::new(
        request,
        siros_openid4vp::routing::ResponseMode::DcApi(siros_openid4vp::routing::DcApiMode::DcApi),
        false,
        supported,
    )
}

/// `let $name = $parameters;` as a signed DC API request over the parameters, the test Verifier's
/// JWS holding them and its `client_id`: its data, its arrival and its request, each kept in the
/// caller's scope.
#[macro_export]
macro_rules! signed_request {
    (let $name:ident = $parameters:expr) => {
        let data = $crate::fixtures::signed_data($parameters).expect("the test Verifier signs");
        let received = $crate::fixtures::signed(&data).expect("the signed request arrives");
        let $name = $crate::fixtures::request_of(&received).expect("the signed request parses");
    };
}

/// The context phase 1 reads a query of the request with under `dc_api`: whether an entry names
/// it, and the Verifier's `vp_formats_supported` value for its format.
#[must_use]
pub fn query_context<'q>(
    request: &'q Request<'q>,
    named: bool,
    supported: Option<siros_openid4vp::json::Node<'q>>,
) -> siros_openid4vp::routing::QueryContext<'q> {
    siros_openid4vp::routing::QueryContext::new(
        request,
        Some(siros_openid4vp::routing::ResponseMode::DcApi(
            siros_openid4vp::routing::DcApiMode::DcApi,
        )),
        named,
        supported,
    )
}

/// The response mode a request's routing answers in; `None` when C5 refuses its mode.
#[must_use]
pub fn mode_of(request: &Request<'_>) -> Option<siros_openid4vp::routing::ResponseMode> {
    match request.envelope().routing().mode() {
        siros_openid4vp::routing::ModeChoice::Answer(mode) => Some(mode),
        siros_openid4vp::routing::ModeChoice::DirectPost
        | siros_openid4vp::routing::ModeChoice::Unsupported => None,
    }
}

/// `let $name = $parameters;` as an unsigned DC API request of the parameters from the model's
/// Origin: its arrival and its request, kept in the caller's scope.
#[macro_export]
macro_rules! unsigned_request {
    (let $name:ident = $parameters:expr) => {
        let received = $crate::fixtures::unsigned($parameters).expect("the request arrives");
        let $name = $crate::fixtures::request_of(&received).expect("the request parses");
    };
}
