//! What the tests share: a credential registered from a metadata text, a signed request of one
//! TS12 entry, the test app's context.

#![allow(dead_code, reason = "each test binary uses a part")]

use std::borrow::Cow;

use siros_i18n::{Bidi, Context};
use siros_openid4vp::ids::{CredentialId, CredentialType, FormatId, LocaleTag};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Binding, Bound, Carriage, NoCandidate, Profile, ViewTypes};
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Choice, Env};
use siros_openid4vp::wallet::{Credential, Document, Facts, Holder};
use siros_openid4vp::wallet_metadata::Placement;
use siros_paso::view::ConvertError;
use siros_syntax::{AllOf, Keyed, checked};
use siros_testkit::fixtures::{request_of, signed, signed_data, unsigned};
use siros_testkit::render::{ENGLISH_PASO, GERMAN_PASO, Language};
use siros_testkit::verifier;
use siros_ts12::{AttestationType, Ts12Document, Ts12Profile, Ts12Type, view};

/// CS-12 §7.2's `sca-iban` type metadata.
pub const CS12_IBAN: &str = include_str!("../data/cs12-sca-iban.json");
/// CS-12 §7.2's `sca-user` type metadata.
pub const CS12_USER: &str = include_str!("../data/cs12-sca-user.json");
/// WE BUILD's test bed's `sca-iban` configuration (nxd-wallet-conformance-backend 179507e).
pub const TESTBED_IBAN: &str = include_str!("../data/testbed-sca-iban.json");

/// The base type a fixture's credential names unless it says otherwise.
pub const BASE: &str = "https://webuildconsortium.eu/sca/sca-iban/1.0";

/// The profile configured for CS-12 §7.1 item 2's three base types.
pub fn profile() -> Ts12Profile {
    const BASE_TYPES: [AttestationType; 3] = [
        checked!(
            AttestationType,
            "https://webuildconsortium.eu/sca/sca-iban/1.0"
        ),
        checked!(
            AttestationType,
            "https://webuildconsortium.eu/sca/sca-user/1.0"
        ),
        checked!(
            AttestationType,
            "https://webuildconsortium.eu/sca/sca-card-dpc/1.0"
        ),
    ];
    Ts12Profile::new(AllOf::new(BASE_TYPES.to_vec()).expect("three types"))
}

/// The registration document of a type metadata text.
pub fn document(own: &str) -> Vec<u8> {
    let node = Node::parse(own).expect("the metadata");
    Ts12Document::compose(&node, &Keyed::empty())
        .expect("the document")
        .content()
        .as_bytes()
        .to_vec()
}

/// A credential the wallet registered with a `ts12` document.
pub fn credential(document: &[u8]) -> Credential<'_> {
    Credential::new(
        CredentialId::parse("card").expect("id"),
        FormatId::parse("dc+sd-jwt").expect("format"),
        br#"{"answers":["q"],"alg":"A"}"#,
        vec![Document {
            key: siros_ts12::DOCUMENT,
            content: document,
        }],
        Facts::new(Holder::Bound, Vec::new()).expect("facts"),
    )
    .expect("credential")
}

/// The wallet's configuration: a priority list.
pub fn env(locales: &[&str]) -> Env {
    Env::new(
        locales
            .iter()
            .map(|tag| LocaleTag::parse(tag).expect("tag"))
            .collect(),
        Vec::new(),
        Choice::First,
    )
    .expect("env")
}

/// The test app's wording of PaSO's amount: the number formatted in the currency.
const AMOUNT_FORMATTED: &str = "amount = {$value :currency currency=$currency}";
/// A wording of PaSO's amount as written: the number, a space, the code.
const AMOUNT_WRITTEN: &str = "amount = {$value} {$currency}";

thread_local! {
    /// The contexts of [`context`], English then German, loaded once per thread.
    static WRITTEN: [&'static Context; 2] = Language::ALL.map(|language| {
        let source = match language {
            Language::English => ENGLISH_PASO,
            Language::German => GERMAN_PASO,
        };
        assert!(source.contains(AMOUNT_FORMATTED), "the test app's amount wording");
        let context = language
            .sources()
            .into_iter()
            .map(|module| {
                if module == source {
                    module.replace(AMOUNT_FORMATTED, AMOUNT_WRITTEN)
                } else {
                    module.to_owned()
                }
            })
            .try_fold(Context::new().bidi(Bidi::None), |context, module| {
                context.module(&module)
            })
            .expect("the test app's sources");
        &*Box::leak(Box::new(context))
    });
}

/// The test app's context in the language of `env`'s first tag the app speaks, English when it
/// speaks none, its amounts worded as written: a wallet's choice (View §3 MAY).
pub fn context(env: &Env) -> &'static Context {
    let language = env
        .priority()
        .iter()
        .find_map(|tag| {
            let primary = tag.as_str().split('-').next()?;
            Language::ALL
                .into_iter()
                .find(|language| language.tag().eq_ignore_ascii_case(primary))
        })
        .unwrap_or(Language::English);
    let at = match language {
        Language::English => 0,
        Language::German => 1,
    };
    WRITTEN.with(|contexts| contexts[at])
}

/// A DC API request's parameters holding one query `sca` and these decoded entries.
pub fn parameters(entries: &[&str], query_extra: &str) -> String {
    let encoded: Vec<String> = entries
        .iter()
        .map(|entry| format!("\"{}\"", verifier::encode(entry).expect("entry")))
        .collect();
    format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj","dcql_query":{{"credentials":[{{"id":"sca","format":"dc+sd-jwt"{query_extra}}}]}},"transaction_data":[{}],"expected_origins":["https://verifier.example"]}}"#,
        encoded.join(",")
    )
}

/// `run` over the signed DC API request of `parameters`.
pub fn with_signed<T>(parameters: &str, run: impl FnOnce(&Request<'_>) -> T) -> T {
    let data = signed_data(parameters).expect("the signature");
    let received = signed(&data).expect("the arrival");
    run(&request_of(&received).expect("the request"))
}

/// `run` over the unsigned DC API request of `parameters`.
pub fn with_unsigned<T>(parameters: &str, run: impl FnOnce(&Request<'_>) -> T) -> T {
    let received = unsigned(parameters).expect("the arrival");
    run(&request_of(&received).expect("the request"))
}

/// The request's entries bound for a credential holding `document`, whose `types` name [`BASE`].
pub fn bound(request: &Request<'_>, document: &[u8], env: &Env) -> Result<Bound, NoCandidate> {
    bound_of(request, document, env, &[BASE])
}

/// The request's entries bound for a credential holding `document`, of these types.
pub fn bound_of(
    request: &Request<'_>,
    document: &[u8],
    env: &Env,
    kinds: &[&str],
) -> Result<Bound, NoCandidate> {
    bound_with(
        request,
        &credential(document),
        env,
        kinds,
        Carriage::Carried,
    )
}

/// The request's entries bound for a credential of these types, its presentation carrying a
/// profile's claims or not, in the test app's [`context`].
pub fn bound_with(
    request: &Request<'_>,
    credential: &Credential<'_>,
    env: &Env,
    kinds: &[&str],
    carriage: Carriage,
) -> Result<Bound, NoCandidate> {
    bound_in(request, credential, env, context(env), kinds, carriage)
}

/// The request's entries bound for a credential of these types in a context.
pub fn bound_in(
    request: &Request<'_>,
    credential: &Credential<'_>,
    env: &Env,
    context: &Context,
    kinds: &[&str],
    carriage: Carriage,
) -> Result<Bound, NoCandidate> {
    let entries: Vec<_> = request.indexed_entries().map(|(index, _)| index).collect();
    let additions = ViewTypes::new(
        kinds
            .iter()
            .map(|kind| CredentialType::parse(Cow::Owned((*kind).to_owned())).expect("type"))
            .collect(),
    );
    profile().bind(
        Binding {
            request,
            query: request.queries().first().expect("a query"),
            credential,
            entries: &entries,
            placement: Some(Placement::Claims),
            additions: &additions,
            carriage,
        },
        env,
        context,
    )
}

/// An entry bound for the metadata's credential, whose `types` are the metadata's `vct` and
/// `extends`, in the test app's [`context`].
pub fn bound_entry(own: &str, entry: &str, locales: &[&str]) -> Result<Bound, NoCandidate> {
    let env = env(locales);
    bound_entry_in(own, entry, &env, context(&env))
}

/// An entry bound for the metadata's credential, as [`bound_entry`] binds it, in a context.
pub fn bound_entry_in(
    own: &str,
    entry: &str,
    env: &Env,
    context: &Context,
) -> Result<Bound, NoCandidate> {
    let metadata = Node::parse(own).expect("the metadata");
    let kinds: Vec<&str> = ["vct", "extends"]
        .iter()
        .filter_map(|member| metadata.get(member).and_then(Node::as_str))
        .collect();
    let document = document(own);
    with_signed(&parameters(&[entry], ""), |request| {
        bound_in(
            request,
            &credential(&document),
            env,
            context,
            &kinds,
            Carriage::Carried,
        )
    })
}

/// The source a listed built-in type of a metadata text converts to in a context for a priority
/// list.
pub fn converted(
    own: &str,
    kind: Ts12Type,
    context: &Context,
    priority: &[LocaleTag],
) -> Result<String, ConvertError> {
    let document = document(own);
    let node = Node::parse(std::str::from_utf8(&document).expect("UTF-8")).expect("the document");
    let read = Ts12Document::read(&node).expect("the document");
    let built_in = read
        .listed(kind)
        .expect("a listed type")
        .built_in()
        .expect("a built-in type");
    view::convert(&built_in, context, priority)
}

/// The test app's [`context`] with the source the type converts to loaded, as a registration
/// carries it to the matcher.
pub fn registered(own: &str, kind: Ts12Type, env: &Env) -> Context {
    let context = context(env);
    let source = converted(own, kind, context, env.priority()).expect("the type converts");
    context
        .clone()
        .module(&source)
        .expect("the converted source loads")
}
