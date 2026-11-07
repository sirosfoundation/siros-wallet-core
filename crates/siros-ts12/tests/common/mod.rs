//! What the tests share: a credential registered from a metadata text, a signed request of one
//! TS12 entry, the test app of its converted module.

#![allow(dead_code, reason = "each test binary uses a part")]

use std::borrow::Cow;

use siros_explain::{AllOf, Keyed, ModuleId, Text};
use siros_i18n::{DefinedForm, Selected};
use siros_openid4vp::ids::{CredentialId, CredentialType, FormatId, LocaleTag};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Binding, Bound, Carriage, NoCandidate, Profile, ViewTypes};
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Amounts, Choice, Env, RenderOptions};
use siros_openid4vp::wallet::{Credential, Document, Facts, Holder};
use siros_openid4vp::wallet_metadata::Placement;
use siros_testkit::fixtures::{
    OPTIONS, request_of, signed, signed_data, unsigned, with_generic_forms,
};
use siros_testkit::render::{
    App, CrateSource, ENGLISH_PASO, GERMAN_PASO, main_locales, main_module,
};
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
        siros_explain::checked!(
            AttestationType,
            "https://webuildconsortium.eu/sca/sca-iban/1.0"
        ),
        siros_explain::checked!(
            AttestationType,
            "https://webuildconsortium.eu/sca/sca-user/1.0"
        ),
        siros_explain::checked!(
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

/// The wallet's configuration of a priority list, amounts as written.
pub fn env(locales: &[&str]) -> Env {
    Env::new(
        locales
            .iter()
            .map(|tag| LocaleTag::parse(tag).expect("tag"))
            .collect(),
        Vec::new(),
        RenderOptions {
            amounts: Amounts::Written,
            ..OPTIONS
        },
        Vec::new(),
        Choice::First,
    )
    .expect("env")
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
/// profile's claims or not.
pub fn bound_with(
    request: &Request<'_>,
    credential: &Credential<'_>,
    env: &Env,
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
    )
}

/// An entry bound for the metadata's credential, whose `types` are the metadata's `vct` and
/// `extends`.
pub fn bound_entry(own: &str, entry: &str, locales: &[&str]) -> Result<Bound, NoCandidate> {
    let metadata = Node::parse(own).expect("the metadata");
    let kinds: Vec<&str> = ["vct", "extends"]
        .iter()
        .filter_map(|member| metadata.get(member).and_then(Node::as_str))
        .collect();
    with_signed(&parameters(&[entry], ""), |request| {
        bound_of(request, &document(own), &env(locales), &kinds)
    })
}

/// The module a type's metadata converts to for a priority list.
pub fn defined(own: &str, kind: Ts12Type, priority: &[LocaleTag]) -> DefinedForm {
    let main = main_locales().expect("the main module");
    let document = document(own);
    let node = Node::parse(std::str::from_utf8(&document).expect("UTF-8")).expect("the document");
    let read = Ts12Document::read(&node).expect("the document");
    let built_in = read
        .listed(kind)
        .expect("a listed type")
        .built_in()
        .expect("a built-in type");
    view::convert(&built_in, &main, priority).expect("the module")
}

/// The texts a bound entry shows, as the test app renders them for `locales`.
pub struct Screen {
    app: App,
    env: Env,
}

impl Screen {
    /// The screen of a bound entry of a type.
    pub fn of(own: &str, kind: Ts12Type, locales: &[&str], selected: &Selected) -> Self {
        let wanted = env(locales);
        let converted = defined(own, kind, wanted.priority());
        let modules = [
            main_module().expect("the main module"),
            CrateSource::openid4vp().load().expect("the core's module"),
            CrateSource::of::<siros_paso::CrateModule>(ENGLISH_PASO, GERMAN_PASO)
                .load()
                .expect("PaSO's module"),
        ];
        assert_eq!(
            selected.module(),
            ModuleId::Defined(converted.id()),
            "the rendering and the conversion name one module"
        );
        Self {
            app: App::new(&modules.iter().collect::<Vec<_>>(), &[&converted])
                .expect("the package")
                .selecting(selected.clone()),
            env: Env::new(
                with_generic_forms(wanted.priority()),
                Vec::new(),
                wanted.options(),
                Vec::new(),
                Choice::First,
            )
            .expect("env"),
        }
    }

    /// A text as plain text.
    pub fn plain(&self, text: &Text) -> String {
        self.app.plain(&self.env, text).expect("the text renders")
    }
}
