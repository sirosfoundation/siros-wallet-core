//! The matcher shares the wallet's code path (spec section 5): the wallet writes its registration
//! with siros-credman's writer, the matcher reads it back, builds its context from it and converts
//! the ad-hoc metadata JWT (PaSO Proof Metadata §5) an entry carries for a type the registration
//! lacks. The two conversions are one source text, and every entry the matcher shows and emits
//! equals the wallet's.

use std::io::Cursor;

use serde_json::{Value, json};
use siros_credman::register::write;
use siros_credman::{Base, Emission, Emitted, Registration, Shown, emit};
use siros_i18n::{Bidi, Context, LocaleTag};
use siros_openid4vp::consent::ConsentEntry;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::matching::{Accepted, Consent, Display, Match, Views, display, offer};
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Choice, Env};
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::{Carried, Verified};
use siros_syntax::{AllOf, Keyed};
use siros_testkit::fixtures::{Held, ORIGIN, parameters};
use siros_testkit::render::Language;
use siros_testkit::verifier::{self, ISSUER, secret_key};

use crate::common::{HaipHost, loaded, registry};
use crate::{NOW, PAY, annex, english, member, payment_metadata};

/// The request matched in `context`, its views and display handed to `then`.
pub fn shown<T>(
    request: &Request<'_>,
    wallet: &Wallet<'_>,
    env: &Env,
    context: &Context,
    then: impl FnOnce(&Views<'_>, &Display<'_>) -> T,
) -> T {
    let registry = registry().expect("the real registry");
    let accepted = Accepted::new(request, &registry).expect("accepted");
    let matched = Match::run(&accepted, wallet, env, context).expect("no fault");
    let consent = Consent::of(&matched).expect("the wallet meets the request");
    let views = Views::of(&matched, env, context).expect("no fault");
    let sets = offer(&matched, &consent, Choice::First);
    let display = display(&sets, &views, &[]).expect("no fault");
    then(&views, &display)
}

/// The registration the test app writes for its matcher in `language`, for `env`'s priority
/// list: its sources in load order and no transaction type, read back through the matcher's
/// reader.
pub fn registered(language: Language, env: &Env) -> Registration<Cursor<Vec<u8>>> {
    let sources = language.sources().map(str::to_owned).to_vec();
    let base = Base::load(
        LocaleTag::parse(language.tag()).expect("a tag"),
        AllOf::new(env.priority().to_vec()).expect("a priority list"),
        Bidi::None,
        AllOf::new(sources).expect("the test app's sources"),
    )
    .expect("the base loads");
    let blob = write(&base, &Keyed::empty()).expect("the registration");
    let registration = Registration::open(Cursor::new(blob)).expect("the matcher reads it");
    assert_eq!(registration.base(), &base);
    registration
}

/// What the End-User sees of a request: each view's record id, which commits to its texts, and
/// its entry, then the display as Credential Manager draws it.
fn seen(
    request: &Request<'_>,
    wallet: &Wallet<'_>,
    env: &Env,
    context: &Context,
) -> (Vec<(String, ConsentEntry)>, Emission) {
    shown(request, wallet, env, context, |views, display| {
        let entries = views
            .iter()
            .map(|view| (view.record.id().as_str().to_owned(), view.entry.clone()))
            .collect();
        (entries, emit(display, context).expect("every choice emits"))
    })
}

#[test]
fn the_matcher_reads_the_wallets_registration_and_shows_an_ad_hoc_entry_as_the_wallet_does() {
    let core = annex("paso-core.md", "A.1");
    let types: Value = serde_json::from_str(&payment_metadata()).expect("the types");
    let claims = json!({"iss": "https://issuer.bank.example", "sub": "https://bank.example/sca/card",
        "format": "dc+sd-jwt", "iat": NOW - 60, "exp": NOW + 600, "transaction_data_type": PAY,
        "metadata": types[PAY]});
    let jwt = verifier::adhoc_jwt(
        &claims.to_string(),
        &secret_key("issuer-secret-1"),
        Some("issuer-key-1"),
        None,
    )
    .expect("the ad-hoc metadata JWT");
    let mut entry: Value = serde_json::from_str(&core[1]).expect("Core A.1's entry");
    entry["metadata"] = json!(jwt);
    let entry = verifier::encode(&entry.to_string()).expect("the entry");
    let text = parameters(
        &member(&core[0], "dcql_query"),
        &format!(r#""transaction_data":["{entry}"],"expected_origins":["{ORIGIN}"]"#),
    );
    siros_testkit::signed_request!(let request = &text);
    // The card's metadata lists no transaction type: the request's JWT alone renders the entry.
    let document = verifier::paso_document(
        "https://bank.example/sca/card",
        "dc+sd-jwt",
        "{}",
        None,
        ISSUER,
    )
    .expect("the card's PaSO document");
    let mut card = Held::new(
        "card",
        "dc+sd-jwt",
        r#"{"type": "https://bank.example/sca/card", "metadata": {}, "values": {"pan_last_four": "1234", "scheme": "visa"},
            "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    );
    card = card.with_issued().expect("the issued SD-JWT");
    card.documents
        .push(("paso".to_owned(), document.into_bytes()));
    let credential = card.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential.clone()]).expect("a wallet");
    let env = english();
    let own = Language::English.shared().expect("the test app's context");

    // The wallet verifies the JWT (Proof Metadata §5.3) before it converts it.
    let host = HaipHost::at(Timestamp(NOW));
    let verified = Verified::of(&request, &[&credential], &host).expect("verified");
    assert!(verified.refusals().is_empty(), "{:?}", verified.refusals());
    let converted = siros_paso::view::verified(&verified, own, env.priority()).expect("converted");
    assert_eq!(converted.len(), 1, "the JWT's source");
    let wallet_context = loaded(own, converted.clone());

    // The matcher reads the JWT unverified and converts it in the registration's context.
    let mut registration = registered(Language::English, &env);
    let matcher_context = registration
        .context(&request)
        .expect("the matcher's context");
    let read = Carried::read(&request).expect("a DC API request");
    let carried =
        siros_paso::view::carried(&read, &matcher_context, env.priority()).expect("converted");
    assert_eq!(carried, converted, "one conversion for both");

    let matcher = seen(&request, &wallet, &env, &matcher_context);
    let payments = matcher
        .1
        .sets()
        .iter()
        .flatten()
        .flatten()
        .filter(|emitted| {
            matches!(
                emitted,
                Emitted::Entry {
                    shown: Shown::Payment(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(payments, 1, "the matcher offers the entry");
    assert_eq!(matcher, seen(&request, &wallet, &env, &wallet_context));
}
