//! The matcher shares the wallet's code path (spec section 5): the wallet writes its registration
//! with siros-credman's writer, the matcher reads it back, builds its context from it and converts
//! the ad-hoc metadata JWT (PaSO Proof Metadata §5) an entry carries for a type the registration
//! lacks. The two conversions are one source text, and every entry the matcher shows and emits
//! equals the wallet's. A claim label with no visible character refuses its entry before
//! Credential Manager reads it.

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
use siros_paso::PasoProfile;
use siros_paso::adhoc::{Carried, Verified};
use siros_paso::labels::LabelViolation;
use siros_paso::outcome::{Outcome, Unsupported};
use siros_syntax::{AllOf, Keyed};
use siros_testkit::fixtures::{Held, ORIGIN, parameters};
use siros_testkit::render::Language;
use siros_testkit::verifier::{self, ISSUER, secret_key};

use crate::common::{HaipHost, loaded, placement, registry};
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

/// Core A.1's `entry` carrying the ad-hoc metadata JWT (PaSO Proof Metadata §5) the card's issuer
/// signs over `metadata`, encoded.
fn carrying(entry: &str, metadata: &Value) -> String {
    let claims = json!({"iss": "https://issuer.bank.example", "sub": "https://bank.example/sca/card",
        "format": "dc+sd-jwt", "iat": NOW - 60, "exp": NOW + 600, "transaction_data_type": PAY,
        "metadata": metadata});
    let jwt = verifier::adhoc_jwt(
        &claims.to_string(),
        &secret_key("issuer-secret-1"),
        Some("issuer-key-1"),
        None,
    )
    .expect("the ad-hoc metadata JWT");
    let mut entry: Value = serde_json::from_str(entry).expect("Core A.1's entry");
    entry["metadata"] = json!(jwt);
    verifier::encode(&entry.to_string()).expect("the entry")
}

/// The request of Core A.1's query whose `transaction_data` holds `entries`.
fn requesting(core: &[String], entries: &[String]) -> String {
    let listed: Vec<String> = entries.iter().map(|entry| format!("\"{entry}\"")).collect();
    parameters(
        &member(&core[0], "dcql_query"),
        &format!(
            r#""transaction_data":[{}],"expected_origins":["{ORIGIN}"]"#,
            listed.join(",")
        ),
    )
}

/// The card whose metadata lists no transaction type: a request's ad-hoc JWT alone renders its
/// entry.
fn card() -> Held {
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
    card
}

/// The Payment entries of an emission.
fn payments(emission: &Emission) -> usize {
    emission
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
        .count()
}

#[test]
fn the_matcher_reads_the_wallets_registration_and_shows_an_ad_hoc_entry_as_the_wallet_does() {
    let core = annex("paso-core.md", "A.1");
    let types: Value = serde_json::from_str(&payment_metadata()).expect("the types");
    let text = requesting(&core, &[carrying(&core[1], &types[PAY])]);
    siros_testkit::signed_request!(let request = &text);
    let card = card();
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
    assert_eq!(payments(&matcher.1), 1, "the matcher offers the entry");
    assert_eq!(matcher, seen(&request, &wallet, &env, &wallet_context));
}

/// The ad-hoc metadata JWT of the request's first entry names `payee.id` `" "`, which shows no
/// visible character: PaSO refuses that metadata, so the entry. The second entry carries the
/// metadata as Payment A.1 writes it; it binds the card, and the matcher emits it.
#[test]
fn a_label_with_no_visible_character_refuses_its_entry_and_the_display_emits() {
    let core = annex("paso-core.md", "A.1");
    let types: Value = serde_json::from_str(&payment_metadata()).expect("the types");
    let mut blank = types[PAY].clone();
    let id = blank["claims"]
        .as_array_mut()
        .expect("claims")
        .iter_mut()
        .find(|claim| claim["path"] == json!(["payee", "id"]))
        .expect("payee.id");
    id["display"] = json!([{"locale": "en", "name": " "}]);
    let text = requesting(
        &core,
        &[carrying(&core[1], &blank), carrying(&core[1], &types[PAY])],
    );
    siros_testkit::signed_request!(let request = &text);
    let card = card();
    let credential = card.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential.clone()]).expect("a wallet");
    let env = english();
    let mut registration = registered(Language::English, &env);
    let base = registration
        .context(&request)
        .expect("the matcher's context");
    let read = Carried::read(&request).expect("a DC API request");
    let carried = siros_paso::view::carried(&read, &base, env.priority()).expect("converted");
    let context = loaded(&base, carried);

    let blank = request.entries().first().expect("the first entry");
    let refused = PasoProfile::default()
        .render(
            blank,
            request.envelope().channel().kind(),
            &credential,
            placement(&credential.format),
            &env,
            &context,
        )
        .expect("no fault");
    assert!(
        matches!(
            refused,
            Err(Outcome::Unsupported(Unsupported::ClaimLabel {
                violation: LabelViolation::Invisible,
                ..
            }))
        ),
        "{refused:?}"
    );
    let (_, emission) = seen(&request, &wallet, &env, &context);
    assert_eq!(payments(&emission), 1, "the second entry emits");
}
