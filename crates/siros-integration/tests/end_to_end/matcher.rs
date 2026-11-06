//! I37's ad-hoc clause (section 4.14 of the design, "Ad-hoc metadata"): an entry whose ad-hoc
//! metadata JWT (PaSO Proof Metadata §5) the registration's package was built without is offered
//! and rendered by the matcher, which reads the JWT unverified and renders its converted module
//! beside the package; each text equals the wallet's for the verified JWT.

use serde_json::{Value, json};
use siros_credman::register::{Registration, package};
use siros_credman::{Emitted, Shown, emit};
use siros_explain::{ModuleId, Text};
use siros_i18n::{Module, Package};
use siros_openid4vp::consent::{Card, ConsentEntry};
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::matching::{Accepted, Consent, Display, Match, Views, display, offer};
use siros_openid4vp::rendering::Rendering;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Choice, Env, Value as RowValue};
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::Carried;
use siros_testkit::fixtures::{Held, ORIGIN, parameters};
use siros_testkit::render::{App, formats};
use siros_testkit::verifier::{self, ISSUER, ISSUER_KEY};

use crate::common::{HaipHost, own_modules, registry};
use crate::{NOW, PAY, annex, english, member, payment_metadata};

/// The texts of an entry a request decides: its overlay's.
fn request_texts(entry: &ConsentEntry) -> Vec<&Text> {
    let mut out: Vec<&Text> = Vec::new();
    if let Some(overlay) = entry.overlay() {
        out.extend(&overlay.hint);
        for row in overlay
            .rows
            .iter()
            .chain(overlay.header.iter().flat_map(|header| &header.rows))
        {
            out.push(&row.label);
            out.extend(row.value.as_ref().and_then(RowValue::text));
            out.extend(&row.section);
        }
        if let Some(transaction) = &overlay.header {
            out.extend([&transaction.counterparty, &transaction.amount]);
        }
    }
    out
}

/// The request matched over `rendering`, its views and display handed to `then`.
fn shown<T>(
    request: &Request<'_>,
    wallet: &Wallet<'_>,
    env: &Env,
    rendering: &Rendering<'_>,
    then: impl FnOnce(&Views<'_>, &Display<'_>) -> T,
) -> T {
    let registry = registry().expect("the real registry");
    let accepted = Accepted::new(request, &registry).expect("accepted");
    let matched = Match::run(&accepted, wallet, env, rendering).expect("no fault");
    let consent = Consent::of(&matched).expect("the wallet meets the request");
    let views = Views::of(&matched, env).expect("no fault");
    let sets = offer(&matched, &consent, Choice::First);
    let display = display(&sets, &views, &[]).expect("no fault");
    then(&views, &display)
}

#[test]
fn the_matcher_offers_and_renders_an_entry_with_ad_hoc_metadata_as_the_wallet_does() {
    let core = annex("paso-core.md", "A.1");
    let types: Value = serde_json::from_str(&payment_metadata()).expect("the types");
    let claims = json!({"iss": "https://issuer.bank.example", "sub": "https://bank.example/sca/card",
        "format": "dc+sd-jwt", "iat": NOW - 60, "exp": NOW + 600, "transaction_data_type": PAY,
        "metadata": types[PAY]});
    let jwt = verifier::adhoc_jwt(&claims.to_string(), &ISSUER_KEY, Some("issuer-key-1"), None)
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
            "jwt": "eyJhbGciOiJFUzI1NiJ9.card.sig", "alg": "ES256", "curve": "P-256", "key_alg": "ES256", "key_curve": "P-256"}"#,
    );
    card.documents = vec![("paso".to_owned(), document.into_bytes())];
    let credential = card.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential.clone()]).expect("a wallet");
    let env = english();
    let modules: Vec<Module> = own_modules();
    let own: Vec<ModuleId> = modules.iter().map(Module::id).collect();
    let formats = formats().expect("the render halves");

    // The wallet verifies the JWT (Proof Metadata §5.3) before it converts it.
    let host = HaipHost::at(Timestamp(NOW));
    let verified = Carried::verified(&request, &[&credential], &host).expect("verified");
    assert!(verified.refusals().is_empty(), "{:?}", verified.refusals());
    let main = siros_testkit::render::main_locales().expect("the main module");
    let converted = siros_paso::view::carried(&verified, &main, env.priority()).expect("converted");
    assert_eq!(converted.len(), 1, "the JWT's module");
    let live = App::new(
        &modules.iter().collect::<Vec<_>>(),
        &converted.iter().collect::<Vec<_>>(),
    )
    .expect("the wallet's app");
    let wallet_rendering = live.rendering().expect("the wallet's rendering");

    // The registration: the card's texts, no transaction type.
    let built = shown(&request, &wallet, &env, &wallet_rendering, |views, _| {
        let cards: Vec<(&str, &Card)> = views
            .iter()
            .map(|view| (view.record.credential.as_str(), view.entry.card()))
            .collect();
        package(
            &Registration {
                modules: &modules.iter().collect::<Vec<_>>(),
                own: &own,
                credentials: &cards,
                statics: &[],
                transactions: &[],
            },
            &env,
            &formats,
        )
        .expect("the registration's package")
    });
    let registered = Package::read(built.bytes(), built.root()).expect("the package");

    // The matcher reads the JWT unverified and converts it over the package's main entries.
    let read = Carried::read(&request);
    let carried = siros_paso::view::carried(
        &read,
        &registered.main_locales().expect("the main entries"),
        env.priority(),
    )
    .expect("converted");
    assert_eq!(carried, converted, "one conversion for both");
    let matcher = Rendering::new(registered, &formats, &own)
        .expect("a registration")
        .carrying(&carried);
    let (texts, differences) = shown(&request, &wallet, &env, &matcher, |views, display| {
        let emission = emit(display, &matcher, &env).expect("no fault");
        assert!(emission.refused().is_empty(), "{:?}", emission.refused());
        let payments = emission
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
        let (mut texts, mut differences) = (0, 0);
        for view in views.iter() {
            assert!(view.selected.is_some(), "the ad-hoc module shows");
            let credential = Some(view.record.credential.as_str());
            let renderer = matcher
                .renderer(view.selected, credential, &env)
                .expect("no fault")
                .expect("a language");
            let wallet = wallet_rendering
                .renderer(view.selected, None, &env)
                .expect("no fault")
                .expect("a language");
            assert_eq!(renderer.inputs(), wallet.inputs());
            for text in request_texts(&view.entry) {
                texts += 1;
                if renderer.formatted(text).expect("renders")
                    != wallet.formatted(text).expect("renders")
                {
                    differences += 1;
                }
            }
        }
        (texts, differences)
    });
    assert!(texts > 0, "the entry shows its texts");
    assert_eq!(differences, 0, "of {texts} texts");
}
