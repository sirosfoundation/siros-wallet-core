//! Decision 19 over an mdoc's dates: `full-date` (tag 1004) and `tdate` (tag 0) elements reach a
//! card as typed values, which the wallet's main module formats, a wallet's message formats with
//! `:siros:date` or `:siros:datetime`, and the matcher reads as held. The expected texts are the
//! test app's CLDR patterns in its `[formats.date]`, applied by hand: en's `MMM d, y`,
//! `MMMM d, y`, `h:mm:ss a` and `h:mm:ss a z`, de's `dd.MM.y`, `d. MMMM y`, `HH:mm:ss` and
//! `HH:mm:ss z`, with each language's date-time glue.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_credman::register::{RegisteredCard, Registration, package};
use siros_credman::{Emitted, Shown, emit};
use siros_explain::{
    Date, DateTime, Explain, Fraction, Messages, ModuleId, Offset, Second, Text, Time, Value,
    checked,
};
use siros_i18n::{Declaration, LanguagePolicy, Module, Package};
use siros_mdoc::registration::{Registered, Resolved};
use siros_openid4vp::cbor::{self, Value as Cbor};
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::json::Node;
use siros_openid4vp::rendering::Rendering;
use siros_openid4vp::rows::{Choice, Env, Row};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, OPTIONS, ORIGIN, parameters};
use siros_testkit::issuer::{self, DOCUMENT, IssueError};
use siros_testkit::render::{App, compilers, formats, main_sources, written};

use crate::common::own_modules;
use crate::matcher::{registered_modules, shown};

const SPACE: &str = "org.iso.18013.5.1";

/// A wallet's messages over a typed date.
#[derive(Debug, Clone, Copy, Explain)]
#[explain(domain = "dated")]
enum Dated {
    Day { value: Date },
    BareDay { value: Date },
    Moment { value: DateTime },
    BareMoment { value: DateTime },
}

/// The wallet's module of [`Dated`], with `[formats.date]` of each language of the main module.
fn dated_module() -> Module {
    let source = |language: &str, cldr: &str| {
        let from = cldr.find("[formats.date]").expect("the date options");
        let options = &cldr[from..];
        let options = options.find("\n[").map_or(options, |end| &options[..end]);
        format!(
            "@locale {language}\n@dir ltr\n---\n\
             day = {{$value :siros:date length=long}}\n\
             bare_day = {{$value}}\n\
             moment = {{$value :siros:datetime length=long}}\n\
             bare_moment = {{$value}}\n\n{options}\n"
        )
    };
    let [en, de] = main_sources();
    Module::load(
        ModuleId::Crate(checked!(siros_explain::Domain, "dated")),
        &Declaration::new(Dated::messages()).expect("a declaration"),
        &[&source("en", &en), &source("de", &de)],
        LanguagePolicy::Any,
        &compilers().expect("the load halves"),
    )
    .expect("the wallet's module")
}

fn wallet_env(language: &str) -> Env {
    Env::new(
        vec![LocaleTag::parse(language).expect("a tag")],
        Vec::new(),
        OPTIONS,
        Vec::new(),
        Choice::First,
    )
    .expect("the configuration")
}

/// The element's value as ISO/IEC 18013-5 §7.2.1 types it.
fn tagged(element: &str, value: &Node<'_>) -> Result<Cbor, IssueError> {
    let date = |tag, value: &Node<'_>| {
        let written = value.as_str().ok_or(IssueError::View("a date"))?;
        Ok(Cbor::Tag(tag, Box::new(Cbor::Text(written.to_owned()))))
    };
    match element {
        "birth_date" => date(1004, value),
        "signed_at" => date(0, value),
        "privileges" => Ok(Cbor::Array(vec![Cbor::Map(vec![(
            Cbor::Text("issue_date".to_owned()),
            date(
                1004,
                value
                    .as_array()
                    .and_then(<[Node<'_>]>::first)
                    .and_then(|first| first.get("issue_date"))
                    .ok_or(IssueError::View("a privilege"))?,
            )?,
        )])])),
        _ => Ok(cbor::of_json(value)?),
    }
}

/// The value of the row labelled `label`.
fn value_of<'r>(rows: &'r [Row], label: &str) -> &'r Text {
    rows.iter()
        .find(|row| written(&row.label) == Some(label))
        .and_then(|row| row.value.as_ref())
        .and_then(siros_openid4vp::rows::Value::text)
        .unwrap_or_else(|| panic!("the row {label}"))
}

/// Catches a date element shown as written, in any path a card's text takes: the kit's row, a
/// wallet's message over its value, and the matcher's held text.
#[test]
fn an_mdocs_dates_show_as_typed_values_in_every_path() {
    let view = format!(
        r#"{{"type": "org.iso.18013.5.1.mDL", "metadata": {{}}, "values": {{"{SPACE}": {{
            "given_name": "2026-09-02",
            "birth_date": "1961-08-17",
            "signed_at": "2026-09-02T10:15:30Z",
            "privileges": [{{"issue_date": "2018-08-09"}}]}}}},
            "issuer_alg": -7, "device_alg": -7, "device_curve": "P-256"}}"#
    );
    let view = Node::parse(&view).expect("a view");
    let stored = issuer::issue_as(&view, tagged).expect("the mdoc");
    let registered = Registered::of(
        &URL_SAFE_NO_PAD.encode(stored),
        &Resolved {
            issuer_curve: Some("P-256"),
            ..Resolved::default()
        },
    )
    .expect("registered");
    let mut held = Held::new(
        "mdl",
        "mso_mdoc",
        std::str::from_utf8(registered.view()).expect("UTF-8"),
    );
    held.documents
        .push((DOCUMENT.to_owned(), registered.document().to_vec()));
    let credential = held.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential]).expect("a wallet");
    let dcql = format!(
        r#"{{"credentials": [{{"id": "mdl", "format": "mso_mdoc", "meta": {{"doctype_value": "org.iso.18013.5.1.mDL"}},
        "claims": [{{"path": ["{SPACE}", "given_name"]}}, {{"path": ["{SPACE}", "birth_date"]}},
                   {{"path": ["{SPACE}", "signed_at"]}}, {{"path": ["{SPACE}", "privileges"]}}]}}]}}"#
    );
    let text = parameters(&dcql, &format!(r#""expected_origins":["{ORIGIN}"]"#));
    siros_testkit::signed_request!(let request = &text);

    let mut modules = own_modules();
    modules.push(dated_module());
    let app = App::new(&modules.iter().collect::<Vec<_>>(), &[]).expect("the wallet's app");
    let rendering = app.rendering().expect("the wallet's rendering");
    let english = wallet_env("en");
    let rows = shown(&request, &wallet, &english, &rendering, |views, _| {
        let view = views.iter().next().expect("the credential's entry");
        view.entry.card().rows.clone()
    });

    let birth = Date::new(1961, 8, 17).expect("a date");
    let signed = DateTime::new(
        Date::new(2026, 9, 2).expect("a date"),
        Time::new(10, 15, Some(Second::new(30, Fraction::NONE).expect("30"))).expect("a time"),
        Some(Offset::new(0).expect("UTC")),
    );
    let issued = Date::new(2018, 8, 9).expect("a date");
    assert_eq!(
        value_of(&rows, "birth_date"),
        &Text::Value(Value::Date(birth))
    );
    assert_eq!(
        value_of(&rows, "signed_at"),
        &Text::Value(Value::DateTime(signed))
    );
    assert_eq!(
        value_of(&rows, "issue_date"),
        &Text::Value(Value::Date(issued))
    );
    assert_eq!(
        value_of(&rows, "given_name"),
        &Text::Raw("2026-09-02".to_owned())
    );

    // The texts bare, through the main module, then through the wallet's messages: en, de.
    let row = |label| value_of(&rows, label).clone();
    let expected: [(Text, &str, &str); 7] = [
        (row("birth_date"), "Aug 17, 1961", "17.08.1961"),
        (
            row("signed_at"),
            "Sep 2, 2026, 10:15:30\u{202f}AM",
            "02.09.2026, 10:15:30",
        ),
        (row("issue_date"), "Aug 9, 2018", "09.08.2018"),
        (
            Text::of(&Dated::Day { value: birth }),
            "August 17, 1961",
            "17. August 1961",
        ),
        (
            Text::of(&Dated::BareDay { value: birth }),
            "Aug 17, 1961",
            "17.08.1961",
        ),
        (
            Text::of(&Dated::Moment { value: signed }),
            "September 2, 2026 at 10:15:30\u{202f}AM GMT+0",
            "2. September 2026 um 10:15:30 GMT+0",
        ),
        (
            Text::of(&Dated::BareMoment { value: signed }),
            "Sep 2, 2026, 10:15:30\u{202f}AM",
            "02.09.2026, 10:15:30",
        ),
    ];
    let german = wallet_env("de");
    for (text, en, de) in &expected {
        assert_eq!(app.plain(&english, text).expect("en"), *en);
        assert_eq!(app.plain(&german, text).expect("de"), *de);
    }

    // The registration's package holds the rows' texts, and the matcher reads them.
    let halves = formats().expect("the render halves");
    let declared: Vec<Module> = own_modules();
    for (env, column) in [(&english, 0), (&german, 1)] {
        let declared_ids: Vec<ModuleId> = declared.iter().map(Module::id).collect();
        let built = shown(&request, &wallet, env, &rendering, |views, _| {
            let cards: Vec<RegisteredCard<'_>> = views
                .iter()
                .map(|view| RegisteredCard {
                    credential: view.record.credential(),
                    card: view.entry.card(),
                })
                .collect();
            package(
                &Registration {
                    modules: &registered_modules(&declared),
                    own: &declared_ids,
                    credentials: &cards,
                    statics: &[],
                    transactions: &[],
                },
                env,
                &halves,
            )
            .expect("the registration's package")
        });
        let matcher = Rendering::new(
            Package::read(built.bytes(), built.root()).expect("the package"),
            &halves,
            &declared_ids,
        )
        .expect("a registration");
        shown(&request, &wallet, env, &matcher, |views, display| {
            let view = views.iter().next().expect("the credential's entry");
            let renderer = matcher
                .renderer(
                    view.selected,
                    view.card_module,
                    Some(view.record.credential().as_str()),
                    env,
                )
                .expect("no fault")
                .expect("a language");
            for (text, en, de) in &expected[..3] {
                assert!(renderer.holds(text).expect("reads"), "{text:?}: held");
                let want = if column == 0 { en } else { de };
                assert_eq!(renderer.plain(text).expect("held"), *want);
            }
            let emission = emit(display, &matcher, env).expect("no fault");
            assert!(emission.refused().is_empty(), "{:?}", emission.refused());
            let drawn = emission.sets().iter().flatten().flatten().any(|emitted| {
                matches!(
                    emitted,
                    Emitted::Entry {
                        shown: Shown::Standard(_),
                        ..
                    }
                )
            });
            assert!(drawn, "the credential's Standard entry");
        });
    }
}
