//! Decision 19 over an mdoc's dates: `full-date` (tag 1004) and `tdate` (tag 0) elements reach a
//! card through `ClaimText::Date` and `ClaimText::DateTime`, which the test app's wording formats
//! with `:siros:date` and `:siros:datetime`, in the wallet and in the matcher alike; a wallet's
//! own statement formats them at another length. The expected texts are the test app's CLDR
//! patterns in its `[formats.date]`, applied by hand: en's `MMM d, y`, `MMMM d, y`, `h:mm:ss a`
//! and `h:mm:ss a z`, de's `dd.MM.y`, `d. MMMM y`, `HH:mm:ss` and `HH:mm:ss z`, with each
//! language's date-time glue.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_credman::{Emitted, Shown, emit};
use siros_i18n::{Context, LocaleTag, Message};
use siros_mdoc::registration::{Registered, Resolved};
use siros_mdoc::stored::Curve;
use siros_openid4vp::cbor::{self, Value as Cbor};
use siros_openid4vp::json::Node;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::{Choice, Env, Row};
use siros_openid4vp::wallet::Wallet;
use siros_syntax::{Date, DateTime, Fraction, Offset, Second, Time};
use siros_testkit::fixtures::{Held, ORIGIN, parameters};
use siros_testkit::issuer::{self, DOCUMENT, IssueError};
use siros_testkit::render::Language;

use crate::matcher::{registered, shown};

const SPACE: &str = "org.iso.18013.5.1";

/// A wallet's own statements over a typed date.
#[derive(Debug, Clone, Copy, Message)]
enum Dated {
    /// A day.
    #[message(id = "dated.day")]
    Day { value: Date },
    /// An instant.
    #[message(id = "dated.moment")]
    Moment { value: DateTime },
}

/// The wallet's wording of [`Dated`] in `language`: both at the long length.
fn dated_wording(language: Language) -> String {
    format!(
        "@locale {}\n@dir ltr\n---\n\n[integration.dated]\n\
         day = {{$value :siros:date length=long}}\n\
         moment = {{$value :siros:datetime length=long}}\n",
        language.tag()
    )
}

fn wallet_env(language: Language) -> Env {
    Env::new(
        vec![LocaleTag::parse(language.tag()).expect("a tag")],
        Vec::new(),
        Choice::First,
    )
    .expect("the configuration")
}

/// The element's value as ISO/IEC 18013-5 §7.2.1 types it.
fn tagged(element: &str, value: &Node<'_>) -> Result<Cbor, IssueError> {
    let date = |tag, value: &Node<'_>| {
        let written = value
            .as_str()
            .ok_or(IssueError::View { member: "a date" })?;
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
                    .ok_or(IssueError::View {
                        member: "a privilege",
                    })?,
            )?,
        )])])),
        _ => Ok(cbor::of_json(value)?),
    }
}

/// The value of the row labelled `label`, as shown.
fn value_of(rows: &[Row], label: &str) -> String {
    rows.iter()
        .find(|row| row.label.to_string() == label)
        .and_then(|row| row.value.as_ref())
        .and_then(siros_openid4vp::rows::Value::text)
        .map(ToString::to_string)
        .unwrap_or_else(|| panic!("the row {label}"))
}

/// The card's rows of the request's one entry, matched in `context`, which Credential Manager
/// draws as a Standard entry.
fn card_rows(request: &Request<'_>, wallet: &Wallet<'_>, env: &Env, context: &Context) -> Vec<Row> {
    shown(request, wallet, env, context, |views, display| {
        let emission = emit(display, context).expect("every choice emits");
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
        let view = views.iter().next().expect("the credential's entry");
        view.entry.card().rows.clone()
    })
}

/// Catches a date element shown as written in a card, in the wallet or in the matcher.
#[test]
fn an_mdocs_dates_show_formatted_in_the_wallet_and_in_the_matcher() {
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
    let registered_mdoc = Registered::of(
        &URL_SAFE_NO_PAD.encode(stored),
        &Resolved {
            issuer_curve: Some(Curve::P256),
            ..Resolved::default()
        },
    )
    .expect("registered");
    let mut held = Held::new(
        "mdl",
        "mso_mdoc",
        std::str::from_utf8(registered_mdoc.view().as_bytes()).expect("UTF-8"),
    );
    held.documents.push((
        DOCUMENT.to_owned(),
        registered_mdoc.document().as_bytes().to_vec(),
    ));
    let credential = held.credential().expect("a credential");
    let wallet = Wallet::new(vec![credential]).expect("a wallet");
    let dcql = format!(
        r#"{{"credentials": [{{"id": "mdl", "format": "mso_mdoc", "meta": {{"doctype_value": "org.iso.18013.5.1.mDL"}},
        "claims": [{{"path": ["{SPACE}", "given_name"]}}, {{"path": ["{SPACE}", "birth_date"]}},
                   {{"path": ["{SPACE}", "signed_at"]}}, {{"path": ["{SPACE}", "privileges"]}}]}}]}}"#
    );
    let text = parameters(&dcql, &format!(r#""expected_origins":["{ORIGIN}"]"#));
    siros_testkit::signed_request!(let request = &text);

    let birth = Date::new(1961, 8, 17).expect("a date");
    let signed = DateTime::new(
        Date::new(2026, 9, 2).expect("a date"),
        Time::new(10, 15, Some(Second::new(30, Fraction::NONE).expect("30"))).expect("a time"),
        Some(Offset::new(0).expect("UTC")),
    );
    // Per language: the card's birth_date, signed_at and issue_date, then the wallet's own
    // statements over birth_date and signed_at.
    let expected = [
        (
            Language::English,
            [
                "Aug 17, 1961",
                "Sep 2, 2026, 10:15:30\u{202f}AM",
                "Aug 9, 2018",
            ],
            [
                "August 17, 1961",
                "September 2, 2026 at 10:15:30\u{202f}AM GMT+0",
            ],
        ),
        (
            Language::German,
            ["17.08.1961", "02.09.2026, 10:15:30", "09.08.2018"],
            ["17. August 1961", "2. September 2026 um 10:15:30 GMT+0"],
        ),
    ];
    for (language, card, long) in expected {
        let env = wallet_env(language);
        let own = language.shared().expect("the test app's context");
        let matcher = registered(language, &env)
            .context(&request)
            .expect("the matcher's context");
        for context in [own, &matcher] {
            let rows = card_rows(&request, &wallet, &env, context);
            assert_eq!(
                ["birth_date", "signed_at", "issue_date"].map(|label| value_of(&rows, label)),
                card,
                "{}",
                language.tag()
            );
            assert_eq!(value_of(&rows, "given_name"), "2026-09-02");
        }
        let worded = own
            .clone()
            .module(&dated_wording(language))
            .expect("the wallet's wording");
        let resolve = |statement: &Dated| {
            worded
                .resolve(statement)
                .expect("the wallet words it")
                .to_string()
        };
        assert_eq!(
            [
                resolve(&Dated::Day { value: birth }),
                resolve(&Dated::Moment { value: signed })
            ],
            long
        );
    }
}
