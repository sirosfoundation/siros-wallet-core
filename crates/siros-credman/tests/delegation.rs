//! A9 and K4 over the core's display: a set needs the wallet's display unless every entry's
//! credential is presentable without the wallet's UI, the request carries no `transaction_data`,
//! every row shows whole, nothing is left to choose and Credential Manager showed everything; the
//! matcher
//! sends `Full` delegation for a set that needs none, and the wallet refuses a background
//! fulfilment of a set that needs it with `access_denied`.

use siros_credman::{
    Delegation, FIELD_MAX, Fulfilment, HostDisplay, Presentable, SetFacts, TransactionData,
    WalletDisplay, WalletDisplayNeeded,
};
use siros_openid4vp::consent::Card;
use siros_openid4vp::ids::{CredentialId, TransactionType};
use siros_openid4vp::matching::{Accepted, Consent, Match, StaticEntry, Views, display, offer};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::rows::{Icon, Label, Row};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, env, parameters, request_of, unsigned};
use siros_testkit::{Binds, TestFormat, TestHost, TestProfile};

const QUERY: &str = r#"{"credentials":[{"id":"q","format":"test"}]}"#;
const OPTIONAL: &str = r#"{"credentials":[{"id":"q","format":"test"},{"id":"r","format":"test"}],
    "credential_sets":[{"options":[["q"]]},{"options":[["r"]],"required":false}]}"#;

fn registry() -> Registry<TestHost> {
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(TestFormat::new().expect("test format"));
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("type"), profile);
    builder.build().expect("registry")
}

fn held(id: &str, queries: &[&str]) -> Held {
    let answers: Vec<String> = queries.iter().map(|q| format!("\"{q}\"")).collect();
    let mut held = Held::new(
        id,
        "test",
        format!(r#"{{"answers":[{}],"alg":"A"}}"#, answers.join(",")),
    );
    held.documents.push((
        "test".to_owned(),
        br#"{"supports":["t1"],"nonconforming":[]}"#.to_vec(),
    ));
    held
}

/// The facts of the display's first set, over the wallet's static entry, and A9's answer to a
/// background fulfilment of it, Credential Manager having shown it as `host`.
fn judged(
    parameters: &str,
    wallet: &[Held],
    presentable: &[&str],
    host: HostDisplay,
) -> (SetFacts, Result<(), WalletDisplayNeeded>) {
    let received = unsigned(parameters).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry();
    let credentials = wallet
        .iter()
        .map(|held| held.credential().expect("credential"))
        .collect();
    let wallet = Wallet::new(credentials).expect("wallet");
    let env = env(&["en"], Vec::new()).expect("env");
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matched = Match::run(&accepted, &wallet, &env).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    let views = Views::of(&matched, &env).expect("views");
    let sets = offer(&matched, &consent, env.choice());
    let statics = [StaticEntry {
        id: "notice".to_owned(),
        card: Card {
            icon: Icon::DEFAULT,
            title: "Notice".to_owned(),
            subtitle: None,
            rows: vec![Row::full_text(Label::text("n".repeat(FIELD_MAX + 1)))],
        },
    }];
    let shown = display(&sets, &views, &statics).expect("display");
    let presentable: Vec<CredentialId<'_>> = presentable
        .iter()
        .map(|id| CredentialId::parse(*id).expect("id"))
        .collect();
    let presentable = Presentable(&presentable);
    let transactions = TransactionData::of(&request);
    let facts = SetFacts::of(&shown.sets()[0], presentable, transactions);
    (
        facts,
        Fulfilment::Background(host).check(&shown, 0, presentable, transactions),
    )
}

/// A case: its name, the request, the wallet, the credentials presentable without the wallet's
/// UI, Credential Manager's display level, and the facts A9 reads.
type Case<'c> = (
    &'c str,
    String,
    Vec<Held>,
    &'c [&'c str],
    HostDisplay,
    SetFacts,
);

#[test]
fn a_set_needs_the_wallet_display_unless_a9_holds() {
    let transaction = |dcql: &str, query: &str| {
        let entry = format!(r#"{{"type":"t1","credential_ids":["{query}"]}}"#);
        parameters(
            dcql,
            &format!(
                r#""transaction_data":["{}"]"#,
                siros_testkit::verifier::encode(&entry).expect("entry")
            ),
        )
    };
    let one = [held("c", &["q"])];
    // A credential id a field shows as its value: the test format's first row.
    let whole = "c".repeat(FIELD_MAX);
    let clipped = "c".repeat(FIELD_MAX + 1);
    let met = SetFacts {
        presentable: true,
        no_transaction_data: true,
        settled: true,
        whole: true,
    };
    let full = HostDisplay::Full;
    // The test profile's overlay shows its transaction's logo, an image no field shows.
    let (whole, clipped) = ([whole.as_str()], [clipped.as_str()]);
    let cases: [Case<'_>; 9] = [
        (
            "presentable, settled, whole, shown",
            parameters(QUERY, ""),
            one.to_vec(),
            &["c"],
            full,
            met,
        ),
        (
            "presentable on the wallet's UI alone",
            parameters(QUERY, ""),
            one.to_vec(),
            &[],
            full,
            SetFacts {
                presentable: false,
                ..met
            },
        ),
        (
            "a transaction",
            transaction(QUERY, "q"),
            one.to_vec(),
            &["c"],
            full,
            SetFacts {
                no_transaction_data: false,
                whole: false,
                ..met
            },
        ),
        (
            "transaction_data binding a query the set does not answer",
            transaction(OPTIONAL, "r"),
            one.to_vec(),
            &["c"],
            full,
            SetFacts {
                no_transaction_data: false,
                ..met
            },
        ),
        (
            "two candidates in one slot",
            parameters(QUERY, ""),
            vec![held("c", &["q"]), held("d", &["q"])],
            &["c", "d"],
            full,
            SetFacts {
                settled: false,
                ..met
            },
        ),
        (
            "an optional addition",
            parameters(OPTIONAL, ""),
            vec![held("c", &["q"]), held("d", &["r"])],
            &["c", "d"],
            full,
            SetFacts {
                settled: false,
                ..met
            },
        ),
        (
            "a field of FIELD_MAX characters",
            parameters(QUERY, ""),
            vec![held(whole[0], &["q"])],
            &whole,
            full,
            met,
        ),
        (
            "a clipped field",
            parameters(QUERY, ""),
            vec![held(clipped[0], &["q"])],
            &clipped,
            full,
            SetFacts {
                whole: false,
                ..met
            },
        ),
        (
            "Credential Manager skipped text",
            parameters(QUERY, ""),
            one.to_vec(),
            &["c"],
            HostDisplay::Skipped,
            met,
        ),
    ];
    for (case, request, wallet, presentable, host, want) in cases {
        let (facts, background) = judged(&request, &wallet, presentable, host);
        assert_eq!(facts, want, "{case}");
        let display = WalletDisplay::of(facts, host);
        let want = if facts == met && host == full {
            WalletDisplay::NotNeeded
        } else {
            WalletDisplay::Needed
        };
        assert_eq!(display, want, "{case}");
        match want {
            WalletDisplay::NotNeeded => {
                assert_eq!(Delegation::of(display), Delegation::Full, "{case}");
                assert_eq!(background, Ok(()), "{case}");
            }
            WalletDisplay::Needed => {
                assert_eq!(Delegation::of(display), Delegation::None, "{case}");
                let refused = background.expect_err(case);
                assert_eq!(refused, WalletDisplayNeeded::Needed { set: 0 }, "{case}");
                assert_eq!(refused.code(), ErrorCode::ACCESS_DENIED, "{case}");
            }
        }
    }
}
