//! The renderings the PaSO rulebooks and Core state in their Annex examples. Payloads and
//! metadata are read verbatim from `data/paso-d2` (PaSO draft 2); each expectation is the
//! example's own sentence and screen. Where the example's data cannot reach its screen (a
//! placeholder digest, a label over §3.3's length), the expectation is the rule that refuses it,
//! then the screen with that one value repaired.

mod common;

use common::{
    Card, PAY, Screen, Seen, Shown, annex, en, entry, env, member, png, presenting, shown, sri,
};
use siros_openid4vp::rows::{Amounts, Env, HttpsUrl, Image, ImageRef, Value};
use siros_paso::outcome::{NotCompatible, Outcome, Unsupported};
use siros_paso::{Fetch, PasoProfile};
use siros_testkit::verifier::ISSUER;

/// An expected title, confirm and deny actions, and hint.
fn said(
    (title, confirm, deny, hint): (&str, &str, &str, Option<&str>),
) -> (String, String, String, Option<String>) {
    (
        title.to_owned(),
        confirm.to_owned(),
        deny.to_owned(),
        hint.map(str::to_owned),
    )
}

/// An expected payment's merchant and amount.
fn paid(merchant: &str, amount: &str) -> Option<(String, String)> {
    Some((merchant.to_owned(), amount.to_owned()))
}

/// An entry rendered for a card whose metadata gives `meta` for the entry's type (`{}`: the
/// Mandate rulebook needs none).
fn render(entry_json: &str, meta: &str, env: &Env, profile: &PasoProfile) -> Result<Seen, Outcome> {
    let kind = member(entry_json, "type");
    let card = Card::new("mso_mdoc", &format!("{{{kind}: {meta}}}"), None, ISSUER);
    let rendered = profile
        .render(
            &entry(entry_json),
            &card.credential(),
            crate::common::placement(&card.credential().format),
            env,
        )
        .expect("no fault")?;
    let kind: String = serde_json::from_str(&kind).expect("the type");
    let screen = Screen::of(&kind, meta, &presenting(env, &rendered.view.locale));
    Ok(Seen { rendered, screen })
}

fn view(rendered: Result<Seen, Outcome>) -> Seen {
    rendered.expect("the entry renders")
}

fn with_logo(url: &str, content: Vec<u8>) -> PasoProfile {
    PasoProfile::default()
        .with_languages(siros_testkit::render::languages())
        .with_resource(
            HttpsUrl::parse(url).expect("url"),
            Fetch::Fetched {
                content,
                media: "image/png".to_owned(),
            },
        )
}

fn amount(text: &str) -> Option<(&'static str, &str)> {
    Some(("currency_amount", text))
}

fn plain(text: &str) -> Option<(&'static str, &str)> {
    Some(("text", text))
}

/// A date as the wallet's en options write it: CLDR 49's medium date, `MMM d, y`. The rulebooks'
/// screens write the day first (`3 Jun 2026`), as CLDR's en-GB does.
fn date(text: &str) -> Option<(&'static str, &str)> {
    Some(("date", text))
}

fn in_section(mut row: Shown, section: &str) -> Shown {
    row.2 = Some(section.to_owned());
    row
}

#[test]
fn payment_a1_renders_as_its_screen_with_a_logo_that_verifies() {
    let blocks = annex("Payment.md", "A.1");
    let (entry_json, meta) = (&blocks[0], member(&blocks[1], PAY));
    let logo = png(64, 64);
    let url = "https://cdn.acme.example/logo.png";
    let written = "sha256-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz=";
    // As written, the #integrity value is no SHA-256 digest (51 base64 characters): no content
    // verifies it, and the entry is not compatible (Core §7.4.2 step 3).
    assert_eq!(written.split_once('-').map(|(_, b)| b.len()), Some(51));
    let as_written = render(entry_json, &meta, &en(), &with_logo(url, logo.clone()));
    assert!(matches!(
        &as_written,
        Err(Outcome::NotCompatible(NotCompatible::Image { failure, .. }))
            if failure.to_string().contains("#integrity")
    ));
    let repaired = entry_json.replace(written, &sri(&logo));
    let rendered = render(&repaired, &meta, &en(), &with_logo(url, logo.clone())).expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Confirm Payment", "Pay", "Cancel", None))
    );
    let shown = rendered.rows();
    assert_eq!(
        shown[..2],
        [
            shown_row("Amount", amount("€49.99")),
            shown_row("Payee", plain("Acme Store"))
        ]
    );
    assert_eq!(
        rendered.view.rows[2].row.value,
        Some(Value::Image(Image::Embedded(ImageRef {
            source: url.to_owned(),
            media: "image/png".to_owned(),
            width: 64,
            height: 64,
        })))
    );
    assert_eq!(
        rendered.plain(&rendered.view.rows[2].row.label),
        "Payee logo"
    );
    assert_eq!(rendered.payment(), paid("Acme Store", "€49.99"));
    assert_eq!(rendered.view.locale.as_str(), "en");
    // German, as the metadata fixes it; the amount as the payload gives it.
    let de = view(render(
        &repaired,
        &meta,
        &env(&["de"], Amounts::Formatted),
        &with_logo(url, logo),
    ));
    assert_eq!(de.labels(), ["Betrag", "Empfänger", "Logo des Empfängers"]);
    assert_eq!(
        (
            de.plain(&de.view.title).as_str(),
            de.plain(&de.view.actions.confirm).as_str()
        ),
        ("Zahlung bestätigen", "Bezahlen")
    );
}

fn shown_row(label: &str, value: Option<(&'static str, &str)>) -> Shown {
    shown(label, value)
}

#[test]
fn core_a4_shows_core_a1_with_payment_a1s_metadata() {
    let core = annex("paso-core.md", "A.1");
    let entry_json = &core[1];
    let meta = member(&annex("Payment.md", "A.1")[1], PAY);
    // Payment A.1's metadata titles the screen; the wallet's table formats the amount.
    let rendered = render(
        entry_json,
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Confirm Payment", "Pay", "Cancel", None))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Amount", amount("€49.99")),
            shown_row("Payee", plain("Shop Inc."))
        ]
    );
    // A.4 exactly: without the metadata's transaction_title the wallet titles it (Proof
    // Metadata §3.2), and amounts stay as written (View §3 MAY).
    let untitled = meta.replace(
        r#""transaction_title": [{"locale": "en", "value": "Confirm Payment"}, {"locale": "de", "value": "Zahlung bestätigen"}], "#,
        "",
    );
    assert_ne!(untitled, meta);
    let rendered = render(
        entry_json,
        &untitled,
        &env(&["en"], Amounts::Written),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Payment Confirmation", "Pay", "Cancel", None))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Amount", amount("49.99 EUR")),
            shown_row("Payee", plain("Shop Inc."))
        ]
    );
    assert_eq!(rendered.payment(), paid("Shop Inc.", "49.99 EUR"));
}

#[test]
fn generic_a1_renders_in_payload_order_in_english_and_german() {
    let blocks = annex("Generic.md", "A.1");
    let meta = member(&blocks[1], "urn:paso:sca:global:generic:login:1");
    let rendered = render(
        &blocks[0],
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Confirm Sign-In", "Sign In", "Cancel", None))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Relying Party", plain("Acme Cloud")),
            shown_row("Device", plain("Chrome on macOS · Berlin, DE")),
            shown_row("Purpose", plain("Sign in to your account")),
        ]
    );
    assert_eq!(rendered.view.payment, None);
    let de = view(render(
        &blocks[0],
        &meta,
        &env(&["de"], Amounts::Formatted),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    ));
    assert_eq!(de.labels(), ["Dienstanbieter", "Gerät", "Zweck"]);
    assert_eq!(
        (
            de.plain(&de.view.title).as_str(),
            de.plain(&de.view.actions.confirm).as_str()
        ),
        ("Anmeldung bestätigen", "Anmelden")
    );
}

#[test]
fn generic_a2_needs_its_long_label_shortened_then_shows_its_screen() {
    let blocks = annex("Generic.md", "A.2");
    let meta = member(&blocks[1], "urn:paso:sca:global:generic:aisp:1");
    // Its last label has 69 grapheme clusters, over the 60 of Proof Metadata §3.3.
    let rendered = render(
        &blocks[0],
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    );
    assert_eq!(
        rendered.as_ref().err().map(ToString::to_string).as_deref(),
        Some("claim ['data_recipients_disclosed'] label: 69 grapheme clusters, more than 60")
    );
    assert!(matches!(
        rendered,
        Err(Outcome::Unsupported(Unsupported::ClaimLabel(..)))
    ));
    let short = "Recipients disclosed separately by the service";
    let meta = meta.replace(
        "Recipients of your data have been disclosed separately by the service",
        short,
    );
    let rendered = render(
        &blocks[0],
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Authorize Data Sharing", "Authorize", "Cancel", None))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Service", plain("Budget Tracker by ExampleFin")),
            shown_row(
                "Data shared",
                plain("Account balances and transaction history (last 90 days)")
            ),
            shown_row("Valid until", date("Sep 2, 2026")),
            shown_row(short, None),
        ]
    );
}

#[test]
fn generic_a3_shows_the_embedded_payment_as_a_section_and_the_hint() {
    let blocks = annex("Generic.md", "A.3");
    let meta = member(&blocks[1], "urn:paso:sca:global:generic:emandate:1");
    let hint = "Streaming Co. will be able to collect up to the amount shown each month for up to 24 months.";
    let rendered = render(
        &blocks[0],
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said((
            "Set Up Recurring Payment",
            "Authorize Mandate",
            "Cancel",
            Some(hint)
        ))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Mandate reference", plain("MND-2026-0042")),
            shown_row("Frequency", plain("Monthly, up to 24 months")),
            in_section(
                shown_row("Amount per collection", amount("€19.99")),
                "Payment Details"
            ),
            in_section(
                shown_row("Payee", plain("Streaming Co.")),
                "Payment Details"
            ),
        ]
    );
    // security_hint has an English entry and no default: German first selects English (View
    // §4); German alone excludes the credential.
    let de_en = view(render(
        &blocks[0],
        &meta,
        &env(&["de", "en"], Amounts::Formatted),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    ));
    assert_eq!(de_en.view.locale.as_str(), "en");
    assert!(matches!(
        render(
            &blocks[0],
            &meta,
            &env(&["de"], Amounts::Formatted),
            &PasoProfile::default().with_languages(siros_testkit::render::languages())
        ),
        Err(Outcome::Excluded(_))
    ));
}

#[test]
fn generic_a4_shows_its_screen_and_the_metadatas_german_labels() {
    let blocks = annex("Generic.md", "A.4");
    let meta = member(&blocks[1], "urn:paso:sca:global:generic:limit-change:1");
    let hint = "Raising your daily limit increases the maximum amount that could be spent if your card is misused.";
    let rendered = render(
        &blocks[0],
        &meta,
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said(("Confirm Limit Change", "Change Limit", "Cancel", Some(hint)))
    );
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Limit type", plain("Daily transaction limit")),
            shown_row("Current limit", amount("€1,000.00")),
            shown_row("New limit", amount("€2,500.00")),
            shown_row("Effective from", date("Jun 3, 2026")),
        ]
    );
    let de = render(
        &blocks[0],
        &meta,
        &env(&["de"], Amounts::Formatted),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        de.text(),
        said((
            "Limit-Änderung bestätigen",
            "Limit ändern",
            "Abbrechen",
            Some(
                "Eine Erhöhung des Tageslimits erhöht den Betrag, der bei Missbrauch maximal abfließen kann."
            )
        ))
    );
    // The German labels are the metadata's; the values' German wording is the wallet's table's.
    let labels = de.labels();
    assert_eq!(
        labels,
        ["Limit-Typ", "Aktuelles Limit", "Neues Limit", "Gültig ab"]
    );
}

#[test]
fn mandate_a1_shows_the_rulebooks_claims_in_table_order_then_the_first_collection() {
    let entry_json = &annex("Mandate.md", "A.1")[0];
    let rendered = render(
        entry_json,
        "{}",
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said((
            "Authorize Recurring Payment",
            "Authorize Mandate",
            "Cancel",
            None
        ))
    );
    let first = "First Collection";
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Mandate reference", plain("MND-2026-0042")),
            shown_row("Authorized party", plain("Streaming Co.")),
            shown_row("Authorized action", plain("Collect monthly subscription")),
            shown_row(
                "Conditions",
                Some((
                    "mini_markdown",
                    "The collection amount is fixed and matches the subscription plan in effect at the time of collection."
                ))
            ),
            shown_row("Maximum amount per use", amount("€19.99")),
            shown_row("Maximum uses", plain("24")),
            shown_row("Per period", plain("over the validity of this mandate")),
            shown_row("Valid from", date("Jun 3, 2026")),
            shown_row("Valid until", date("Jun 2, 2028")),
            in_section(shown_row("Amount", amount("€19.99")), first),
            in_section(shown_row("Payee", plain("Streaming Co.")), first),
        ]
    );
}

#[test]
fn mandate_a2_draws_the_agents_logo_under_its_name_and_keeps_list_markers_literal() {
    let entry_json = &annex("Mandate.md", "A.2")[0];
    let url = "https://cdn.exampleai.com/shopbot-logo.png";
    let logo = png(96, 96);
    // As written, its digest is a placeholder no content verifies.
    assert!(matches!(
        render(entry_json, "{}", &en(), &with_logo(url, logo.clone())),
        Err(Outcome::NotCompatible(NotCompatible::Image { .. }))
    ));
    let repaired = entry_json.replace(
        "sha256-9zXk0Lq2nE7uH8sW4tY1pR3vQ6cB5aD8fG2hJ4kL6mN=",
        &sri(&logo),
    );
    let rendered = render(&repaired, "{}", &en(), &with_logo(url, logo)).expect("renders");
    assert_eq!(
        rendered.text(),
        said((
            "Authorize Agent Purchase",
            "Authorize Agent",
            "Cancel",
            None
        ))
    );
    let conditions = "- Only from retailers listed at trusted-retailers.example/v1\n- Total price (incl. tax & shipping) **must** be ≤ the maximum amount\n- Single purchase only; agent **must not** retry after a failed attempt";
    let shown = rendered.rows();
    assert_eq!(
        shown,
        [
            shown_row("Mandate reference", plain("MND-AGT-2026-0019")),
            shown_row("Authorized party", plain("ShopBot by ExampleAI")),
            shown_row("Authorized party", Some(("image", "<image>"))),
            shown_row(
                "Authorized action",
                plain("Purchase noise-cancelling over-ear headphones")
            ),
            shown_row(
                "Conditions",
                Some(("mini_markdown", &conditions.replace("**", "")))
            ),
            shown_row("Maximum amount per use", amount("€200.00")),
            shown_row("Maximum uses", plain("1")),
            shown_row("Per period", plain("over the validity of this mandate")),
            shown_row("Valid until", date("Jun 9, 2026")),
        ]
    );
    assert_eq!(
        rendered.view.rows[2].row.value,
        Some(Value::Image(Image::Embedded(ImageRef {
            source: url.to_owned(),
            media: "image/png".to_owned(),
            width: 96,
            height: 96,
        })))
    );
    // Each list item keeps its "- "; the strong emphasis of "must" and "must not" leaves the
    // text, as a value from outside any module holds no style.
    assert_eq!(
        shown[4].1,
        Some(("mini_markdown", conditions.replace("**", "")))
    );
}

#[test]
fn mandate_a3_names_a_delegate_without_limits() {
    let entry_json = &annex("Mandate.md", "A.3")[0];
    let rendered = render(
        entry_json,
        "{}",
        &en(),
        &PasoProfile::default().with_languages(siros_testkit::render::languages()),
    )
    .expect("renders");
    assert_eq!(
        rendered.text(),
        said((
            "Authorize Account Delegate",
            "Authorize Delegate",
            "Cancel",
            None
        ))
    );
    let conditions = "- View statements and download documents\n- **Must not** initiate transfers or change account-holder details\n- **Must not** add or remove other delegates";
    assert_eq!(
        rendered.rows(),
        [
            shown_row("Mandate reference", plain("MND-DEL-2026-0007")),
            shown_row("Authorized party", plain("Alex Schmidt")),
            shown_row("Authorized action", plain("Manage account on my behalf")),
            shown_row(
                "Conditions",
                Some(("mini_markdown", &conditions.replace("**", "")))
            ),
            shown_row("Valid from", date("Jun 10, 2026")),
            shown_row("Valid until", date("Sep 10, 2026")),
        ]
    );
    // Its strong emphasis leaves the text, as a value from outside any module holds no style.
    assert!(
        !rendered.rows()[3]
            .1
            .as_ref()
            .expect("a value")
            .1
            .contains("**")
    );
}
