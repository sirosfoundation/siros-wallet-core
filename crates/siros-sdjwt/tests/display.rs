//! The card and its rows from SD-JWT VC Type Metadata (§7, §8), against the draft's Appendix B.2
//! (`data/figure-28-*`, `figure-29-*`: Figures 28 and 29 of draft-ietf-oauth-sd-jwt-vc-14) and
//! the effective metadata of §8.5.2 (`data/figure-21-*`, Figure 21).

use siros_i18n::LanguagePolicy;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Format, Shown};
use siros_openid4vp::request::Item;
use siros_sdjwt::{SdJwtVc, type_metadata};
use siros_testkit::fixtures::{Held, env, icon, parameters, request_of, unsigned};
use siros_testkit::render::{App, CrateSource, main_locales, main_module, written};

const FIGURE_28: &str = include_str!("data/figure-28-sd-jwt-vc-payload.json");
const FIGURE_29: &str = include_str!("data/figure-29-type-metadata.json");
const LOGO: &str = "https://betelgeuse.example.com/public/education-logo.png";
const LOGO_DE: &str = "https://betelgeuse.example.com/public/education-logo-de.png";

/// The card the plug-in draws for a credential of the view, every claim of the query shown:
/// its title, its icon's reference, and its rows as (label, value).
fn card(
    view: &str,
    paths: &[&str],
    locales: &[&'static str],
) -> (String, String, Vec<(String, Option<String>)>) {
    let kind = Node::parse(view).expect("view");
    let kind = kind.get("type").and_then(Node::as_str).expect("type");
    let claims: Vec<String> = paths
        .iter()
        .map(|path| format!(r#"{{"path": {path}}}"#))
        .collect();
    let dcql = format!(
        r#"{{"credentials": [{{"id": "edu", "format": "dc+sd-jwt", "meta": {{"vct_values": ["{kind}"]}}, "claims": [{}]}}]}}"#,
        claims.join(", ")
    );
    let text = parameters(&dcql, "");
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let format = SdJwtVc::new().expect("format");
    let query = format
        .query(
            &request.queries()[0],
            siros_testkit::fixtures::query_context(&request, false, None),
        )
        .map_err(|refusals| format!("{refusals:?}"))
        .expect("query");
    let held = Held::new("edu", "dc+sd-jwt", view);
    let icons = [icon(LOGO, 1000), icon(LOGO_DE, 1000)]
        .into_iter()
        .map(|icon| icon.expect("icon"))
        .collect();
    let env = env(locales, icons).expect("env");
    let items: Vec<Item> = (0..paths.len())
        .map(|k| Item::new(k).expect("item"))
        .collect();
    let card = query
        .draw(
            &held.credential().expect("credential"),
            Shown {
                everyone: &items,
                chosen: &[],
            },
            &env,
        )
        .expect("card");
    let rows = card
        .rows
        .iter()
        .map(|row| {
            (
                as_written(&row.label),
                row.value.as_ref().and_then(|v| v.text()).map(as_written),
            )
        })
        .collect();
    (
        as_written(&card.title),
        card.icon.reference.to_string(),
        rows,
    )
}

/// A text the issuer or the credential wrote, as written; another text as the value it holds.
fn as_written(text: &siros_explain::Text) -> String {
    written(text).map_or_else(|| format!("{text:?}"), str::to_owned)
}

fn rows(pairs: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
    pairs
        .iter()
        .map(|(label, value)| ((*label).to_owned(), Some((*value).to_owned())))
        .collect()
}

#[test]
fn appendix_b_2_shows_its_card_and_claim_labels() {
    let view = format!(
        r#"{{"type": "https://betelgeuse.example.com/education_credential/v42", "metadata": {FIGURE_29}, "values": {FIGURE_28}}}"#
    );
    let leaves = [
        r#"["name"]"#,
        r#"["address", "street_address"]"#,
        r#"["degrees", null, "field_of_study"]"#,
        r#"["degrees", null, "date_awarded"]"#,
    ];
    let degrees = [
        "Intergalactic Politics",
        "Space Navigation",
        "Quantum Mechanics",
        "2020-05-15",
        "2018-06-20",
        "2016-07-25",
    ];
    let mut en = vec![
        ("Name", "Zaphod Beeblebrox"),
        ("Street Address", "42 Galaxy Way"),
    ];
    en.extend(degrees[..3].iter().map(|v| ("Field of Study", *v)));
    en.extend(degrees[3..].iter().map(|v| ("Date Awarded", *v)));
    let mut de = vec![
        ("Vor- und Nachname", "Zaphod Beeblebrox"),
        ("Straße", "42 Galaxy Way"),
    ];
    de.extend(degrees[..3].iter().map(|v| ("Studienfach", *v)));
    de.extend(degrees[3..].iter().map(|v| ("Verleihungsdatum", *v)));
    // The display entry and each claim's label in the locale (§7, §8.2); rows in the metadata's
    // claims order (OpenID4VCI B.2), null selecting every degree.
    assert_eq!(
        card(&view, &leaves, &["en-US"]),
        (
            "Betelgeuse Education Credential".to_owned(),
            LOGO.to_owned(),
            rows(&en)
        )
    );
    assert_eq!(
        card(&view, &leaves, &["de-DE"]),
        (
            "Betelgeuse-Bildungsnachweis".to_owned(),
            LOGO_DE.to_owned(),
            rows(&de)
        )
    );
    // en: basic filtering finds en-US, the first tag extending it.
    let (title, _, name) = card(&view, &leaves[..1], &["en"]);
    assert_eq!(
        (title.as_str(), name),
        (
            "Betelgeuse Education Credential",
            rows(&[("Name", "Zaphod Beeblebrox")])
        )
    );
    // A container is a heading row, then its members; an element without a label shows its
    // name.
    let (_, _, containers) = card(&view, &[r#"["address"]"#, r#"["degrees"]"#], &["en-US"]);
    let labels: Vec<&str> = containers.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "Address",
            "Street Address",
            "city",
            "postal_code",
            "country",
            "Degrees",
            "Field of Study",
            "Date Awarded",
            "Field of Study",
            "Date Awarded",
            "Field of Study",
            "Date Awarded"
        ]
    );
}

#[test]
fn the_effective_metadata_of_section_8_5_2_labels_the_claims() {
    // The child type's effective claim metadata (Figure 21): Full Name from the base type, Town
    // overriding City, Nationalities added.
    let figure_21 = include_str!("data/figure-21-effective-claim-metadata.json");
    let view = format!(
        r#"{{"type": "https://example.com/custom-type-metadata", "metadata": {figure_21}, "values": {{"name": "Arthur Dent", "address": {{"city": "Milliways"}}, "nationalities": ["British"]}}}}"#
    );
    let (_, _, rows) = card(
        &view,
        &[
            r#"["name"]"#,
            r#"["address", "city"]"#,
            r#"["nationalities"]"#,
        ],
        &["en"],
    );
    let labels: Vec<&str> = rows.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(labels, ["Full Name", "Town", "Nationalities"]);
}

/// Section 4.14 of the design: Figure 29's `display` loads as a defined module, and a view naming it
/// shows the same texts through the renderer, per language, with the wallet's own text for an
/// unlabelled claim as before.
#[test]
fn figure_29_loads_as_a_defined_module() {
    let document = Node::parse(FIGURE_29).expect("metadata");
    let digest = type_metadata::module_of(&document);
    let hex: String = digest.digest().iter().map(|b| format!("{b:02x}")).collect();
    let view = format!(
        r#"{{"type": "https://betelgeuse.example.com/education_credential/v42", "metadata": {FIGURE_29}, "values": {FIGURE_28}, "display_module": "{hex}"}}"#
    );
    let priority: Vec<LocaleTag> = ["en-US", "de-DE"]
        .iter()
        .map(|tag| LocaleTag::parse(tag).expect("tag"))
        .collect();
    let main = main_locales().expect("the main module's locales");
    let form = type_metadata::convert(&document, &main, &priority, LanguagePolicy::Any)
        .expect("the module");
    let crates = CrateSource::openid4vp().load().expect("the crate module");
    let main_module = main_module().expect("the main module");
    let app = App::new(&[&main_module, &crates], &[&form]).expect("the package");
    let rendering = app.rendering().expect("the rendering");
    let text = parameters(
        r#"{"credentials": [{"id": "edu", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://betelgeuse.example.com/education_credential/v42"]}, "claims": [{"path": ["name"]}]}]}"#,
        "",
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let format = SdJwtVc::new().expect("format");
    let query = format
        .query(
            &request.queries()[0],
            siros_testkit::fixtures::query_context(&request, false, None),
        )
        .map_err(|refusals| format!("{refusals:?}"))
        .expect("query");
    let held = Held::new("edu", "dc+sd-jwt", view);
    let credential = held.credential().expect("credential");
    let module = query.card_module(&credential).expect("the view's module");
    assert_eq!(module, Some(digest));
    let items = [Item::new(0).expect("item")];
    for (tags, title, label) in [
        (["en-US", "en"], "Betelgeuse Education Credential", "Name"),
        (
            ["de-DE", "de"],
            "Betelgeuse-Bildungsnachweis",
            "Vor- und Nachname",
        ),
    ] {
        let env = env(&tags, Vec::new()).expect("env");
        let card = query
            .draw(
                &credential,
                Shown {
                    everyone: &items,
                    chosen: &[],
                },
                &env,
            )
            .expect("card");
        let renderer = rendering
            .renderer(None, module, None, &env)
            .expect("no fault")
            .expect("a language");
        assert_eq!(renderer.plain(&card.title).expect("title"), title);
        assert_eq!(renderer.plain(&card.rows[0].label).expect("label"), label);
    }
    // A package that holds the module not: the entry cannot render.
    let bare = App::new(&[&main_module, &crates], &[]).expect("the package");
    let bare = bare.rendering().expect("the rendering");
    let env = env(&["en-US", "en"], Vec::new()).expect("env");
    assert!(matches!(
        bare.renderer(None, module, None, &env).expect("no fault"),
        Err(siros_openid4vp::rendering::Unrendered::Module(_))
    ));
}

/// A display entry whose `locale` is no language tag has no language to load in.
#[test]
fn a_locale_of_no_tag_is_refused() {
    let document =
        Node::parse(r#"{"display": [{"locale": "not a tag", "name": "A"}]}"#).expect("json");
    assert!(matches!(
        type_metadata::convert(&document, &[], &[], LanguagePolicy::Any),
        Err(type_metadata::ConvertError::Locale(_))
    ));
}
