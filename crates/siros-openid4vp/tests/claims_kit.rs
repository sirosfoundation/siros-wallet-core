//! The claims kit against the specifications: OpenID4VCI 1.0's `credential_metadata_mso_mdoc`
//! example (`data/openid4vci-credential_metadata_mso_mdoc.json`, OpenID4VCI commit d57324db70,
//! SHA-256 166fa15860ad1435a1898f2ac2a67c399b22d420a167acc552be90da3db35df1) for the card and
//! its rows, OpenID4VP §6.3's value matching, B.2-B.3's `vp_formats_supported` rule, and the
//! elements an option discloses.

mod common;

use std::num::NonZeroU32;

use siros_i18n::{Bidi, Context};
use siros_openid4vp::claims::kit::{
    CardError, ClaimsQuery, Constraint, DrawError, IssuedMetadata, IssuedShape, MergeError,
    VpFormatsMember, format_entry, merge_metadata, vp_formats_refusal,
};
use siros_openid4vp::claims::{ArrayIndex, ClaimPath, Claims, ClaimsError, Step};
use siros_openid4vp::ids::{LocaleTag, QueryId};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Member, OptionIndex, Shown};
use siros_openid4vp::request::Item;
use siros_openid4vp::rows::{
    BooleanText, Choice, Env, Icon, IconReference, ImageMedia, Value, WalletText,
};
use siros_openid4vp::text::TextError;
use siros_testkit::render::Language;

use common::{ClaimsTest, parameters, request_of, unsigned};

const MDOC: ClaimsTest = ClaimsTest {
    member: "doctype_value",
    label: "name",
};

/// The test app's English context.
fn english() -> &'static Context {
    Language::English.shared().expect("the test app")
}

/// The test app's English text of a statement.
fn worded(statement: &dyn siros_i18n::Message) -> String {
    english()
        .resolve(statement)
        .expect("the test app words it")
        .to_string()
}

/// The wallet's configuration with one locale.
fn env_in(locale: &'static str) -> Env {
    Env::new(vec![tag(locale)], Vec::new(), Choice::First).expect("env")
}

fn tag(text: &'static str) -> LocaleTag {
    LocaleTag::parse(text).expect("tag")
}

fn query_text(claims: &str, member: &str, value: &str) -> String {
    parameters(
        &format!(
            r#"{{"credentials": [{{"id": "q", "format": "x", "meta": {{"{member}": {value}}}, "claims": {claims}}}]}}"#
        ),
        "",
    )
}

#[test]
fn the_card_and_its_rows_follow_the_openid4vci_mdoc_example() {
    let metadata: serde_json::Value = serde_json::from_str(include_str!(
        "data/openid4vci-credential_metadata_mso_mdoc.json"
    ))
    .expect("example");
    let display = &metadata["credential_configurations_supported"]["org.iso.18013.5.1.mDL"]["credential_metadata"];
    let view = format!(
        r#"{{"type": "org.iso.18013.5.1.mDL", "metadata": {display}, "values": {{"org.iso.18013.5.1": {{"given_name": "Erika", "family_name": "Mustermann", "birth_date": "1971-09-01"}}, "org.iso.18013.5.1.aamva": {{"organ_donor": true}}}}}}"#
    );
    let view = Node::parse(&view).expect("view");
    let claims = r#"[{"path": ["org.iso.18013.5.1.aamva", "organ_donor"]}, {"path": ["org.iso.18013.5.1", "birth_date"]},
                     {"path": ["org.iso.18013.5.1", "family_name"]}, {"path": ["org.iso.18013.5.1", "given_name"]}]"#;
    let text = query_text(claims, "doctype_value", r#""org.iso.18013.5.1.mDL""#);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = ClaimsQuery::parse(&MDOC, &request.queries()[0], None).expect("query");
    let logo = "https://state.example.org/public/mdl.png";
    let icon = Icon {
        reference: IconReference::Logo(logo.into()),
        media: ImageMedia::PNG,
        size: NonZeroU32::new(800).expect("size"),
    };
    let items: Vec<Item> = (0..4).map(|k| Item::new(k).expect("item")).collect();
    let card_in = |locales: &[&'static str]| {
        let env = Env::new(
            locales.iter().copied().map(tag).collect(),
            vec![(logo.to_owned(), icon.clone())],
            Choice::First,
        )
        .expect("env");
        let shown = Shown {
            everyone: &items,
            chosen: &[],
        };
        let card = query
            .card(&MDOC, &view, shown, &env, english())
            .expect("card");
        let rows: Vec<(String, Option<String>)> = card
            .rows
            .iter()
            .map(|row| {
                let value = row.value.as_ref().and_then(Value::text);
                (row.label.to_string(), value.map(ToString::to_string))
            })
            .collect();
        (card.title.to_string(), card.icon, rows)
    };
    let yes = worded(&BooleanText::Yes);
    let values = ["Erika", "Mustermann", "1971-09-01", yes.as_str()];
    let card = |title: &str, labels: [&str; 4]| {
        let rows = labels.iter().zip(values);
        let rows = rows.map(|(label, value)| ((*label).to_owned(), Some(value.to_owned())));
        (title.to_owned(), icon.clone(), rows.collect::<Vec<_>>())
    };
    // Rows follow the metadata's claims order (OpenID4VCI B.2). A claim without display shows
    // its data element identifier; a boolean the wallet's yes.
    assert_eq!(
        card_in(&["en-US"]),
        card(
            "Mobile Driving License",
            ["Given Name", "Surname", "birth_date", "organ_donor"]
        )
    );
    // Over the priority list: de selects no entry, ja-JP the card's and given_name's; family_name
    // has neither and shows its data element identifier.
    assert_eq!(
        card_in(&["de", "ja-JP"]),
        card(
            "モバイル運転免許証",
            ["名前", "family_name", "birth_date", "organ_donor"]
        )
    );
}

/// D2: RFC 4647 §3.4's Lookup over the priority list, then §3.3.1's filtering, then the entry
/// without a locale.
#[test]
fn locale_selection_looks_up_filters_then_takes_the_untagged_entry() {
    let entries = r#"[{"locale": "de-DE", "name": "de-DE"}, {"locale": "en", "name": "en"}, {"name": "default"}]"#;
    let entries = Node::parse(entries).expect("entries");
    let pick = |tags: &[LocaleTag]| {
        format_entry(entries.as_array().expect("array"), tags)
            .and_then(|e| e.get("name"))
            .and_then(Node::as_str)
            .map(str::to_owned)
    };
    assert_eq!(pick(&[tag("en-US")]).as_deref(), Some("en"), "Lookup cuts");
    assert_eq!(pick(&[tag("de")]).as_deref(), Some("de-DE"), "filtering");
    assert_eq!(pick(&[tag("fr")]).as_deref(), Some("default"));
    assert_eq!(
        pick(&[tag("fr"), tag("de")]).as_deref(),
        Some("de-DE"),
        "a later locale of the list before the default"
    );
    assert_eq!(
        pick(&[tag("de"), tag("en")]).as_deref(),
        Some("en"),
        "Lookup over the whole list before filtering"
    );
    let tagged = Node::parse(r#"[{"locale": "ja", "name": "ja"}]"#).expect("entries");
    let none = format_entry(tagged.as_array().expect("array"), &[tag("en")]);
    assert_eq!(none, None, "no entry for the language");
}

/// Each refusal rule of the metadata merge, over a document that breaks it alone.
#[test]
fn the_merge_refuses_what_makes_no_view() {
    struct AsWritten;
    impl IssuedShape for AsWritten {
        const LABEL: &'static str = "name";
    }
    let object = |text: &str| {
        let node = Node::parse(text).expect("json").into_owned();
        node.as_object().cloned().expect("an object")
    };
    let issued = |configuration: &str| IssuedMetadata {
        configuration: Some(object(configuration)),
        ..IssuedMetadata::default()
    };
    let rows: [(IssuedMetadata<'_>, MergeError); 3] = [
        (
            issued(r#"{"auxiliary_data": []}"#),
            MergeError::AuxiliaryDataPublished,
        ),
        (
            issued(r#"{"display": {}}"#),
            MergeError::NotEntries { member: "display" },
        ),
        (
            issued(r#"{"claims": [{"display": []}]}"#),
            MergeError::Path { position: 0 },
        ),
    ];
    for (input, refusal) in rows {
        assert_eq!(
            merge_metadata::<AsWritten>(None, &input),
            Err(refusal),
            "{input:?}"
        );
    }
    assert!(matches!(
        merge_metadata::<AsWritten>(None, &issued(r#"{"display": [{"locale": "1 2"}]}"#)),
        Err(MergeError::Locale { .. })
    ));
}

#[test]
fn values_match_by_equal_json_of_one_type() {
    // §6.3: one of the selected elements equals one of the values.
    // Python's json reads them: an integer is no double, a JSON object is unordered.
    let cases: [(&str, &str, bool); 17] = [
        (r#"["Doe"]"#, r#""Doe""#, true),
        (r#"[1.0]"#, "1", false),
        (r#"[1.5]"#, "1.50", true),
        (r#"[1e2]"#, "100.0", true),
        (r#"[{"a": 1, "b": 2}]"#, r#"{"b": 2, "a": 1}"#, true),
        (r#"[{"a": 1, "b": 2}]"#, r#"{"a": 1}"#, false),
        (r#"[{"a": 1}]"#, r#"{"a": 2}"#, false),
        (r#"[{"a": 1}]"#, r#"{"a": 1, "b": 2}"#, false),
        (r#"["Doe"]"#, r#""doe""#, false),
        (r#"[1]"#, "1", true),
        (r#"["1"]"#, "1", false),
        (r#"[1]"#, r#""1""#, false),
        (r#"[true]"#, "true", true),
        (r#"[true]"#, r#""true""#, false),
        (r#"[false, 90210]"#, "90210", true),
        (r#"[null]"#, "null", true),
        (r#"[null]"#, "false", false),
    ];
    for (values, held, want) in cases {
        let text = query_text(
            &format!(r#"[{{"path": ["c"], "values": {values}}}]"#),
            "vct_values",
            r#"["t"]"#,
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let format = ClaimsTest {
            member: "vct_values",
            label: "label",
        };
        let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
        let view = format!(r#"{{"type": "t", "values": {{"c": {held}}}}}"#);
        let answered = !query
            .answerable(&format, &Node::parse(&view).expect("view"), &[])
            .expect("the view's types")
            .is_empty();
        assert_eq!(answered, want, "values {values} against {held}");
    }
}

#[test]
fn vp_formats_supported_admits_by_each_member_it_states() {
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let id = QueryId::parse("q").expect("id");
    // A value whose *_alg_values members are non-empty arrays of the format's identifiers.
    let rules: [(&str, bool); 5] = [
        (r#"{"sd-jwt_alg_values": ["ES256"]}"#, true),
        (r#"{"sd-jwt_alg_values": []}"#, false),
        (r#"{"sd-jwt_alg_values": [-7]}"#, false),
        (r#"{"other": 5}"#, true),
        (r#"[]"#, false),
    ];
    for (supported, accepted) in rules {
        let node = Node::parse(supported).expect("json");
        assert_eq!(
            vp_formats_refusal(&format, &id, Some(&node)).is_none(),
            accepted,
            "{supported}"
        );
    }
    let text = query_text(r#"[{"path": ["c"]}]"#, "vct_values", r#"["t"]"#);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let es256 = Node::parse(r#""ES256""#).expect("alg");
    let constraints = [Constraint {
        member: VpFormatsMember::new("sd-jwt_alg_values"),
        matched: vec![es256],
        also: Vec::new(),
    }];
    // A member the Verifier states must list an identifier the presentation can match; a member
    // it leaves out, or no value at all, constrains nothing.
    let admitted = |supported: Option<&str>| {
        let node = supported.map(|s| Node::parse(s).expect("json"));
        let query = ClaimsQuery::parse(&format, &request.queries()[0], node).expect("query");
        query.admits(&format, &constraints).is_ok()
    };
    assert!(admitted(None));
    assert!(admitted(Some(r#"{"kb-jwt_alg_values": ["ES384"]}"#)));
    assert!(admitted(Some(
        r#"{"sd-jwt_alg_values": ["ES384", "ES256"]}"#
    )));
    assert!(!admitted(Some(r#"{"sd-jwt_alg_values": ["ES384"]}"#)));
    let broken = Node::parse(r#"{"sd-jwt_alg_values": []}"#).expect("json");
    assert!(ClaimsQuery::parse(&format, &request.queries()[0], Some(broken)).is_err());
}

#[test]
fn an_option_discloses_its_elements_once_in_claim_order() {
    let claims = r#"[{"id": "a", "path": ["ns", "a"]}, {"id": "b", "path": ["ns", "b"]}, {"id": "again", "path": ["ns", "a"]},
                     {"id": "list", "path": ["ns", "list", null]}, {"id": "w", "path": ["tx", "w"]}]"#;
    let text = parameters(
        &format!(
            r#"{{"credentials": [{{"id": "q", "format": "x", "meta": {{"doctype_value": "t"}}, "claims": {claims}, "claim_sets": [["b", "a", "again", "list", "w"], ["a"]]}}]}}"#
        ),
        "",
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = ClaimsQuery::parse(&MDOC, &request.queries()[0], None).expect("query");
    let view = Node::parse(
        r#"{"type": "t", "values": {"ns": {"a": 1, "b": 2, "list": [4, 5]}, "tx": {"w": 3}}}"#,
    )
    .expect("view");
    let written = [Member::element("tx", "w")];
    let at = |position: usize| {
        let (option, _) = query
            .claims()
            .options()
            .indexed()
            .nth(position)
            .expect("an option");
        option
    };
    let names = |option: usize| -> Vec<String> {
        query
            .disclosed(&MDOC, at(option), &view, &written)
            .expect("disclosed")
            .iter()
            .map(|(path, value)| format!("{path:?}={}", value.json_spaced()))
            .collect()
    };
    // In the option's order; a claim selecting a disclosed element adds nothing; the element the
    // transaction writes is answered by the proof.
    assert_eq!(
        names(0),
        [
            r#"[Key("ns"), Key("b")]=2"#,
            r#"[Key("ns"), Key("a")]=1"#,
            r#"[Key("ns"), Key("list"), Index(0)]=4"#,
            r#"[Key("ns"), Key("list"), Index(1)]=5"#
        ]
    );
    assert_eq!(names(1), [r#"[Key("ns"), Key("a")]=1"#]);
}

#[test]
fn claims_path_pointers_follow_section_7() {
    let view =
        Node::parse(r#"{"type": "t", "values": {"a": {"b": [10, 20, {"c": 30}]}, "s": "x"}}"#)
            .expect("view");
    let values = view.get("values").expect("values");
    // The selection, else the component at which it fails and whether the claim is found.
    let select = |path: &str| -> Result<Vec<String>, String> {
        let text = query_text(
            &format!(r#"[{{"path": {path}}}]"#),
            "vct_values",
            r#"["t"]"#,
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let format = ClaimsTest {
            member: "vct_values",
            label: "label",
        };
        let query = ClaimsQuery::parse(&format, &request.queries()[0], None)
            .map_err(|r| format!("refused: {}", r.items()[0].text()))?;
        let claim = query
            .claims()
            .claim(Item::new(0).expect("item"))
            .expect("claim");
        let found = !query
            .answerable(&format, &view, &[])
            .expect("the view's types")
            .is_empty();
        let selected = claim
            .path()
            .select(values)
            .map_err(|e| format!("component {} fails, found {found}", e.step()))?;
        Ok(selected
            .iter()
            .map(|(path, value)| format!("{path:?}={}", value.json_spaced()))
            .collect())
    };
    // §7.1: a string selects a member, an integer an element, null every element.
    assert_eq!(
        select(r#"["a", "b", 1]"#),
        Ok(vec![r#"[Key("a"), Key("b"), Index(1)]=20"#.to_owned()])
    );
    assert_eq!(
        select(r#"["a", "b", null]"#).map(|s| s.len()),
        Ok(3),
        "null selects every element of the array"
    );
    assert_eq!(
        select(r#"["a", "b", 9]"#),
        Ok(Vec::new()),
        "an index past the array selects nothing"
    );
    assert_eq!(
        select(r#"["a", "x"]"#),
        Ok(Vec::new()),
        "an absent member selects nothing"
    );
    // An index on a non-array, or a member name on a non-object, is an error at its component:
    // the claim is not found.
    assert_eq!(
        select(r#"["s", 0]"#),
        Err("component 1 fails, found false".to_owned())
    );
    assert_eq!(
        select(r#"["a", "b", "c"]"#),
        Err("component 2 fails, found false".to_owned())
    );
    // A pointer is a non-empty array of strings, non-negative integers and null.
    for invalid in [
        "[]",
        r#"["a", -1]"#,
        r#"["a", 1.5]"#,
        r#"["a", true]"#,
        r#""a""#,
        r#"[{"a": 1}]"#,
    ] {
        assert!(
            select(invalid).is_err_and(|why| why.starts_with("refused: ")),
            "{invalid}"
        );
    }
    assert_eq!(
        select(r#"["a", "b", -0]"#).map(|s| s.len()),
        Ok(1),
        "-0 is the integer 0"
    );
    // A path built of components equals the pointer parsed from them.
    assert_eq!(
        ClaimPath::parse(&Node::parse(r#"["a", null, 1]"#).expect("pointer")),
        Some(ClaimPath::of(
            Step::Key("a".into()),
            [Step::All, Step::Index(ArrayIndex::new(1))]
        ))
    );
}

#[test]
fn claim_metadata_labels_the_elements_its_path_selects() {
    // SD-JWT VC §8.2 and OpenID4VCI: the first metadata claim whose path selects an element
    // labels it; a member name selects no array element, null every one. An array of values
    // gives the elements no claim labels the array's label. A claim the metadata describes
    // comes first (B.2), the others in the request's order.
    let view = Node::parse(
        r#"{"type": "t", "metadata": {"claims": [
            {"path": ["list", "x"], "display": [{"locale": "en", "label": "A member"}]},
            {"path": ["list", 1], "display": [{"locale": "en", "label": "Second"}]},
            {"path": ["list", null], "display": [{"locale": "en", "label": "Any item"}]},
            {"path": ["tags"], "display": [{"locale": "en", "label": "Tags"}]}]},
           "values": {"list": ["x", "y"], "tags": ["a", "b"], "other": "z"}}"#,
    )
    .expect("view");
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let text = query_text(
        r#"[{"path": ["list"]}, {"path": ["tags"]}, {"path": ["other"]}]"#,
        "vct_values",
        r#"["t"]"#,
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
    let env = env_in("en");
    let items: Vec<Item> = (0..3).map(|k| Item::new(k).expect("item")).collect();
    let card = query
        .card(
            &format,
            &view,
            Shown {
                everyone: &items,
                chosen: &[],
            },
            &env,
            english(),
        )
        .expect("card");
    let rows: Vec<(String, Option<String>)> = card
        .rows
        .iter()
        .map(|row| {
            (
                row.label.to_string(),
                row.value
                    .as_ref()
                    .and_then(Value::text)
                    .map(ToString::to_string),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("Tags", Some("a")),
            ("Tags", Some("b")),
            ("Any item", Some("x")),
            ("Second", Some("y")),
            ("other", Some("z"))
        ]
        .map(|(label, value)| (label.to_owned(), value.map(str::to_owned)))
    );
}

/// OpenID4VP §6.3's `id` and §6.4.1's `claim_sets`, one fixture per clause.
#[test]
fn claims_breaking_section_6_3_or_6_4_1_are_refused() {
    let with = |members: &str| {
        let query = format!("{{{members}}}");
        Claims::parse(&Node::parse(&query).expect("JSON")).map(|_| ())
    };
    let table = [
        (
            r#""claims":[{"id":"a b","path":["a"]}]"#,
            ClaimsError::Id { claim: 0 },
        ),
        (
            r#""claims":[{"id":"","path":["a"]}]"#,
            ClaimsError::Id { claim: 0 },
        ),
        (
            r#""claims":[{"id":1,"path":["a"]}]"#,
            ClaimsError::Id { claim: 0 },
        ),
        (
            r#""claims":[{"id":"a","path":["a"]},{"id":"a","path":["b"]}]"#,
            ClaimsError::IdTwice { id: "a".to_owned() },
        ),
        (
            r#""claims":[{"id":"a","path":["a"]},{"path":["b"]}],"claim_sets":[["a"]]"#,
            ClaimsError::IdAbsent { claim: 1 },
        ),
        (
            r#""claims":[{"id":"a","path":["a"]}],"claim_sets":[]"#,
            ClaimsError::ClaimSets,
        ),
        (
            r#""claims":[{"id":"a","path":["a"]}],"claim_sets":[["b"]]"#,
            ClaimsError::ClaimSets,
        ),
        (r#""claim_sets":[["a"]]"#, ClaimsError::ClaimSets),
    ];
    for (members, refused) in table {
        assert_eq!(with(members), Err(refused), "{members}");
    }
    assert_eq!(
        with(r#""claims":[{"id":"a-b_1","path":["a"]},{"path":["b"]}]"#),
        Ok(())
    );
    assert_eq!(
        with(r#""claims":[{"id":"a","path":["a"]}],"claim_sets":[["a"]]"#),
        Ok(())
    );
}

/// A claim's JSON number (RFC 8259 §6) shows as the value it writes, read by hand: a number
/// statement carrying the value's exact literal; as written beyond a decimal's 38 fraction
/// digits or an `i128`'s units, a text statement.
#[test]
fn a_json_number_shows_as_the_value_it_writes() {
    // A wording that names the statement a value takes and writes the literal it carries.
    let marked = Context::new()
        .bidi(Bidi::None)
        .module(
            "@locale en\n---\n[openid4vp.wallet]\ncredential = Credential\nlabel = {$label}\n\
             number = number {$value}\ntext = text {$value}\n",
        )
        .expect("the test's wording");
    let table = [
        ("0", "number 0"),
        ("42", "number 42"),
        (
            "123456789012345678901234567890",
            "number 123456789012345678901234567890",
        ),
        ("-7", "number -7"),
        ("1.5", "number 1.5"),
        ("-0.25", "number -0.25"),
        ("1.0", "number 1.0"),
        ("1e3", "number 1000"),
        ("0e5", "number 0"),
        ("0.5e1", "number 5"),
        ("2.50E-1", "number 0.250"),
        ("-1.2e+2", "number -120"),
        ("1e-38", "number 0.00000000000000000000000000000000000001"),
        ("1e-39", "text 1e-39"),
        ("1e39", "text 1e39"),
        ("1e400", "text 1e400"),
        ("1e-400", "text 1e-400"),
    ];
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let env = env_in("en");
    for (written, expected) in table {
        let text = query_text(r#"[{"path": ["n"]}]"#, "vct_values", r#"["t"]"#);
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
        let view = format!(r#"{{"type": "t", "values": {{"n": {written}}}}}"#);
        let view = Node::parse(&view).expect("view");
        let items = [Item::new(0).expect("item")];
        let shown = Shown {
            everyone: &items,
            chosen: &[],
        };
        let card = query
            .card(&format, &view, shown, &env, &marked)
            .expect("card");
        let [row] = card.rows.as_slice() else {
            panic!("one row for {written}: {:?}", card.rows)
        };
        let shown = row
            .value
            .as_ref()
            .and_then(Value::text)
            .map(ToString::to_string);
        assert_eq!(shown.as_deref(), Some(expected), "{written}");
    }
}

/// A card's statement the wallet's context words none of fails the card, the `ResolveError` its
/// cause.
#[test]
fn a_card_the_context_words_none_of_fails_with_its_cause() {
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let text = query_text(r#"[{"path": ["a"]}]"#, "vct_values", r#"["t"]"#);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
    let view = Node::parse(r#"{"type": "t", "values": {"a": "x"}}"#).expect("view");
    let items = [Item::new(0).expect("item")];
    let shown = Shown {
        everyone: &items,
        chosen: &[],
    };
    let drawn = query.card(&format, &view, shown, &env_in("en"), &Context::new());
    assert!(
        matches!(
            drawn,
            Err(DrawError::Unworded(
                siros_i18n::ResolveError::Unknown { .. }
            ))
        ),
        "{drawn:?}"
    );
}

/// Each text the card reads goes through display text: the entry's name, a claim's label, the
/// issuer, and a member name standing in for a label. An entry for another language is not read.
/// Every metadata text reads through the rule of display text, whatever its language; a member
/// name only where it stands in for a label of the query's claim; a blank text gives way to the
/// next choice; a claim's value shows as written.
#[test]
fn what_could_be_shown_reads_through_the_rule_of_display_text() {
    let format = ClaimsTest {
        member: "vct_values",
        label: "label",
    };
    let text = query_text(r#"[{"path": ["a"]}]"#, "vct_values", r#"["t"]"#);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let query = ClaimsQuery::parse(&format, &request.queries()[0], None).expect("query");
    let env = env_in("en");
    let refused = [
        (
            "the entry's name",
            r#"{"type": "t", "metadata": {"display": [{"locale": "en", "name": "\u202eCard"}]}, "values": {"a": 1}}"#,
        ),
        (
            "another language's name",
            r#"{"type": "t", "metadata": {"display": [{"locale": "en", "name": "Card"}, {"locale": "de", "name": "\u202eKarte"}]}, "values": {"a": 1}}"#,
        ),
        (
            "a description",
            r#"{"type": "t", "metadata": {"display": [{"name": "Card", "description": "\u200b"}]}, "values": {"a": 1}}"#,
        ),
        (
            "a logo's alternative text",
            r#"{"type": "t", "metadata": {"display": [{"name": "Card", "logo": {"uri": "https://i.example/l", "alt_text": "\u2029"}}]}, "values": {"a": 1}}"#,
        ),
        (
            "a claim's label",
            r#"{"type": "t", "metadata": {"claims": [{"path": ["a"], "display": [{"locale": "en", "label": "A\u200bB"}]}]}, "values": {"a": 1}}"#,
        ),
        (
            "the label of a claim the query leaves out",
            r#"{"type": "t", "metadata": {"claims": [{"path": ["b"], "display": [{"locale": "de", "label": "\u0378"}]}]}, "values": {"a": 1}}"#,
        ),
        (
            "the issuer",
            r#"{"type": "t", "issuer": "Bank\u2028", "metadata": {}, "values": {"a": 1}}"#,
        ),
        (
            "a name of white space and a control",
            r#"{"type": "t", "metadata": {"display": [{"name": " \n"}]}, "values": {"a": 1}}"#,
        ),
        (
            "a member name standing in for a label",
            r#"{"type": "t", "metadata": {}, "values": {"a": {"\ue000": 1}}}"#,
        ),
    ];
    let read = |view: &str| {
        let view = Node::parse(view).expect("view");
        let options: Vec<OptionIndex> = query
            .claims()
            .options()
            .indexed()
            .map(|(option, _)| option)
            .collect();
        query.displayable(&format, &view, &options, &env)
    };
    for (case, view) in refused {
        assert!(
            matches!(read(view), Err(CardError::Text(TextError::Unsafe))),
            "{case}"
        );
    }
    let items = [Item::new(0).expect("item")];
    let shown = Shown {
        everyone: &items,
        chosen: &[],
    };
    for (case, view, title, subtitle, label) in [
        (
            "blank texts",
            r#"{"type": "t", "issuer": " ", "metadata": {"display": [{"name": "\u3000"}], "claims": [{"path": ["a"], "display": [{"label": " "}]}]}, "values": {"a": 1}}"#,
            worded(&WalletText::Credential),
            None,
            "a".to_owned(),
        ),
        (
            "a blank member name",
            r#"{"type": "t", "metadata": {}, "values": {"a": {" ": 1}}}"#,
            worded(&WalletText::Credential),
            None,
            worded(&WalletText::Claim),
        ),
        (
            "a name outside the query and a value",
            r#"{"type": "t", "issuer": "Bank", "metadata": {"display": [{"name": "Card"}], "claims": [{"path": ["a"], "display": [{"label": "A"}]}]}, "values": {"a": "\u202ex", "\ue000": 2}}"#,
            "Card".to_owned(),
            Some("Bank".to_owned()),
            "A".to_owned(),
        ),
    ] {
        assert!(read(view).is_ok(), "{case}");
        let view = Node::parse(view).expect("view");
        let card = query
            .card(&format, &view, shown, &env, english())
            .expect(case);
        assert_eq!(card.title.to_string(), title, "{case}");
        assert_eq!(
            card.subtitle.as_ref().map(ToString::to_string),
            subtitle,
            "{case}"
        );
        assert_eq!(card.rows[0].label.to_string(), label, "{case}");
    }
}
