//! The claims kit against the specifications: OpenID4VCI 1.0's `credential_metadata_mso_mdoc`
//! example (`data/openid4vci-credential_metadata_mso_mdoc.json`, OpenID4VCI commit d57324db70,
//! SHA-256 166fa15860ad1435a1898f2ac2a67c399b22d420a167acc552be90da3db35df1) for the card and
//! its rows, OpenID4VP §6.3's value matching, B.2-B.3's `vp_formats_supported` rule, and the
//! elements an option discloses.

mod common;

use std::num::NonZeroU32;

use siros_openid4vp::claims::kit::{ClaimsQuery, Constraint, format_entry, vp_formats_refusal};
use siros_openid4vp::claims::{ClaimPath, Step};
use siros_openid4vp::ids::{LocaleTag, QueryId};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Member, OptionIndex, Shown};
use siros_openid4vp::request::Item;
use siros_openid4vp::rows::{Amounts, Choice, Env, Icon, ImageMedia};

use common::{ClaimsTest, parameters, request_of, unsigned};

const MDOC: ClaimsTest = ClaimsTest {
    member: "doctype_value",
    label: "name",
};

fn tag(text: &'static str) -> LocaleTag<'static> {
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
        reference: logo.into(),
        media: ImageMedia::PNG,
        size: NonZeroU32::new(800).expect("size"),
    };
    let items: Vec<Item> = (0..4).map(|k| Item::new(k).expect("item")).collect();
    let card_in = |locales: &[&'static str]| {
        let env = Env::new(
            locales.iter().copied().map(tag),
            vec![(logo.to_owned(), icon.clone())],
            Amounts::Formatted,
            Choice::First,
        )
        .expect("env");
        let shown = Shown {
            everyone: &items,
            chosen: &[],
        };
        let card = query.card(&MDOC, &view, shown, &env).expect("card");
        let rows: Vec<(String, Option<String>)> = card
            .rows
            .iter()
            .map(|row| {
                let value = row.value.as_ref().and_then(|v| v.text());
                (row.label.text.clone(), value.map(str::to_owned))
            })
            .collect();
        (card.title, card.icon, rows)
    };
    let values = ["Erika", "Mustermann", "1971-09-01", "true"];
    let card = |title: &str, labels: [&str; 4]| {
        let rows = labels.iter().zip(values);
        let rows = rows.map(|(label, value)| ((*label).to_owned(), Some(value.to_owned())));
        (title.to_owned(), icon.clone(), rows.collect::<Vec<_>>())
    };
    // Rows follow the metadata's claims order (OpenID4VCI B.2). A claim without display shows
    // its data element identifier; a boolean its JSON text.
    assert_eq!(
        card_in(&["en-US"]),
        card(
            "Mobile Driving License",
            ["Given Name", "Surname", "birth_date", "organ_donor"]
        )
    );
    // RFC 4647 Lookup over the priority list: de selects no entry, ja-JP the card's and
    // given_name's; family_name has neither, so its first entry.
    assert_eq!(
        card_in(&["de", "ja-JP"]),
        card(
            "モバイル運転免許証",
            ["名前", "Surname", "birth_date", "organ_donor"]
        )
    );
}

#[test]
fn locale_selection_tries_lookup_then_basic_filtering_then_the_untagged_entry() {
    let entries = r#"[{"locale": "de-DE", "name": "de-DE"}, {"locale": "en", "name": "en"}, {"name": "default"}]"#;
    let entries = Node::parse(entries).expect("entries");
    let pick = |tags: &[&LocaleTag<'_>]| {
        format_entry(entries.as_array().expect("array"), tags)
            .and_then(|e| e.get("name"))
            .and_then(Node::as_str)
            .map(str::to_owned)
    };
    // RFC 4647 Lookup: en-US finds en. Basic filtering: de finds de-DE. Else the entry without a locale.
    assert_eq!(pick(&[&tag("en-US")]).as_deref(), Some("en"));
    assert_eq!(pick(&[&tag("de")]).as_deref(), Some("de-DE"));
    assert_eq!(pick(&[&tag("fr")]).as_deref(), Some("default"));
    assert_eq!(
        pick(&[&tag("fr"), &tag("de")]).as_deref(),
        Some("de-DE"),
        "a later locale of the list before the default"
    );
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
        member: "sd-jwt_alg_values",
        matched: vec![es256],
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
    let names = |option: usize| -> Vec<String> {
        query
            .disclosed(&MDOC, OptionIndex(option), &view, &written)
            .expect("disclosed")
            .iter()
            .map(|(path, value)| format!("{path:?}={}", value.python_text()))
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
            .claims
            .claim(Item::new(0).expect("item"))
            .expect("claim");
        let found = !query
            .answerable(&format, &view, &[])
            .expect("the view's types")
            .is_empty();
        let selected = claim
            .path
            .select(values)
            .map_err(|e| format!("component {} fails, found {found}", e.step()))?;
        Ok(selected
            .iter()
            .map(|(path, value)| format!("{path:?}={}", value.python_text()))
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
            [Step::All, Step::Index(Some(1))]
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
    let env = Env::new([tag("en")], Vec::new(), Amounts::Formatted, Choice::First).expect("env");
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
        )
        .expect("card");
    let rows: Vec<(&str, Option<&str>)> = card
        .rows
        .iter()
        .map(|row| {
            (
                row.label.text.as_str(),
                row.value.as_ref().and_then(|v| v.text()),
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
    );
    // claim_sets is a non-empty array (§6.4.1).
    let empty_sets = parameters(
        r#"{"credentials": [{"id": "q", "format": "x", "meta": {"vct_values": ["t"]}, "claims": [{"id": "a", "path": ["a"]}], "claim_sets": []}]}"#,
        "",
    );
    let received = unsigned(&empty_sets).expect("received");
    let request = request_of(&received).expect("request");
    assert!(ClaimsQuery::parse(&format, &request.queries()[0], None).is_err());
    // A claim's id is a string (§6.3).
    let identified = |id: &str| {
        let text = parameters(
            &format!(
                r#"{{"credentials": [{{"id": "q", "format": "x", "meta": {{"vct_values": ["t"]}}, "claims": [{{"id": {id}, "path": ["a"]}}]}}]}}"#
            ),
            "",
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        ClaimsQuery::parse(&format, &request.queries()[0], None).is_ok()
    };
    assert_eq!((identified(r#""a""#), identified("1")), (true, false));
}
