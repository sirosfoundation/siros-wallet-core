//! Matching mdocs: OpenID4VP 1.0's DCQL example `simple_mdoc` (`siros-openid4vp/tests/data/
//! spec_vectors`), the card of OpenID4VCI 1.0's `credential_metadata_mso_mdoc` example
//! (`siros-openid4vp/tests/data/openid4vci-credential_metadata_mso_mdoc.json`, OpenID4VCI commit
//! d57324db70), the format's request rules with their error codes, the Verifier's algorithms
//! (B.2.4 and its table of device MAC identifiers, RFC 9864's fully-specified algorithms), and
//! the KeyAuthorizations that admit response members (B.2.1, ISO/IEC 18013-5 §9.1.2.4).

use sha2::{Digest, Sha256};
use siros_mdoc::Mdoc;
use siros_openid4vp::matching::{Accepted, Match};
use siros_openid4vp::plugins::{Format, Member, Registry, Shown};
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::request::{Item, Request};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, env, icon, parameters, query_context};

/// An mdoc of a docType and values; IssuerAuth ES256 on P-256, the device key `device_alg` on
/// `device_curve`; the KeyAuthorizations given.
fn mdoc(id: &str, doctype: &str, values: &str, device: (i64, &str), authorizations: &str) -> Held {
    let (alg, curve) = device;
    Held::new(
        id,
        "mso_mdoc",
        format!(
            r#"{{"type": "{doctype}", "metadata": {{}}, "values": {values}, "issuer_alg": -7, "issuer_curve": "P-256", "device_alg": {alg}, "device_curve": "{curve}", "key_authorizations": {authorizations}}}"#
        ),
    )
}

siros_testkit::test_host! {
    /// The core's modules and the device MAC's stand-in.
    #[derive(Default)]
    struct MdocHost {
        handles { platform: siros_testkit::TestPlatform => siros_openid4vp::host::Platform }
        zero_sized {
            siros_testkit::TestHaip => siros_openid4vp::host::Haip,
            siros_testkit::TestRequestDecryption => siros_openid4vp::host::RequestDecryption
        }
        optional {
            siros_testkit::TestCoseEncrypt => siros_openid4vp::host::CoseEncrypt,
            siros_mdoc::TestDeviceMac => siros_mdoc::DeviceMac
        }
        lacks {}
    }
}

fn registry() -> Registry<MdocHost> {
    let mut builder = Registry::<MdocHost>::builder();
    builder.format(Mdoc::new().expect("format"));
    builder.build().expect("registry")
}

/// The first query's candidates with their options, and the exclusions' clauses.
fn matched(request: &Request<'_>, held: &[Held]) -> (Vec<(String, Vec<usize>)>, Vec<String>) {
    let registry = registry();
    let wallet = Wallet::new(
        held.iter()
            .map(|h| h.credential().expect("credential"))
            .collect(),
    )
    .expect("wallet");
    let accepted = Accepted::new(request, &registry).expect("accepted");
    let matched =
        Match::run(&accepted, &wallet, &env(&["en"], Vec::new()).expect("env")).expect("match");
    let (index, _) = request.indexed_queries().next().expect("query");
    let candidates = matched
        .candidates(index)
        .iter()
        .map(|c| {
            (
                c.credential.id.to_string(),
                c.options.iter().map(|o| o.0).collect(),
            )
        })
        .collect();
    let clauses = matched
        .excluded()
        .iter()
        .map(|x| x.exclude.clause().to_string())
        .collect();
    (candidates, clauses)
}

#[test]
fn the_doctype_value_decides_and_claims_are_name_space_and_element() {
    let path = format!(
        "{}/../siros-openid4vp/tests/data/spec_vectors/simple_mdoc.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = parameters(&std::fs::read_to_string(path).expect("vector"), "");
    siros_testkit::unsigned_request!(let request = &text);
    let values =
        r#"{"org.iso.7367.1": {"vehicle_holder": "J"}, "org.iso.18013.5.1": {"given_name": "J"}}"#;
    let (found, _) = matched(
        &request,
        &[
            mdoc("car", "org.iso.7367.1.mVRC", values, (-7, "P-256"), "{}"),
            mdoc("mdl", "org.iso.18013.5.1.mDL", values, (-7, "P-256"), "{}"),
        ],
    );
    assert_eq!(found, [("car".to_owned(), vec![0])]);
}

#[test]
fn the_openid4vci_example_draws_its_card() {
    let content = include_bytes!(
        "../../siros-openid4vp/tests/data/openid4vci-credential_metadata_mso_mdoc.json"
    );
    let hash: String = Sha256::digest(content)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hash, "166fa15860ad1435a1898f2ac2a67c399b22d420a167acc552be90da3db35df1",
        "the file is the pinned one"
    );
    let metadata: serde_json::Value = serde_json::from_slice(content).expect("json");
    let metadata = &metadata["credential_configurations_supported"]["org.iso.18013.5.1.mDL"]["credential_metadata"];
    let values = r#"{"org.iso.18013.5.1": {"given_name": "Erika", "family_name": "Mustermann", "birth_date": "1971-09-01"}, "org.iso.18013.5.1.aamva": {"organ_donor": true}}"#;
    let held = Held::new(
        "mdl",
        "mso_mdoc",
        format!(
            r#"{{"type": "org.iso.18013.5.1.mDL", "metadata": {metadata}, "values": {values}}}"#
        ),
    );
    let paths = [
        r#"["org.iso.18013.5.1", "given_name"]"#,
        r#"["org.iso.18013.5.1", "family_name"]"#,
        r#"["org.iso.18013.5.1", "birth_date"]"#,
        r#"["org.iso.18013.5.1.aamva", "organ_donor"]"#,
    ];
    let claims: Vec<String> = paths
        .iter()
        .map(|p| format!(r#"{{"path": {p}}}"#))
        .collect();
    let text = parameters(
        &format!(
            r#"{{"credentials": [{{"id": "mdl", "format": "mso_mdoc", "meta": {{"doctype_value": "org.iso.18013.5.1.mDL"}}, "claims": [{}]}}]}}"#,
            claims.join(", ")
        ),
        "",
    );
    siros_testkit::unsigned_request!(let request = &text);
    let format = Mdoc::new().expect("format");
    let query = format
        .query(&request.queries()[0], query_context(&request, false, None))
        .map_err(|r| format!("{r:?}"))
        .expect("query");
    let logo = "https://state.example.org/public/mdl.png";
    let items: Vec<Item> = (0..4).map(|k| Item::new(k).expect("item")).collect();
    let card = |locales: &[&'static str]| {
        let env = env(locales, vec![icon(logo, 800).expect("icon")]).expect("env");
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
        let rows: Vec<(String, String)> = card
            .rows
            .iter()
            .map(|row| {
                (
                    row.label.text.clone(),
                    row.value
                        .as_ref()
                        .and_then(|v| v.text())
                        .expect("value")
                        .to_owned(),
                )
            })
            .collect();
        (card.title, card.icon.reference.to_string(), rows)
    };
    let rows = |labels: [&str; 4]| -> Vec<(String, String)> {
        labels
            .iter()
            .zip(["Erika", "Mustermann", "1971-09-01", "true"])
            .map(|(label, value)| ((*label).to_owned(), value.to_owned()))
            .collect()
    };
    // en-US: the card's name and logo; a claim's `name`; a claim without display shows its data
    // element identifier; a boolean its JSON text.
    assert_eq!(
        card(&["en-US"]),
        (
            "Mobile Driving License".to_owned(),
            logo.to_owned(),
            rows(["Given Name", "Surname", "birth_date", "organ_donor"])
        )
    );
    // de, then ja-JP (the wallet's own strings take the first locale, which its table serves):
    // Lookup selects no entry for de, the card's and given_name's for ja-JP; family_name has
    // neither, so its first entry.
    let (title, _, ja) = card(&["de", "ja-JP"]);
    assert_eq!(
        (title.as_str(), ja),
        (
            "モバイル運転免許証",
            rows(["名前", "Surname", "birth_date", "organ_donor"])
        )
    );
}

/// The rules the request breaks, as (text, code).
fn refusals(dcql: &str, extra: &str) -> Vec<(String, ErrorCode)> {
    let text = parameters(dcql, extra);
    siros_testkit::unsigned_request!(let request = &text);
    let registry = registry();
    match Accepted::new(&request, &registry) {
        Ok(_) => Vec::new(),
        Err(refused) => refused
            .refusals()
            .iter()
            .map(|refusal| (refusal.text(), refusal.code()))
            .collect(),
    }
}

#[test]
fn each_format_rule_refuses_with_its_code() {
    let query = |members: &str| {
        format!(r#"{{"credentials": [{{"id": "r", "format": "mso_mdoc"{members}}}]}}"#)
    };
    // B.2.3: meta.doctype_value is a string.
    for meta in [
        "",
        r#", "meta": {}"#,
        r#", "meta": {"doctype_value": ["x"]}"#,
    ] {
        assert_eq!(
            refusals(&query(meta), ""),
            [(
                "mso_mdoc r: meta.doctype_value is not a string (B.2.3)".to_owned(),
                ErrorCode::INVALID_REQUEST
            )],
            "{meta}"
        );
    }
    // B.2.4: a COSE algorithm identifier is an integer.
    let meta = r#", "meta": {"doctype_value": "t"}"#;
    for listed in [r#"["ES256"]"#, "[-7.0]", "[true]", "[]"] {
        assert_eq!(
            refusals(
                &query(meta),
                &format!(
                    r#""client_metadata":{{"vp_formats_supported":{{"mso_mdoc":{{"deviceauth_alg_values":{listed}}}}}}}"#
                )
            ),
            [(
                "mso_mdoc r: vp_formats_supported is not an object of non-empty algorithm arrays"
                    .to_owned(),
                ErrorCode::INVALID_REQUEST
            )],
            "{listed}"
        );
    }
    // §7.2: a claims path pointer into an mdoc is a name space and a data element identifier.
    for path in [
        r#"["ns"]"#,
        r#"["ns", "el", 0]"#,
        r#"["ns", null]"#,
        r#"["ns", 1]"#,
    ] {
        assert_eq!(
            refusals(&query(&format!(r#"{meta}, "claims": [{{"path": ["ns", "ok"]}}, {{"path": {path}}}]"#)), ""),
            [(
                "mso_mdoc r: claims[1].path is not [name space, data element identifier] (OpenID4VP §7.2)"
                    .to_owned(),
                ErrorCode::INVALID_REQUEST
            )],
            "{path}"
        );
    }
    assert_eq!(
        refusals(
            &query(&format!(r#"{meta}, "claims": [{{"path": ["ns", "el"]}}]"#)),
            ""
        ),
        []
    );
}

#[test]
fn the_verifiers_algorithms_admit_the_credentials_they_list() {
    let clause = "OpenID4VP B.2 vp_formats_supported";
    let p256 = r#"{"kty": "EC", "crv": "P-256", "kid": "reader-p256", "x": "x", "y": "y", "use": "enc", "alg": "ECDH-ES"}"#;
    let p384 = r#"{"kty": "EC", "crv": "P-384", "kid": "reader-p384", "x": "x", "y": "y"}"#;
    let x25519 = r#"{"kty": "OKP", "crv": "X25519", "kid": "reader-x25519", "x": "x"}"#;
    let p521 = r#"{"kty": "EC", "crv": "P-521", "kid": "reader-p521", "x": "x", "y": "y"}"#;
    let x448 = r#"{"kty": "OKP", "crv": "X448", "kid": "reader-x448", "x": "x"}"#;
    // (supported, the Verifier's keys, IssuerAuth's alg and curve, the device key's).
    type Admission = (
        &'static str,
        &'static str,
        (i64, &'static str),
        (i64, &'static str),
        Option<&'static str>,
    );
    let cases: [Admission; 19] = [
        // B.2.4's example: -7 on P-256 matches the fully-specified -9.
        (
            r#"{"issuerauth_alg_values": [-9], "deviceauth_alg_values": [-9]}"#,
            "",
            (-7, "P-256"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-35]}"#,
            "",
            (-7, "P-256"),
            (-7, "P-256"),
            Some(clause),
        ),
        // A MAC-only list admits the mdoc when a Verifier key on the device key's curve lets the
        // wallet agree the MAC key, and only then.
        (
            r#"{"deviceauth_alg_values": [-65537]}"#,
            "",
            (-7, "P-256"),
            (-7, "P-256"),
            Some(clause),
        ),
        (
            r#"{"deviceauth_alg_values": [-65537]}"#,
            p256,
            (-7, "P-256"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-65537]}"#,
            p384,
            (-7, "P-256"),
            (-7, "P-256"),
            Some(clause),
        ),
        // B.2.4's table: the MAC's identifier is the device key's curve's.
        (
            r#"{"deviceauth_alg_values": [-65538]}"#,
            p384,
            (-7, "P-256"),
            (-35, "P-384"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-65540]}"#,
            x25519,
            (-7, "P-256"),
            (-8, "X25519"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-65537]}"#,
            x25519,
            (-7, "P-256"),
            (-8, "X25519"),
            Some(clause),
        ),
        // RFC 9864: ES384 on P-384 is ESP384 (-51), ES512 on P-521 ESP512 (-52), EdDSA on
        // Ed25519 Ed25519 (-19), ES256 on brainpoolP256r1 ESB256 (-265).
        (
            r#"{"issuerauth_alg_values": [-51]}"#,
            "",
            (-35, "P-384"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-52]}"#,
            "",
            (-36, "P-521"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-19]}"#,
            "",
            (-7, "P-256"),
            (-8, "Ed25519"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-265]}"#,
            "",
            (-7, "brainpoolP256r1"),
            (-7, "P-256"),
            None,
        ),
        // RFC 9864: ES384 on brainpoolP320r1 and brainpoolP384r1 are ESB320 (-266) and ESB384
        // (-267), ES512 on brainpoolP512r1 ESB512 (-268), EdDSA on Ed448 Ed448 (-53).
        (
            r#"{"issuerauth_alg_values": [-266]}"#,
            "",
            (-35, "brainpoolP320r1"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-267]}"#,
            "",
            (-35, "brainpoolP384r1"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-268]}"#,
            "",
            (-36, "brainpoolP512r1"),
            (-7, "P-256"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-53]}"#,
            "",
            (-7, "P-256"),
            (-8, "Ed448"),
            None,
        ),
        (
            r#"{"issuerauth_alg_values": [-9]}"#,
            "",
            (-7, "P-384"),
            (-7, "P-256"),
            Some(clause),
        ),
        // B.2.4's table: P-521 -65539, X448 -65541.
        (
            r#"{"deviceauth_alg_values": [-65539]}"#,
            p521,
            (-7, "P-256"),
            (-36, "P-521"),
            None,
        ),
        (
            r#"{"deviceauth_alg_values": [-65541]}"#,
            x448,
            (-7, "P-256"),
            (-8, "X448"),
            None,
        ),
    ];
    for (supported, keys, (issuer_alg, issuer_curve), (device_alg, device_curve), want) in cases {
        let text = parameters(
            r#"{"credentials": [{"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": "t"}}]}"#,
            &format!(
                r#""client_metadata":{{"vp_formats_supported":{{"mso_mdoc":{supported}}},"jwks":{{"keys":[{keys}]}}}}"#
            ),
        );
        siros_testkit::unsigned_request!(let request = &text);
        let held = Held::new(
            "c",
            "mso_mdoc",
            format!(
                r#"{{"type": "t", "metadata": {{}}, "values": {{}}, "issuer_alg": {issuer_alg}, "issuer_curve": "{issuer_curve}", "device_alg": {device_alg}, "device_curve": "{device_curve}"}}"#
            ),
        );
        let (found, clauses) = matched(&request, &[held]);
        assert_eq!(
            clauses.first().map(String::as_str),
            want,
            "{supported} {keys} {issuer_curve} {device_curve}"
        );
        assert_eq!(found.is_empty(), want.is_some());
    }
}

#[test]
fn key_authorizations_admit_the_response_members() {
    let format = Mdoc::new().expect("format");
    let text = parameters(
        r#"{"credentials": [{"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": "t"}}]}"#,
        "",
    );
    siros_testkit::unsigned_request!(let request = &text);
    let query = format
        .query(&request.queries()[0], query_context(&request, false, None))
        .map_err(|r| format!("{r:?}"))
        .expect("query");
    let carried = |authorizations: &str, members: &[Member]| {
        let held = mdoc("c", "t", "{}", (-7, "P-256"), authorizations);
        query
            .carries(&held.credential().expect("credential"), members)
            .expect("carries")
    };
    let paso = [
        Member::element("urn:paso:sca:1", "jti"),
        Member::element("urn:paso:sca:1", "transaction_data_hash"),
    ];
    let qes = [Member::element(
        "org.cloudsignatureconsortium.dm.1",
        "qesApproval",
    )];
    // ISO/IEC 18013-5 §9.1.2.4: a name space authorizes every element of it; an element list
    // authorizes its elements alone.
    assert!(carried(r#"{"namespaces": ["urn:paso:sca:1"]}"#, &paso));
    assert!(carried(
        r#"{"elements": {"org.cloudsignatureconsortium.dm.1": ["qesApproval"]}}"#,
        &qes
    ));
    assert!(!carried(
        r#"{"elements": {"org.cloudsignatureconsortium.dm.1": ["other"]}}"#,
        &qes
    ));
    assert!(!carried(r#"{"namespaces": ["org.iso.18013.5.1"]}"#, &paso));
    assert!(!carried("{}", &paso), "none authorized");
    assert!(carried("{}", &[]), "no member");
    // A claim is no data element.
    assert!(!carried(
        r#"{"namespaces": ["urn:paso:sca:1"]}"#,
        &[Member::claim("jti")]
    ));
}

#[test]
fn an_element_the_transaction_writes_answers_the_claim_naming_it() {
    // A DeviceSigned element the transaction writes answers a claim naming it, unless the claim
    // asks for values: the element's value is made at presentation.
    let format = Mdoc::new().expect("format");
    let answerable = |claim: &str, provided: &[Member]| {
        let text = parameters(
            &format!(
                r#"{{"credentials": [{{"id": "q", "format": "mso_mdoc", "meta": {{"doctype_value": "t"}}, "claims": [{claim}]}}]}}"#
            ),
            "",
        );
        siros_testkit::unsigned_request!(let request = &text);
        let query = format
            .query(&request.queries()[0], query_context(&request, false, None))
            .map_err(|r| format!("{r:?}"))
            .expect("query");
        let held = mdoc("c", "t", "{}", (-7, "P-256"), "{}");
        let options = query
            .answerable(
                &held.credential().expect("credential"),
                &env(&["en"], Vec::new()).expect("env"),
                provided,
            )
            .expect("answerable");
        !options.is_empty()
    };
    let written = [Member::element("urn:paso:sca:1", "jti")];
    let named = r#"{"path": ["urn:paso:sca:1", "jti"]}"#;
    assert!(answerable(named, &written));
    assert!(!answerable(named, &[]), "nothing written, nothing held");
    assert!(
        !answerable(
            r#"{"path": ["urn:paso:sca:1", "jti"], "values": ["j"]}"#,
            &written
        ),
        "a claim asking for values"
    );
    assert!(
        !answerable(r#"{"path": ["urn:paso:sca:1", "other"]}"#, &written),
        "another element"
    );
    // The card of a credential answering through the written element draws, unless its values
    // hold the element's name space as no object: the wallet's data is broken, and the card
    // faults.
    let text = parameters(
        &format!(
            r#"{{"credentials": [{{"id": "q", "format": "mso_mdoc", "meta": {{"doctype_value": "t"}}, "claims": [{named}]}}]}}"#
        ),
        "",
    );
    siros_testkit::unsigned_request!(let request = &text);
    let query = format
        .query(&request.queries()[0], query_context(&request, false, None))
        .map_err(|r| format!("{r:?}"))
        .expect("query");
    let env = env(&["en"], Vec::new()).expect("env");
    let items = [Item::new(0).expect("item")];
    let drawn = |values: &str| {
        let held = mdoc("c", "t", values, (-7, "P-256"), "{}");
        let credential = held.credential().expect("credential");
        let answered = query
            .answerable(&credential, &env, &written)
            .expect("answerable");
        let shown = Shown {
            everyone: &items,
            chosen: &[],
        };
        (
            !answered.is_empty(),
            query.draw(&credential, shown, &env).is_ok(),
        )
    };
    assert_eq!(drawn("{}"), (true, true));
    assert_eq!(drawn(r#"{"urn:paso:sca:1": "x"}"#), (true, false));
}
