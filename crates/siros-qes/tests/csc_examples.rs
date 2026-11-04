//! The profile against the CSC data model bindings' own examples (§7.1.2, §7.3) and its rules
//! (§6.3, §6.4, §7.2.1), through the core, as check_qes.py runs them. The examples are the
//! model's reading of the specification (`tests/data`).

mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use siros_openid4vp::consent::Header;
use siros_openid4vp::matching::{Accepted, Match};
use siros_openid4vp::plugins::ProfileFinding;
use siros_openid4vp::resolve::{Finding, Outcome};
use siros_openid4vp::rows::Label;
use siros_openid4vp::wallet::Holder;
use siros_qes::{CLAIM, FailedDocument, FailedDocuments, Fetched, NAMESPACE, QesProfile, TYPE};

use common::fixtures::{
    CONTRACT, HREFS, approval, embedded, known, nist, published, terms, with_documents,
};
use common::{
    Fields, Holding, Matched, QUERY_7_1_2, QUERY_SD_JWT, ShownRow, Viewed, approve, csc, entry,
    env, hex, parameters, phase_one, registry, request_of, serving, shown, unsigned, wallet,
};

/// The refusal texts of a request.
fn refusals(text: &str, profile: Option<QesProfile>) -> Vec<String> {
    let received = unsigned(text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(profile);
    match Accepted::new(&request, &registry) {
        Ok(_) => Vec::new(),
        Err(refused) => refused.texts().collect(),
    }
}

/// A row as the expected tables write it.
fn row(
    section: Option<&str>,
    label: &str,
    kind: Option<&'static str>,
    text: Option<&str>,
) -> ShownRow {
    (
        section.map(str::to_owned),
        label.to_owned(),
        kind,
        text.map(str::to_owned),
    )
}

/// A consent header.
fn header(title: &str, confirm: &str, cancel: &str) -> Header {
    Header {
        title: Label::text(title),
        confirm: Label::text(confirm),
        cancel: Label::text(cancel),
    }
}

/// The attestation approving signatures, as an mdoc.
fn attestation() -> Holding {
    Holding::approving("att", "mso_mdoc", &["eu_eidas_qes"])
}

/// The one consent entry of a request for §7.1.2's query and the credential.
fn viewed(entry_json: &str, held: &Holding, profile: QesProfile, locale: &'static str) -> Viewed {
    let text = parameters(QUERY_7_1_2, &[entry(entry_json)]);
    let (_, views) = phase_one(
        &text,
        std::slice::from_ref(held),
        &registry(Some(profile)),
        &env(locale),
    )
    .expect("accepted");
    let [view] = views.as_slice() else {
        panic!("one entry: {views:?}")
    };
    view.clone()
}

#[test]
fn csc_7_3_binds_once_its_credential_ids_name_its_query() {
    // Catches the profile refusing §7.3's entry, or registering under another type identifier.
    let request = Fields::of(&csc("csc-7.3-request"));
    let dcql = request.get("dcql_query").expect("dcql_query");
    let as_written = csc("csc-7.3-entry");
    assert_eq!(
        refusals(
            &parameters(dcql, &[entry(&as_written)]),
            Some(QesProfile::default())
        ),
        ["C2 entry 0: credential_ids ['xyz123'] names no Credential Query of the request"],
        "§7.3 as written: its entry names no query of its request"
    );
    let fixed = Fields::of(&as_written)
        .set("credential_ids", r#"["qscd_service_attestation"]"#)
        .json();
    let text = parameters(dcql, &[entry(&fixed)]);
    assert_eq!(
        refusals(&text, None),
        [format!("C1 entry 0: no profile for type {TYPE}")],
        "without the profile its type is unknown"
    );
    let (matched, _) = phase_one(
        &text,
        &[attestation()],
        &registry(Some(QesProfile::default())),
        &env("en"),
    )
    .expect("accepted");
    assert_eq!(
        matched,
        Matched {
            candidates: vec![("att".to_owned(), vec![0])],
            excluded: Vec::new(),
        }
    );
}

#[test]
fn csc_7_1_2_is_rendered_by_6_4() {
    // Catches a §6.4 rendering that differs from the model's: the statement of what the
    // approval creates and under which framework, each document's label, one-time password,
    // link and integrity in its section, the approval's header, no warning, the overlay before
    // the credential's rows.
    let view = viewed(
        &approval().json(),
        &attestation(),
        QesProfile::default(),
        "en",
    );
    let doc = |n: u8| format!("Document {n}");
    let (d1, d2, d3) = (doc(1), doc(2), doc(3));
    assert_eq!(
        shown(view.entry.rows()),
        [
            row(
                None,
                "Creates qualified electronic signatures under the EU eIDAS regulation",
                None,
                None
            ),
            row(None, "Signatures", Some("text"), Some("2")),
            row(Some(&d1), "Name", Some("text"), Some("Example Contract")),
            row(Some(&d1), "One-time password", Some("text"), Some("51623")),
            row(Some(&d1), "Document link", Some("url"), Some(HREFS[0])),
            row(Some(&d1), "Integrity", Some("text"), Some("Not checked")),
            row(
                Some(&d2),
                "Name",
                Some("text"),
                Some("Example Terms of Service")
            ),
            row(Some(&d2), "Document link", Some("url"), Some(HREFS[1])),
            row(Some(&d2), "Integrity", Some("text"), Some("Not checked")),
            row(Some(&d3), "Name", Some("text"), Some("Example Invoice")),
            row(Some(&d3), "One-time password", Some("text"), Some("83920")),
            row(Some(&d3), "Document link", Some("url"), Some(HREFS[2])),
            row(Some(&d3), "Integrity", Some("text"), Some("Not checked")),
            row(None, "userName", Some("text"), Some("willeke")),
        ]
    );
    let overlay = view.entry.overlay().expect("the approval's overlay");
    assert_eq!(
        (&overlay.header, &overlay.hint),
        (&None, &None),
        "no transaction header, no hint"
    );
    assert_eq!(
        view.header,
        Some(header("Approve qualified signatures", "Approve", "Cancel"))
    );
    assert_eq!(
        viewed(
            &approval().json(),
            &attestation(),
            QesProfile::default(),
            "de"
        )
        .header,
        Some(header(
            "Qualifizierte Signaturen freigeben",
            "Freigeben",
            "Abbrechen"
        )),
        "German: the profile's own strings, the wallet's cancel"
    );
}

#[test]
fn a_seal_a_nameless_document_and_an_embedded_link_are_rendered_by_6_4() {
    // Catches the seal's statement and title, a document without a label, a link other than
    // https shown as included in the request, and no integrity row without a checksum.
    let seal = Fields::of(&embedded())
        .set("signatureQualifier", r#""eu_eidas_qeseal""#)
        .json();
    let held = Holding::approving("att", "mso_mdoc", &["eu_eidas_qeseal"]);
    let view = viewed(&seal, &held, QesProfile::default(), "en");
    let (d1, d2) = (Some("Document 1"), Some("Document 2"));
    assert_eq!(
        shown(view.entry.rows()),
        [
            row(
                None,
                "Creates qualified electronic seals under the EU eIDAS regulation",
                None,
                None
            ),
            row(None, "Signatures", Some("text"), Some("2")),
            row(d1, "Name", Some("text"), Some("Example Configuration")),
            row(
                d1,
                "Document link",
                Some("text"),
                Some("Included in the request")
            ),
            row(d2, "This document has no name", None, None),
            row(
                d2,
                "Document link",
                Some("url"),
                Some("https://rp.example/a.pdf")
            ),
            row(None, "userName", Some("text"), Some("willeke")),
        ]
    );
    assert_eq!(
        view.header,
        Some(header("Approve qualified seals", "Approve", "Cancel"))
    );
}

#[test]
fn a_held_document_is_checked_against_its_checksum() {
    // Catches §6.3 and §6.4 on the documents the wallet holds: a match shows the integrity
    // checked; a mismatch or a failed fetch aborts, the credential excluded; a document without
    // a label says so.
    let holding = |href: &str, fetched: Fetched| QesProfile::new([(href.to_owned(), fetched)]);
    let contract = || Fetched::Content(CONTRACT.to_vec());
    let rows = shown(
        viewed(
            &with_documents(&[terms(true)]),
            &attestation(),
            holding(HREFS[1], contract()),
            "en",
        )
        .entry
        .rows(),
    );
    assert_eq!(
        rows.get(rows.len() - 2),
        Some(&row(
            Some("Document 1"),
            "Integrity",
            Some("text"),
            Some("Checked automatically")
        ))
    );
    let failing = parameters(QUERY_7_1_2, &[entry(&approval().json())]);
    for (k, fetched) in [(0, contract()), (2, Fetched::Failed)] {
        let (matched, views) = phase_one(
            &failing,
            &[attestation()],
            &registry(Some(holding(HREFS[k], fetched))),
            &env("en"),
        )
        .expect("accepted");
        assert_eq!(
            (matched, views.len()),
            (
                Matched {
                    candidates: Vec::new(),
                    excluded: vec![(
                        "att".to_owned(),
                        format!("document {} does not match its checksum", k + 1),
                        "CSC §6.3".to_owned()
                    )],
                },
                0
            )
        );
    }
    let nameless = viewed(
        &with_documents(&[terms(false)]),
        &attestation(),
        QesProfile::default(),
        "en",
    );
    assert_eq!(
        shown(nameless.entry.rows()).get(2),
        Some(&row(
            Some("Document 1"),
            "This document has no name",
            None,
            None
        ))
    );
}

#[test]
fn only_a_credential_whose_rulebook_approves_the_qualifier_and_carries_the_approval_binds() {
    // Catches the binding rules (§6.3; §7.2.1 and its Note 22) and their order: the qualifier
    // the credential's rulebook approves, then the presentation carrying qesApproval; a
    // credential without a key answers no query requiring holder binding (OpenID4VP §6.1).
    let profile = || registry(Some(QesProfile::default()));
    let mdoc = parameters(QUERY_7_1_2, &[entry(&approval().json())]);
    let excluded = |id: &str, reason: &str, clause: &str| Matched {
        candidates: Vec::new(),
        excluded: vec![(id.to_owned(), reason.to_owned(), clause.to_owned())],
    };
    let qualifier = "the credential cannot approve eu_eidas_qes";
    let note_22 = "CSC §6.3; §7.2.1 Note 22";
    let seal = || Holding::approving("att", "mso_mdoc", &["eu_eidas_qeseal"]);
    let cases = [
        (seal(), excluded("att", qualifier, note_22)),
        (seal().uncarried(), excluded("att", qualifier, note_22)),
        (
            attestation().uncarried(),
            excluded(
                "att",
                "the presentation cannot carry qesApproval",
                "CSC §7.2.1; OpenID4VP B.2",
            ),
        ),
    ];
    for (held, want) in cases {
        let (matched, _) = phase_one(&mdoc, std::slice::from_ref(&held), &profile(), &env("en"))
            .expect("accepted");
        assert_eq!(matched, want, "{held:?}");
    }
    let sd_jwt = parameters(QUERY_SD_JWT, &[entry(&approval().json())]);
    let intended = Holding::approving("intended", "dc+sd-jwt", &["eu_eidas_qes"]);
    let other = Holding {
        qes: None,
        ..Holding::approving("other", "dc+sd-jwt", &[])
    };
    let unbound = Holding {
        holder: Holder::Unbound,
        ..Holding::approving("unbound", "dc+sd-jwt", &["eu_eidas_qes"])
    };
    let (matched, _) =
        phase_one(&sd_jwt, &[intended, other, unbound], &profile(), &env("en")).expect("accepted");
    assert_eq!(
        matched,
        Matched {
            candidates: vec![("intended".to_owned(), vec![0])],
            excluded: vec![("other".to_owned(), qualifier.to_owned(), note_22.to_owned())],
        }
    );
}

#[test]
fn a_qes_document_the_profile_cannot_read_is_a_fault() {
    // Catches a malformed QES document in the wallet's registration read as approving nothing:
    // it is an error where the profile reads it. A document without qualifiers approves none.
    let text = parameters(QUERY_7_1_2, &[entry(&approval().json())]);
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let registry = registry(Some(QesProfile::default()));
    let accepted = Accepted::new(&request, &registry).expect("accepted");
    let matching = |document: &str| {
        let held = [Holding {
            qes: Some(document.to_owned()),
            ..attestation()
        }];
        let wallet = wallet(&held);
        Match::run(&accepted, &wallet, &env("en"))
            .map(|matched| matched.excluded().len())
            .map_err(|fault| fault.to_string())
    };
    assert_eq!(
        matching(r#"{"signature_qualifiers": ["eu_eidas_qes"]}"#),
        Ok(0)
    );
    assert_eq!(matching("{}"), Ok(1));
    for malformed in [
        "eu_eidas_qes",
        r#"["eu_eidas_qes"]"#,
        r#"{"signature_qualifiers": "eu_eidas_qes"}"#,
        r#"{"signature_qualifiers": [1]}"#,
        r#"{"signature_qualifiers": ["eu_eidas_qes"], "rulebook": "x"}"#,
    ] {
        let got = matching(malformed);
        assert!(
            got.as_ref()
                .is_err_and(|fault| fault.starts_with("att: the qes document")),
            "{malformed}: {got:?}"
        );
    }
}

#[test]
fn qes_approval_is_the_digest_of_the_bytes_its_format_names() {
    // Catches a wrong qesApproval (§7.2, §7.2.1) for any hashAlgorithmOID: the digest of the
    // entry as received, base64, in a Key Binding JWT claim; of its decoded UTF-8 bytes, a bstr,
    // in the DeviceSigned element; a member the format does not carry.
    let registry = registry(Some(QesProfile::default()));
    for n in 1..=10 {
        let oid = format!("2.16.840.1.101.3.4.2.{n}");
        let (json, documents) = known(&oid, &[], &[]);
        let raw = entry(&json);
        let decoded = URL_SAFE_NO_PAD.decode(&raw).expect("base64url");
        let cases = [
            (
                QUERY_7_1_2,
                attestation(),
                serde_json::json!([[
                    ["element", NAMESPACE, "qesApproval"],
                    {"bytes": hex(&nist(&oid, &decoded))}
                ]]),
            ),
            (
                QUERY_SD_JWT,
                Holding::approving("att", "dc+sd-jwt", &["eu_eidas_qes"]),
                serde_json::json!([[
                    ["claim", CLAIM],
                    {"text": STANDARD.encode(nist(&oid, raw.as_bytes()))}
                ]]),
            ),
        ];
        for (query, held, want) in cases {
            let text = parameters(query, std::slice::from_ref(&raw));
            let site = serving(documents.clone());
            let got = approve(&text, &held, &registry, |resource| site.answer(resource));
            assert_eq!(got.ok(), Some(want), "{oid} {}", held.format);
        }
    }
}

#[test]
fn phase_2_verifies_each_document_the_profile_does_not_hold() {
    // Catches §6.3 checked by phase 2: each linked document with a checksum the profile does not
    // hold is fetched and verified; one whose fetch fails or whose content does not match makes
    // phase 2 fall back with what the fetch returned; informed, the matcher excludes the
    // credential (abort); a held document is not fetched again.
    let held = attestation();
    let (json, documents) = known("2.16.840.1.101.3.4.2.1", &[1], &[2]);
    let text = parameters(QUERY_7_1_2, &[entry(&json)]);
    let registry = registry(Some(QesProfile::default()));
    let site = serving(documents);
    let findings = match approve(&text, &held, &registry, |resource| site.answer(resource)) {
        Err(Outcome::Fallback(findings)) => findings,
        other => panic!("a fallback: {other:?}"),
    };
    let profile_findings: Vec<&ProfileFinding> = findings
        .items()
        .iter()
        .map(|finding| match finding {
            Finding::Revalidation { record: 0, finding } => finding,
            other => panic!("the record's revalidation: {other:?}"),
        })
        .collect();
    let failed: Vec<Vec<FailedDocument>> = profile_findings
        .iter()
        .map(|finding| {
            finding
                .data::<FailedDocuments>()
                .expect("QES's finding")
                .documents()
                .to_vec()
        })
        .collect();
    assert_eq!(
        failed,
        [vec![
            FailedDocument {
                href: HREFS[1].to_owned(),
                fetched: Fetched::Content([published(1), b"!".to_vec()].concat()),
            },
            FailedDocument {
                href: HREFS[2].to_owned(),
                fetched: Fetched::Failed,
            },
        ]]
    );
    let informed = registry.informed(&profile_findings).expect("informed");
    let (matched, _) =
        phase_one(&text, std::slice::from_ref(&held), &informed, &env("en")).expect("accepted");
    assert_eq!(
        matched,
        Matched {
            candidates: Vec::new(),
            excluded: vec![(
                "att".to_owned(),
                "document 2 does not match its checksum".to_owned(),
                "CSC §6.3".to_owned()
            )],
        }
    );
    let (_, without_first) = known("2.16.840.1.101.3.4.2.1", &[], &[0]);
    let holding_first = common::registry(Some(QesProfile::new([(
        HREFS[0].to_owned(),
        Fetched::Content(published(0)),
    )])));
    let site = serving(without_first);
    let approved = approve(&text, &held, &holding_first, |resource| {
        site.answer(resource)
    });
    assert!(approved.is_ok(), "a held document is not fetched again");
}
