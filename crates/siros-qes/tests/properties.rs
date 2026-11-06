//! The properties check_props.py states of the QES profile, over a seeded stream of entries,
//! credentials, held documents and hosts shaped as its `qes_body` and `dress` shape them:
//!
//! - binding (`check_qes_binding`, CSC §6.3, §7.2.1 Note 22): a credential binds the query's
//!   entry exactly when its rulebook approves the entry's qualifier, its presentation carries the
//!   approval, and no document the profile holds fails its checksum; excluded otherwise, for the
//!   first rule it breaks;
//! - the box (`P-QES box`): the approval's rows, opening with a full-text statement, before the
//!   credential's, no warning, the approval's header;
//! - the findings (`expected_findings`, §6.3): phase 2 falls back exactly on the documents with
//!   href and checksum the profile does not hold whose fetch fails or does not match;
//! - the fallback (`check_fallback`): informed, the matcher excludes the credential;
//! - the response (`R-qesApproval`, §7.2.1): the digest by hashAlgorithmOID of the bytes the
//!   format names.

mod common;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::seq::IndexedRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::json;
use siros_explain::Text;
use siros_openid4vp::effects::Fetch;
use siros_openid4vp::json::quote;
use siros_openid4vp::plugins::{ProfileFinding, Registry};
use siros_openid4vp::resolve::{Finding, Outcome};
use siros_qes::{CLAIM, DocumentHref, FailedDocuments, Fetched, NAMESPACE, QesProfile, QesTitle};
use siros_testkit::Published;
use siros_testkit::TestHost;

use common::fixtures::{nist, sri};
use common::{
    Holding, Matched, QUERY_7_1_2, QUERY_SD_JWT, approve, entry, env, hex, parameters, phase_one,
    plain, registry, serving,
};

/// check_props.py's documents: the first published as it is, the second altered, the third not
/// at all.
const DOCS: [&str; 3] = [
    "https://rp.example/doc0.pdf",
    "https://rp.example/doc1.pdf",
    "https://rp.example/doc2.pdf",
];
const DOC: &[u8] = b"%PDF-1.7 contract";
const OIDS: [&str; 3] = [
    "2.16.840.1.101.3.4.2.1",
    "2.16.840.1.101.3.4.2.2",
    "2.16.840.1.101.3.4.2.8",
];
const QUALIFIERS: [&str; 2] = ["eu_eidas_qes", "eu_eidas_qeseal"];

/// What a fetch of a document returns.
fn published_content(href: &str) -> Option<Vec<u8>> {
    match DOCS.iter().position(|doc| *doc == href) {
        Some(0) => Some(DOC.to_vec()),
        Some(1) => Some([DOC, b"!"].concat()),
        _ => None,
    }
}

/// A linked document of the stream.
struct Doc {
    href: &'static str,
    checksum: bool,
}

/// One case of the stream.
struct Case {
    entry: String,
    qualifier: &'static str,
    oid: &'static str,
    docs: Vec<Doc>,
    held: Vec<(usize, Fetched)>,
    approved: Option<Vec<&'static str>>,
    credential: Holding,
}

fn case(rng: &mut ChaCha8Rng) -> Case {
    let count = rng.random_range(1..=3);
    let mut docs = Vec::new();
    let mut json_docs = Vec::new();
    for k in 0..count {
        let href = *DOCS.choose(rng).expect("a document");
        let checksum = rng.random_bool(0.5);
        let otp = k == 0 && rng.random_bool(0.5);
        let labelled = !(k + 1 == count && rng.random_bool(0.3));
        let mut members = Vec::new();
        if labelled {
            members.push(format!(r#""label": "Document {k}""#));
        }
        members.push(r#""hash": "aGFzaA==", "hashType": "sodr""#.to_owned());
        members.push(if otp {
            r#""access": {"type": "OTP", "oneTimePassword": "51623"}"#.to_owned()
        } else {
            r#""access": {"type": "public"}"#.to_owned()
        });
        members.push(format!(r#""href": {}"#, quote(href)));
        if checksum {
            members.push(format!(r#""checksum": {}"#, quote(&sri(DOC))));
        }
        json_docs.push(format!("{{{}}}", members.join(", ")));
        docs.push(Doc { href, checksum });
    }
    let qualifier = *QUALIFIERS.choose(rng).expect("a qualifier");
    let oid = *OIDS.choose(rng).expect("an OID");
    let entry = format!(
        r#"{{"type": "{}", "credential_ids": ["xyz123"], "numSignatures": {count}, "signatureQualifier": "{qualifier}", "documentInfos": [{}], "hashAlgorithmOID": "{oid}"}}"#,
        siros_qes::TYPE,
        json_docs.join(", ")
    );
    let format = if rng.random_bool(0.5) {
        "mso_mdoc"
    } else {
        "dc+sd-jwt"
    };
    let approved: Vec<&str> = QUALIFIERS
        .iter()
        .copied()
        .filter(|_| rng.random_bool(0.6))
        .collect();
    let mut credential = Holding::approving("c", format, &approved);
    let approved = if approved.is_empty() && rng.random_bool(0.5) {
        credential.qes = None;
        None
    } else {
        Some(approved)
    };
    if rng.random_bool(0.2) {
        credential = credential.uncarried();
    }
    let held = (0..3)
        .filter(|_| rng.random_bool(0.25))
        .map(|k| {
            let fetched = published_content(DOCS[k]).map_or(Fetched::Failed, Fetched::Content);
            (k, fetched)
        })
        .collect();
    Case {
        entry,
        qualifier,
        oid,
        docs,
        held,
        approved,
        credential,
    }
}

impl Case {
    fn profile(&self) -> QesProfile {
        QesProfile::new(
            self.held
                .iter()
                .map(|(k, fetched)| (DocumentHref::new(DOCS[*k]), fetched.clone())),
        )
    }

    fn held(&self, href: &str) -> Option<&Fetched> {
        self.held
            .iter()
            .find(|(k, _)| DOCS[*k] == href)
            .map(|(_, fetched)| fetched)
    }

    /// The clause of the first binding rule the credential breaks.
    fn broken(&self) -> Option<&'static str> {
        let approves = self
            .approved
            .as_ref()
            .is_some_and(|approved| approved.contains(&self.qualifier));
        if !approves {
            return Some("CSC §6.3; §7.2.1 Note 22");
        }
        if !self.credential.carries() {
            return Some("CSC §7.2.1; OpenID4VP B.2");
        }
        self.docs
            .iter()
            .any(|doc| {
                doc.checksum
                    && self.held(doc.href).is_some_and(|fetched| match fetched {
                        Fetched::Content(content) => sri(content) != sri(DOC),
                        Fetched::Failed => true,
                    })
            })
            .then_some("CSC §6.3")
    }

    /// The documents phase 2 fetches and finds failing, with what the fetch returns.
    fn failing(&self) -> Vec<(&'static str, Option<Vec<u8>>)> {
        self.docs
            .iter()
            .filter(|doc| doc.checksum && self.held(doc.href).is_none())
            .map(|doc| (doc.href, published_content(doc.href)))
            .filter(|(_, content)| content.as_deref().is_none_or(|c| sri(c) != sri(DOC)))
            .collect()
    }
}

#[test]
fn the_profile_keeps_the_properties_the_model_states() {
    // Catches a binding, a box, a finding, a fallback or a response breaking the model's stated
    // rule on combinations no fixture holds: several documents, some held, either format.
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let mut seen = [0usize; 4];
    for at in 0..400 {
        let case = case(&mut rng);
        let raw = entry(&case.entry);
        let query = if case.credential.format == "mso_mdoc" {
            QUERY_7_1_2
        } else {
            QUERY_SD_JWT
        };
        let text = parameters(query, std::slice::from_ref(&raw));
        let registry = registry(Some(case.profile()));
        let held = std::slice::from_ref(&case.credential);
        let (matched, views) = phase_one(&text, held, &registry, &env("en")).expect("accepted");
        if let Some(clause) = case.broken() {
            assert_eq!(
                matched,
                Matched {
                    candidates: Vec::new(),
                    excluded: vec![("c".to_owned(), clause.to_owned())],
                },
                "case {at}: {}",
                case.entry
            );
            seen[0] += 1;
            continue;
        }
        assert_eq!(matched.candidates, [("c".to_owned(), vec![0])], "case {at}");
        let [view] = views.as_slice() else {
            panic!("case {at}: one entry")
        };
        let overlay = view.entry.overlay().expect("the approval's overlay");
        let rows: Vec<_> = view.entry.rows().collect();
        let title = if case.qualifier == "eu_eidas_qes" {
            QesTitle::TitleSignatures
        } else {
            QesTitle::TitleSeals
        };
        assert!(
            overlay.header.is_none()
                && overlay.hint.is_none()
                && rows.first().is_some_and(|row| row.value.is_none())
                && rows.last().map(|row| plain(&row.label, "en")).as_deref() == Some("userName")
                && view.header.as_ref().map(|h| &h.title) == Some(&Text::of(&title)),
            "case {at}: {:?}",
            view.entry
        );
        let failing = case.failing();
        let published = serving(published());
        let mut asked = Vec::new();
        let outcome = approve(&text, &case.credential, &registry, |resource| {
            asked.push(resource.url().written().to_owned());
            published.answer(resource)
        });
        match outcome {
            Err(Outcome::Fallback(findings)) => {
                let finding: Vec<&ProfileFinding> = findings
                    .items()
                    .iter()
                    .map(|finding| match finding {
                        Finding::Revalidation { record: 0, finding } => finding,
                        other => panic!("case {at}: {other:?}"),
                    })
                    .collect();
                let found: Vec<(String, Option<Vec<u8>>)> = finding
                    .iter()
                    .filter_map(|finding| finding.data::<FailedDocuments>())
                    .flat_map(|failed| failed.documents())
                    .map(|document| {
                        let content = match document.fetched() {
                            Fetched::Content(content) => Some(content.clone()),
                            Fetched::Failed => None,
                        };
                        (document.href().as_str().to_owned(), content)
                    })
                    .collect();
                let want: Vec<(String, Option<Vec<u8>>)> = failing
                    .iter()
                    .map(|(href, content)| ((*href).to_owned(), content.clone()))
                    .collect();
                assert_eq!(found, want, "case {at}: the findings");
                let informed = registry.informed(&finding).expect("informed");
                let (again, _) = phase_one(&text, held, &informed, &env("en")).expect("accepted");
                assert!(
                    again.candidates.is_empty()
                        && again
                            .excluded
                            .iter()
                            .all(|(_, clause)| clause == "CSC §6.3"),
                    "case {at}: informed, {again:?}"
                );
                seen[1] += 1;
            }
            Ok(members) => {
                assert!(failing.is_empty(), "case {at}: no fallback on {failing:?}");
                let want = if case.credential.format == "mso_mdoc" {
                    let decoded = URL_SAFE_NO_PAD.decode(&raw).expect("base64url");
                    json!([[["element", NAMESPACE, "qesApproval"], {"bytes": hex(&nist(case.oid, &decoded))}]])
                } else {
                    json!([[["claim", CLAIM], {"text": STANDARD.encode(nist(case.oid, raw.as_bytes()))}]])
                };
                assert_eq!(members, want, "case {at}: qesApproval");
                seen[if case.credential.format == "mso_mdoc" {
                    2
                } else {
                    3
                }] += 1;
            }
            Err(other) => panic!("case {at}: {other:?}"),
        }
        for (failed, href) in asked.iter().enumerate() {
            assert!(
                fails_on(&text, &case.credential, &registry, &published, failed, href),
                "case {at}: ask {failed} of {asked:?} answered as failed, no fallback on {href}"
            );
        }
    }
    assert!(
        seen.iter().all(|count| *count >= 20),
        "each property held on at least 20 cases: {seen:?}"
    );
}

/// Whether phase 2 falls back on `href`, unfetched, when the caller answers its `failed`-th ask
/// as a failed fetch and every other ask from `published`: phase 2 reads every answer it asks for.
fn fails_on(
    text: &str,
    held: &Holding,
    registry: &Registry<TestHost>,
    published: &Published,
    failed: usize,
    href: &str,
) -> bool {
    let mut asks = 0..;
    let outcome = approve(text, held, registry, |resource| {
        if asks.next() == Some(failed) {
            Fetch::Unfetched
        } else {
            published.answer(resource)
        }
    });
    let Err(Outcome::Fallback(findings)) = outcome else {
        return false;
    };
    findings
        .items()
        .iter()
        .filter_map(|finding| match finding {
            Finding::Revalidation { finding, .. } => finding.data::<FailedDocuments>(),
            Finding::Diverged { .. }
            | Finding::Rendered { .. }
            | Finding::Unusable { .. }
            | Finding::Format { .. } => None,
        })
        .flat_map(FailedDocuments::documents)
        .any(|document| document.href().as_str() == href && *document.fetched() == Fetched::Failed)
}

/// What is published at the documents' hrefs.
fn published() -> Vec<(String, Vec<u8>)> {
    DOCS.iter()
        .filter_map(|href| published_content(href).map(|content| ((*href).to_owned(), content)))
        .collect()
}
