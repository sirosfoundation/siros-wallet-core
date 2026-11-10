//! check_props.py `check_response` and the checks it calls: phase 2 for one selection against
//! what the display showed, the findings it must make (`expected_findings`), the consent re-run
//! after a fallback (`check_fallback`), what binds each presentation to the request
//! (`check_session`), each profile's members (`check_members`, `check_signals`), and the records
//! phase 2 rejects or falls back on (`check_tampered`).

use crate::common::HaipHost;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use siros_explain::Explain;
use siros_openid4vp::json::{Node, quote};
use siros_openid4vp::matching::{Accepted, EntryView, Match, ShownDigest, Views};
use siros_openid4vp::plugins::ProfileFinding;
use siros_openid4vp::request::{EntryIndex, Multiplicity};
use siros_openid4vp::resolve::{Delivery, Finding, Outcome, Prepared};
use siros_openid4vp::wallet::{Credential, Wallet};
use siros_paso::adhoc::AdhocFailure;
use siros_paso::{OptionalModule, PasoFinding};
use siros_qes::FailedDocuments;
use siros_testkit::oracle;

use crate::common::sri;
use crate::dressed::{Case, document};
use crate::generate::{NOW, published, resources};
use crate::outcome::{given, jwt_claims};
use crate::spec::select;
use crate::tally::Tally;

mod members;
mod session;
mod tampered;

use members::members;
use session::{members_of, mode, opened_jwe, read_mdoc, read_sd_jwt, response_key, session};
use tampered::{renewed, tampered};

/// What phase 2 must find for a record: its credential refused, PaSO's refused JWT (with the
/// identifier of the §5.3 step it fails) and failed images, QES's failed documents.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Found {
    Unusable,
    Paso {
        lacks: Option<OptionalModule>,
        refused: Vec<(String, &'static str)>,
        failed: Vec<String>,
    },
    Qes(Vec<String>),
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn credential<'w>(case: &'w Case<'_>, id: &str) -> &'w Credential<'w> {
    case.wallet
        .credentials()
        .iter()
        .find(|c| c.id.as_str() == id)
        .expect("a credential of the wallet")
}

/// A record's id written as Python's `json.dumps([...], ensure_ascii=False, separators=(",",
/// ":"))` writes the model's: `[query, credential, option, [entries], {attested}, request,
/// shown]`.
fn record_id(
    query: &str,
    credential: &str,
    option: usize,
    entries: &[usize],
    attested: &[(String, String)],
    request: &str,
    shown: &str,
) -> String {
    let entries: Vec<String> = entries.iter().map(ToString::to_string).collect();
    let pairs: Vec<String> = attested
        .iter()
        .map(|(name, text)| format!("{}:{}", quote(name), quote(text)))
        .collect();
    format!(
        "[{},{},{option},[{}],{{{}}},{},{}]",
        quote(query),
        quote(credential),
        entries.join(","),
        pairs.join(","),
        quote(request),
        quote(shown)
    )
}

/// A record's fields: query, credential, option, entries, attested pairs, request digest, and
/// the digest of the texts its entry shows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fields {
    query: String,
    credential: String,
    option: usize,
    entries: Vec<usize>,
    attested: Vec<(String, String)>,
    request: String,
    shown: String,
}

impl Fields {
    fn of(view: &EntryView<'_>) -> Self {
        let record = &view.record;
        Self {
            query: record.query().to_string(),
            credential: record.credential().to_string(),
            option: record.option().position(),
            entries: record.entries().iter().map(|e| e.get()).collect(),
            attested: record
                .attested()
                .map(|attested| {
                    attested
                        .pairs()
                        .iter()
                        .map(|(name, text)| (name.as_str().to_owned(), text.as_str().to_owned()))
                        .collect()
                })
                .unwrap_or_default(),
            request: record.request().as_str().to_owned(),
            shown: ShownDigest::of(view.entry.card(), view.header, view.entry.overlay()).hex(),
        }
    }

    /// The fields an id holds, read as JSON.
    fn parse(id: &str) -> Self {
        let node = Node::parse(id).expect("a record id is JSON");
        let [query, credential, option, entries, attested, request, shown] =
            node.as_array().expect("a record id is an array")
        else {
            panic!("a record id has seven items: {id}");
        };
        let number = |node: &Node<'_>| match node {
            Node::Number(n) => usize::try_from(n.as_u64().expect("a natural")).expect("an index"),
            other => panic!("no index: {other:?}"),
        };
        Self {
            query: query.as_str().expect("a query").to_owned(),
            credential: credential.as_str().expect("a credential").to_owned(),
            option: number(option),
            entries: entries
                .as_array()
                .expect("entries")
                .iter()
                .map(number)
                .collect(),
            attested: attested
                .as_object()
                .expect("attested")
                .members()
                .iter()
                .map(|m| {
                    (
                        m.name.to_string(),
                        m.value.as_str().expect("a text").to_owned(),
                    )
                })
                .collect(),
            request: request.as_str().expect("a digest").to_owned(),
            shown: shown.as_str().expect("a digest").to_owned(),
        }
    }

    fn id(&self) -> String {
        record_id(
            &self.query,
            &self.credential,
            self.option,
            &self.entries,
            &self.attested,
            &self.request,
            &self.shown,
        )
    }
}

/// Phase 2 for one selection, against what the display showed: the records are the views'; a
/// fallback exactly when something no longer holds, with those findings; else `vp_token` holds
/// the selection's queries, each with its records' presentations in order, one without
/// `multiple`; each presentation binds the session; one at most carries transaction members,
/// exactly its record's, valued by each profile's rule; `dc_api.jwt` encrypts the response to the
/// first usable key. With `tamper`, records that do not fit the request are rejected, and a
/// metadata refresh after the display makes phase 2 fall back.
pub fn check(
    case: &Case<'_>,
    matched: &Match<'_>,
    views: &Views<'_>,
    ids: &[&str],
    host: &HaipHost,
    tamper: bool,
    tally: &mut Tally,
) {
    let records: Vec<&EntryView<'_>> = ids
        .iter()
        .map(|id| views.by_id(id).expect("a shown record"))
        .collect();
    // Each id Credential Manager returns is the record its entry carries.
    for (id, view) in ids.iter().zip(&records) {
        assert_eq!(
            Fields::parse(id),
            Fields::of(view),
            "R-records are the views'"
        );
    }
    // OpenID4VP §8.4: a record names every entry its credential authorizes, as the match bound
    // them.
    for view in &records {
        let candidate = matched
            .candidate(view.pick.query, view.pick.candidate)
            .expect("the record's candidate");
        let bound: &[EntryIndex] = candidate
            .bound
            .as_ref()
            .map_or(&[], |binding| binding.bound.entries.entries());
        assert_eq!(
            view.record.entries(),
            bound,
            "R-record entries are the bound ones"
        );
    }
    let want = expected_findings(case, &records);
    let published = published();
    let authenticated = siros_testkit::fixtures::authenticate(
        case.request.envelope(),
        case.registry,
        case.context,
        host,
    )
    .expect("authentic");
    match Prepared::prepare(
        &authenticated,
        ids,
        case.wallet,
        case.registry,
        case.env,
        case.context,
        host,
    )
    .and_then(|prepared| prepared.respond(|resource| published.answer(resource), host))
    {
        Err(Outcome::Fallback(findings)) => {
            let mut got: Vec<(usize, Found)> = findings
                .items()
                .iter()
                .map(|finding| match finding {
                    Finding::Unusable { record } => (record.get(), Found::Unusable),
                    Finding::Revalidation { record, finding } => (record.get(), found(finding)),
                    Finding::Diverged { record } | Finding::Rendered { record, .. } => {
                        panic!("R-phase 2 derives every record: {record} diverged")
                    }
                    Finding::Format { record, .. } => {
                        panic!("R-phase 2: the real formats find nothing ({record})")
                    }
                })
                .collect();
            got.sort();
            // Phase 2 checks what the matcher could not, and falls back exactly when something
            // no longer holds, with those findings: the credential's validity and status, Proof
            // Metadata §5.3 step 5, View §3, CSC §6.3.
            assert!(
                !want.is_empty() && got == want,
                "R-fallback findings: {got:?} {want:?}"
            );
            for (_, finding) in &got {
                tally.add(match finding {
                    Found::Unusable => "findings: a credential the runtime refuses",
                    Found::Paso { refused, .. } if !refused.is_empty() => {
                        "findings: PaSO's ad-hoc metadata refused"
                    }
                    Found::Paso { .. } => "findings: PaSO's images failing",
                    Found::Qes(_) => "findings: QES's documents failing",
                });
            }
            fallback(case, &records, findings.items(), tally);
            tally.add("responses falling back");
        }
        Ok(response) => {
            assert!(want.is_empty(), "R-no fallback: {want:?}");
            tally.add("responses");
            answered(case, &records, &response, host, tally);
            if tamper {
                tampered(case, views, &records, tally);
                renewed(case, ids, &records, host, tally);
            }
        }
        Err(other) => panic!("R-phase 2: {other}"),
    }
}

/// A profile's finding in the shape the checks state it: PaSO's expired JWT and failed images,
/// QES's failed documents.
fn found(finding: &ProfileFinding) -> Found {
    if let Some(paso) = finding.data::<PasoFinding>() {
        return Found::Paso {
            lacks: paso.lacks(),
            refused: paso
                .refused()
                .map(|refused| (refused.jwt.as_str().to_owned(), refused.failure.id()))
                .into_iter()
                .collect(),
            failed: paso
                .failed()
                .iter()
                .map(|image| image.url.clone())
                .collect(),
        };
    }
    let qes = finding
        .data::<FailedDocuments>()
        .expect("a finding of PaSO or QES");
    Found::Qes(
        qes.documents()
            .iter()
            .map(|document| document.href().as_str().to_owned())
            .collect(),
    )
}

/// The first step of Proof Metadata §5.3 the generator's ad-hoc metadata JWT fails for a
/// credential of this PaSO document and format: an unpublished `kid` (step 3), a signature other
/// than the issuer key's deterministic ES256 one (step 2, RFC 6979), an `exp` at or before `NOW`
/// (step 5), a `sub` or `format` other than the credential's (step 6). The generator writes no
/// other defect.
fn refused_step(jwt: &str, document: &Value, format: &str) -> Option<AdhocFailure> {
    let parts: Vec<&str> = jwt.split('.').collect();
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("base64url"))
            .expect("the JWT's header");
    let claims = jwt_claims(jwt);
    let input = format!("{}.{}", parts[0], parts[1]);
    let issuers = siros_testkit::jose::sign(
        &siros_testkit::verifier::secret_key("issuer-secret-1"),
        &input,
    )
    .expect("signs");
    if header["kid"] != json!("issuer-key-1") {
        Some(AdhocFailure::UnknownKey)
    } else if parts[2] != issuers {
        Some(AdhocFailure::Signature)
    } else if claims["exp"].as_u64().expect("exp") <= NOW {
        Some(AdhocFailure::Expired)
    } else if claims["sub"] != document["type"] || claims["format"] != json!(format) {
        Some(AdhocFailure::Binding)
    } else {
        None
    }
}

/// What phase 2 must find, stated here: a credential the host says can no longer be
/// presented; for PaSO, an ad-hoc metadata JWT failing a step of Proof Metadata §5.3
/// ([`refused_step`]) alone, else each https image whose fetch fails or whose content does not
/// match its #integrity (View §3); for QES, a document with href and checksum whose fetch fails or
/// does not match (CSC §6.3).
fn expected_findings(case: &Case<'_>, records: &[&EntryView<'_>]) -> Vec<(usize, Found)> {
    let fetched = resources();
    let fetch = |url: &str| {
        fetched
            .iter()
            .find(|(known, _, _)| *known == url)
            .map(|(_, content, _)| content.as_slice())
    };
    let mut out = Vec::new();
    for (k, view) in records.iter().enumerate() {
        if case
            .unusable
            .iter()
            .any(|id| id == view.record.credential().as_str())
        {
            out.push((k, Found::Unusable));
            continue;
        }
        let Some(first) = view.record.entries().first() else {
            continue;
        };
        let entry = case.entry_json(*first);
        let kind = entry["type"].as_str().expect("type");
        if kind.starts_with("urn:paso:sca:") {
            let held = credential(case, view.record.credential().as_str());
            let document = document(held, "paso").expect("a PaSO document");
            let held_credential = credential(case, view.record.credential().as_str());
            let refused: Vec<(String, &'static str)> = entry
                .get("metadata")
                .and_then(Value::as_str)
                .and_then(|jwt| {
                    refused_step(jwt, &document, held_credential.format.as_str())
                        .map(|failure| (jwt.to_owned(), failure.id()))
                })
                .into_iter()
                .collect();
            let images: Vec<Vec<Value>> = if !refused.is_empty() {
                // A refused JWT is the record's finding alone: phase 2 fetches none of the
                // record's images.
                Vec::new()
            } else if kind.contains(":mandate:") {
                case.spec
                    .mandate
                    .iter()
                    .filter(|claim| claim.displayed && claim.value_type.as_deref() == Some("image"))
                    .map(|claim| claim.path.iter().map(|p| json!(p)).collect())
                    .collect()
            } else {
                given(&entry, &document).expect("the metadata that rendered")["claims"]
                    .as_array()
                    .expect("claims")
                    .iter()
                    .filter(|claim| {
                        claim.get("display").is_some()
                            && claim.get("value_type") == Some(&json!("image"))
                    })
                    .map(|claim| claim["path"].as_array().expect("a path").clone())
                    .collect()
            };
            let payload = &entry["payload"];
            let mut failed = Vec::new();
            for pointer in images {
                for path in select(payload, &pointer) {
                    let (last, parent) = path.split_last().expect("a path");
                    let value = crate::spec::at(payload, &path);
                    let Some(url) = value.as_str().filter(|v| v.starts_with("https://")) else {
                        continue;
                    };
                    let integrity = &crate::spec::at(payload, parent)
                        [format!("{}#integrity", last.as_str().expect("a key"))];
                    let verified = fetch(url)
                        .is_some_and(|content| Some(sri(content).as_str()) == integrity.as_str());
                    if !verified {
                        failed.push(url.to_owned());
                    }
                }
            }
            if !refused.is_empty() || !failed.is_empty() {
                out.push((
                    k,
                    Found::Paso {
                        lacks: None,
                        refused,
                        failed,
                    },
                ));
            }
        } else if kind == siros_qes::TYPE {
            let bad: Vec<String> = entry["documentInfos"]
                .as_array()
                .expect("documentInfos")
                .iter()
                .filter_map(|d| {
                    let href = d.get("href")?.as_str()?;
                    let checksum = d.get("checksum")?.as_str()?;
                    let matches = fetch(href).is_some_and(|content| sri(content) == checksum);
                    (!matches).then(|| href.to_owned())
                })
                .collect();
            if !bad.is_empty() {
                out.push((k, Found::Qes(bad)));
            }
        } else {
            panic!("a record of no profile the dressed run registers: {kind}");
        }
    }
    out
}

/// The wallet re-runs the consent with the findings: no credential the host refused, and no
/// record that failed comes back with the entries it had.
fn fallback(case: &Case<'_>, records: &[&EntryView<'_>], findings: &[Finding], tally: &mut Tally) {
    let gone: Vec<&str> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::Unusable { record } => {
                Some(records[record.get()].record.credential().as_str())
            }
            Finding::Diverged { .. }
            | Finding::Rendered { .. }
            | Finding::Revalidation { .. }
            | Finding::Format { .. } => None,
        })
        .collect();
    let informed = oracle::informed(case.registry, findings).expect("each profile informed");
    let kept = Wallet::new(
        case.wallet
            .credentials()
            .iter()
            .filter(|c| !gone.contains(&c.id.as_str()))
            .cloned()
            .collect(),
    )
    .expect("a wallet");
    let accepted = Accepted::new(case.request, &informed).expect("accepted");
    let again = Match::run(&accepted, &kept, case.env, case.context).expect("no fault");
    for finding in findings {
        let (record, revalidated) = match finding {
            Finding::Unusable { record } => (record.get(), false),
            Finding::Revalidation { record, .. } => (record.get(), true),
            Finding::Diverged { record } | Finding::Rendered { record, .. } => {
                panic!("R-fallback: {record} diverged")
            }
            Finding::Format { record, .. } => panic!("R-fallback: {record}, a format's finding"),
        };
        let view = records[record];
        let back = again
            .candidates(view.pick.query)
            .iter()
            .find(|c| c.credential.id == *view.record.credential());
        assert!(
            back.is_none_or(|back| revalidated
                && back.bound.as_ref().is_some_and(
                    |binding| binding.bound.entries.entries() != view.record.entries()
                )),
            "R-fallback offers the failed record again"
        );
    }
    tally.add("fallbacks re-run");
}

/// A response's checks: its `vp_token` and `data`, each presentation's session and members.
fn answered(
    case: &Case<'_>,
    records: &[&EntryView<'_>],
    built: &siros_openid4vp::resolve::Built<'_>,
    host: &HaipHost,
    tally: &mut Tally,
) {
    let mut by_query: Vec<(&str, Vec<&EntryView<'_>>)> = Vec::new();
    for view in records {
        let query = view.record.query().as_str();
        match by_query.iter_mut().find(|(known, _)| *known == query) {
            Some((_, views)) => views.push(view),
            None => by_query.push((query, vec![view])),
        }
    }
    let text = built.response().vp_token().json();
    let order: Vec<String> = Node::parse(&text)
        .expect("vp_token is JSON")
        .as_object()
        .expect("vp_token is an object")
        .names()
        .map(str::to_owned)
        .collect();
    let queries: Vec<&str> = by_query.iter().map(|(query, _)| *query).collect();
    // OpenID4VP §8.1: vp_token holds each presented query's presentations, in the selection's
    // order; one presentation for a query without `multiple` (§6.1).
    assert_eq!(order, queries, "R-vp_token queries");
    let token: Value = serde_json::from_str(&text).expect("vp_token");
    for (query, views) in &by_query {
        let multiple = case
            .request
            .queries()
            .iter()
            .find(|q| q.id().as_str() == *query)
            .is_some_and(|q| q.multiple() == Multiplicity::Many);
        assert!(
            token[query].as_array().expect("presentations").len() == views.len()
                && (views.len() == 1 || multiple),
            "R-vp_token arrays"
        );
    }
    let Delivery::DcApi(data) = built.delivery() else {
        panic!("R-a DC API request answers on the DC API");
    };
    let data: Value = serde_json::from_str(data.as_str()).expect("data");
    match data.get("response").and_then(Value::as_str) {
        None => {
            // Annex A: dc_api's data is {"vp_token": ...}.
            assert_eq!(
                mode(case),
                "dc_api",
                "R-dc_api.jwt answered without encryption"
            );
            assert_eq!(data, json!({"vp_token": token}), "R-dc_api data");
            tally.add("responses plain");
        }
        Some(jwe) => {
            // A.2, §8.3: dc_api.jwt's data is {"response": JWE}.
            assert_eq!(
                data.as_object().map(serde_json::Map::len),
                Some(1),
                "R-dc_api.jwt data"
            );
            // OpenID4VP §8.3 under HAIP §5 (reading 25): the first P-256 key with `alg` ECDH-ES
            // and 32-octet coordinates; A256GCM when listed, else A128GCM.
            assert_eq!(mode(case), "dc_api.jwt", "R-dc_api encrypted");
            let metadata: Value = serde_json::from_str(
                case.request
                    .client_metadata()
                    .expect("client_metadata")
                    .get(),
            )
            .expect("client_metadata");
            let key = metadata["jwks"]["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .find(|k| response_key(k))
                .expect("a key the key rule accepts");
            let listed = |enc: &str| {
                metadata
                    .get("encrypted_response_enc_values_supported")
                    .is_none_or(|values| values.as_array().is_some_and(|v| v.contains(&json!(enc))))
            };
            let enc = if metadata
                .get("encrypted_response_enc_values_supported")
                .is_some()
                && listed("A256GCM")
            {
                "A256GCM"
            } else {
                assert!(
                    listed("A128GCM"),
                    "R-response encryption: an enc the rule accepts"
                );
                "A128GCM"
            };
            let (protected, plaintext) = opened_jwe(jwe);
            assert_eq!(
                protected,
                json!({"alg": "ECDH-ES", "enc": enc, "kid": key["kid"]}),
                "R-response encryption"
            );
            let plaintext: Value = serde_json::from_slice(&plaintext).expect("the plaintext");
            assert_eq!(
                plaintext,
                json!({"vp_token": token}),
                "R-encrypted plaintext"
            );
            tally.add("responses encrypted");
        }
    }
    let mut carrying = 0;
    for (query, views) in &by_query {
        let format = case
            .request
            .queries()
            .iter()
            .find(|q| q.id().as_str() == *query)
            .map(|q| q.format().as_str())
            .expect("the query's format");
        for (view, written) in views
            .iter()
            .zip(token[query].as_array().expect("presentations"))
        {
            let read = match format {
                "mso_mdoc" => Some(read_mdoc(written)),
                "dc+sd-jwt" => Some(read_sd_jwt(written)),
                _ => None,
            };
            let presentation = read.as_ref().unwrap_or(written);
            let held = credential(case, view.record.credential().as_str());
            session(case, view, held, format, presentation, host, tally);
            let got = members_of(format, presentation);
            if view.record.entries().is_empty() {
                // A presentation without a transaction carries no member.
                assert!(got.is_empty(), "R-members without a transaction: {got:?}");
                continue;
            }
            carrying += 1;
            members(case, view, format, &got, host, tally);
        }
    }
    // C3: one confirmation carries one transaction.
    assert!(carrying <= 1, "R-one transaction per response");
}
