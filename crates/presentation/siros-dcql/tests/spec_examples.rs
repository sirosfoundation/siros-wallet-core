//! The specification's own DCQL examples, parsed and evaluated.
//!
//! Vectors from the OpenID4VP 1.0 repository (`1.0/examples/query_lang`),
//! committed verbatim under `tests/spec_vectors/`. They matter for two
//! reasons: they are queries the authors wrote rather than ones shaped by
//! this implementation's assumptions, and they exercise combinations —
//! nested mdoc claims, alternative claim sets, multi-credential requests —
//! that are tedious to invent and easy to get subtly wrong.

use serde_json::{json, Value};
use siros_dcql::{
    execute, ClaimPath, CredentialFormat, CredentialRef, CryptographicBinding, DcqlQuery,
    ExactFormat, PathComponent, PathError, QueryResult, Satisfaction, SetRequirement,
};

/// Whether the wallet can satisfy the request.
fn satisfiable(result: &QueryResult) -> bool {
    result.satisfaction() == Satisfaction::Satisfiable
}

fn vector(name: &str) -> DcqlQuery {
    let path = format!(
        "{}/tests/spec_vectors/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    DcqlQuery::from_json(&text).unwrap_or_else(|e| panic!("parsing {name}: {e}"))
}

/// An mdoc, resolved with the §7.2 two-component rules.
struct Mdoc {
    id: CredentialRef,
    format: CredentialFormat,
    namespaces: Value,
}

impl siros_dcql::Credential for Mdoc {
    fn id(&self) -> &CredentialRef {
        &self.id
    }
    fn format(&self) -> &CredentialFormat {
        &self.format
    }
    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        let (ns, element) = siros_dcql::mdoc_components(path)?;
        self.namespaces
            .get(ns)
            .and_then(|n| n.get(element))
            .map(|v| vec![v.clone()])
            .ok_or(PathError::Empty)
    }
    /// The spec's own vectors are all holder-bound credentials.
    fn binding(&self) -> CryptographicBinding {
        CryptographicBinding::Bound
    }
}

/// A JSON credential, resolved with the §7.1 rules.
struct Json {
    id: CredentialRef,
    format: CredentialFormat,
    body: Value,
}

impl siros_dcql::Credential for Json {
    fn id(&self) -> &CredentialRef {
        &self.id
    }
    fn format(&self) -> &CredentialFormat {
        &self.format
    }
    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        siros_dcql::resolve_json(&self.body, path).map(|v| v.into_iter().cloned().collect())
    }
    /// The spec's own vectors are all holder-bound credentials.
    fn binding(&self) -> CryptographicBinding {
        CryptographicBinding::Bound
    }
}

fn json_cred(id: &str, format: &str, body: Value) -> Json {
    Json {
        id: CredentialRef::new(id),
        format: CredentialFormat::new(format),
        body,
    }
}

/// Build a credential body that satisfies every one of `claims`.
///
/// Naively setting `path[0]` is not enough, and the spec's own vectors are
/// what proved it: `["address", "street_address"]` needs a nested object, and
/// a `values` restriction needs one of the listed values rather than a
/// placeholder. A fixture that ignores either produces a credential the
/// engine correctly rejects, which then reads as an engine bug.
fn body_satisfying(claims: &[siros_dcql::ClaimsQuery]) -> Value {
    let mut root = json!({});
    for claim in claims {
        let leaf = claim
            .values()
            .as_ref()
            .and_then(|v| v.first().cloned())
            .unwrap_or_else(|| json!("value"));
        insert_at(&mut root, claim.path().components(), leaf);
    }
    root
}

fn insert_at(node: &mut Value, path: &[PathComponent], leaf: Value) {
    let Some((head, rest)) = path.split_first() else {
        *node = leaf;
        return;
    };
    match head {
        PathComponent::Key(k) => {
            if !node.is_object() {
                *node = json!({});
            }
            let entry = node
                .as_object_mut()
                .expect("just made an object")
                .entry(k.clone())
                .or_insert(Value::Null);
            insert_at(entry, rest, leaf);
        }
        // Null selects every element, so one element is enough to satisfy it.
        PathComponent::Null | PathComponent::Index(_) => {
            let index = match head {
                PathComponent::Index(i) => usize::try_from(*i).unwrap_or(0),
                _ => 0,
            };
            if !node.is_array() {
                *node = json!([]);
            }
            let array = node.as_array_mut().expect("just made an array");
            while array.len() <= index {
                array.push(Value::Null);
            }
            insert_at(&mut array[index], rest, leaf);
        }
    }
}

/// Every published vector parses, including fields this crate does not act on.
#[test]
fn every_spec_vector_parses() {
    for name in [
        "simple",
        "simple_mdoc",
        "complex_mdoc",
        "claims_alternatives",
        "credentials_alternatives",
        "multi_credentials",
        "value_matching_simple",
    ] {
        let q = vector(name);
        assert!(
            !q.credentials().is_empty(),
            "{name} has no credential queries"
        );
        for c in q.credentials() {
            assert!(!c.id().is_empty(), "{name}: a credential query has no id");
            assert!(
                !c.format().as_str().is_empty(),
                "{name}: a credential query has no format"
            );
        }
    }
}

/// `claims_alternatives` offers two claim sets, the first of which discloses
/// more precise location data. §6.4.1 says the wallet returns the first it
/// can satisfy, so a wallet holding everything must take that one.
#[test]
fn claims_alternatives_takes_the_verifiers_first_choice() {
    let q = vector("claims_alternatives");
    let full = [json_cred(
        "pid",
        "dc+sd-jwt",
        json!({
            "family_name": "Mustermann", "postal_code": "90210",
            "locality": "Musterstadt", "region": "Bavaria",
            "date_of_birth": "1979-04-12"
        }),
    )];

    let r = execute(&q, &full, &ExactFormat);
    let claims = &r.query("pid").unwrap().candidates()[0].claims();
    let ids: Vec<_> = claims
        .iter()
        .filter_map(|c| c.claim_id().map(|id| id.as_str()))
        .collect();
    assert_eq!(ids, ["a", "c", "d", "e"], "first claim_set should win");

    // Without `locality` the first option cannot be satisfied, so the second
    // is used — and nothing from the first leaks into it.
    let partial = [json_cred(
        "pid",
        "dc+sd-jwt",
        json!({
            "family_name": "Mustermann", "postal_code": "90210",
            "date_of_birth": "1979-04-12"
        }),
    )];
    let r = execute(&q, &partial, &ExactFormat);
    let ids: Vec<_> = r.query("pid").unwrap().candidates()[0]
        .claims()
        .iter()
        .filter_map(|c| c.claim_id().map(|id| id.as_str()))
        .collect();
    assert_eq!(ids, ["a", "b", "e"]);
}

/// `complex_mdoc` uses dotted ISO namespaces throughout. Resolving them
/// depends on the namespace surviving as one path component.
#[test]
fn complex_mdoc_resolves_dotted_namespaces() {
    let q = vector("complex_mdoc");
    let first = &q.credentials()[0];
    let path = first.claims()[0].path().components();
    assert_eq!(
        path.len(),
        2,
        "mdoc paths are exactly two components (§7.2.1)"
    );
    assert!(
        path[0].as_key().unwrap_or_default().contains('.'),
        "the first component is a dotted ISO namespace"
    );

    // A wallet holding exactly what the first query asks for matches it.
    let mut ns = serde_json::Map::new();
    for claim in first.claims() {
        let (namespace, element) = siros_dcql::mdoc_components(claim.path()).expect("mdoc path");
        ns.entry(namespace.to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("namespace object")
            .insert(element.to_string(), json!("value"));
    }
    let held = [Mdoc {
        id: CredentialRef::new("mdl-1"),
        format: CredentialFormat::new("mso_mdoc"),
        namespaces: Value::Object(ns),
    }];

    let r = execute(&q, &held, &ExactFormat);
    assert!(
        r.query(first.id()).unwrap().is_satisfied(),
        "a wallet holding every requested element should match"
    );
}

/// `value_matching_simple` restricts a claim's value. §6.3 requires an exact
/// match on type and value; anything else is treated as absent.
#[test]
fn value_matching_vector_accepts_only_the_listed_value() {
    let q = vector("value_matching_simple");
    let cq = &q.credentials()[0];

    let matching = [json_cred(
        "c",
        cq.format().as_str(),
        body_satisfying(cq.claims()),
    )];
    assert!(
        execute(&q, &matching, &ExactFormat)
            .query(cq.id())
            .unwrap()
            .is_satisfied(),
        "a credential carrying every claim, with the listed values, must match"
    );

    // Same credential with one restricted value changed: §6.4.1 says such a
    // claim is treated as if it did not exist, so the whole credential drops
    // out rather than matching with a claim the verifier excluded.
    let restricted = cq
        .claims()
        .iter()
        .find(|c| c.values().is_some())
        .expect("the vector restricts at least one value");
    let mut body = body_satisfying(cq.claims());
    insert_at(
        &mut body,
        restricted.path().components(),
        json!("definitely-not-it"),
    );

    let wrong = [json_cred("c", cq.format().as_str(), body)];
    assert!(!execute(&q, &wrong, &ExactFormat)
        .query(cq.id())
        .unwrap()
        .is_satisfied());
}

/// `credentials_alternatives` uses `credential_sets` with several options, so
/// satisfying any one option satisfies the request (§6.4).
#[test]
fn credentials_alternatives_is_satisfied_by_one_option() {
    let q = vector("credentials_alternatives");
    let sets = q.credential_sets().expect("the vector has credential_sets");
    let option = sets
        .iter()
        .find(|s| s.requirement() == SetRequirement::Required)
        .map(|s| s.options()[0].clone())
        .expect("a required set");

    // Hold exactly the credentials named by one option, with every claim
    // those queries ask for.
    let held: Vec<Json> = option
        .iter()
        .filter_map(|id| q.credential(id))
        .map(|cq| json_cred(cq.id(), cq.format().as_str(), body_satisfying(cq.claims())))
        .collect();

    // mdoc queries in the vector cannot be answered by a JSON credential, so
    // only assert when the chosen option is entirely JSON-based.
    if option
        .iter()
        .filter_map(|id| q.credential(id))
        .all(|c| c.format() != "mso_mdoc")
    {
        assert!(
            satisfiable(&execute(&q, &held, &ExactFormat)),
            "holding one full option should satisfy the request"
        );
    }
}

/// `multi_credentials` asks for several credentials at once. With no
/// `credential_sets`, all of them are required (§6.4) — so a wallet holding
/// only some must not report the request as satisfiable.
#[test]
fn multi_credentials_requires_all_when_no_sets_are_given() {
    let q = vector("multi_credentials");
    if q.credential_sets().is_some() || q.credentials().len() < 2 {
        return; // vector changed shape; the rule is covered in selection.rs
    }
    let first = &q.credentials()[0];
    let held = [json_cred("only-one", first.format().as_str(), json!({}))];
    assert!(!satisfiable(&execute(&q, &held, &ExactFormat)));
}
