//! The runner's own proof: a full vector, schema-validated and run
//! against the real engine — the pre-authorized OID4VCI issuance, end
//! to end, with the world asserting every fetch and every host ask.

use engine_conformance::runner::{run_vector, Verdict};
use engine_conformance::script::VectorFile;
use engine_conformance::{load, schema_path, vectors_dir};

/// A minimal valid generator block (the schema requires the repo, the
/// full commit and the date).
fn generator() -> engine_conformance::script::Generator {
    engine_conformance::script::Generator {
        repo: "sirosfoundation/engine-vectors".to_owned(),
        commit: "0000000000000000000000000000000000000000".to_owned(),
        date: "2026-11-03".to_owned(),
    }
}

/// Builds a vector from its JSON document, validated against the real
/// schema first — the same gate load() applies to the files.
fn vector(
    id: &str,
    provenance: &str,
    setup: serde_json::Value,
    script: serde_json::Value,
) -> VectorFile {
    let document = serde_json::json!({
        "id": id,
        "description": "the runner self-test",
        "provenance": provenance,
        "generator": {
            "repo": "sirosfoundation/engine-vectors",
            "commit": "0000000000000000000000000000000000000000",
            "date": "2026-11-03"
        },
        "spec_refs": ["the runner self-test"],
        "setup": setup,
        "script": script,
    });

    // The real schema must accept the document before it runs: the
    // self-test validates the validator too.
    let schema_text = std::fs::read_to_string(schema_path())
        .unwrap_or_else(|err| panic!("read the schema: {err}"));
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).unwrap_or_else(|err| panic!("parse the schema: {err}"));
    engine_conformance::schema::validate(&schema, &document)
        .unwrap_or_else(|errors| panic!("the self-test vector fails the schema: {errors:?}"));

    serde_json::from_value(document).unwrap_or_else(|err| panic!("deserialize the vector: {err}"))
}

/// The pre-authorized OID4VCI transcript: the offer, the issuer
/// metadata, the AS metadata, the token exchange, the proof signing,
/// the credential request, the notification, and the completion.
fn preauth_setup() -> serde_json::Value {
    serde_json::json!({
        "time": 1_700_000_000,
        "entropy_seed": 42,
        "pdp": { "trusted": true, "decision": "self-test" }
    })
}

fn preauth_script() -> serde_json::Value {
    serde_json::json!([
        {
            "wmp_in": {
                "method": "wmp.flow.start",
                "params": {
                    "flow_id": "flow-selftest-1",
                    "flow_type": "oid4vci",
                    "params": {
                        "credential_issuer": "https://issuer.example",
                        "credential_configuration_ids": ["UniversityDegree"],
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": "preauth-code-1"
                            }
                        }
                    }
                }
            }
        },
        {
            "http_out": {
                "expect": {
                    "method": "GET",
                    "url": "https://issuer.example/.well-known/openid-credential-issuer",
                    "purpose": "IssuerMetadata"
                },
                "reply": {
                    "status": 200,
                    "content_type": "application/json",
                    "body": {
                        "credential_issuer": "https://issuer.example",
                        "authorization_servers": ["https://as.example"],
                        "credential_configurations_supported": {
                            "UniversityDegree": { "scope": "openid" }
                        }
                    }
                }
            }
        },
        {
            "http_out": {
                "expect": {
                    "method": "GET",
                    "url": "https://as.example/.well-known/oauth-authorization-server",
                    "purpose": "AsMetadata"
                },
                "reply": {
                    "status": 200,
                    "body": {
                        "issuer": "https://as.example",
                        "token_endpoint": "https://as.example/token"
                    }
                }
            }
        },
        {
            "http_out": {
                "expect": {
                    "method": "POST",
                    "url": "https://as.example/token",
                    "purpose": "Token",
                    "form": {
                        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "pre-authorized_code": "preauth-code-1"
                    }
                },
                "reply": {
                    "status": 200,
                    "body": {
                        "access_token": "at-selftest-1",
                        "token_type": "Bearer",
                        "c_nonce": "nonce-selftest-1"
                    }
                }
            }
        },
        {
            "host_ask": {
                "expect": { "kind": "sign" },
                "answer": { "value": { "signature": [1, 2, 3, 4] } }
            }
        },
        {
            "http_out": {
                "expect": {
                    "method": "POST",
                    "url": "https://issuer.example/credential",
                    "purpose": "Credential",
                    "json": {
                        "credential_configuration_id": "UniversityDegree"
                    }
                },
                "reply": {
                    "status": 200,
                    "body": {
                        "credential": "credential-jwt-selftest-1",
                        "notification_id": "notif-selftest-1"
                    }
                }
            }
        },
        {
            "http_out": {
                "expect": {
                    "method": "POST",
                    "url": "https://issuer.example/notification",
                    "purpose": "Notification",
                    "json": {
                        "notification_id": "notif-selftest-1",
                        "event": "credential_accepted"
                    }
                },
                "reply": { "status": 200, "body": {} }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": {
                        "flow_id": "flow-selftest-1",
                        "step": "offer_parsed",
                        "payload": {
                            "credential_issuer": "https://issuer.example",
                            "credential_configuration_ids": ["UniversityDegree"]
                        }
                    }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": { "flow_id": "flow-selftest-1", "step": "metadata_resolved" }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": { "flow_id": "flow-selftest-1", "step": "as_discovered" }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": { "flow_id": "flow-selftest-1", "step": "trust_evaluated" }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": { "flow_id": "flow-selftest-1", "step": "token_received" }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.progress",
                    "params": { "flow_id": "flow-selftest-1", "step": "credential_received" }
                }
            }
        },
        {
            "wmp_out": {
                "expect": {
                    "method": "wmp.flow.complete",
                    "params": {
                        "flow_id": "flow-selftest-1",
                        "result": { "credential": "credential-jwt-selftest-1" }
                    }
                }
            }
        }
    ])
}

#[test]
fn the_pre_authorized_flow_runs_end_to_end() {
    // The runner drives the real engine — the runtime, both flow
    // families, the session service — through the whole transcript.
    let vector = vector(
        "selftest.vci.preauth.001",
        "spec",
        preauth_setup(),
        preauth_script(),
    );
    // The multi-threaded runtime: the flow methods bridge through
    // block_in_place, which the current-thread runtime forbids.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("build the tokio runtime: {err}"));
    let verdict = runtime.block_on(async { run_vector(&vector) });
    assert_eq!(
        verdict,
        Verdict::Pass,
        "the pre-authorized transcript must pass against the real engine"
    );
}

#[test]
fn a_mismatched_expectation_fails_with_the_difference() {
    // The token endpoint answers a different grant than the vector
    // expects: the world fails the vector with the difference.
    let mut steps = preauth_script().as_array().unwrap().clone();
    steps[3]["http_out"]["expect"]["form"]["pre-authorized_code"] =
        serde_json::json!("a-different-code");
    let script = serde_json::Value::Array(steps);

    let vector = vector(
        "selftest.vci.preauth.mismatch",
        "spec",
        preauth_setup(),
        script,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("build the tokio runtime: {err}"));
    let verdict = runtime.block_on(async { run_vector(&vector) });
    match verdict {
        Verdict::Fail(reason) => {
            assert!(
                reason.contains("pre-authorized_code"),
                "the failure names the member that differed: {reason}"
            );
        }
        other => panic!("the mismatch must fail, got {other:?}"),
    }
}

#[test]
fn an_unexpected_fetch_fails_the_vector() {
    // The script ends after the AS metadata: the token exchange the
    // engine makes has no http_out step, which fails the vector.
    let mut steps = preauth_script().as_array().unwrap().clone();
    steps.truncate(3);
    let script = serde_json::Value::Array(steps);

    let vector = vector(
        "selftest.vci.preauth.short",
        "spec",
        preauth_setup(),
        script,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("build the tokio runtime: {err}"));
    let verdict = runtime.block_on(async { run_vector(&vector) });
    match verdict {
        Verdict::Fail(reason) => {
            assert!(
                reason.contains("unexpected HTTP request")
                    || reason.contains("was not satisfied")
                    || reason.contains("was never satisfied"),
                "the failure names the unscripted fetch: {reason}"
            );
        }
        other => panic!("the truncated script must fail, got {other:?}"),
    }
}

#[test]
fn a_go_observed_vector_past_its_review_refuses_to_gate() {
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or_default();
    let past = (today - 1) * 86_400;
    let date = unix_to_date(past as i64);
    let setup = preauth_setup();
    let mut document = serde_json::json!([]);
    let _ = &mut document;

    // A vector with the expired review_by and no reason.
    let vector = VectorFile {
        id: "selftest.sunset.001".to_owned(),
        description: "the sunset".to_owned(),
        provenance: "go-observed".to_owned(),
        generator: generator(),
        review_by: Some(date),
        review_reason: None,
        spec_refs: None,
        known_divergence: None,
        config: None,
        setup: Some(setup),
        script: vec![],
        notes: None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("build the tokio runtime: {err}"));
    let verdict = runtime.block_on(async { run_vector(&vector) });
    match verdict {
        Verdict::Skip(reason) => assert!(
            reason.contains("review_by"),
            "the skip names the sunset: {reason}"
        ),
        other => panic!("the expired vector must skip, got {other:?}"),
    }
}

/// YYYY-MM-DD for a unix timestamp.
fn unix_to_date(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    // The civil-from-days algorithm (Howard Hinnant).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[test]
fn the_repository_loads_when_present() {
    // The sibling checkout may be absent in some CI contexts; when it
    // is present with only the schema, the load finds zero vectors and
    // does not treat the schema as one.
    if !engine_conformance::repository_dir().is_dir() {
        return;
    }
    match load() {
        Ok(vectors) => {
            assert!(
                vectors.iter().all(|v| v.id != ""),
                "every loaded vector has an id"
            );
        }
        Err(reason) => panic!("the sibling vectors repository must load: {reason}"),
    }
}

#[test]
fn the_repository_vector_runs() {
    // The repository's first scenario file, loaded and run through the
    // same path CI uses.
    let repo = engine_conformance::repository_dir();
    if !repo.is_dir() {
        return;
    }
    let vectors = match load() {
        Ok(vectors) => vectors,
        Err(reason) => panic!("the vectors repository must load: {reason}"),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("build the tokio runtime: {err}"));
    for vector in &vectors {
        let verdict = runtime.block_on(async { run_vector(vector) });
        assert_eq!(
            verdict,
            Verdict::Pass,
            "the repository vector {} must pass",
            vector.id
        );
    }
}
