//! Runs `tests/vectors/proof_time.json`: the 20-character `proof_time`, its refusals, and the
//! Verifier's tolerance.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use serde_json::Value;
use siros_codec::date::DateTime;
use siros_zkp_req_nym_auth::verify::Tolerance;

#[test]
fn proof_time_vectors() {
    let path = format!(
        "{}/tests/vectors/proof_time.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for e in v["render"].as_array().unwrap() {
        let t = DateTime::from_unix(e["secs"].as_i64().unwrap()).unwrap();
        assert_eq!(t.to_string(), e["text"].as_str().unwrap(), "{e}");
        assert_eq!(DateTime::parse(&t.to_string()), Some(t), "{e}");
    }
    for e in v["render_errors"].as_array().unwrap() {
        assert_eq!(
            DateTime::from_unix(e["secs"].as_i64().unwrap()),
            None,
            "{e}"
        );
    }
    for e in v["parse_ok"].as_array().unwrap() {
        let t = DateTime::parse(e["text"].as_str().unwrap()).unwrap();
        assert_eq!(t.unix(), e["secs"].as_i64().unwrap(), "{e}");
    }
    for e in v["parse_errors"].as_array().unwrap() {
        assert_eq!(DateTime::parse(e["text"].as_str().unwrap()), None, "{e}");
    }
    for e in v["tolerance"].as_array().unwrap() {
        let seconds = |name: &str| u32::try_from(e[name].as_u64().unwrap()).unwrap();
        let tolerance = Tolerance::seconds(seconds("future_secs"), seconds("past_secs"));
        let now = DateTime::from_unix(e["now_secs"].as_i64().unwrap()).unwrap();
        let admitted = DateTime::parse(e["proof_time"].as_str().unwrap())
            .is_some_and(|t| tolerance.admits(now, t));
        assert_eq!(admitted, e["expect"] == "ok", "{e}");
    }
}
