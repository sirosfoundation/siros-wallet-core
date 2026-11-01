//! C4: a credential is usable at `now` exactly when `not_before ≤ now < not_after`.

use serde_json::json;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_credential::{Credential, UsableCredential};

use crate::common::{credential, mdoc, sd_jwt};

fn vc(nbf: Option<f64>, exp: Option<f64>) -> Credential {
    let mut payload = json!({"vct": "https://credentials.example/identity"});
    if let Some(nbf) = nbf {
        payload["nbf"] = json!(nbf);
    }
    if let Some(exp) = exp {
        payload["exp"] = json!(exp);
    }
    credential("dc+sd-jwt", &sd_jwt(&payload, &[]))
}

fn at(text: &str) -> DateTime {
    DateTime::parse(text).unwrap()
}

#[test]
fn validity_boundaries() {
    let whole = vc(Some(1_700_000_000.0), Some(1_800_000_000.0));
    let fractional = vc(Some(1_700_000_000.5), Some(1_800_000_000.5));
    let unbounded = vc(None, None);
    let mdoc = credential(
        "mso_mdoc",
        &mdoc(
            vec![("given_name", Cbor::text("Ada"))],
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ),
    );
    let unix = |seconds| DateTime::from_unix(seconds).unwrap();
    let rows: [(&str, &Credential, DateTime, Result<(), &str>); 14] = [
        (
            "before nbf",
            &whole,
            unix(1_699_999_999),
            Err("not_yet_valid"),
        ),
        ("at nbf", &whole, unix(1_700_000_000), Ok(())),
        ("before exp", &whole, unix(1_799_999_999), Ok(())),
        ("at exp", &whole, unix(1_800_000_000), Err("expired")),
        (
            "before a fractional nbf",
            &fractional,
            unix(1_700_000_000),
            Err("not_yet_valid"),
        ),
        (
            "after a fractional nbf",
            &fractional,
            unix(1_700_000_001),
            Ok(()),
        ),
        (
            "before a fractional exp",
            &fractional,
            unix(1_800_000_000),
            Ok(()),
        ),
        (
            "after a fractional exp",
            &fractional,
            unix(1_800_000_001),
            Err("expired"),
        ),
        (
            "no nbf, the first second",
            &unbounded,
            unix(DateTime::MIN_UNIX),
            Ok(()),
        ),
        (
            "no exp, the last second",
            &unbounded,
            unix(DateTime::MAX_UNIX),
            Ok(()),
        ),
        (
            "before validFrom",
            &mdoc,
            at("2025-12-31T23:59:59Z"),
            Err("not_yet_valid"),
        ),
        ("at validFrom", &mdoc, at("2026-01-01T00:00:00Z"), Ok(())),
        (
            "before validUntil",
            &mdoc,
            at("2026-12-31T23:59:59Z"),
            Ok(()),
        ),
        (
            "at validUntil",
            &mdoc,
            at("2027-01-01T00:00:00Z"),
            Err("expired"),
        ),
    ];
    for (case, credential, now, expected) in rows {
        let usable = UsableCredential::at(credential, now)
            .map(|_| ())
            .map_err(|e| e.code());
        assert_eq!(usable, expected, "{case}");
    }
}
