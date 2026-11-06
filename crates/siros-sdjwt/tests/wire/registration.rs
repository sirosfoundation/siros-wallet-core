//! The registration (S1, S2): the view of an issued SD-JWT.

use siros_openid4vp::claims::kit::ClaimsFormat;
use siros_openid4vp::claims::{ClaimPath, Concrete};
use siros_openid4vp::json::Node;
use siros_sdjwt::{Registered, RegistrationError, Resolved, SdJwtVc};
use siros_testkit::sd_jwt_issuer;

use crate::common::{compact, compact_under, decoy, disclosure, issued, json_fixture};

/// RFC 9901 A.3's SD-JWT VC: its `vct`, its issuer, its holder key and its validity.
#[test]
fn view_of_a3() {
    let compact = issued("a3");
    let registered = Registered::of(&compact, &Resolved::default()).unwrap();
    assert_eq!(registered.document(), compact.as_bytes());
    let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
    let input = json_fixture("a3/processed.json");
    assert_eq!(view.get("type"), input.get("vct"));
    assert_eq!(view.get("issuer"), input.get("iss"));
    assert_eq!(view.get("alg").and_then(Node::as_str), Some("ES256"));
    assert_eq!(view.get("curve").and_then(Node::as_str), Some("P-256"));
    assert_eq!(view.get("key_alg").and_then(Node::as_str), Some("ES256"));
    assert_eq!(view.get("key_curve").and_then(Node::as_str), Some("P-256"));
    let validity = view.get("validity").unwrap();
    assert_eq!(validity.get("not_before"), None);
    assert_eq!(validity.get("not_after"), input.get("exp"));
    assert_eq!(
        view.get("values").unwrap().get("nationalities"),
        input.get("nationalities")
    );
}

/// `["DE", decoy, FR]`: the core's walk over the view finds FR at 2, and nothing at the decoy's 1.
#[test]
fn walk_keeps_issued_positions() {
    let (fr, fr_digest) = disclosure(r#"["lklxF5jMYlGTPUovMNIvCA","FR"]"#);
    let payload = format!(
        r#"{{"vct":"t","nationalities":["DE",{{"...":"{}"}},{{"...":"{fr_digest}"}}]}}"#,
        decoy("decoy")
    );
    let registered = Registered::of(&compact(&payload, &[&fr]), &Resolved::default()).unwrap();
    let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
    let values = view.get("values").unwrap();
    let format = SdJwtVc::new().unwrap();
    let selected = |path: &str| -> Vec<(usize, String)> {
        let path = Node::parse(path).unwrap();
        ClaimPath::parse(&path)
            .unwrap()
            .select_held(values, |element| format.withheld(element))
            .unwrap()
            .into_iter()
            .map(|(path, value)| match path.last() {
                Some(Concrete::Index(at)) => (*at, value.as_str().unwrap().to_owned()),
                other => panic!("{other:?}"),
            })
            .collect()
    };
    let row = |at: usize, value: &str| (at, value.to_owned());
    assert_eq!(selected(r#"["nationalities",0]"#), [row(0, "DE")]);
    assert_eq!(selected(r#"["nationalities",1]"#), []);
    assert_eq!(selected(r#"["nationalities",2]"#), [row(2, "FR")]);
    assert_eq!(
        selected(r#"["nationalities",null]"#),
        [row(0, "DE"), row(2, "FR")]
    );
}

/// The view holds each number as the payload's text writes it, in a JSON text a beyond-double
/// number leaves readable (RFC 8259 §6).
#[test]
fn numbers_stay_as_the_issuer_wrote_them() {
    let payload = r#"{"vct":"t","nbf":1.50,"n":1.10,"m":1E2,"big":1e400}"#;
    let registered = Registered::of(&compact(payload, &[]), &Resolved::default()).unwrap();
    let text = std::str::from_utf8(registered.view()).unwrap();
    for written in [
        r#""n":1.10"#,
        r#""m":1E2"#,
        r#""big":1e400"#,
        r#""not_before":1.50"#,
    ] {
        assert!(text.contains(written), "{written} in {text}");
    }
    assert!(Node::parse(text).is_ok(), "{text}");
}

/// What makes no view: one fixture per rule.
#[test]
fn refusals() {
    let rows: [(&str, &str, RegistrationError); 5] = [
        ("no vct", "{}", RegistrationError::Vct),
        (
            "an iss of a number",
            r#"{"vct":"t","iss":1}"#,
            RegistrationError::Iss,
        ),
        (
            "a jwk without a curve",
            r#"{"vct":"t","cnf":{"jwk":{"kty":"EC"}}}"#,
            RegistrationError::Key,
        ),
        (
            "an exp of a string",
            r#"{"vct":"t","exp":"soon"}"#,
            RegistrationError::Validity("exp"),
        ),
        (
            "an exp beyond the double range",
            r#"{"vct":"t","exp":1e400}"#,
            RegistrationError::Validity("exp"),
        ),
    ];
    for (case, payload, cause) in rows {
        assert_eq!(
            Registered::of(&compact(payload, &[]), &Resolved::default()),
            Err(cause),
            "{case}"
        );
    }
}

/// SD-JWT VC §3.2.2: a disclosure of a registered claim or of a sub-claim of one refuses the
/// credential; §3.2.1: its `typ` is `dc+sd-jwt`.
#[test]
fn sd_jwt_vc_refusals() {
    for claim in [
        "iss",
        "nbf",
        "exp",
        "cnf",
        "vct",
        "vct#integrity",
        "aka_vcts",
        "status",
    ] {
        let (revealing, digest) = disclosure(&format!(r#"["2GLC42sKQveCfGfryNRN9w","{claim}",1]"#));
        let vct = if claim == "vct" { "" } else { r#""vct":"t","# };
        let payload = format!(r#"{{{vct}"_sd":["{digest}"]}}"#);
        assert_eq!(
            Registered::of(&compact(&payload, &[&revealing]), &Resolved::default()).map(|_| ()),
            Err(RegistrationError::SelectivelyDisclosed(claim)),
            "{claim}"
        );
    }
    let (key, digest) = disclosure(r#"["2GLC42sKQveCfGfryNRN9w","jwk",{"crv":"P-256"}]"#);
    let payload = format!(r#"{{"vct":"t","cnf":{{"_sd":["{digest}"]}}}}"#);
    assert_eq!(
        Registered::of(&compact(&payload, &[&key]), &Resolved::default()),
        Err(RegistrationError::SelectivelyDisclosed("cnf")),
    );
    for header in [r#"{"alg":"ES256"}"#, r#"{"alg":"ES256","typ":"JWT"}"#] {
        assert_eq!(
            Registered::of(
                &compact_under(header, r#"{"vct":"t"}"#, &[]),
                &Resolved::default()
            ),
            Err(RegistrationError::Typ),
            "{header}"
        );
    }
}

/// A view the issuer stand-in writes, with objects and arrays in arrays, registers as it states.
#[test]
fn issued_view_returns() {
    let written = Node::parse(
        r#"{"type":"t","metadata":{},"values":{"name":"Ada","grp":{"c":1.5,"d":null},
            "list":[1,{"e":true},[2,3]]},"issuer":"https://issuer.example","alg":"EdDSA",
            "curve":"Ed25519","key_alg":"ES256","key_curve":"P-256",
            "validity":{"not_before":1,"not_after":2}}"#,
    )
    .unwrap();
    let issued = sd_jwt_issuer::issue(&written).unwrap();
    let resolved = Resolved {
        issuer_curve: Some("Ed25519"),
        ..Resolved::default()
    };
    let registered = Registered::of(&issued, &resolved).unwrap();
    let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
    assert_eq!(view, sd_jwt_issuer::registered_view(&written).unwrap());
}
