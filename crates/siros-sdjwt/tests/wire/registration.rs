//! The registration (S1, S2): the view of an issued SD-JWT.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use siros_openid4vp::claims::kit::ClaimsFormat;
use siros_openid4vp::claims::{ClaimPath, Concrete};
use siros_openid4vp::json::Node;
use siros_openid4vp::request::Curve;
use siros_openid4vp::wallet::Holder;
use siros_sdjwt::{
    HolderKeyFault, JwkCoordinate, PermanentClaim, Registered, RegistrationError, Resolved,
    SdJwtVc, SigningAlg, ValidityClaim,
};
use siros_testkit::sd_jwt_issuer;

use crate::common::{compact, compact_under, decoy, disclosure, issued, json_fixture};

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 9901 A.3's SD-JWT VC: its `vct`, its issuer, its holder key and its validity.
#[test]
fn view_of_a3() {
    let compact = issued("a3");
    let registered = Registered::of(&compact, &Resolved::default()).unwrap();
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
                Some(Concrete::Index(at)) => (at.position(), value.as_str().unwrap().to_owned()),
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
    let rows: [(&str, &str, RegistrationError); 4] = [
        ("no vct", "{}", RegistrationError::Vct),
        (
            "an iss of a number",
            r#"{"vct":"t","iss":1}"#,
            RegistrationError::Iss,
        ),
        (
            "an exp of a string",
            r#"{"vct":"t","exp":"soon"}"#,
            RegistrationError::Validity(ValidityClaim::Exp),
        ),
        (
            "an exp beyond the double range",
            r#"{"vct":"t","exp":1e400}"#,
            RegistrationError::Validity(ValidityClaim::Exp),
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
    for (claim, permanent) in [
        ("iss", PermanentClaim::Iss),
        ("nbf", PermanentClaim::Nbf),
        ("exp", PermanentClaim::Exp),
        ("cnf", PermanentClaim::Cnf),
        ("vct", PermanentClaim::Vct),
        ("vct#integrity", PermanentClaim::VctIntegrity),
        ("aka_vcts", PermanentClaim::AkaVcts),
        ("status", PermanentClaim::Status),
    ] {
        let (revealing, digest) = disclosure(&format!(r#"["2GLC42sKQveCfGfryNRN9w","{claim}",1]"#));
        let vct = if claim == "vct" { "" } else { r#""vct":"t","# };
        let payload = format!(r#"{{{vct}"_sd":["{digest}"]}}"#);
        assert_eq!(
            Registered::of(&compact(&payload, &[&revealing]), &Resolved::default()).map(|_| ()),
            Err(RegistrationError::SelectivelyDisclosed(permanent)),
            "{claim}"
        );
    }
    let (key, digest) = disclosure(r#"["2GLC42sKQveCfGfryNRN9w","jwk",{"crv":"P-256"}]"#);
    let payload = format!(r#"{{"vct":"t","cnf":{{"_sd":["{digest}"]}}}}"#);
    assert_eq!(
        Registered::of(&compact(&payload, &[&key]), &Resolved::default()),
        Err(RegistrationError::SelectivelyDisclosed(PermanentClaim::Cnf)),
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

/// `cnf`'s shape (RFC 7800 §3.1, §3.2), the JWK of its curve (RFC 7518 §6.2, RFC 8037 §2) and an
/// `alg` it signs under (RFC 7518 §3.4, RFC 9901 §4.3); each key form the JOSE registries give
/// registers, with its algorithm.
#[test]
fn the_holder_key() {
    let (x, y) = (b64(&[1; 32]), b64(&[2; 32]));
    let p256 = |edit: &str| format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"{edit}}}"#);
    let registered = |cnf: &str| {
        let payload = format!(r#"{{"vct":"t","cnf":{cnf}}}"#);
        Registered::of(&compact(&payload, &[]), &Resolved::default())
    };
    let refusals: Vec<(&str, String, HolderKeyFault)> = vec![
        ("a number", "5".to_owned(), HolderKeyFault::Cnf),
        ("an array", "[]".to_owned(), HolderKeyFault::Cnf),
        ("empty", "{}".to_owned(), HolderKeyFault::Cnf),
        (
            "a kid alone",
            r#"{"kid":"k"}"#.to_owned(),
            HolderKeyFault::Cnf,
        ),
        (
            "a jwk of a number",
            r#"{"jwk":1}"#.to_owned(),
            HolderKeyFault::Jwk,
        ),
        (
            "no crv",
            r#"{"jwk":{"kty":"EC"}}"#.to_owned(),
            HolderKeyFault::Curve,
        ),
        (
            "a curve that agrees keys only",
            r#"{"jwk":{"kty":"OKP","crv":"X25519"}}"#.to_owned(),
            HolderKeyFault::Curve,
        ),
        (
            "kty RSA on P-256",
            format!(r#"{{"jwk":{{"kty":"RSA","crv":"P-256","x":"{x}","y":"{y}"}}}}"#),
            HolderKeyFault::KeyType,
        ),
        (
            "no y",
            format!(r#"{{"jwk":{{"kty":"EC","crv":"P-256","x":"{x}"}}}}"#),
            HolderKeyFault::Coordinate(JwkCoordinate::Y),
        ),
        (
            "an x of a P-384 size on P-256",
            format!(
                r#"{{"jwk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{y}"}}}}"#,
                b64(&[1; 48])
            ),
            HolderKeyFault::Coordinate(JwkCoordinate::X),
        ),
        (
            "alg none",
            format!(r#"{{"jwk":{}}}"#, p256(r#","alg":"none""#)),
            HolderKeyFault::Alg,
        ),
        (
            "alg HS256",
            format!(r#"{{"jwk":{}}}"#, p256(r#","alg":"HS256""#)),
            HolderKeyFault::Alg,
        ),
        (
            "alg ES384 on P-256",
            format!(r#"{{"jwk":{}}}"#, p256(r#","alg":"ES384""#)),
            HolderKeyFault::Alg,
        ),
    ];
    for (case, cnf, cause) in refusals {
        assert_eq!(
            registered(&cnf).map(|_| ()),
            Err(RegistrationError::Key(cause)),
            "{case}"
        );
    }
    // (kty, crv, coordinate size, stated alg, the view's key_alg).
    let keys = [
        ("EC", "P-256", 32, None, "ES256"),
        ("EC", "P-384", 48, Some("ES384"), "ES384"),
        ("EC", "P-521", 66, None, "ES512"),
        ("EC", "secp256k1", 32, None, "ES256K"),
        ("OKP", "Ed25519", 32, None, "EdDSA"),
        ("OKP", "Ed25519", 32, Some("Ed25519"), "Ed25519"),
        ("OKP", "Ed448", 57, Some("EdDSA"), "EdDSA"),
    ];
    for (kty, crv, size, alg, key_alg) in keys {
        let coordinate = b64(&vec![3; size]);
        let y = if kty == "EC" {
            format!(r#","y":"{coordinate}""#)
        } else {
            String::new()
        };
        let alg = alg.map_or(String::new(), |alg| format!(r#","alg":"{alg}""#));
        let cnf =
            format!(r#"{{"jwk":{{"kty":"{kty}","crv":"{crv}","x":"{coordinate}"{y}{alg}}}}}"#);
        let registered = registered(&cnf).unwrap_or_else(|e| panic!("{cnf}: {e}"));
        assert_eq!(registered.holder(), Holder::Bound);
        let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
        assert_eq!(
            view.get("key_alg").and_then(Node::as_str),
            Some(key_alg),
            "{cnf}"
        );
        assert_eq!(
            view.get("key_curve").and_then(Node::as_str),
            Some(crv),
            "{cnf}"
        );
    }
    let keyless = Registered::of(&compact(r#"{"vct":"t"}"#, &[]), &Resolved::default()).unwrap();
    assert_eq!(keyless.holder(), Holder::Unbound);
}

/// A curve the JWS algorithm rules out makes no view (RFC 7518 §3.4).
#[test]
fn a_curve_the_algorithm_rules_out() {
    let issued = compact(r#"{"vct":"t"}"#, &[]);
    let curve = Resolved {
        issuer_curve: Curve::new("P-384"),
        ..Resolved::default()
    };
    assert_eq!(
        Registered::of(&issued, &curve),
        Err(RegistrationError::IssuerCurve {
            alg: SigningAlg::parse("ES256").unwrap(),
            curve: "P-384".to_owned(),
        })
    );
}

/// RFC 9901 §7.1 step 6 checks `exp` "in the processed payload, if present". A digest whose
/// disclosure the credential lacks reads as a decoy (§4.2.5), so a withheld `exp` leaves a view
/// stating no validity for the operating environment's rules to judge (§9.7).
#[test]
fn a_withheld_exp_is_no_exp() {
    let (_, digest) = disclosure(r#"["2GLC42sKQveCfGfryNRN9w","exp",1785000000]"#);
    let payload = format!(r#"{{"vct":"t","_sd":["{digest}"]}}"#);
    let registered = Registered::of(&compact(&payload, &[]), &Resolved::default()).unwrap();
    let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
    assert_eq!(view.get("validity"), None);
}

/// A view the issuer stand-in writes, with objects and arrays in arrays, registers as it states:
/// the permanent claims in `values`, `cnf` holding its key, `validity` the written dates.
#[test]
fn issued_view_returns() {
    const ZERO: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // (validity as written, `nbf` and `exp` as the payload's).
    let dates = [
        (r#"{"not_before":1,"not_after":2}"#, r#""nbf":1,"exp":2,"#),
        (r#"{"not_after":1785000000}"#, r#""exp":1785000000,"#),
        (r#"{"not_before":1.5}"#, r#""nbf":1.5,"#),
    ];
    for (validity, permanent) in dates {
        let written = format!(
            r#"{{"type":"t","metadata":{{}},"values":{{"name":"Ada","grp":{{"c":1.5,"d":null}},
                "list":[1,{{"e":true}},[2,3]]}},"issuer":"https://issuer.example","alg":"EdDSA",
                "curve":"Ed25519","key_alg":"ES256","key_curve":"P-256","validity":{validity}}}"#,
        );
        let expected = format!(
            r#"{{"type":"t","metadata":{{}},"values":{{"vct":"t","iss":"https://issuer.example",
                {permanent}"cnf":{{"jwk":{{"crv":"P-256","alg":"ES256","kty":"EC","x":"{ZERO}",
                "y":"{ZERO}"}}}},"name":"Ada","grp":{{"c":1.5,"d":null}},
                "list":[1,{{"e":true}},[2,3]]}},"issuer":"https://issuer.example","alg":"EdDSA",
                "curve":"Ed25519","key_alg":"ES256","key_curve":"P-256","validity":{validity}}}"#,
        );
        let issued = sd_jwt_issuer::issue(&Node::parse(&written).unwrap()).unwrap();
        let resolved = Resolved {
            issuer_curve: Curve::new("Ed25519"),
            ..Resolved::default()
        };
        let registered = Registered::of(&issued, &resolved).unwrap();
        let view = Node::parse(std::str::from_utf8(registered.view()).unwrap()).unwrap();
        assert_eq!(view, Node::parse(&expected).unwrap(), "{validity}");
    }
}
