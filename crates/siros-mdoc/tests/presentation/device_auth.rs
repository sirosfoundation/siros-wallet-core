//! How the device authenticates the document (OpenID4VP B.2.4, ISO/IEC 18013-5 §9.1.3), with
//! the device MAC module and without it.

use std::any::Any;

use siros_mdoc::{DeviceAuthRefused, Mdoc};
use siros_openid4vp::effects::Fetch;
use siros_openid4vp::host::CoreHost;
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{HostedFormat, Member, MemberValue, Registry};
use siros_openid4vp::resolve::{Finding, Outcome, Prepared};
use siros_openid4vp::wallet::Wallet;
use siros_testkit::fixtures::{Held, env, first_selection, parameters, request_of, unsigned};
use siros_testkit::render::Language;

use super::{MdocHost, P256, P384, QUERY, device_auth, issued, present, read, view};

siros_testkit::test_host! {
    /// The core's modules, without the device MAC.
    #[derive(Default)]
    struct MaclessHost {
        handles { platform: siros_testkit::TestPlatform => siros_openid4vp::host::Platform }
        zero_sized {
            siros_testkit::TestHaip => siros_openid4vp::host::Haip,
            siros_testkit::TestRequestDecryption => siros_openid4vp::host::RequestDecryption
        }
        optional {}
        lacks { siros_mdoc::DeviceMac }
    }
}

#[test]
fn the_device_authenticates_by_signature_or_by_mac_as_check_respond_states() {
    // A signature when the Verifier states nothing or lists no MAC for the device key's curve; a
    // MAC, agreed with the first Verifier key on that curve, when it lists only the MAC, or both
    // and the presentation carries no transaction; a signature for a transaction when both are
    // listed.
    let transaction = || {
        vec![(
            Member::element("urn:paso:sca:1", "jti"),
            MemberValue::Text("j".to_owned()),
        )]
    };
    // (deviceauth_alg_values, the Verifier's keys, whether a transaction is carried, the mode
    // and the MAC's Verifier key).
    type Case = (
        Option<&'static str>,
        String,
        bool,
        (&'static str, Option<&'static str>),
    );
    let cases: [Case; 6] = [
        (None, P256.to_owned(), false, ("deviceSignature", None)),
        (
            Some("[-9]"),
            P256.to_owned(),
            false,
            ("deviceSignature", None),
        ),
        (
            Some("[-65537]"),
            format!("{P384}, {P256}"),
            false,
            ("deviceMac", Some("reader-p256")),
        ),
        (
            Some("[-9, -65537]"),
            P256.to_owned(),
            false,
            ("deviceMac", Some("reader-p256")),
        ),
        (
            Some("[-9, -65537]"),
            P256.to_owned(),
            true,
            ("deviceSignature", None),
        ),
        (
            Some("[-65537]"),
            P256.to_owned(),
            true,
            ("deviceMac", Some("reader-p256")),
        ),
    ];
    let held = issued(&view(-7, "P-256"));
    for (deviceauth, keys, carries, (mode, reader)) in cases {
        let supported = deviceauth.map_or_else(String::new, |listed| {
            format!(
                r#","vp_formats_supported":{{"mso_mdoc":{{"deviceauth_alg_values":{listed}}}}}"#
            )
        });
        let metadata = format!(r#"{{"jwks":{{"keys":[{keys}]}}{supported}}}"#);
        let members = if carries { transaction() } else { Vec::new() };
        let presentation = present(QUERY, &metadata, &held, members, false).expect("presentation");
        assert_eq!(
            device_auth(&read(&presentation)),
            (mode.to_owned(), reader.map(str::to_owned)),
            "{deviceauth:?} {keys} {carries}"
        );
    }
}

/// The VP Token phase 2 answers over `host` for the first selection of `QUERY` with the client
/// metadata, its fetches unanswered.
fn respond<H>(host: &H, client_metadata: &str, held: &Held) -> Result<String, Outcome>
where
    Mdoc: HostedFormat<H>,
    H: CoreHost
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip>
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::RequestDecryption>,
{
    let text = parameters(
        &format!(r#"{{"credentials": [{QUERY}]}}"#),
        &format!(r#""client_metadata":{client_metadata}"#),
    );
    let received = unsigned(&text).expect("received");
    let request = request_of(&received).expect("request");
    let mut builder = Registry::<H>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(Mdoc::new().expect("format"));
    let registry = builder.build().expect("registry");
    let wallet = Wallet::new(vec![held.credential().expect("credential")]).expect("wallet");
    let env = env(&["en"], Vec::new()).expect("env");
    let context = Language::English.shared().expect("the test app");
    let ids = first_selection(&request, &wallet, &registry, &env, context).expect("a selection");
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let authenticated =
        siros_testkit::fixtures::authenticate(request.envelope(), &registry, context, host)
            .expect("authentic");
    Prepared::prepare(
        &authenticated,
        &ids,
        &wallet,
        &registry,
        &env,
        context,
        host,
    )
    .and_then(|prepared| prepared.respond(|_| Fetch::Unfetched, host))
    .map(|built| built.response().vp_token().json())
}

/// The device authentication of a VP Token's one presentation.
fn mode(token: &str) -> (String, Option<String>) {
    let token = Node::parse(token).expect("vp_token").into_owned();
    let presentation = token
        .get("q")
        .and_then(Node::as_array)
        .and_then(|presentations| presentations.first())
        .expect("a presentation");
    device_auth(&read(presentation))
}

/// RFC 9053 §7.1 keeps X25519 to ECDH, so the key signs nothing: the document carries a device MAC
/// (ISO/IEC 18013-5 §9.1.3.5) where a Verifier key on its curve agrees one and the Verifier's list
/// allows it, and no device authentication otherwise.
#[test]
fn a_key_that_only_agrees_authenticates_by_mac_alone() {
    const X25519: &str = r#"{"kty": "OKP", "crv": "X25519", "kid": "reader-x25519", "x": "AA"}"#;
    let signing_nothing =
        |curve: &str| issued(&view(-7, curve).replace(r#""device_alg": -7, "#, ""));
    let listing = |listed: &str| {
        format!(r#","vp_formats_supported":{{"mso_mdoc":{{"deviceauth_alg_values":{listed}}}}}"#)
    };
    let rows = [
        ("X25519", X25519, String::new(), Some("reader-x25519")),
        ("X25519", X25519, listing("[-65540]"), Some("reader-x25519")),
        ("X25519", X25519, listing("[5]"), Some("reader-x25519")),
        ("X25519", P256, String::new(), None),
        // A label 3 of no signature algorithm leaves a P-256 key signing nothing.
        ("P-256", P256, String::new(), Some("reader-p256")),
        ("P-256", P384, String::new(), None),
    ];
    for (curve, keys, supported, macs) in rows {
        let held = signing_nothing(curve);
        let metadata = format!(r#"{{"jwks":{{"keys":[{keys}]}}{supported}}}"#);
        let host = MdocHost::default();
        match respond(&host, &metadata, &held) {
            Ok(response) if macs.is_some() => assert_eq!(
                mode(&response),
                ("deviceMac".to_owned(), macs.map(str::to_owned)),
                "{metadata}"
            ),
            Err(Outcome::Fallback(findings)) if macs.is_none() => {
                let [Finding::Format { finding, .. }] = findings.items() else {
                    panic!("{metadata}: {findings:?}");
                };
                let finding: &dyn Any = finding.as_ref();
                assert_eq!(
                    finding.downcast_ref::<DeviceAuthRefused>(),
                    Some(&DeviceAuthRefused::KeyAgreementOnly),
                    "{metadata}"
                );
            }
            other => panic!("{metadata}: {other:?}"),
        }
    }
}

#[test]
fn a_build_without_the_device_mac_signs_where_the_verifier_lists_a_signature_and_falls_back_otherwise()
 {
    // B.2.4: the device key's signature (-9 for ES256) only where deviceauth_alg_values lists
    // it or is absent; the MAC alone listed leaves the build no device authentication, which
    // phase 2 finds before the End-User authenticates. The build with the module MACs wherever
    // the MAC is listed, the presentation carrying no transaction.
    let held = issued(&view(-7, "P-256"));
    for (deviceauth, signs, macs) in [
        (None, true, false),
        (Some("[-9, -65537]"), true, true),
        (Some("[-65537]"), false, true),
    ] {
        let supported = deviceauth.map_or_else(String::new, |listed| {
            format!(
                r#","vp_formats_supported":{{"mso_mdoc":{{"deviceauth_alg_values":{listed}}}}}"#
            )
        });
        let metadata = format!(r#"{{"jwks":{{"keys":[{P256}]}}{supported}}}"#);
        let macless = MaclessHost::default();
        match respond(&macless, &metadata, &held) {
            Ok(response) if signs => {
                assert_eq!(
                    mode(&response),
                    ("deviceSignature".to_owned(), None),
                    "{deviceauth:?}"
                );
                assert_eq!(macless.platform.authentications(), 1, "{deviceauth:?}");
            }
            Err(Outcome::Fallback(findings)) if !signs => {
                let [Finding::Format { finding, .. }] = findings.items() else {
                    panic!("{deviceauth:?}: {findings:?}");
                };
                let finding: &dyn Any = finding.as_ref();
                assert_eq!(
                    finding.downcast_ref::<DeviceAuthRefused>(),
                    Some(&DeviceAuthRefused::NoDeviceMac),
                    "{deviceauth:?}"
                );
                assert_eq!(macless.platform.authentications(), 0, "{deviceauth:?}");
            }
            other => panic!("{deviceauth:?}: {other:?}"),
        }
        let held_mac = MdocHost::default();
        let response = respond(&held_mac, &metadata, &held).expect("answered");
        let want = if macs {
            ("deviceMac".to_owned(), Some("reader-p256".to_owned()))
        } else {
            ("deviceSignature".to_owned(), None)
        };
        assert_eq!(mode(&response), want, "{deviceauth:?}");
        assert_eq!(held_mac.platform.authentications(), 1, "{deviceauth:?}");
    }
}
