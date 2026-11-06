//! Known answers from the specifications: every hash B.3.3.1 names on its standard's example,
//! RFC 9861 §5's KT128 and KT256 among them, W3C SRI §3's example digests, OpenID4VP
//! B.3.3.1's hash rule, the session phase 2 binds and §5.9's audience, and §8.3's choice of the
//! response encryption and its JWE.

#[path = "../common/mod.rs"]
mod common;
mod handover;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use k12::{ExtendableOutput, Kt256};
use serde_json::Value as Json;
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;
use siros_openid4vp::hash::{Blake2, HashAlgorithm, K12, Sha2, Sha3};
use siros_openid4vp::host::CoreHost;
use siros_openid4vp::matching::{Accepted, Consent, Match, Views, display, offer};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::request::Request;
use siros_openid4vp::resolve::{Delivery, Prepared};
use siros_openid4vp::rows::{Choice, Env, SriMetadata};
use siros_openid4vp::sri;
use siros_openid4vp::wallet::Wallet;
use siros_testkit::{Binds, Published, TestHost};

use common::{Held, entry, env, parameters, registry, request_of, test_queries, unsigned};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_named_hash_matches_its_standards_examples() {
    let algorithms: Vec<Box<dyn HashAlgorithm>> = Sha2::ALL
        .into_iter()
        .map(|algorithm| Box::new(algorithm) as Box<dyn HashAlgorithm>)
        .chain(
            Sha3::ALL
                .into_iter()
                .map(|a| Box::new(a) as Box<dyn HashAlgorithm>),
        )
        .chain(
            Blake2::ALL
                .into_iter()
                .map(|a| Box::new(a) as Box<dyn HashAlgorithm>),
        )
        .chain(
            K12::ALL
                .into_iter()
                .map(|a| Box::new(a) as Box<dyn HashAlgorithm>),
        )
        .collect();
    let digest = |name: &str, message: &[u8]| {
        let algorithm = algorithms
            .iter()
            .find(|algorithm| algorithm.name().as_str() == name)
            .expect("a Hash Name String B.3.3.1 allows");
        let digest = algorithm.digest(message);
        assert_eq!(digest.len(), algorithm.octets().get(), "{name}");
        hex(&digest).to_uppercase()
    };
    // "abc" in FIPS 180-4's and FIPS 202's examples, RFC 7693 Appendices A and B; RFC 6920 §2's
    // truncations keep the leftmost bits; CPython's hashlib for BLAKE2b's 32-byte output, which
    // RFC 7693 does not publish.
    let abc = [
        (
            "sha-256",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        ),
        ("sha-256-128", "BA7816BF8F01CFEA414140DE5DAE2223"),
        ("sha-256-120", "BA7816BF8F01CFEA414140DE5DAE22"),
        ("sha-256-96", "BA7816BF8F01CFEA414140DE"),
        ("sha-256-64", "BA7816BF8F01CFEA"),
        ("sha-256-32", "BA7816BF"),
        (
            "sha-384",
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7",
        ),
        (
            "sha-512",
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
        ),
        (
            "sha3-224",
            "E642824C3F8CF24AD09234EE7D3C766FC9A3A5168D0C94AD73B46FDF",
        ),
        (
            "sha3-256",
            "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
        ),
        (
            "sha3-384",
            "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25",
        ),
        (
            "sha3-512",
            "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0",
        ),
        (
            "blake2s-256",
            "508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982",
        ),
        (
            "blake2b-256",
            "BDDD813C634239723171EF3FEE98579B94964E3BB1CB3E427262C8C068D52319",
        ),
        (
            "blake2b-512",
            "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923",
        ),
    ];
    for (name, want) in abc {
        assert_eq!(digest(name, b"abc"), want, "{name}");
    }
    // RFC 9861 §5: KT128 and KT256 of ptn(n), k12-256 and k12-512 with an empty customization
    // string; KT256 over 8192 bytes builds a tree of two chunks.
    let ptn = |n: usize| (0..n).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let kangaroo = [
        (
            "k12-256",
            1,
            "2BDA92450E8B147F8A7CB629E784A058EFCA7CF7D8218E02D345DFAA65244A1F",
        ),
        (
            "k12-512",
            8192,
            "C6EE8E2AD3200C018AC87AAA031CDAC22121B412D07DC6E0DCCBB53423747E9A1C18834D99DF596CF0CF4B8DFAFB7BF02D139D0C9035725ADC1A01B7230A41FA",
        ),
    ];
    for (name, n, want) in kangaroo {
        assert_eq!(digest(name, &ptn(n)), want, "{name} of ptn({n})");
    }
}

#[test]
fn subresource_integrity_follows_the_w3c_example() {
    let body = b"alert('Hello, world.');";
    let s384 = "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO";
    let s512 = "sha512-Q2bFTOhEALkN8hOms2FKTDLy7eugP2zFZ1T8LCvX42Fp3WoNr3bjZSAHeOsHrbV1Fu9/A0EzCinRE7Af1ofPrw==";
    let cases = [
        (body.to_vec(), s384.to_owned(), true),
        (body.to_vec(), s512.to_owned(), true),
        (body.to_vec(), format!("{s384} {s512}"), true),
        // The strongest algorithm decides; any of its digests may match.
        (body.to_vec(), format!("sha384-AAAA {s512}"), true),
        (body.to_vec(), format!("{s384} sha512-AAAA"), false),
        ([&body[..], b" "].concat(), s384.to_owned(), false),
        (body.to_vec(), "md5-AAAA".to_owned(), false),
        (
            body.to_vec(),
            sri::integrity(body).as_str().to_owned(),
            true,
        ),
        (
            body.to_vec(),
            format!("{} {s384}", sri::integrity(body).as_str()),
            true,
        ),
    ];
    for (content, metadata, want) in cases {
        let written = SriMetadata::written(metadata);
        assert_eq!(sri::matches(&content, &written), want, "{written:?}");
    }
    assert_eq!(
        sri::integrity(body).as_str(),
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
        )
    );
}

/// What phase 2 answered: the VP Token's and the Authorization Response's JSON, and the delivery.
struct Answer {
    vp_token: String,
    json: String,
    delivery: Delivery,
}

/// The response to the first selection the consent offers, over the default of the registry's
/// host.
fn answer<'a, H: CoreHost + Default>(
    request: &'a Request<'a>,
    wallet: &'a Wallet<'a>,
    registry: &'a Registry<H>,
    env: &'a Env,
) -> Answer {
    let accepted = Accepted::new(request, registry).expect("accepted");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let matched = Match::run(&accepted, wallet, env, &rendering).expect("match");
    let consent = Consent::of(&matched).expect("consent");
    let views = Views::of(&matched, env).expect("views");
    let sets = offer(&matched, &consent, Choice::First);
    let shown = display(&sets, &views, &[]).expect("display");
    let first: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
    let ids = shown
        .set(0)
        .and_then(|set| set.select(&first))
        .expect("selection")
        .ids();
    let host = H::default();
    let authenticated = siros_testkit::fixtures::authenticate(request.envelope(), registry, &host)
        .expect("authentic");
    let app = siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
        .expect("the test app");
    let rendering = app.rendering().expect("the rendering");
    let built = Prepared::prepare(
        &authenticated,
        &ids,
        wallet,
        registry,
        env,
        &rendering,
        &host,
    )
    .and_then(|prepared| prepared.respond(|resource| Published::default().answer(resource), &host))
    .expect("response");
    Answer {
        vp_token: built.response().vp_token().json(),
        json: built.response().json(),
        delivery: built.delivery().clone(),
    }
}

#[test]
fn transaction_data_hashes_follow_b_3_3_1() {
    let lists: [&[Option<&str>]; 7] = [
        &[None, None],
        &[Some(r#"["sha-512", "sha-256"]"#), Some(r#"["sha-256"]"#)],
        &[Some(r#"["sha-384", "sha-512"]"#), Some(r#"["sha-512"]"#)],
        &[Some(r#"["sha-384"]"#), None],
        &[Some(r#"["sha-256-128"]"#)],
        &[Some(r#"["md5", "k12-512"]"#)],
        &[Some(r#"["sha3-256"]"#), Some(r#"["sha3-256"]"#)],
    ];
    // One hash per entry, over the strings as received, by an algorithm every entry allows:
    // sha-256 by default; the first of the first list the others allow; none in common excludes.
    let want = [
        Some((None, "sha-256")),
        Some((Some("sha-256"), "sha-256")),
        Some((Some("sha-512"), "sha-512")),
        None,
        Some((Some("sha-256-128"), "sha-256-128")),
        Some((Some("k12-512"), "k12-512")),
        Some((Some("sha3-256"), "sha3-256")),
    ];
    let oracle = |alg: &str, data: &[u8]| -> Vec<u8> {
        match alg {
            "sha-256" => Sha256::digest(data).to_vec(),
            "sha-512" => Sha512::digest(data).to_vec(),
            "sha-256-128" => Sha256::digest(data)[..16].to_vec(),
            "k12-512" => {
                let mut out = [0u8; 64];
                Kt256::digest_xof(data, &mut out);
                out.to_vec()
            }
            "sha3-256" => Sha3_256::digest(data).to_vec(),
            other => panic!("no oracle for {other}"),
        }
    };
    let registry = registry(Binds::Every);
    let env = env("en");
    let holder = Held::answering("c", &["q"], &["t1"]);
    let wallet = Wallet::new(vec![holder.credential()]).expect("wallet");
    for (algs, want) in lists.into_iter().zip(want) {
        let entries: Vec<String> = algs
            .iter()
            .map(|alg| {
                let listed = alg.map_or(String::new(), |list| {
                    format!(r#", "transaction_data_hashes_alg": {list}"#)
                });
                entry(&format!(
                    r#"{{"type": "t1", "credential_ids": ["q"]{listed}}}"#
                ))
            })
            .collect();
        let raw: Vec<String> = entries.iter().map(|e| format!("\"{e}\"")).collect();
        let text = parameters(
            &test_queries(&["q"]),
            &format!(r#""transaction_data":[{}]"#, raw.join(",")),
        );
        let received = unsigned(&text).expect("received");
        let request = request_of(&received).expect("request");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
        let Some((alg, used)) = want else {
            assert_eq!(
                matched.excluded()[0].exclude.clause(),
                "OpenID4VP B.3.3.1",
                "{algs:?}"
            );
            continue;
        };
        let response = answer(&request, &wallet, &registry, &env);
        let token: Json = serde_json::from_str(&response.vp_token).expect("vp_token");
        let proof = &token["q"][0]["proof"];
        assert_eq!(
            proof
                .get("transaction_data_hashes_alg")
                .and_then(Json::as_str),
            alg,
            "{algs:?}"
        );
        let hashes: Vec<String> = entries
            .iter()
            .map(|e| URL_SAFE_NO_PAD.encode(oracle(used, e.as_bytes())))
            .collect();
        assert_eq!(
            proof["transaction_data_hashes"],
            serde_json::json!(hashes),
            "{algs:?}"
        );
    }
}

/// A registered algorithm writes exactly the octets it states: the core refuses another length
/// with a `Fault`, and a digest of the stated length is the response's hash. The algorithm is an
/// extension's, of the name of B.3.3.1's default.
#[test]
fn a_hash_algorithms_digest_holds_the_octets_it_states() {
    use siros_openid4vp::envelope::Envelope;
    use siros_openid4vp::hash::{HashAlgorithm, HashesError};
    use siros_openid4vp::ids::TransactionType;
    use siros_openid4vp::modes::DcApi;
    use siros_openid4vp::resolve::Outcome;
    use siros_openid4vp::routing::VpToken;
    use siros_testkit::{TestFormat, TestHash, TestProfile};

    let data = entry(r#"{"type": "t1", "credential_ids": ["q"]}"#);
    let text = parameters(
        &test_queries(&["q"]),
        &format!(r#""transaction_data":["{data}"]"#),
    );
    let received = unsigned(&text).expect("received");
    let holder = Held::answering("c", &["q"], &["t1"]);
    let wallet = Wallet::new(vec![holder.credential()]).expect("wallet");
    let env = env("en");
    for writes in [32, 31] {
        let mut builder = Registry::<TestHost>::builder();
        builder.response_type(VpToken);
        builder.mode(DcApi);
        builder.hash(TestHash {
            name: Sha2::Sha256.name(),
            octets: Sha2::Sha256.octets(),
            writes,
        });
        builder.format(TestFormat::new().expect("format"));
        let profile = builder.profile(TestProfile::new(Binds::Every));
        builder.exact(TransactionType::parse("t1").expect("type"), profile);
        let registry = builder.build().expect("registry");
        let envelope = Envelope::parse(&received, &registry).expect("envelope");
        let request = Request::parse(&envelope).expect("request");
        let accepted = Accepted::new(&request, &registry).expect("accepted");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let matched = Match::run(&accepted, &wallet, &env, &rendering).expect("match");
        let consent = Consent::of(&matched).expect("consent");
        let views = Views::of(&matched, &env).expect("views");
        let sets = offer(&matched, &consent, Choice::First);
        let shown = display(&sets, &views, &[]).expect("display");
        let first: Vec<&str> = shown.sets()[0].iter().map(|slot| slot[0].id()).collect();
        let ids = shown
            .set(0)
            .and_then(|set| set.select(&first))
            .expect("selection")
            .ids();
        let host = TestHost::default();
        let authenticated =
            siros_testkit::fixtures::authenticate(request.envelope(), &registry, &host)
                .expect("authentic");
        let app =
            siros_testkit::render::App::of(&[siros_testkit::render::CrateSource::openid4vp()])
                .expect("the test app");
        let rendering = app.rendering().expect("the rendering");
        let outcome = Prepared::prepare(
            &authenticated,
            &ids,
            &wallet,
            &registry,
            &env,
            &rendering,
            &host,
        )
        .and_then(|prepared| {
            prepared.respond(|resource| Published::default().answer(resource), &host)
        });
        match (writes, outcome) {
            (32, Ok(response)) => {
                let token: Json =
                    serde_json::from_str(&response.response().vp_token().json()).expect("vp_token");
                assert_eq!(
                    token["q"][0]["proof"]["transaction_data_hashes"],
                    serde_json::json!([URL_SAFE_NO_PAD.encode(Sha256::digest(data.as_bytes()))])
                );
            }
            (31, Err(Outcome::Fault(fault))) => {
                let cause = std::error::Error::source(&fault)
                    .and_then(|cause| cause.downcast_ref::<HashesError>());
                assert_eq!(
                    cause,
                    Some(&HashesError::Digest {
                        name: Sha2::Sha256.name(),
                        octets: 31,
                        stated: 32,
                    })
                );
            }
            (writes, other) => panic!("{writes} octets: {other:?}"),
        }
    }
}
