//! G4: known answers from the specs and from vectors the provers ship.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use serde_json::Value;
use siros_codec::date::Date;
use siros_dcql::DocType;
use siros_mdoc::{device_signing_input, DeviceNameSpaces, SessionTranscript};
use siros_oid4vp::ClientId;
use siros_oid4vp::{Handover, JwkThumbprint};
use siros_zkp_req_nym_auth::age::{AgeRange, Bound, Bounds};
use siros_zkp_req_nym_auth::catalogue::Config;
use siros_zkp_req_nym_auth::verifier_id::{
    pseudonym_sha256, verifier_input, Intermediary, ProverInput, VerifierId,
};

/// A range, D, E, C, and where the case comes from.
type AgeCase = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    &'static str,
);

fn date(text: &str) -> Date {
    Date::parse(text).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// e2: the digest of the data the device key signs, with no `DeviceSigned` element.
fn challenge_digest(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
    *device_signing_input(
        &SessionTranscript::new(session_transcript.to_vec()),
        &DocType::new(doc_type),
        &DeviceNameSpaces::empty(),
    )
    .digest()
    .as_bytes()
}

fn vectors(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// E and C of `age_check` (nym_auth catalogue). `None` is a missing bound.
#[test]
fn age_check_bounds() {
    let cases: [AgeCase; 12] = [
        // The catalogue's example.
        (
            "13-17",
            "2026-10-09",
            Some("2008-10-10"),
            Some("2013-10-09"),
            "nym_auth_rulebook.md, Example",
        ),
        // The narrowest range of the BBS-CD rulebook, Section 2.
        (
            "18-18",
            "2026-02-28",
            Some("2007-03-01"),
            Some("2008-02-28"),
            "bbs-cd-nym_auth-v1.md, Section 2",
        ),
        // The archive's verifier request: T 2026-10-07T12:00:00Z, E open, C 2008-10-07.
        (
            "18+",
            "2026-10-07",
            None,
            Some("2008-10-07"),
            "nym-auth-circuits verifier.json",
        ),
        // 29 February, worked by hand from the rule: D minus N years keeps month and day.
        (
            "18+",
            "2028-02-29",
            None,
            Some("2010-02-28"),
            "2010-02-29 is no date; C is the day before",
        ),
        (
            "17-",
            "2028-02-29",
            Some("2010-03-01"),
            None,
            "2010-02-29 is no date; E is the day after",
        ),
        (
            "20-20",
            "2024-02-29",
            Some("2003-03-01"),
            Some("2004-02-29"),
            "2004 is a leap year, 2003 is not",
        ),
        (
            "0-0",
            "2024-02-29",
            Some("2023-03-01"),
            Some("2024-02-29"),
            "the first year of life",
        ),
        (
            "16-16",
            "2032-02-29",
            Some("2015-03-01"),
            Some("2016-02-29"),
            "C on a leap day, E after one",
        ),
        (
            "0+",
            "2025-03-01",
            None,
            Some("2025-03-01"),
            "age 0 or more: born by D",
        ),
        (
            "018+",
            "2026-10-09",
            None,
            Some("2008-10-09"),
            "leading zeros: age 18",
        ),
        (
            "2026+",
            "2026-10-09",
            None,
            Some("0000-10-09"),
            "C in year 0000",
        ),
        (
            "65-",
            "2026-12-31",
            Some("1961-01-01"),
            None,
            "E crosses a year end",
        ),
    ];
    for (range, d, e, c, why) in cases {
        let bounds = AgeRange::parse(range).unwrap().bounds(date(d));
        let want = Bounds {
            earliest: e.map(|e| Bound::Date(date(e))),
            cutoff: c.map(|c| Bound::Date(date(c))),
        };
        assert_eq!(bounds, want, "{range} at {d}: {why}");
    }
}

/// A bound before year 0000, or one more than `u64::MAX` years back, is no `full-date`: the
/// systems answer `unsupported` for it.
#[test]
fn age_check_bounds_out_of_every_window() {
    let d = date("2026-10-09");
    let bounds = AgeRange::parse("2027+").unwrap().bounds(d);
    assert!(matches!(bounds.cutoff, Some(Bound::Date(c)) if c.year() == -1));
    assert!(!bounds.within(Date::FIRST, Date::LAST));
    let huge = AgeRange::parse("99999999999999999999999+")
        .unwrap()
        .bounds(d);
    assert_eq!(huge.cutoff, Some(Bound::Unencodable));
    assert!(!huge.within(Date::FIRST, Date::LAST));
}

/// `verifier_input` and the pseudonym, against the nym-auth-circuits archive's values.
#[test]
fn pseudonym_vectors() {
    let v = vectors("pseudonym.json");
    let seed: [u8; 16] = hex(v["secret_seed"].as_str().unwrap()).try_into().unwrap();
    let config = Config::KnownOffenderMatchingSsc;
    for verifier in v["verifiers"].as_array().unwrap() {
        let client_id = verifier["client_id"].as_str().unwrap();
        let client = ClientId::parse(client_id).unwrap();
        let id = VerifierId::x509_san_dns(&client, Intermediary::Absent).unwrap();
        let vi = verifier_input(&config, &id);
        assert_eq!(
            vi.as_bytes().to_vec(),
            hex(verifier["verifier_input"].as_str().unwrap()),
            "{client_id}"
        );
        let nym = pseudonym_sha256(&config, &seed, &ProverInput::ZEROS, &vi);
        assert_eq!(
            nym.as_bytes().to_vec(),
            hex(verifier["pseudonym"].as_str().unwrap()),
            "{client_id}"
        );
    }
}

/// The SessionTranscript of both channels and e2, against the challenge vectors the provers
/// share (OpenID4VP 1.0, B.2.6; system rulebooks, Section 5).
#[test]
fn session_vectors() {
    let v = vectors("session.json");
    for e in v["redirect"].as_array().unwrap() {
        let s = |k: &str| e[k].as_str().unwrap();
        let thumbprint = JwkThumbprint::new(hex(s("jwk_thumbprint_hex")).try_into().unwrap());
        let handover = Handover::redirect(
            s("client_id"),
            s("nonce"),
            Some(&thumbprint),
            s("response_uri"),
        );
        let transcript = handover.session_transcript();
        assert_eq!(
            transcript,
            hex(s("session_transcript_hex")),
            "{}",
            s("name")
        );
        assert_eq!(
            challenge_digest(&transcript, s("doc_type")).to_vec(),
            hex(s("challenge_digest_hex")),
            "{}",
            s("name")
        );
    }
    for e in v["dc_api"].as_array().unwrap() {
        let s = |k: &str| e[k].as_str().unwrap();
        let transcript = hex(s("session_transcript_hex"));
        assert_eq!(
            challenge_digest(&transcript, s("doc_type")).to_vec(),
            hex(s("challenge_digest_hex")),
            "{}",
            s("name")
        );
        if let Some(thumbprint) = e["jwk_thumbprint_hex"].as_str() {
            let thumbprint = JwkThumbprint::new(hex(thumbprint).try_into().unwrap());
            let handover = Handover::dc_api(s("origin"), s("nonce"), Some(&thumbprint));
            assert_eq!(handover.session_transcript(), transcript, "{}", s("name"));
        }
    }
    for e in v["transcript_only"].as_array().unwrap() {
        let s = |k: &str| e[k].as_str().unwrap();
        let digest = challenge_digest(&hex(s("session_transcript_hex")), s("doc_type"));
        assert_eq!(
            digest.to_vec(),
            hex(s("challenge_digest_hex")),
            "{}",
            s("name")
        );
    }
}
