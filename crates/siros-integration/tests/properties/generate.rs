//! Random requests and wallets as check.py's `random_run` draws them for the core, kept when the
//! core with the test plug-ins accepts the request, then dressed with the real plug-ins as
//! check_props.py's `dress` and its helpers dress them: each query a real format with claims or
//! `_req` over four items, each entry a real transaction data type with its payload, each
//! credential a card of a real format with display metadata, PaSO and QES documents.

use crate::common::HaipHost;
use rand::Rng;
use rand::seq::IndexedRandom;
use rand_chacha::ChaCha8Rng;
use siros_openid4vp::effects::MediaType;
use siros_openid4vp::host::Timestamp;
use siros_openid4vp::json::quote;
use siros_openid4vp::rows::HttpsUrl;
use siros_paso::Reading;
use siros_paso::Signal;
use siros_paso::risk::SignalType;
use siros_testkit::{Published, PublishedResource};

mod dress;
mod payloads;
mod random;

pub use dress::Dressed;
use dress::dress;
use random::{Abstract, AbstractCredential};

/// The instant phase 2 answers at (check_props.py RUNTIME_NOW).
pub const NOW: u64 = 1_785_000_000;
/// The PaSO types and the QES type the dressing maps the abstract types to.
pub const TYPE_POOL: [&str; 5] = [
    "urn:paso:sca:global:payment:1",
    "urn:paso:sca:com.example:custom:1",
    "urn:paso:sca:global:generic:x:1",
    "urn:paso:sca:global:mandate:agentic:1",
    siros_qes::TYPE,
];
/// PaSO's Default risk signal profile.
pub const DEFAULT_PROFILE: &str = "urn:paso:risk-profile:global:default:1";
/// The remote logos: the first published as it is, the second altered, the third not at all.
pub const REMOTE: [&str; 3] = [
    "https://cdn.example/logo0.png",
    "https://cdn.example/logo1.png",
    "https://cdn.example/logo2.png",
];
/// The linked documents, fetched as the logos are.
pub const DOCS: [&str; 3] = [
    "https://rp.example/doc0.pdf",
    "https://rp.example/doc1.pdf",
    "https://rp.example/doc2.pdf",
];
/// The documents' content as published.
pub const DOC: &[u8] = b"%PDF-1.7 contract";
/// The cards' logos; the wallet resolved icons for the first two.
const LOGOS: [&str; 3] = [
    "https://issuer.example/logo0.png",
    "https://issuer.example/logo1.png",
    "https://issuer.example/logo2.png",
];
/// The card type of each claims format.
pub const SD_JWT_TYPE: &str = "https://issuer.example/card";
/// The mdoc card's docType.
pub const MDOC_TYPE: &str = "org.example.card";
/// Risk Signals A.6's issuer key, which a card's PaSO metadata publishes.
pub const ENC_KEY: &str = r#"{"kty": "EC", "crv": "P-256", "kid": "issuer-enc-1", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "use": "enc", "alg": "ECDH-ES"}"#;
const FORMATS: [&str; 2] = ["dc+sd-jwt", "mso_mdoc"];
const QUALIFIERS: [&str; 2] = ["eu_eidas_qes", "eu_eidas_qeseal"];
/// The hash algorithms an abstract entry lists (check.py ALGS); `None` lists none.
const ALGS: [Option<&[&str]>; 10] = [
    None,
    None,
    None,
    Some(&["sha-256"]),
    Some(&["sha-512", "sha-256"]),
    Some(&["sha-384"]),
    Some(&["sha3-256", "sha-512"]),
    Some(&["k12-256"]),
    Some(&["blake2b-512", "sha-256-128"]),
    Some(&["md5", "k12-512"]),
];

/// A PNG of a size: the signature, an IHDR chunk, an empty IDAT and IEND, each with its CRC.
pub fn png(width: u32, height: u32) -> Vec<u8> {
    let chunk = |kind: &[u8], data: &[u8]| {
        let mut out = u32::try_from(data.len())
            .expect("a chunk length")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut crc = 0xFFFF_FFFFu32;
        for byte in kind.iter().chain(data) {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        out.extend_from_slice(&(!crc).to_be_bytes());
        out
    };
    let mut header = width.to_be_bytes().to_vec();
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &header));
    out.extend(chunk(b"IDAT", &[]));
    out.extend(chunk(b"IEND", &[]));
    out
}

/// The logo the host publishes.
pub fn logo_png() -> Vec<u8> {
    png(16, 16)
}

/// What a fetch returns: the first logo and document as published, the second altered.
pub fn resources() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let logo = logo_png();
    vec![
        (REMOTE[0], logo.clone(), "image/png"),
        (REMOTE[1], [logo.as_slice(), b"\0"].concat(), "image/png"),
        (DOCS[0], DOC.to_vec(), "application/pdf"),
        (DOCS[1], [DOC, b"!"].concat(), "application/pdf"),
    ]
}

/// A measured signal's last reading: its age at [`NOW`], its status, its value, whether the wallet
/// can measure it again (check_props.py SIGNALS).
pub struct Measured {
    /// The signal type.
    pub kind: &'static str,
    /// Seconds before [`NOW`].
    pub age: u64,
    /// `ok`, `denied` or `unavailable`.
    pub status: &'static str,
    /// The value of an `ok` reading.
    pub value: Option<&'static str>,
    /// Whether the wallet can measure it again.
    pub retakes: bool,
}

/// Some Default profile signals measured, one denied, two older than their 600 s bound (one the
/// wallet can measure again, one it cannot); the rest not implemented.
pub const SIGNALS: [Measured; 5] = [
    Measured {
        kind: "urn:paso:risk:global:geolocation:1",
        age: 30,
        status: "ok",
        value: Some(r#"{"lat": 52.52, "lon": 13.405, "accuracy": 12}"#),
        retakes: true,
    },
    Measured {
        kind: "urn:paso:risk:global:call_activity:1",
        age: 30,
        status: "denied",
        value: None,
        retakes: true,
    },
    Measured {
        kind: "urn:paso:risk:global:device_motion:1",
        age: 900,
        status: "ok",
        value: Some(r#"{"window_ms": 1000}"#),
        retakes: true,
    },
    Measured {
        kind: "urn:paso:risk:global:screen_capture:1",
        age: 900,
        status: "ok",
        value: Some(r#"{"active": false}"#),
        retakes: false,
    },
    Measured {
        kind: "urn:paso:risk:global:device_basics:1",
        age: 5,
        status: "ok",
        value: Some(r#"{"os": "android"}"#),
        retakes: true,
    },
];

/// The host of [`NOW`] with [`SIGNALS`], the credentials `unusable` no longer valid.
pub fn host(unusable: &[String]) -> HaipHost {
    let mut host = HaipHost::at(Timestamp(NOW));
    host.paso.signals = SIGNALS
        .iter()
        .map(|signal| {
            let reading = match (signal.status, signal.value) {
                ("ok", Some(value)) => Reading::Ok(
                    serde_json::value::RawValue::from_string(value.to_owned()).expect("a value"),
                ),
                ("denied", None) => Reading::Denied,
                _ => Reading::Unavailable,
            };
            siros_paso::Measured {
                signal: SignalType::parse(signal.kind.to_owned()).expect("a signal type"),
                last: Signal {
                    collected_at: Timestamp(NOW - signal.age),
                    reading,
                    retakes: signal.retakes,
                },
            }
        })
        .collect();
    host.platform.unusable = unusable.to_vec();
    host
}

/// [`resources`], published for phase 2's fetches.
pub fn published() -> Published {
    Published::new(
        resources()
            .into_iter()
            .map(|(url, content, media)| PublishedResource {
                url: HttpsUrl::parse(url).expect("an https URL"),
                content,
                media: MediaType::parse(media).expect("a media type"),
            })
            .collect(),
    )
}

/// A JSON object written member by member in the order given, each value a JSON text.
#[derive(Default)]
struct Obj(Vec<(String, String)>);

impl Obj {
    /// The object with one more member.
    fn with(mut self, name: &str, json: impl Into<String>) -> Self {
        self.put(name, json);
        self
    }

    fn put(&mut self, name: &str, json: impl Into<String>) {
        self.0.push((name.to_owned(), json.into()));
    }

    fn remove(&mut self, name: &str) {
        self.0.retain(|(known, _)| known != name);
    }

    fn text(&self) -> String {
        let members: Vec<String> = self
            .0
            .iter()
            .map(|(name, json)| format!("{}: {json}", quote(name)))
            .collect();
        format!("{{{}}}", members.join(", "))
    }
}

fn string(text: &str) -> String {
    quote(text).to_string()
}

/// `k` distinct elements in random order (Python's `random.sample`).
fn sample<T: Clone>(rng: &mut ChaCha8Rng, from: &[T], k: usize) -> Vec<T> {
    from.choose_multiple(rng, k).cloned().collect()
}

fn pick<T: Copy>(rng: &mut ChaCha8Rng, from: &[T]) -> T {
    *from.choose(rng).expect("a non-empty choice")
}

/// The Cartesian product of the choices, the first varying slowest.
fn product<T: Clone>(choices: &[Vec<T>]) -> Vec<Vec<T>> {
    choices.iter().fold(vec![Vec::new()], |done, choice| {
        done.iter()
            .flat_map(|prefix| {
                choice.iter().map(move |item| {
                    let mut next = prefix.clone();
                    next.push(item.clone());
                    next
                })
            })
            .collect()
    })
}

/// The dressed cases of one random request the core with the test plug-ins accepts: four wallets,
/// each dressed. None when the core refuses the abstract request.
pub fn cases(rng: &mut ChaCha8Rng, max_queries: usize) -> Vec<Dressed> {
    let request = Abstract::draw(rng, max_queries);
    if !request.accepted(rng) {
        return Vec::new();
    }
    (0..4)
        .map(|_| {
            let wallet: Vec<AbstractCredential> = (0..rng.random_range(0..=3))
                .map(|k| AbstractCredential::draw(rng, k, &request.queries))
                .collect();
            dress(rng, &request, &wallet)
        })
        .collect()
}
