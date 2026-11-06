//! check_props.py's `dress`: the abstract run dressed with the real formats and profiles.

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use serde_json::{Value, json};
use siros_explain::Text;
use siros_openid4vp::arrival::{DcApiProtocol, Received};
use siros_openid4vp::consent::Card;
use siros_openid4vp::ids::LocaleTag;
use siros_openid4vp::matching::StaticEntry;
use siros_openid4vp::rows::{Amounts, Choice, Env, Icon, ImageMedia, RenderOptions, Row};
use siros_openid4vp::wallet::Holder;
use siros_testkit::fixtures::{self, Held, OPTIONS, ORIGIN, with_generic_forms};
use siros_testkit::verifier::{self, ISSUER};
use std::borrow::Cow;
use std::num::NonZeroU32;

use super::payloads::{adhoc, payload, qes_body, tx_metadata};
use super::random::{Abstract, AbstractCredential, AbstractQuery, parameters};
use super::{
    ENC_KEY, FORMATS, LOGOS, MDOC_TYPE, Obj, QUALIFIERS, SD_JWT_TYPE, TYPE_POOL, pick, sample,
    string,
};

/// A dressed case: the request as received, the wallet, its configuration and static entries, and
/// the credentials the host says can no longer be presented.
pub struct Dressed {
    /// The DC API protocol.
    pub protocol: DcApiProtocol,
    /// The DC API `data`: the parameters, or the test Verifier's JWS over them.
    pub data: String,
    /// The request parameters.
    pub parameters: String,
    /// The credentials as the wallet registers them.
    pub credentials: Vec<Held>,
    /// The wallet's configuration.
    pub env: Env,
    /// The wallet's static entries.
    pub statics: Vec<StaticEntry>,
    /// The credentials no longer valid.
    pub unusable: Vec<String>,
}

impl Dressed {
    /// The request as the DC API delivers it.
    pub fn received(&self) -> Received<'_> {
        fixtures::received(self.protocol, &self.data).expect("a dressed request arrives")
    }
}

/// A display array: one entry per locale, sometimes a default entry (`entries_for`).
pub(super) fn entries_for(
    rng: &mut ChaCha8Rng,
    locales: &[&str],
    mut make: impl FnMut(&mut ChaCha8Rng, Option<&str>) -> Value,
) -> Value {
    let mut out: Vec<Value> = locales
        .iter()
        .map(|locale| {
            let mut entry = make(rng, Some(locale));
            entry["locale"] = json!(locale);
            entry
        })
        .collect();
    if out.is_empty() || rng.random_bool(0.25) {
        out.push(make(rng, None));
    }
    Value::Array(out)
}

/// Python's `str` of an optional locale.
pub(super) fn shown(locale: Option<&str>) -> &str {
    locale.unwrap_or("None")
}

/// The format's members for an abstract query: its options become `claim_sets` over four items
/// (`query_body`).
pub(super) fn query_body(query: &AbstractQuery, format: &str) -> Value {
    let options = &query.options;
    let (meta, paths) = claims_layout(format);
    let claims: Vec<Value> = paths
        .iter()
        .enumerate()
        .map(|(i, path)| json!({"id": format!("k{i}"), "path": path}))
        .collect();
    let mut body = json!({"meta": meta, "claims": claims});
    if !options.is_empty() {
        body["claim_sets"] = json!(
            options
                .iter()
                .map(|o| o.iter().map(|i| format!("k{i}")).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
    }
    body
}

/// A claims format's `meta` and its four claims' paths.
pub(super) fn claims_layout(format: &str) -> (Value, [Vec<&'static str>; 4]) {
    if format == "dc+sd-jwt" {
        (
            json!({"vct_values": [SD_JWT_TYPE]}),
            [vec!["c0"], vec!["c1"], vec!["grp", "c2"], vec!["list"]],
        )
    } else {
        (
            json!({"doctype_value": MDOC_TYPE}),
            [
                vec!["ns", "c0"],
                vec!["ns", "c1"],
                vec!["ns", "c2"],
                vec!["ns2", "c3"],
            ],
        )
    }
}

/// A card's display metadata and claims, and its values (`card_and_claims`).
pub(super) fn card_and_claims(rng: &mut ChaCha8Rng, id: &str) -> (Value, Value) {
    let count = rng.random_range(0..=2);
    let locales = sample(rng, &["en", "de", "en-US", "de-DE"], count);
    let display = entries_for(rng, &locales, |rng, locale| {
        json!({"name": format!("Card {id} {}", locale.unwrap_or("default")),
               "logo": {"uri": pick(rng, &LOGOS)},
               "rendering": {"simple": {"logo": {"uri": pick(rng, &LOGOS)}}}})
    });
    let paths: [&[&str]; 8] = [
        &["c0"],
        &["c1"],
        &["grp", "c2"],
        &["list"],
        &["ns", "c0"],
        &["ns", "c1"],
        &["ns", "c2"],
        &["ns2", "c3"],
    ];
    let claims: Vec<Value> = paths
        .iter()
        .map(|path| {
            let mut claim = json!({"path": path});
            if rng.random_bool(0.8) {
                let last = path[path.len() - 1];
                claim["display"] = entries_for(rng, &locales, |_, locale| {
                    let text = format!("{last} {}", shown(locale));
                    json!({"name": text, "label": text})
                });
            }
            claim
        })
        .collect();
    let mut values = serde_json::Map::new();
    for (name, value) in [
        ("c0", json!("v0")),
        ("c1", json!(true)),
        ("grp", json!({"c2": "v2"})),
        ("list", json!(["a", "b"])),
        ("ns", json!({"c0": "m0", "c1": "m1", "c2": 7})),
        ("ns2", json!({"c3": "m3"})),
    ] {
        if !rng.random_bool(0.15) {
            drop(values.insert(name.to_owned(), value));
        }
    }
    (
        json!({"display": display, "claims": claims}),
        Value::Object(values),
    )
}

/// `ui_labels` with each label sometimes (`ui`).
pub(super) fn ui(rng: &mut ChaCha8Rng, locales: &[&str], title: &str, confirm: &str) -> Value {
    let mut out = serde_json::Map::new();
    let mut label = |rng: &mut ChaCha8Rng, key: &str, probability: f64, prefix: &str| {
        if rng.random_bool(probability) {
            let array = entries_for(
                rng,
                locales,
                |_, locale| json!({"value": format!("{prefix} {}", shown(locale))}),
            );
            drop(out.insert(key.to_owned(), array));
        }
    };
    label(rng, "transaction_title", 0.7, title);
    label(rng, "affirmative_action_label", 0.7, confirm);
    label(rng, "denial_action_label", 0.3, "No");
    label(rng, "security_hint", 0.4, "Check the payee");
    Value::Object(out)
}

/// The wallet's icons for the first two logos.
pub(super) fn icons() -> Vec<(String, Icon)> {
    LOGOS[..2]
        .iter()
        .zip(700..)
        .map(|(uri, size)| {
            (
                (*uri).to_owned(),
                Icon {
                    reference: siros_openid4vp::rows::IconReference::Logo(Cow::Borrowed(uri)),
                    media: ImageMedia::PNG,
                    size: NonZeroU32::new(size).expect("a size"),
                },
            )
        })
        .collect()
}

/// A static entry the wallet adds to every set.
pub(super) fn static_entry(k: usize) -> StaticEntry {
    StaticEntry {
        id: siros_openid4vp::ids::StaticEntryId::parse(format!("static:{k}"))
            .expect("a static entry id"),
        card: Card {
            icon: Icon {
                reference: siros_openid4vp::rows::IconReference::Asset(Cow::Borrowed(
                    "wallet:warning",
                )),
                media: ImageMedia::PNG,
                size: NonZeroU32::new(1024).expect("a size"),
            },
            title: Text::Raw(format!("Notice {k}")),
            subtitle: None,
            rows: vec![Row::full_text(Text::Raw(format!("Wallet notice {k}")))],
        },
    }
}

/// One credential of the abstract wallet dressed: a format among those of the queries it answers,
/// its card, its PaSO metadata for the types it supports, its QES qualifiers.
pub(super) fn dress_credential(
    rng: &mut ChaCha8Rng,
    credential: &AbstractCredential,
    formats: &[(String, &'static str)],
    types: &[(&'static str, &'static str)],
) -> Held {
    let answering: Vec<&str> = credential
        .answers
        .iter()
        .filter_map(|q| formats.iter().find(|(id, _)| id == q).map(|(_, f)| *f))
        .filter(|format| FORMATS.contains(format))
        .collect();
    let format = if answering.is_empty() {
        pick(rng, &FORMATS)
    } else {
        pick(rng, &answering)
    };
    let (meta, values) = card_and_claims(rng, &credential.id);
    let mut supported: Vec<&str> = credential
        .supports
        .iter()
        .filter_map(|t| types.iter().find(|(abstract_type, _)| abstract_type == t))
        .map(|(_, real)| *real)
        .collect();
    supported.sort_unstable();
    let mut tts = serde_json::Map::new();
    let mut qualifiers = Vec::new();
    for kind in supported {
        if kind == siros_qes::TYPE {
            let count = rng.random_range(1..=2);
            qualifiers = sample(rng, &QUALIFIERS, count);
            continue;
        }
        match tx_metadata(rng, kind) {
            Some(meta) => drop(tts.insert(kind.to_owned(), meta)),
            None if kind.contains(":mandate:") => drop(tts.insert(kind.to_owned(), json!({}))),
            None => {}
        }
    }
    let alg = pick(rng, &["ES256", "EdDSA"]);
    let curve = if alg == "EdDSA" { "Ed25519" } else { "P-256" };
    let view = json!({"type": if format == "dc+sd-jwt" { SD_JWT_TYPE } else { MDOC_TYPE }, "metadata": meta,
           "values": values, "issuer": if rng.random_bool(0.5) { Value::Null } else { json!("Issuer") },
           "key_authorizations": {
               "namespaces": if rng.random_bool(0.9) { json!(["urn:paso:sca:1"]) } else { json!([]) },
               "elements": if rng.random_bool(0.9) { json!({"org.cloudsignatureconsortium.dm.1": ["qesApproval"]}) } else { json!({}) }},
           "jwt": format!("eyJhbGciOiJFUzI1NiJ9.{}.sig", credential.id), "alg": alg, "curve": curve,
           "key_alg": "ES256", "key_curve": "P-256", "issuer_alg": pick(rng, &[-7, -35]), "issuer_curve": "P-256",
           "device_alg": -7, "device_curve": "P-256"});
    let keys = rng
        .random_bool(0.6)
        .then(|| format!(r#"{{"keys": [{ENC_KEY}]}}"#));
    let card_type = if format == "dc+sd-jwt" {
        SD_JWT_TYPE
    } else {
        MDOC_TYPE
    };
    let mut documents = vec![(
        "paso".to_owned(),
        verifier::paso_document(
            card_type,
            format,
            &Value::Object(tts).to_string(),
            keys.as_deref(),
            ISSUER,
        )
        .expect("a PaSO document")
        .into_bytes(),
    )];
    if !qualifiers.is_empty() {
        documents.push((
            "qes".to_owned(),
            json!({"signature_qualifiers": qualifiers})
                .to_string()
                .into_bytes(),
        ));
    }
    let mut held = Held::new(&credential.id, format, view.to_string());
    if format == "mso_mdoc" {
        held = held.with_issued().expect("the IssuerSigned");
    }
    held.documents.extend(documents);
    held.holder = if rng.random_bool(0.9) {
        Holder::Bound
    } else {
        Holder::Unbound
    };
    if rng.random_bool(0.5) {
        held.authorities = vec![("aki".to_owned(), vec!["k1".to_owned()])];
    }
    held
}

/// The Verifier's client metadata: sometimes its algorithms, sometimes keys the wallet can and
/// cannot encrypt to, with content encryptions.
pub(super) fn client_metadata(rng: &mut ChaCha8Rng) -> Value {
    let mut metadata = json!({});
    if rng.random_bool(0.3) {
        let count = rng.random_range(1..=2);
        let sd_jwt = sample(rng, &["ES256", "Ed25519"], count);
        let count = rng.random_range(1..=2);
        let issuer = sample(rng, &[-7, -9, -35], count);
        let device = pick(rng, &[&[-9][..], &[-65537], &[-7, -65537], &[-65538]]);
        metadata["vp_formats_supported"] = json!({
            "dc+sd-jwt": {"sd-jwt_alg_values": sd_jwt},
            "mso_mdoc": {"issuerauth_alg_values": issuer, "deviceauth_alg_values": device}});
    }
    if rng.random_bool(0.3) {
        let enc: Value = serde_json::from_str(ENC_KEY).expect("the key");
        let mut verifier_enc = enc.clone();
        verifier_enc["kid"] = json!("verifier-enc");
        let mut p384 = enc;
        p384["kid"] = json!("verifier-p384");
        p384["crv"] = json!("P-384");
        p384["alg"] = json!("ECDH-ES+A128KW");
        let keys = [
            json!({"kty": "RSA", "kid": "r", "n": "n", "e": "AQAB"}),
            json!({"kty": "OKP", "crv": "X25519", "kid": "x", "x": "AA"}),
            verifier_enc,
            p384,
        ];
        let count = rng.random_range(1..=3);
        metadata["jwks"] = json!({"keys": sample(rng, &keys, count)});
        if rng.random_bool(0.5) {
            metadata["encrypted_response_enc_values_supported"] = json!(pick(
                rng,
                &[
                    &["A256GCM", "A128GCM"][..],
                    &["A128CBC-HS256", "A128GCM"],
                    &["XC20P"]
                ]
            ));
        }
    }
    metadata
}

/// The request dressed: each query a real format, each entry a real type, the Verifier signed
/// mostly, sometimes stating its algorithms or asking for an encrypted response.
pub(super) fn dress(
    rng: &mut ChaCha8Rng,
    request: &Abstract,
    wallet: &[AbstractCredential],
) -> Dressed {
    let real = sample(rng, &TYPE_POOL, 2);
    let types = [
        ("t1", real[0]),
        ("t2", real[1]),
        ("t9", "urn:example:unknown:1"),
    ];
    let count = rng.random_range(1..=2);
    let locales: Vec<LocaleTag> = sample(rng, &["en", "de", "en-US", "de-CH"], count)
        .into_iter()
        .map(|tag| LocaleTag::parse(tag).expect("a tag"))
        .collect();
    let amounts = if rng.random_bool(0.5) {
        Amounts::Formatted
    } else {
        Amounts::Written
    };
    let env = Env::new(
        with_generic_forms(&locales),
        Vec::new(),
        RenderOptions { amounts, ..OPTIONS },
        icons(),
        Choice::First,
    )
    .expect("the configuration");
    let formats: Vec<(String, &'static str)> = request
        .queries
        .iter()
        .map(|q| {
            let format = if q.registered {
                pick(rng, &FORMATS)
            } else {
                "x-unregistered"
            };
            (q.id.clone(), format)
        })
        .collect();
    let queries: Vec<String> = request
        .queries
        .iter()
        .zip(&formats)
        .map(|(q, (_, format))| {
            let body = if FORMATS.contains(format) {
                query_body(q, format)
            } else {
                json!({})
            };
            let mut object = Obj::default()
                .with("id", string(&q.id))
                .with("format", string(format))
                .with("multiple", q.multiple.to_string())
                .with(
                    "require_cryptographic_holder_binding",
                    q.holder_binding.to_string(),
                );
            if rng.random_bool(0.1) {
                object.put(
                    "trusted_authorities",
                    r#"[{"type": "aki", "values": ["k1"]}]"#,
                );
            }
            for (name, value) in body.as_object().expect("a body") {
                object.put(name, value.to_string());
            }
            object.text()
        })
        .collect();
    let entries: Vec<String> = request
        .entries
        .iter()
        .map(|e| {
            let kind = types
                .iter()
                .find(|(abstract_type, _)| *abstract_type == e.kind)
                .map(|(_, real)| *real)
                .expect("a mapped type");
            let mut entry = Obj::default()
                .with("type", string(kind))
                .with("credential_ids", json!(e.credential_ids).to_string());
            if kind == siros_qes::TYPE {
                qes_body(rng, &mut entry);
            } else {
                entry.put("payload", payload(rng, kind));
            }
            if kind.starts_with("urn:paso:sca:") && rng.random_bool(0.15) {
                entry.put("metadata", string(&adhoc(rng, kind)));
            }
            if kind.starts_with("urn:paso:sca:") && rng.random_bool(0.03) {
                // A member PaSO does not define.
                entry.put("transaction_data_hashes_alg", r#"["sha-256"]"#);
            }
            verifier::encode(&entry.text()).expect("an entry")
        })
        .collect();
    let credentials: Vec<Held> = wallet
        .iter()
        .map(|credential| dress_credential(rng, credential, &formats, &types))
        .collect();
    let statics = (0..pick(rng, &[0, 0, 1, 2])).map(static_entry).collect();
    let metadata = client_metadata(rng);
    let unusable = credentials
        .iter()
        .filter(|_| rng.random_bool(0.1))
        .map(|held| held.id.clone())
        .collect();
    let signed = rng.random_bool(0.9);
    let expected_origins: Option<&[&str]> = signed.then(|| {
        if rng.random_bool(0.97) {
            &[ORIGIN][..]
        } else {
            &["https://elsewhere.example"][..]
        }
    });
    let response_mode = if metadata.get("jwks").is_some() && rng.random_bool(0.7) {
        "dc_api.jwt"
    } else {
        "dc_api"
    };
    let parameters = parameters(
        &queries,
        request.sets.as_deref(),
        &entries,
        response_mode,
        &metadata.to_string(),
        expected_origins,
    );
    let (protocol, data) = if signed {
        let data = fixtures::signed_data(&parameters).expect("the test Verifier signs");
        (DcApiProtocol::Signed, data)
    } else {
        (DcApiProtocol::Unsigned, parameters.clone())
    };
    Dressed {
        protocol,
        data,
        parameters,
        credentials,
        env,
        statics,
        unusable,
    }
}
