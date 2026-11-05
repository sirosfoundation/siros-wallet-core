//! What the PaSO tests share: PaSO cards as the wallet registers them, entries as a Verifier
//! sends them, signed requests, the wallet's configuration, the Annex blocks of the PaSO
//! specifications, and PNG fixtures with their integrity values.

#![allow(dead_code)]

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use siros_explain::{Messages, ModuleId, Text};
use siros_i18n::{Declaration, Formatted, Module};
use siros_openid4vp::ids::{CredentialId, DocumentKey, FormatId, LocaleTag};
use siros_openid4vp::json::Node;
use siros_openid4vp::request::Entry;
use siros_openid4vp::rows::{Amounts, Choice, Env, RenderOptions, Row, Value};
use siros_openid4vp::wallet::{Credential, Document, Facts, Holder};
use siros_paso::Rendered;
use siros_paso::outcome::Outcome;
use siros_paso::render::{TransactionView, ViewRow};
use siros_paso::value::ValueKind;
use siros_testkit::fixtures::OPTIONS;
use siros_testkit::render::{App, CrateSource, GERMAN_PASO, compilers, main_module, main_sources};
use siros_testkit::verifier;

/// The Payment rulebook's type.
pub const PAY: &str = "urn:paso:sca:global:payment:1";
/// A type PaSO View's generic renderer renders.
pub const CUSTOM: &str = "urn:paso:sca:com.example:fixture:1";
/// The card's type.
pub const CARD_TYPE: &str = "https://bank.example/sca/card";
/// The Origin of every request.
pub const ORIGIN: &str = "https://verifier.example";

/// A credential the wallet registered with a PaSO document: its view, as a format plug-in reads
/// it, and the document `verifier::paso_document` writes from the issuer's signed metadata.
pub struct Card {
    /// The credential's id.
    pub id: &'static str,
    /// The format.
    pub format: &'static str,
    /// The format's view.
    pub view: String,
    /// The PaSO document.
    pub document: String,
    /// Whether it is bound to a key.
    pub holder: Holder,
}

impl Card {
    /// A card of a format whose metadata lists `types` (a JSON object of type to metadata),
    /// with the risk signal encryption keys and the issuer given.
    pub fn new(format: &'static str, types: &str, keys: Option<&str>, issuer: &str) -> Self {
        Self {
            id: "card",
            format,
            view: r#"{"answers":["q"],"alg":"A"}"#.to_owned(),
            document: verifier::paso_document(CARD_TYPE, format, types, keys, issuer)
                .expect("the document"),
            holder: Holder::Bound,
        }
    }

    /// An SD-JWT VC card of the issuer with a key set.
    pub fn sd_jwt(types: &str) -> Self {
        Self::new("dc+sd-jwt", types, None, verifier::ISSUER)
    }

    /// The credential as the registration holds it.
    pub fn credential(&self) -> Credential<'_> {
        Credential::new(
            CredentialId::parse(self.id).expect("id"),
            FormatId::parse(self.format).expect("format"),
            self.view.as_bytes(),
            vec![Document {
                key: DocumentKey::parse("paso").expect("key"),
                content: self.document.as_bytes(),
            }],
            Facts::new(self.holder, Vec::new()).expect("facts"),
        )
        .expect("credential")
    }

    /// The document's integrity value.
    pub fn integrity(&self) -> String {
        let document: Json = serde_json::from_str(&self.document).expect("document");
        document["integrity"]
            .as_str()
            .expect("integrity")
            .to_owned()
    }
}

/// An entry as the Verifier encodes it, decoded as the wallet receives it.
pub fn entry(json: &str) -> Entry<'static> {
    Entry::decode(Cow::Owned(verifier::encode(json).expect("entry"))).expect("decodes")
}

/// The wallet's configuration: a priority list and an amounts mode.
pub fn env(locales: &[&str], amounts: Amounts) -> Env {
    Env::new(
        locales
            .iter()
            .map(|tag| LocaleTag::parse(tag).expect("tag"))
            .collect(),
        Vec::new(),
        RenderOptions { amounts, ..OPTIONS },
        Vec::new(),
        Choice::First,
    )
    .expect("env")
}

/// English, amounts formatted.
pub fn en() -> Env {
    env(&["en"], Amounts::Formatted)
}

/// Signed request parameters: `dc_api`, the model's nonce, the DCQL query, the entries
/// encoded, `expected_origins` holding the Origin, then `extra` members.
pub fn parameters(dcql: &str, entries: &[&str], extra: &str) -> String {
    let encoded: Vec<String> = entries
        .iter()
        .map(|e| format!("\"{}\"", verifier::encode(e).expect("entry")))
        .collect();
    let transaction_data = if entries.is_empty() {
        String::new()
    } else {
        format!(",\"transaction_data\":[{}]", encoded.join(","))
    };
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(",{extra}")
    };
    format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n-0S6_WzA2Mj","dcql_query":{dcql}{transaction_data},"expected_origins":["{ORIGIN}"]{extra}}}"#
    )
}

/// One query `q` of a format.
pub fn one_query(format: &str) -> String {
    format!(r#"{{"credentials":[{{"id":"q","format":"{format}"}}]}}"#)
}

/// The ```json blocks of a PaSO Annex section (`### A.n`) as written in the specification file
/// of `tests/data/paso-d2`: object members keep their order.
pub fn annex(file: &str, section: &str) -> Vec<String> {
    let path = format!("{}/tests/data/paso-d2/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).expect("the specification file");
    let start = text
        .find(&format!("### {section} "))
        .or_else(|| text.find(&format!("### {section}\n")))
        .expect("the section");
    let body = &text[start + 4..];
    let end = body.find("\n### ").unwrap_or(body.len());
    body[..end]
        .split("```json\n")
        .skip(1)
        .map(|block| block[..block.find("```").expect("a closing fence")].to_owned())
        .collect()
}

/// A member of a JSON text, written back with its members in their order.
pub fn member(json: &str, name: &str) -> String {
    let node = Node::parse(json).expect("JSON");
    node.get(name)
        .expect("the member")
        .python_text()
        .to_string()
}

/// The section of a PaSO specification file from a heading to the next heading.
pub fn section(file: &str, heading: &str) -> String {
    let path = format!("{}/tests/data/paso-d2/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).expect("the specification file");
    let start = text.find(&format!("{heading}\n")).expect("the heading");
    let rest = &text[start + heading.len() + 1..];
    let end = rest
        .match_indices('\n')
        .find(|(k, _)| rest[k + 1..].starts_with('#'))
        .map_or(rest.len(), |(k, _)| k);
    rest[..end].to_owned()
}

/// The markdown tables of a text, each as rows of cells, the header first, code ticks dropped.
pub fn tables(text: &str) -> Vec<Vec<Vec<String>>> {
    let mut out = Vec::new();
    let mut current: Vec<Vec<String>> = Vec::new();
    for line in text.lines().chain([""]) {
        if line.starts_with('|') {
            let cells: Vec<String> = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .collect();
            if !cells
                .iter()
                .all(|c| c.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
            {
                current.push(cells);
            }
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    out
}

/// A PNG of a size: the signature, an IHDR chunk, an empty IDAT and IEND, each with its CRC.
pub fn png(width: u32, height: u32) -> Vec<u8> {
    let chunk = |kind: &[u8], data: &[u8]| {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
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

/// W3C SRI integrity metadata with sha256, computed here.
pub fn sri(content: &[u8]) -> String {
    format!("sha256-{}", STANDARD.encode(Sha256::digest(content)))
}

/// A Data URL of a PNG.
pub fn data_png(width: u32, height: u32) -> String {
    format!(
        "data:image/png;base64,{}",
        STANDARD.encode(png(width, height))
    )
}

/// A row as the examples state it: the label's text, the value's kind and text, the section.
pub type Shown = (String, Option<(&'static str, String)>, Option<String>);

/// A label and a value of a kind.
pub fn shown(label: &str, value: Option<(&'static str, &str)>) -> Shown {
    (
        label.to_owned(),
        value.map(|(kind, text)| (kind, text.to_owned())),
        None,
    )
}

/// The profile's module as the test app loads it.
pub fn paso_module() -> CrateSource {
    CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: siros_paso::CrateModule::ENGLISH,
        german: GERMAN_PASO,
    }
}

/// The module a type's metadata converts to, over the test app's main module.
pub fn defined(kind: &str, meta: &str) -> Module {
    let given = Node::parse(meta).expect("the metadata");
    let [en, de] = main_sources();
    let converted = siros_paso::view::convert(kind, &given, &[&en, &de]).expect("converts");
    let sources: Vec<&str> = converted
        .sources
        .entries()
        .iter()
        .map(|entry| entry.value().as_str())
        .collect();
    Module::load(
        ModuleId::Defined(converted.module),
        &Declaration::defined(converted.declaration).expect("a declaration"),
        &sources,
        converted.policy,
        &compilers().expect("compilers"),
    )
    .expect("the converted module loads")
}

/// The test app of a type's renderings in an `Env`: the main module, the core's and the
/// profile's modules, and the module the type's metadata converts to.
pub struct Screen {
    app: App,
    env: Env,
}

impl Screen {
    /// The screen of a type whose metadata the card gives as `meta`.
    pub fn of(kind: &str, meta: &str, env: &Env) -> Self {
        let modules = [
            main_module().expect("the main module"),
            CrateSource::openid4vp().load().expect("the core's module"),
            paso_module().load().expect("the profile's module"),
            defined(kind, meta),
        ];
        Self {
            app: App::new(&modules.iter().collect::<Vec<_>>()).expect("the package"),
            env: env.clone(),
        }
    }

    /// A text as plain text.
    pub fn plain(&self, text: &Text) -> String {
        self.app.plain(&self.env, text).expect("the text renders")
    }

    /// A text as formatted text.
    pub fn formatted(&self, text: &Text) -> Formatted {
        self.app
            .formatted(&self.env, text)
            .expect("the text renders")
    }

    /// A row as [`Shown`] reads it; an image's value text is `<image>`.
    pub fn row(&self, row: &ViewRow) -> Shown {
        let value = row.row.value.as_ref().map(|value| {
            (
                row.kind.map_or("<none>", ValueKind::as_str),
                value
                    .text()
                    .map_or_else(|| "<image>".to_owned(), |text| self.plain(text)),
            )
        });
        (
            self.plain(&row.row.label),
            value,
            row.row.section.as_ref().map(|section| self.plain(section)),
        )
    }

    /// The rows of a rendering, as [`Shown`] reads them.
    pub fn rows(&self, view: &TransactionView) -> Vec<Shown> {
        view.rows.iter().map(|row| self.row(row)).collect()
    }

    /// A rendering's title, confirm and deny actions, and hint.
    pub fn actions(&self, view: &TransactionView) -> (String, String, String, Option<String>) {
        (
            self.plain(&view.title),
            self.plain(&view.actions.confirm),
            self.plain(&view.actions.deny),
            view.actions.hint.as_ref().map(|hint| self.plain(hint)),
        )
    }
}

/// A rendering and the test app's screen of its type, which renders its texts.
pub struct Seen {
    /// The rendering.
    pub rendered: Rendered,
    /// The screen of its type.
    pub screen: Screen,
}

impl std::ops::Deref for Seen {
    type Target = Rendered;

    fn deref(&self) -> &Rendered {
        &self.rendered
    }
}

impl Seen {
    /// The title, the confirm and deny actions, the hint.
    pub fn text(&self) -> (String, String, String, Option<String>) {
        self.screen.actions(&self.rendered.view)
    }

    /// The rows.
    pub fn rows(&self) -> Vec<Shown> {
        self.screen.rows(&self.rendered.view)
    }

    /// A text of the rendering.
    pub fn plain(&self, text: &Text) -> String {
        self.screen.plain(text)
    }

    /// The payment's merchant and amount.
    pub fn payment(&self) -> Option<(String, String)> {
        let (merchant, amount) = self.view.payment_texts()?;
        Some((self.plain(merchant), self.plain(amount)))
    }

    /// The rows' labels.
    pub fn labels(&self) -> Vec<String> {
        self.rows().into_iter().map(|row| row.0).collect()
    }
}

impl Seen {
    /// A text of the rendering, formatted.
    pub fn formatted(&self, text: &Text) -> Formatted {
        self.screen.formatted(text)
    }
}

/// The outcome's kind and clause, the model's way of naming the rule that decided it.
pub fn outcome(rendered: &Result<Rendered, Outcome>) -> String {
    match rendered {
        Ok(_) => "Rendered".to_owned(),
        Err(Outcome::Unsupported(rule)) => format!("Unsupported [{}]", rule.clause()),
        Err(Outcome::NotCompatible(rule)) => format!("NotCompatible [{}]", rule.clause()),
        Err(Outcome::Excluded(rule)) => format!("Excluded [{}]", rule.clause()),
    }
}

/// The value of a row, when it shows one.
pub fn value(row: &Row) -> Option<&Value> {
    row.value.as_ref()
}

/// What the registration view gains for a card: a [`Card`]'s view is the test format's, which
/// states no type.
pub fn additions<'c>(
    credential: &'c siros_openid4vp::wallet::Credential<'c>,
) -> Box<dyn siros_openid4vp::plugins::ViewAdditions + 'c> {
    use siros_openid4vp::plugins::Format;
    siros_testkit::TestFormat::new()
        .expect("the test format")
        .additions(credential)
        .expect("the view's additions")
}

/// The placement the plug-in of `format` states: siros-mdoc's, siros-sdjwt's or the test
/// format's; `None` for another format.
pub fn placement(
    format: &siros_openid4vp::ids::FormatId<'_>,
) -> Option<siros_openid4vp::wallet_metadata::Placement> {
    let mdoc = siros_mdoc::Mdoc::new().expect("the mdoc plug-in");
    let sd_jwt = siros_sdjwt::SdJwtVc::new().expect("the SD-JWT VC plug-in");
    let test = siros_testkit::TestFormat::new().expect("the test format");
    siros_testkit::fixtures::placement(&[&mdoc, &sd_jwt, &test], format)
}
