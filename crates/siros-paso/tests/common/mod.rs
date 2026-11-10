//! What the PaSO tests share: PaSO cards as the wallet registers them, entries as a Verifier
//! sends them, signed requests, the wallet's configuration, the Annex blocks of the PaSO
//! specifications, and PNG fixtures with their integrity values.

#![allow(dead_code)]

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use siros_i18n::Bidi;
use siros_i18n::{Context, Text};
use siros_openid4vp::ids::{CredentialId, DocumentKey, FormatId, LocaleTag};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Exclude;
use siros_openid4vp::request::Entry;
use siros_openid4vp::rows::{Choice, Env, Row, Value};
use siros_openid4vp::wallet::{Credential, Document, Facts, Holder};
use siros_paso::Rendered;
use siros_paso::labels::LabelLimits;
use siros_paso::outcome::Excluded;
use siros_paso::render::{Registered, TransactionView, ViewRow};
use siros_paso::rulebook::PasoType;
use siros_paso::rules::BindExcluded;
use siros_paso::value::ValueKind;
use siros_testkit::render::{ENGLISH_PASO, GERMAN_PASO, Language};
use siros_testkit::verifier;

/// The rule that excluded a credential, read from its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcludedBy {
    /// View §4: no locale completes the display.
    Locale,
    /// Core §6 and OpenID4VP B.2: the presentation cannot carry the SCA response claims.
    Carriage,
    /// Core §7.4.2 step 2: no entry renders for the credential.
    NoEntry,
}

impl ExcludedBy {
    /// The rule of an exclusion PaSO gave.
    pub fn of(exclude: &Exclude) -> Self {
        let rule: &dyn std::error::Error = exclude.rule();
        if rule.downcast_ref::<Excluded>().is_some() {
            return Self::Locale;
        }
        match rule.downcast_ref::<BindExcluded>() {
            Some(BindExcluded::Carriage) => Self::Carriage,
            Some(BindExcluded::NoEntry) => Self::NoEntry,
            None => panic!("no exclusion of PaSO's: {exclude}"),
        }
    }
}

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

/// The wallet's configuration: a priority list.
pub fn env(locales: &[&str]) -> Env {
    Env::new(
        locales
            .iter()
            .map(|tag| LocaleTag::parse(tag).expect("tag"))
            .collect(),
        Vec::new(),
        Choice::First,
    )
    .expect("env")
}

/// English.
pub fn en() -> Env {
    env(&["en"])
}

/// The language of the first tag of `env`'s list whose language the test app speaks, English
/// when it speaks none: the language a wallet presents in.
pub fn language(env: &Env) -> Language {
    env.priority()
        .iter()
        .find_map(|tag| {
            let primary = tag.as_str().split('-').next()?;
            Language::ALL
                .into_iter()
                .find(|language| language.tag().eq_ignore_ascii_case(primary))
        })
        .unwrap_or(Language::English)
}

/// The test app's context in `env`'s [`language`].
pub fn context(env: &Env) -> &'static Context {
    language(env).shared().expect("the test app's context")
}

/// The test app's wording of PaSO's amount: the number formatted in the currency.
const AMOUNT_FORMATTED: &str = "amount = {$value :currency currency=$currency}";
/// A wording of PaSO's amount as written: the number, a space, the code.
const AMOUNT_WRITTEN: &str = "amount = {$value} {$currency}";

thread_local! {
    /// The contexts of [`amounts_written`], English then German, loaded once per thread.
    static WRITTEN: [&'static Context; 2] = Language::ALL.map(|language| {
        let source = match language {
            Language::English => ENGLISH_PASO,
            Language::German => GERMAN_PASO,
        };
        assert!(source.contains(AMOUNT_FORMATTED), "the test app's amount wording");
        let context = language
            .sources()
            .into_iter()
            .map(|module| {
                if module == source {
                    module.replace(AMOUNT_FORMATTED, AMOUNT_WRITTEN)
                } else {
                    module.to_owned()
                }
            })
            .try_fold(Context::new().bidi(Bidi::None), |context, module| {
                context.module(&module)
            })
            .expect("the test app's sources");
        &*Box::leak(Box::new(context))
    });
}

/// The test app's context in `env`'s [`language`], its amounts worded as written: a wallet's
/// choice (View §3 MAY).
pub fn amounts_written(env: &Env) -> &'static Context {
    let at = match language(env) {
        Language::English => 0,
        Language::German => 1,
    };
    WRITTEN.with(|contexts| contexts[at])
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
        .json_spaced()
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

/// The source a type's metadata converts to for a priority list in a context; `None` for
/// metadata that does not convert, whose entries do not render.
pub fn converted(
    kind: &str,
    meta: &str,
    context: &Context,
    priority: &[LocaleTag],
) -> Option<String> {
    let given = Node::parse(meta).expect("the metadata");
    let registered = Registered::of(PasoType::parse(kind).ok()?, &given);
    siros_paso::view::convert(&registered, LabelLimits::PASO, context, priority).ok()
}

/// The wallet's `base` context with the source each type of each card's PaSO document converts
/// to, as the registration carries it.
pub fn registered(base: &Context, cards: &[&Card], env: &Env) -> Context {
    let mut context = base.clone();
    let mut loaded: Vec<String> = Vec::new();
    for card in cards {
        let node = siros_paso::document::PasoDocument::json(card.document.as_bytes())
            .expect("the document");
        let document = siros_paso::document::PasoDocument::read(&node).expect("the document");
        for (kind, meta) in document.types() {
            let meta = meta.json_compact().to_string();
            if let Some(source) = converted(kind.as_str(), &meta, &context, env.priority())
                && !loaded.contains(&source)
            {
                context = context.module(&source).expect("a converted source loads");
                loaded.push(source);
            }
        }
    }
    context
}

/// The matcher's context for a request: the [`registered`] context, with the sources of the
/// ad-hoc metadata the request's entries carry, read unverified (`siros_paso::view::carried`).
pub fn request_context(
    base: &Context,
    request: &siros_openid4vp::request::Request<'_>,
    cards: &[&Card],
    env: &Env,
) -> Context {
    let mut context = registered(base, cards, env);
    let read = siros_paso::adhoc::Carried::read(request).expect("a DC API request");
    for source in siros_paso::view::carried(&read, &context, env.priority())
        .expect("the carried metadata's sources load")
    {
        context = context.module(&source).expect("a carried source loads");
    }
    context
}

/// A text as plain text.
pub fn plain(text: &Text) -> String {
    text.to_string()
}

/// A row as [`Shown`] reads it; an image's value text is `<image>`.
pub fn row(row: &ViewRow) -> Shown {
    let value = row.row.value.as_ref().map(|value| {
        (
            row.kind.map_or("<none>", ValueKind::as_str),
            value.text().map_or_else(|| "<image>".to_owned(), plain),
        )
    });
    (
        plain(&row.row.label),
        value,
        row.row.section.as_ref().map(plain),
    )
}

/// The rows of a rendering, as [`Shown`] reads them.
pub fn rows(view: &TransactionView) -> Vec<Shown> {
    view.rows.iter().map(row).collect()
}

/// A rendering's title, confirm and deny actions, and hint.
pub fn actions(view: &TransactionView) -> (String, String, String, Option<String>) {
    (
        plain(&view.title),
        plain(&view.actions.confirm),
        plain(&view.actions.deny),
        view.actions.hint.as_ref().map(plain),
    )
}

/// A rendering's texts as plain text.
pub struct Seen {
    /// The rendering.
    pub rendered: Rendered,
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
        actions(&self.rendered.view)
    }

    /// The rows.
    pub fn rows(&self) -> Vec<Shown> {
        rows(&self.rendered.view)
    }

    /// The payment's merchant and amount.
    pub fn payment(&self) -> Option<(String, String)> {
        let (merchant, amount) = self.view.payment_texts()?;
        Some((plain(merchant), plain(amount)))
    }

    /// The rows' labels.
    pub fn labels(&self) -> Vec<String> {
        self.rows().into_iter().map(|row| row.0).collect()
    }
}

/// The value of a row, when it shows one.
pub fn value(row: &Row) -> Option<&Value> {
    row.value.as_ref()
}

/// The closure's result over the record phase 2 revalidates for the card's first selection: a
/// [`ProfileProbe`] of PaSO's profile in a registry over `host`, a probe format of the card's
/// identifier standing in for its plug-in, the resources fetched by `fetch`.
pub fn read_card_record<H, R>(
    request: &siros_openid4vp::request::Request<'_>,
    card: &Card,
    env: &Env,
    context: &Context,
    fetch: impl FnMut(&siros_openid4vp::effects::Resource) -> siros_openid4vp::effects::Fetch,
    host: &H,
    read: impl for<'a> FnOnce(siros_openid4vp::plugins::FetchedRecord<'a>, &'a H) -> R + 'static,
) -> R
where
    H: siros_openid4vp::host::CoreHost
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip>
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::RequestDecryption>
        + 'static,
    siros_paso::PasoProfile: siros_openid4vp::host::ProfileHost<H>,
    R: 'static,
{
    use siros_testkit::probe::{ProbeFormat, ProfileProbe, Selection, read_record};

    let credential = card.credential();
    let mut builder = siros_openid4vp::plugins::Registry::<H>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.client_prefix(siros_testkit::TestPrefix::Request);
    builder
        .format(ProbeFormat::new(card.format, placement(&credential.format)).expect("the format"));
    let handle = builder.profile(ProfileProbe(siros_paso::PasoProfile::default()));
    builder.prefix(
        siros_openid4vp::ids::TypePrefix::parse(siros_paso::rulebook::PASO).expect("the prefix"),
        handle,
    );
    let registry = builder.build().expect("the registry");
    let wallet = siros_openid4vp::wallet::Wallet::new(vec![credential]).expect("the wallet");
    read_record(
        Selection {
            request,
            wallet: &wallet,
            registry: &registry,
            env,
            context,
        },
        fetch,
        host,
        read,
    )
    .expect("the flow reaches the record's revalidation")
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
