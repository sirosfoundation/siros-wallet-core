//! What the tests share: the HAIP and WE BUILD builds' hosts and registries, W3C SRI written from
//! its definition, and the test app's context of a presentation: the testkit's sources in the
//! wallet's language, with the View sources the PaSO and TS12 metadata of the wallet's
//! credentials and of the request convert to.

#![allow(dead_code, reason = "each test binary uses a part")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use siros_i18n::{Bidi, Context, LocaleTag};
use siros_mdoc::{DeviceMac, Mdoc, TestDeviceMac};
use siros_openid4vp::envelope::Channel;
use siros_openid4vp::hash::Sha2;
use siros_openid4vp::host::{Haip, Platform, RequestDecryption, Timestamp};
use siros_openid4vp::json::Node;
use siros_openid4vp::modes::{DcApiJwt, DirectPost, DirectPostJwt};
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::request::Request;
use siros_openid4vp::routing::VpToken;
use siros_openid4vp::rows::Env;
use siros_openid4vp::uri::{EncryptedRequests, RequestPost};
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::{Carried, Verified};
use siros_paso::document::PasoDocument;
use siros_paso::labels::LabelLimits;
use siros_paso::render::Registered;
use siros_paso::view::ConvertError;
use siros_paso::{
    CoseEncrypt, IssuerTrust, Paso, PasoProfile, RandomIds, RootCertificate, TestCoseEncrypt,
    TestIssuerTrust, TestPaso, TestRandomIds,
};
use siros_qes::QesProfile;
use siros_sdjwt::SdJwtVc;
use siros_syntax::AllOf;
use siros_testkit::render::{ENGLISH_PASO, GERMAN_PASO, Language};
use siros_testkit::{TestHaip, TestPlatform, TestRequestDecryption};
use siros_ts12::{AttestationType, Ts12Document, Ts12Profile, Ts12Type};

siros_testkit::test_host! {
    /// The HAIP build's host: every module, each a test double.
    #[derive(Debug, Clone, Default)]
    pub struct HaipHost {
        handles {
            platform: TestPlatform => Platform,
            paso: TestPaso => Paso,
            random_ids: TestRandomIds => RandomIds,
            issuer_trust: TestIssuerTrust => IssuerTrust
        }
        zero_sized {
            TestHaip => Haip,
            TestRequestDecryption => RequestDecryption
        }
        optional { TestCoseEncrypt => CoseEncrypt, TestDeviceMac => DeviceMac }
        lacks {}
    }
}

siros_testkit::test_host! {
    /// The WE BUILD build's host: no `CoseEncrypt` and no `DeviceMac` (section 4.10.4).
    #[derive(Debug, Clone, Default)]
    pub struct WeBuildHost {
        handles {
            platform: TestPlatform => Platform,
            paso: TestPaso => Paso,
            random_ids: TestRandomIds => RandomIds,
            issuer_trust: TestIssuerTrust => IssuerTrust
        }
        zero_sized {
            TestHaip => Haip,
            TestRequestDecryption => RequestDecryption
        }
        optional {}
        lacks { CoseEncrypt }
    }
}

/// CS-12 §7.1 item 2: the three base types.
const WE_BUILD_TYPES: [AttestationType; 3] = [
    siros_syntax::checked!(
        AttestationType,
        "https://webuildconsortium.eu/sca/sca-iban/1.0"
    ),
    siros_syntax::checked!(
        AttestationType,
        "https://webuildconsortium.eu/sca/sca-user/1.0"
    ),
    siros_syntax::checked!(
        AttestationType,
        "https://webuildconsortium.eu/sca/sca-card-dpc/1.0"
    ),
];

/// The WE BUILD build's registry (section 4.10.4): SD-JWT VC, `x509_hash` alone, siros-paso and
/// siros-ts12, CS-02's rule and answer reader, `direct_post.jwt`, `direct_post`'s errors and `dc_api.jwt`,
/// the POST of `wallet_metadata` with encrypted Request Objects, `Sha2`.
pub fn we_build_registry() -> Result<Registry<WeBuildHost>, String> {
    let mut builder = Registry::<WeBuildHost>::builder();
    builder.hash(Sha2::Sha256);
    builder.response_type(VpToken);
    builder.jwe_mode(DirectPostJwt);
    builder.error_mode(DirectPostJwt);
    builder.error_mode(DirectPost);
    builder.jwe_mode(DcApiJwt);
    builder.request_post(RequestPost);
    builder.request_encryption(EncryptedRequests);
    builder.format(SdJwtVc::new().map_err(|e| e.to_string())?);
    builder.client_prefix(siros_x509::X509Hash);
    PasoProfile::default()
        .register(&mut builder)
        .map(drop)
        .map_err(|e| e.to_string())?;
    let types = AllOf::new(WE_BUILD_TYPES.to_vec()).ok_or("the three base types")?;
    Ts12Profile::new(types).register(&mut builder);
    builder.object_rule(siros_webuild::Cs02Claims);
    builder.answer_reader(siros_webuild::Cs02ErrorAnswer);
    builder.build().map_err(|e| e.to_string())
}

/// The test app's context as a WE BUILD wallet registers its credentials for `env`'s priority
/// list: its [`own_modules`] and the source each type of each credential's TS12 document
/// converts to.
pub fn we_build_app(wallet: &Wallet<'_>, env: &Env, amounts: Amounts) -> Context {
    let own = own_modules(env, amounts);
    let mut sources: Vec<String> = Vec::new();
    for credential in wallet.credentials() {
        let Some(bytes) = credential.document(siros_ts12::DOCUMENT.as_str()) else {
            continue;
        };
        let text = std::str::from_utf8(bytes).expect("UTF-8");
        let node = Node::parse(text).expect("a TS12 document");
        let document = Ts12Document::read(&node).expect("a TS12 document");
        for kind in [Ts12Type::Payment, Ts12Type::LoginRisk] {
            let Some(entry) = document.listed(kind) else {
                continue;
            };
            let built_in = entry.built_in().expect("a built-in type");
            sources.push(
                siros_ts12::view::convert(&built_in, own, env.priority()).expect("the source"),
            );
        }
    }
    loaded(own, sources)
}

impl HaipHost {
    /// The host whose platform and PaSO module both read the clock at `now`, its trust store
    /// siros-x509's test root.
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
            paso: TestPaso::at(now),
            random_ids: TestRandomIds::default(),
            issuer_trust: TestIssuerTrust {
                roots: vec![
                    RootCertificate::parse(&siros_testkit::x509::root().expect("the root"))
                        .expect("a certificate"),
                ],
            },
        }
    }
}

/// The real registry: the SD-JWT VC and mdoc formats, PaSO under `urn:paso:sca:`, QES
/// for its type, the test Verifier's Client Identifier Prefix and siros-x509's two.
pub fn registry() -> Result<Registry<HaipHost>, String> {
    registry_with(PasoProfile::default())
}

/// The real registry with this PaSO profile.
pub fn registry_with(paso: PasoProfile) -> Result<Registry<HaipHost>, String> {
    let mut builder = Registry::<HaipHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(SdJwtVc::new().map_err(|e| e.to_string())?);
    builder.format(Mdoc::new().map_err(|e| e.to_string())?);
    paso.register(&mut builder)
        .map(drop)
        .map_err(|e| e.to_string())?;
    siros_qes::register(&mut builder, QesProfile::default()).map_err(|e| e.to_string())?;
    builder.client_prefix(siros_testkit::TestPrefix::Request);
    builder.client_prefix(siros_x509::X509Hash);
    builder.client_prefix(siros_x509::X509SanDns);
    builder.build().map_err(|e| e.to_string())
}

/// W3C SRI integrity metadata with sha256.
pub fn sri(content: &[u8]) -> String {
    format!("sha256-{}", STANDARD.encode(Sha256::digest(content)))
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

/// How the wallet words a PaSO amount (View §3 MAY): the test app's wording formats the number
/// in its currency (`€49.99`); a wallet may write it as given, the number then the code
/// (`49.99 EUR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amounts {
    /// Formatted in the currency.
    Formatted,
    /// As written.
    Written,
}

/// The test app's wording of PaSO's amount: the number formatted in the currency.
const AMOUNT_FORMATTED: &str = "amount = {$value :currency currency=$currency}";
/// A wording of PaSO's amount as written: the number, a space, the code.
const AMOUNT_WRITTEN: &str = "amount = {$value} {$currency}";

thread_local! {
    /// The test app's contexts with amounts as written, English then German, loaded once per
    /// thread.
    static WRITTEN: [&'static Context; 2] = Language::ALL.map(|language| {
        let paso = match language {
            Language::English => ENGLISH_PASO,
            Language::German => GERMAN_PASO,
        };
        assert!(paso.contains(AMOUNT_FORMATTED), "the test app's amount wording");
        let context = language
            .sources()
            .into_iter()
            .map(|source| {
                if source == paso {
                    source.replace(AMOUNT_FORMATTED, AMOUNT_WRITTEN)
                } else {
                    source.to_owned()
                }
            })
            .try_fold(Context::new().bidi(Bidi::None), |context, source| {
                context.module(&source)
            })
            .expect("the test app's sources");
        &*Box::leak(Box::new(context))
    });
}

/// The language a wallet presents in: the first tag of `env`'s priority list whose language the
/// test app speaks, English when it speaks none.
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

/// The wallet's own context: the test app's sources in `env`'s [`language`], its amounts worded
/// as `amounts`.
pub fn own_modules(env: &Env, amounts: Amounts) -> &'static Context {
    let language = language(env);
    match amounts {
        Amounts::Formatted => language.shared().expect("the test app's sources"),
        Amounts::Written => {
            let at = match language {
                Language::English => 0,
                Language::German => 1,
            };
            WRITTEN.with(|contexts| contexts[at])
        }
    }
}

/// `own` with each source loaded once, in order: two credentials of one type convert to one
/// source.
pub fn loaded(own: &Context, sources: impl IntoIterator<Item = String>) -> Context {
    let mut seen: Vec<String> = Vec::new();
    let mut context = own.clone();
    for source in sources {
        if !seen.contains(&source) {
            context = context.module(&source).expect("a converted source loads");
            seen.push(source);
        }
    }
    context
}

/// The source a PaSO type's metadata converts to in `own` for a priority list; `None` for
/// metadata PaSO refuses, whose entries do not render.
fn converted(registered: &Registered<'_>, own: &Context, priority: &[LocaleTag]) -> Option<String> {
    match siros_paso::view::convert(registered, LabelLimits::PASO, own, priority) {
        Ok(source) => Some(source),
        Err(ConvertError::Metadata(_)) => None,
        Err(other) => panic!("the metadata converts: {other}"),
    }
}

/// The test app's context as the wallet registers its credentials for `env`'s priority list:
/// its [`own_modules`], the source each type of each credential's PaSO document converts to,
/// and the sources of the ad-hoc metadata the request's entries carry: over the DC API read
/// unverified as the matcher reads it, phase 2 verifying it; in the URI flow verified through
/// `host` for the wallet's credentials before it converts.
pub fn wallet_app(
    wallet: &Wallet<'_>,
    request: &Request<'_>,
    env: &Env,
    amounts: Amounts,
    host: &HaipHost,
) -> Context {
    let own = own_modules(env, amounts);
    let mut sources: Vec<String> = Vec::new();
    for credential in wallet.credentials() {
        let Some(bytes) = credential.document("paso") else {
            continue;
        };
        let node = PasoDocument::json(bytes).expect("a PaSO document");
        let document = PasoDocument::read(&node).expect("a PaSO document");
        for (kind, meta) in document.types() {
            sources.extend(converted(&Registered::of(kind, meta), own, env.priority()));
        }
    }
    let registered = loaded(own, sources);
    let carried = match request.envelope().channel() {
        Channel::DcApi(_) => {
            let read = Carried::read(request).expect("a DC API request");
            siros_paso::view::carried(&read, &registered, env.priority())
        }
        Channel::Uri => {
            let held: Vec<_> = wallet.credentials().iter().collect();
            let verified = Verified::of(request, &held, host).expect("the PaSO documents read");
            siros_paso::view::verified(&verified, &registered, env.priority())
        }
    }
    .expect("the ad-hoc metadata's sources");
    loaded(&registered, carried)
}
