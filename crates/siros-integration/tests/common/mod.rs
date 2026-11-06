//! What the tests share: the HAIP build's host and the registry of every real plug-in over it,
//! W3C SRI written from its definition, and the test app of a PaSO type's texts.

#![allow(dead_code, reason = "each test binary uses a part")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use siros_explain::{Messages, ModuleId};
use siros_i18n::{DefinedForm, LocaleTag, Module, Selected};
use siros_mdoc::{DeviceMac, Mdoc, TestDeviceMac};
use siros_openid4vp::envelope::Channel;
use siros_openid4vp::host::{Haip, Platform, RequestDecryption, Timestamp};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::request::Request;
use siros_openid4vp::rows::Env;
use siros_openid4vp::wallet::Wallet;
use siros_paso::adhoc::{Carried, Verified};
use siros_paso::document::PasoDocument;
use siros_paso::{
    CoseEncrypt, IssuerTrust, Paso, PasoProfile, RandomIds, RootCertificate, TestCoseEncrypt,
    TestIssuerTrust, TestPaso, TestRandomIds,
};
use siros_qes::QesProfile;
use siros_sdjwt::SdJwtVc;
use siros_testkit::render::{
    App, CrateSource, ENGLISH_PASO, ENGLISH_QES, GERMAN_PASO, GERMAN_QES, main_locales, main_module,
};
use siros_testkit::{TestHaip, TestPlatform, TestRequestDecryption};

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

impl HaipHost {
    /// The host whose platform and PaSO module both read the clock at `now`, its trust store
    /// siros-x509's test root.
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
            paso: TestPaso::at(now),
            random_ids: TestRandomIds::default(),
            issuer_trust: TestIssuerTrust {
                roots: vec![RootCertificate::new(siros_x509::test_util::root())],
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

/// A PaSO type's metadata converted for a priority list; `None` for metadata that does not
/// convert, whose entries do not render.
fn converted(kind: &str, given: &str, priority: &[LocaleTag]) -> Option<DefinedForm> {
    let node = Node::parse(given).expect("the metadata");
    let main = main_locales().expect("the main module");
    siros_paso::view::convert(kind, &node, &main, priority).ok()
}

/// The wallet's modules beside the defined ones: the main module, the test app's, the core's,
/// PaSO's and QES's.
pub fn own_modules() -> Vec<Module> {
    let paso = CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: ENGLISH_PASO,
        german: GERMAN_PASO,
    };
    let qes = CrateSource {
        id: siros_qes::CrateModule::ID,
        messages: siros_qes::CrateModule::messages(),
        english: ENGLISH_QES,
        german: GERMAN_QES,
    };
    vec![
        main_module().expect("the main module"),
        CrateSource::testkit()
            .load()
            .expect("the test app's module"),
        CrateSource::openid4vp().load().expect("the core's module"),
        paso.load().expect("PaSO's module"),
        qes.load().expect("QES's module"),
    ]
}

/// The test app of a type's rendering: the wallet's own modules and the module the type's
/// metadata converts to for the priority list, shown in the locale View §4 selected.
pub fn paso_app(kind: &str, given: &str, priority: &[LocaleTag], locale: &LocaleTag) -> App {
    let defined = converted(kind, given, priority).expect("converts");
    let selected = Selected::new(ModuleId::Defined(defined.id()), locale.clone());
    let modules = own_modules();
    App::new(&modules.iter().collect::<Vec<_>>(), &[&defined])
        .expect("the package")
        .selecting(selected)
}

/// The test app as the wallet registers its credentials for `env`'s priority list: the wallet's
/// own modules, the module each type of each credential's PaSO document converts to, and the
/// module of the ad-hoc metadata each entry of the request carries: over the DC API read
/// unverified as the matcher reads it, phase 2 verifying it; in the URI flow verified through
/// `host` for the wallet's credentials before it converts.
pub fn wallet_app(wallet: &Wallet<'_>, request: &Request<'_>, env: &Env, host: &HaipHost) -> App {
    let mut metadata: Vec<(String, String)> = Vec::new();
    for credential in wallet.credentials() {
        let Some(bytes) = credential.document("paso") else {
            continue;
        };
        let node = PasoDocument::json(bytes).expect("a PaSO document");
        let document = PasoDocument::read(&node).expect("a PaSO document");
        metadata.extend(
            document
                .types()
                .map(|(kind, meta)| (kind.to_owned(), meta.python_compact().to_string())),
        );
    }
    let modules = own_modules();
    let mut defined: Vec<DefinedForm> = Vec::new();
    for (kind, meta) in &metadata {
        if let Some(module) = converted(kind, meta, env.priority())
            && defined.iter().all(|known| known.id() != module.id())
        {
            defined.push(module);
        }
    }
    let main = main_locales().expect("the main module");
    let carried = match request.envelope().channel() {
        Channel::DcApi(_) => {
            let read = Carried::read(request).expect("a DC API request");
            siros_paso::view::carried(&read, &main, env.priority())
        }
        Channel::Uri => {
            let held: Vec<_> = wallet.credentials().iter().collect();
            let verified = Verified::of(request, &held, host).expect("the PaSO documents read");
            siros_paso::view::verified(&verified, &main, env.priority())
        }
    }
    .expect("the main module's formats");
    for module in carried {
        if defined.iter().all(|known| known.id() != module.id()) {
            defined.push(module);
        }
    }
    App::new(
        &modules.iter().collect::<Vec<_>>(),
        &defined.iter().collect::<Vec<_>>(),
    )
    .expect("the package")
}
