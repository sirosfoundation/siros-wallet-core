//! What the tests share: the HAIP build's host and the registry of every real plug-in over it,
//! W3C SRI written from its definition, and the test app of a PaSO type's texts.

#![allow(dead_code, reason = "each test binary uses a part")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use siros_explain::{Messages, ModuleId};
use siros_i18n::{Declaration, Module};
use siros_mdoc::{DeviceMac, Mdoc, TestDeviceMac};
use siros_openid4vp::host::{Haip, Platform, RequestDecryption, Timestamp};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Registry;
use siros_paso::{
    CoseEncrypt, Paso, PasoProfile, RandomIds, TestCoseEncrypt, TestPaso, TestRandomIds,
};
use siros_qes::QesProfile;
use siros_sdjwt::SdJwtVc;
use siros_testkit::render::{App, CrateSource, GERMAN_PASO, compilers, main_module, main_sources};
use siros_testkit::{TestHaip, TestPlatform, TestRequestDecryption};

siros_testkit::test_host! {
    /// The HAIP build's host: every module, each a test double.
    #[derive(Debug, Clone, Default)]
    pub struct HaipHost {
        handles {
            platform: TestPlatform => Platform,
            paso: TestPaso => Paso,
            random_ids: TestRandomIds => RandomIds
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
    /// The host whose platform and PaSO module both read the clock at `now`.
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
            paso: TestPaso::at(now),
            random_ids: TestRandomIds::default(),
        }
    }
}

/// The real registry: the SD-JWT VC and mdoc formats, PaSO under `urn:paso:sca:`, QES
/// for its type, the test Verifier's Client Identifier Prefix and siros-x509's two.
pub fn registry() -> Result<Registry<HaipHost>, String> {
    let mut builder = Registry::<HaipHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
    builder.format(SdJwtVc::new().map_err(|e| e.to_string())?);
    builder.format(Mdoc::new().map_err(|e| e.to_string())?);
    PasoProfile::default()
        .register(&mut builder)
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

/// The test app of a type's rendering: the main module, the core's and PaSO's modules, and the
/// module the type's metadata converts to.
pub fn paso_app(kind: &str, given: &str) -> App {
    let node = Node::parse(given).expect("the metadata");
    let [en, de] = main_sources();
    let converted = siros_paso::view::convert(kind, &node, &[&en, &de]).expect("converts");
    let sources: Vec<&str> = converted
        .sources
        .entries()
        .iter()
        .map(|entry| entry.value().as_str())
        .collect();
    let defined = Module::load(
        ModuleId::Defined(converted.module),
        &Declaration::defined(converted.declaration).expect("a declaration"),
        &sources,
        converted.policy,
        &compilers().expect("compilers"),
    )
    .expect("the converted module loads");
    let paso = CrateSource {
        id: siros_paso::CrateModule::ID,
        messages: siros_paso::CrateModule::messages(),
        english: siros_paso::CrateModule::ENGLISH,
        german: GERMAN_PASO,
    };
    let modules = [
        main_module().expect("the main module"),
        CrateSource::openid4vp().load().expect("the core's module"),
        paso.load().expect("PaSO's module"),
        defined,
    ];
    App::new(&modules.iter().collect::<Vec<_>>()).expect("the package")
}
