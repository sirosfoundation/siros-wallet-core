//! What the tests share: the HAIP build's host and the registry of every real plug-in over it,
//! W3C SRI written from its definition.

#![allow(dead_code, reason = "each test binary uses a part")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use siros_mdoc::{DeviceMac, Mdoc, TestDeviceMac};
use siros_openid4vp::host::{CoseEncrypt, Haip, Platform, RequestDecryption, Timestamp};
use siros_openid4vp::plugins::Registry;
use siros_paso::{Paso, PasoProfile, TestPaso};
use siros_qes::QesProfile;
use siros_sdjwt::SdJwtVc;
use siros_testkit::{TestCoseEncrypt, TestHaip, TestPlatform, TestRequestDecryption};

siros_testkit::test_host! {
    /// The HAIP build's host: every module, each a test double.
    #[derive(Debug, Clone, Default)]
    pub struct HaipHost {
        handles { platform: TestPlatform => Platform, paso: TestPaso => Paso }
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
