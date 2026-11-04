//! The host of siros-paso's tests: the core's doubles and the PaSO module's.

#![allow(dead_code)]

use siros_openid4vp::host::{CoseEncrypt, Haip, Platform, RequestDecryption, Timestamp};
use siros_paso::{Paso, TestPaso};
use siros_testkit::{TestCoseEncrypt, TestHaip, TestPlatform, TestRequestDecryption};

siros_testkit::test_host! {
    /// The platform and PaSO doubles, HAIP's and the `COSE_Encrypt` module's stand-ins.
    #[derive(Debug, Clone, Default)]
    pub struct PasoHost {
        handles { platform: TestPlatform => Platform, paso: TestPaso => Paso }
        zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional { TestCoseEncrypt => CoseEncrypt }
        lacks {}
    }
}

siros_testkit::test_host! {
    /// [`PasoHost`]'s modules without the `COSE_Encrypt` module.
    #[derive(Debug, Clone, Default)]
    pub struct SealerlessHost {
        handles { platform: TestPlatform => Platform, paso: TestPaso => Paso }
        zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional {}
        lacks { CoseEncrypt }
    }
}

impl PasoHost {
    /// The host whose platform and PaSO module both read the clock at `now`.
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
            paso: TestPaso::at(now),
        }
    }
}
