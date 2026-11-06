//! The host of siros-paso's tests: the core's doubles and the PaSO module's.

#![allow(dead_code)]

use siros_openid4vp::host::{Haip, Platform, RequestDecryption, Timestamp};
use siros_paso::{
    CoseEncrypt, IssuerTrust, Paso, RandomIds, RootCertificate, TestCoseEncrypt, TestIssuerTrust,
    TestPaso, TestRandomIds,
};
use siros_testkit::{TestHaip, TestPlatform, TestRequestDecryption};

siros_testkit::test_host! {
    /// The platform, PaSO, identifier and trust store doubles, HAIP's and the `COSE_Encrypt`
    /// module's stand-ins.
    #[derive(Debug, Clone, Default)]
    pub struct PasoHost {
        handles {
            platform: TestPlatform => Platform,
            paso: TestPaso => Paso,
            random_ids: TestRandomIds => RandomIds,
            issuer_trust: TestIssuerTrust => IssuerTrust
        }
        zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional { TestCoseEncrypt => CoseEncrypt }
        lacks {}
    }
}

siros_testkit::test_host! {
    /// [`PasoHost`]'s modules without the `COSE_Encrypt` module.
    #[derive(Debug, Clone, Default)]
    pub struct SealerlessHost {
        handles {
            platform: TestPlatform => Platform,
            paso: TestPaso => Paso,
            random_ids: TestRandomIds => RandomIds,
            issuer_trust: TestIssuerTrust => IssuerTrust
        }
        zero_sized { TestHaip => Haip, TestRequestDecryption => RequestDecryption }
        optional {}
        lacks { CoseEncrypt }
    }
}

impl PasoHost {
    /// The host whose platform and PaSO module both read the clock at `now`, its trust store
    /// siros-x509's test root.
    pub fn at(now: Timestamp) -> Self {
        Self {
            platform: TestPlatform::at(now),
            paso: TestPaso::at(now),
            random_ids: TestRandomIds::default(),
            issuer_trust: TestIssuerTrust {
                roots: vec![
                    RootCertificate::parse(&siros_testkit::x509::root()).expect("a certificate"),
                ],
            },
        }
    }
}
