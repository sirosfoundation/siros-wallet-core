//! Test plug-ins and deterministic host modules for the tests of the SIROS wallet core crates, and
//! the Verifier's side: a format whose credentials say which queries and options they answer
//! ([`TestFormat`]), a profile that binds by first match over the types a credential supports, or
//! every such entry ([`TestProfile`]), the doubles of the core's host modules ([`TestPlatform`],
//! [`TestHaip`], [`JweHaip`], [`TestRequestDecryption`]) with [`test_host!`], their JOSE
//! ([`jose`]) and the COSE_Encrypt stand-in ([`cose`]), the test Verifier's Client Identifier
//! Prefix and a trust service double ([`prefix`]), the `request_uri` POST's contribution and the
//! Response URI answer's reader ([`TestPostContribution`], [`TestAnswerReader`]), a response
//! type and its parameters, a response mode, a hash algorithm and a scope query a test
//! configures ([`TestResponseType`], [`TestResponseParameters`], [`TestMode`], [`TestHash`],
//! [`TestScope`]), the resources
//! a test publishes for phase 2's fetches ([`Published`]), the issuer stand-ins ([`issuer`], [`sd_jwt_issuer`]), the
//! encoders of [`verifier`], the reading of an mdoc presentation in the reference model's shape
//! ([`reading`]), a Verifier's reading of an SD-JWT presentation ([`sd_jwt_reading`]), the fixtures
//! the format plug-ins' tests share ([`fixtures`]), the probes that hand a test what the core's
//! flow gives a plug-in ([`probe`]), the certificates and chains the X.509 tests sign under
//! ([`x509`]), and the reference
//! model's shapes the tests read ([`oracle`]), the test doubles' fault ([`fault`], [`caused`]),
//! and the test app: its wording of every crate in English and German, a context per language
//! ([`render`]).

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

pub mod cose;
mod doubles;
pub mod fixtures;
mod format;
mod host;
pub mod issuer;
pub mod jose;
pub mod oracle;
mod post;
pub mod prefix;
pub mod probe;
mod profile;
mod published;
pub mod reading;
pub mod render;
pub mod rules;
pub mod sd_jwt_issuer;
pub mod sd_jwt_reading;
pub mod verifier;
pub mod x509;

use std::error::Error;

use siros_explain::Explain;
use siros_openid4vp::plugins::{Detail, Fault};

siros_explain::scope!("testkit");

/// The test doubles' fault error, which tests' own plug-ins fault with too.
#[derive(Debug, thiserror::Error, Explain)]
#[error("{detail}")]
#[explain(id = "fault")]
struct TestFault {
    #[explain(skip)]
    detail: Detail,
    #[source]
    cause: Option<Box<dyn Error + Send + Sync>>,
}

/// The test doubles' fault, its log line written by `detail`.
#[must_use]
pub fn fault(detail: Detail) -> Fault {
    Fault::new(TestFault {
        detail,
        cause: None,
    })
}

/// The test doubles' fault caused by an error, its log line written by `detail`.
#[must_use]
pub fn caused(detail: Detail, cause: impl Error + Send + Sync + 'static) -> Fault {
    Fault::new(TestFault {
        detail,
        cause: Some(Box::new(cause)),
    })
}

pub use doubles::{
    TestBody, TestChoice, TestHash, TestMode, TestResponseParameters, TestResponseType,
};
pub use fixtures::TestScope;
pub use format::{DoubleText, TestFormat};
pub use host::{JweHaip, TestHaip, TestHost, TestPlatform, digest_prefix, pin_and_device};
pub use jose::TestRequestDecryption;
pub use post::{TestAnswerReader, TestPostContribution};
pub use prefix::{NamedPrefix, Registration, TestPrefix, TestTrust};
pub use profile::{Binds, Stale, TestProfile};
pub use published::{Published, PublishedResource};

/// The access traits [`test_host!`] implements.
#[doc(hidden)]
pub mod reexport {
    pub use siros_openid4vp::host::{Empty, Has, Held, MayHave};
}
