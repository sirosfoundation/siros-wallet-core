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
//! a test publishes for phase 2's fetches ([`Published`]), the issuer stand-in ([`issuer`]), the
//! encoders of [`verifier`], the reading of an mdoc presentation in the reference model's shape
//! ([`reading`]), the fixtures the format plug-ins' tests share ([`fixtures`]), the probes that
//! hand a test what the core's flow gives a plug-in ([`probe`]), and the reference
//! model's shapes the tests read ([`oracle`]), and the test app's texts: its main module, the
//! crate modules in its English and German, and a renderer over them ([`render`]).

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
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
pub mod verifier;

use siros_explain::{Message, Messages};
use siros_openid4vp::plugins::FaultDomain;

/// The test doubles' domain, as their fault message, which tests' own plug-ins fault in too.
pub const FAULT: FaultDomain = siros_explain::checked!(FaultDomain, "testkit.fault");

/// The test doubles' messages: those their error types and rules declare, and their fault's.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        let declared: &[fn() -> Vec<Message>] = &[
            issuer::IssueError::messages,
            verifier::EncodeError::messages,
            fixtures::FixtureError::messages,
            reading::ReadError::messages,
            oracle::OracleError::messages,
            render::AppError::messages,
            rules::FormatRule::messages,
            rules::EntryRule::messages,
            rules::Excluded::messages,
            rules::TestRule::messages,
            rules::TestExclusion::messages,
        ];
        declared
            .iter()
            .flat_map(|messages| messages())
            .chain([FAULT.message()])
            .collect()
    }
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
