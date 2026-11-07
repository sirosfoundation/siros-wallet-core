//! The rules the test format and the test profile apply, and the exclusions they give.

use siros_explain::Explain;
use siros_openid4vp::hash::HashesAlgRule;
use siros_openid4vp::json::JsonError;
use siros_openid4vp::plugins::{Clause, Exclusion};
use siros_openid4vp::refusal::{ErrorCode, RequestRule};

/// A rule of the test format's queries: `invalid_request`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.format")]
pub enum FormatRule {
    /// The Verifier's `algs` is no array.
    #[error("test {query}: algs is not an array")]
    Algs {
        /// The query's id.
        query: String,
    },
    /// The query is no JSON with unique member names.
    #[error("test {query}: {cause}")]
    Json {
        /// The query's id.
        query: String,
        /// Why.
        cause: JsonError,
    },
    /// `options` is no array of item arrays.
    #[error("test {query}: options is not an array of item arrays")]
    Options {
        /// The query's id.
        query: String,
    },
}

impl RequestRule for FormatRule {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST
    }
}

/// B.3.3.1's rule an entry of the test profile breaks, under the entry: its code is the rule's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.profile", id = "entry")]
#[error("test entry {entry}: {rule}")]
pub struct EntryRule {
    /// The entry's position.
    pub entry: usize,
    /// The rule.
    pub rule: HashesAlgRule,
}

impl RequestRule for EntryRule {
    fn code(&self) -> ErrorCode {
        self.rule.code()
    }
}

/// Why the test format or the test profile excludes a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.excluded")]
pub enum Excluded {
    /// The Verifier's `algs` admit no algorithm of the credential.
    #[error("algs [{listed}] admit no algorithm of the credential")]
    Algs {
        /// The algorithms, each as Python's `repr` writes it.
        listed: String,
    },
    /// No entry the profile binds is compatible.
    #[error("no entry is compatible")]
    NoEntry,
    /// No hash algorithm every bound entry allows.
    #[error("no hash algorithm every entry allows")]
    NoAlgorithm,
}

impl Exclusion for Excluded {
    fn clause(&self) -> Clause {
        Clause::cited(match self {
            Self::Algs { .. } | Self::NoEntry => "test",
            Self::NoAlgorithm => "OpenID4VP B.3.3.1",
        })
    }
}

/// A test's own request rule: its text and its code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.test", id = "rule")]
#[error("{text}")]
pub struct TestRule {
    /// What the rule found.
    pub text: String,
    /// The code the Verifier receives.
    #[explain(skip)]
    pub code: ErrorCode,
}

impl TestRule {
    /// A rule with the code `invalid_request`.
    pub fn invalid_request(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            code: ErrorCode::INVALID_REQUEST,
        }
    }

    /// A rule with the code `invalid_transaction_data`.
    pub fn invalid_transaction_data(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            code: ErrorCode::INVALID_TRANSACTION_DATA,
        }
    }
}

impl RequestRule for TestRule {
    fn code(&self) -> ErrorCode {
        self.code
    }
}

/// A test's own exclusion: its text, under the clause `test`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.test", id = "excluded")]
#[error("{0}")]
pub struct TestExclusion(#[explain(name = "text")] pub String);

impl TestExclusion {
    /// The exclusion of a text.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

impl Exclusion for TestExclusion {
    fn clause(&self) -> Clause {
        Clause::cited("test")
    }
}

/// The rule over a Request Object's claims double: the claim it names is present.
#[derive(Debug, Clone, Copy)]
pub struct TestObjectRule(pub &'static str);

/// A Request Object without the claim [`TestObjectRule`] requires.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "testkit.object")]
#[error("the Request Object states no {0}")]
pub struct ClaimAbsent(#[explain(name = "claim")] &'static str);

impl RequestRule for ClaimAbsent {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST_OBJECT
    }
}

impl siros_openid4vp::authenticate::ObjectRule for TestObjectRule {
    fn check(
        &self,
        claims: &siros_openid4vp::json::Object<'_>,
    ) -> Option<siros_openid4vp::refusal::Refusal> {
        claims
            .get(self.0)
            .is_none()
            .then(|| siros_openid4vp::refusal::Refusal::new(ClaimAbsent(self.0)))
    }
}
