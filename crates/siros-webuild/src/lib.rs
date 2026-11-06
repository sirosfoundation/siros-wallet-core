//! WE BUILD's deployment rules beside its profile, which the WE BUILD build registers in the
//! SIROS wallet core: CS-02 §8.2's Request Object claims ([`Cs02Claims`], an `ObjectRule`) and
//! CS-02 §8.3's error answer from the Response URI ([`Cs02ErrorAnswer`], an `AnswerReader`).
//!
//! ```
//! use siros_openid4vp::plugins::Registry;
//! use siros_testkit::TestHost;
//! use siros_webuild::{Cs02Claims, Cs02ErrorAnswer};
//!
//! let mut builder = Registry::<TestHost>::builder();
//! builder.object_rule(Cs02Claims);
//! builder.answer_reader(Cs02ErrorAnswer);
//! assert!(builder.build().is_ok());
//! ```

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

use siros_explain::{Explain, Explained, IntoArg, Message, Messages, kind};
use siros_openid4vp::authenticate::ObjectRule;
use siros_openid4vp::json::{Node, Object};
use siros_openid4vp::refusal::{ErrorCode, ErrorDescription, Refusal, RequestRule, is_nqschars};
use siros_openid4vp::uri::{AnswerMembers, AnswerReader};
use siros_openid4vp::wallet_metadata::ParameterName;

/// The crate's messages: those its error types declare.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        [
            ClaimAbsent::messages(),
            ErrorAnswerForm::messages(),
            VerifierError::messages(),
        ]
        .concat()
    }
}

/// CS-02 §8.2: "The Presentation Request Object MUST include" `exp` and `aud`: A14 for either
/// absent, with `invalid_request_object`. RFC 7519's checks of their values stay the core's A9
/// and A10.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cs02Claims;

/// A claim CS-02 §8.2 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredClaim {
    /// `exp`.
    Exp,
    /// `aud`.
    Aud,
}

impl RequiredClaim {
    /// Its member name in the Request Object.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exp => "exp",
            Self::Aud => "aud",
        }
    }
}

impl IntoArg for RequiredClaim {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self.name()
    }
}

/// A claim CS-02 §8.2 requires that the Request Object lacks. Only [`Cs02Claims`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "webuild")]
#[error("the Request Object holds no {}, which CS-02 §8.2 requires", .0.name())]
pub struct ClaimAbsent(#[explain(name = "claim")] RequiredClaim);

impl ClaimAbsent {
    /// The claim.
    #[must_use]
    pub const fn claim(self) -> RequiredClaim {
        self.0
    }
}

impl RequestRule for ClaimAbsent {
    /// RFC 9101 §6.2: the Request Object breaks a rule.
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_REQUEST_OBJECT
    }
}

impl ObjectRule for Cs02Claims {
    /// `exp`, then `aud`: the first absent one.
    fn check(&self, claims: &Object<'_>) -> Option<Refusal> {
        [RequiredClaim::Exp, RequiredClaim::Aud]
            .into_iter()
            .find(|claim| claims.get(claim.name()).is_none())
            .map(|claim| Refusal::new(ClaimAbsent(claim)))
    }
}

/// `error` (RFC 6749 §5.2).
const ERROR: ParameterName = siros_explain::checked!(ParameterName, "error");
/// `error_description` (RFC 6749 §5.2).
const ERROR_DESCRIPTION: ParameterName =
    siros_explain::checked!(ParameterName, "error_description");

/// CS-02 §8.3's error answer: `error`, with `error_description`, as RFC 6749 §5.2 writes them;
/// the outcome the wallet shows the End-User (CS-02 §6.1.7).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cs02ErrorAnswer;

/// An `error` value a Verifier writes (RFC 6749 Appendix A.7): one or more characters of
/// %x20-21, %x23-5B, %x5D-7E.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierCode(String);

impl VerifierCode {
    /// The code; `None` for a text outside Appendix A.7.
    #[must_use]
    pub fn parse(text: String) -> Option<Self> {
        is_nqschars(&text).then_some(Self(text))
    }

    /// Its text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A code is named by its text in a message.
impl IntoArg for VerifierCode {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}

/// The outcome a Verifier reports in its answer. Only [`Cs02ErrorAnswer`] makes one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "webuild")]
#[error("the Verifier answered {code:?}: {description:?}")]
pub struct VerifierError {
    code: VerifierCode,
    description: Option<ErrorDescription>,
}

impl VerifierError {
    /// `error`.
    #[must_use]
    pub const fn code(&self) -> &VerifierCode {
        &self.code
    }

    /// `error_description`.
    #[must_use]
    pub const fn description(&self) -> Option<&ErrorDescription> {
        self.description.as_ref()
    }
}

/// An error answer outside RFC 6749 §5.2's form: an `error` outside Appendix A.7, an
/// `error_description` outside Appendix A.8, or a description without an `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "webuild")]
#[error("error and error_description are not as RFC 6749 §5.2 writes them")]
pub struct ErrorAnswerForm;

impl AnswerReader for Cs02ErrorAnswer {
    fn names(&self) -> &'static [ParameterName] {
        &[ERROR, ERROR_DESCRIPTION]
    }

    /// No outcome without `error`; a [`VerifierError`] with one; [`ErrorAnswerForm`] for either
    /// member outside RFC 6749 §5.2's form.
    fn read(
        &self,
        members: &AnswerMembers<'_>,
    ) -> Result<Option<Box<dyn Explained>>, Box<dyn Explained>> {
        let refused = || Box::new(ErrorAnswerForm) as Box<dyn Explained>;
        let text = |member: &Node<'_>| member.as_str().map(str::to_owned).ok_or_else(refused);
        let description = members
            .get(ERROR_DESCRIPTION)
            .map(|member| text(member).and_then(|t| ErrorDescription::parse(t).ok_or_else(refused)))
            .transpose()?;
        let Some(error) = members.get(ERROR) else {
            return match description {
                None => Ok(None),
                Some(_) => Err(refused()),
            };
        };
        let code = VerifierCode::parse(text(error)?).ok_or_else(refused)?;
        Ok(Some(Box::new(VerifierError { code, description })))
    }
}
