//! The plug-ins' phase 2 over the build's host: each plug-in implements it under the bounds of
//! the modules it calls, and the registry takes the plug-in only when the build's host meets
//! them.

use siros_explain::Explain;
use siros_syntax::AllOf;

use super::{Authentication, AuthenticationNeed, Presentation, SignFailed, Usable};
use crate::plugins::{
    Answered, Fault, FetchedRecord, FindingData, Format, FormatQuery, Member, Members, OptionIndex,
    Profile,
};
use crate::refusal::Refusal;
use crate::request::Query;
use crate::routing::AnsweredContext;
use crate::rows::{Env, HttpsUrl};
use crate::session::Session;

/// A profile's phase 2 over the build's host; its bounds name the modules it calls.
pub trait ProfileHost<H>: Profile {
    /// The https resources the profile revalidates the record with, in the order it reads them;
    /// the caller fetches each distinct URL once. The record, the profile's own data and the
    /// host's modules decide them.
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault>;

    /// The profile with what phase 2 found, for re-running the consent: the matcher then treats
    /// those conditions as known to fail.
    #[must_use]
    fn informed(&self, findings: &[&Self::Finding]) -> Self;

    /// The End-User authentication the record needs (CS-12 §5 item 4; TS12 §3.6).
    ///
    /// # Errors
    ///
    /// The profile cannot read the record.
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault>;

    /// What the matcher assumed and phase 2 can check, checked now with the resources the
    /// profile wanted: the finding when something no longer holds.
    ///
    /// # Errors
    ///
    /// The profile's fault.
    fn revalidate(
        &self,
        record: FetchedRecord<'_>,
        host: &H,
    ) -> Result<Option<Self::Finding>, Fault>;

    /// The response members for the record's entries, from the request, the credential, what
    /// the record attests, the host's modules, and how the wallet authenticated the End-User.
    ///
    /// # Errors
    ///
    /// The profile's fault.
    fn respond(
        &self,
        record: Answered<'_>,
        host: &H,
        authentication: &Authentication,
    ) -> Result<Members, Fault>;
}

/// A format's phase 2 over the build's host: each query read again under the response mode the
/// request's rules accepted. Only that reading has phase-2 methods.
pub trait FormatHost<H>: Format {
    /// The query read for phase 2, with the rules phase 1 read it with; refused with the format's
    /// request rules it breaks, as [`Format::query`] refuses it.
    ///
    /// # Errors
    ///
    /// The format's request rules the query breaks.
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: AnsweredContext<'q>,
    ) -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>>;
}

/// A query a format read for phase 2: phase 1's methods, and each answerable option as phase 2
/// reads it.
pub trait AnsweredQuery<H>: FormatQuery {
    /// The credential's answerable options, in the Verifier's order: the options
    /// [`FormatQuery::answerable`] gives, each with what phase 2 needs of it. `provided`: the
    /// response members the transaction bound to the credential writes.
    ///
    /// # Errors
    ///
    /// The format's fault.
    fn choose<'a>(
        &'a self,
        credential: Usable<'a>,
        env: &Env,
        provided: &[Member],
    ) -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault>;
}

/// An answerable option in phase 2: only its query's [`AnsweredQuery::choose`] makes one, so it
/// carries its own query, credential and option.
pub trait AnsweredOption<H> {
    /// The option.
    fn option(&self) -> OptionIndex;

    /// What phase 1 assumed of the credential and the option and could not check, checked now;
    /// the format's finding when it no longer holds.
    ///
    /// # Errors
    ///
    /// The format's fault.
    fn revalidate(
        &self,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Option<Box<dyn FindingData>>, Fault>;

    /// The presentation of the option's items, its proof holding `members` beside the format's
    /// own.
    ///
    /// # Errors
    ///
    /// The format's contract broken, or a step that failed with its reason.
    fn present(
        &self,
        members: &Members,
        session: &Session<'_>,
        host: &H,
    ) -> Result<Presentation, PresentError>;
}

/// Why a format made no presentation: its contract broken, or a step that failed without a bug,
/// such as a cancelled key prompt.
#[derive(Debug, thiserror::Error, Explain)]
pub enum PresentError {
    /// The plug-in broke its contract.
    #[error(transparent)]
    Fault(#[from] Fault),
    /// A step failed: a cancelled key prompt.
    #[error("the presentation failed: {reason}")]
    #[explain(id = "present.failed")]
    Failed {
        /// The plug-in's own error.
        reason: Box<dyn Explain>,
    },
}

impl From<SignFailed> for PresentError {
    fn from(failed: SignFailed) -> Self {
        match failed {
            SignFailed::Fault(fault) => Self::Fault(fault),
            cancelled @ SignFailed::Cancelled => Self::Failed {
                reason: Box::new(cancelled),
            },
        }
    }
}
