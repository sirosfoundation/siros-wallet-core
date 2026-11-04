//! The effects the core hands its caller as data, and the answers the caller gives (sans-I/O).
//!
//! A step holds one slot per question, typed by the question's kind, and its continuation fills
//! every slot through the caller's function: a trust question, an [`Evaluation`] in AuthZEN's
//! shape, takes a [`Decision`]; a [`Resource`] takes a [`Fetch`]. The caller performs
//! the step's questions from `questions()`, then calls the continuation with a function that
//! answers one question; the continuation calls it once per slot, in order.

mod authzen;
mod media;

pub use authzen::{
    Action, ActionName, Decided, Decision, Entity, EntityId, EntityType, Evaluation, Verdict,
};
pub use media::{MediaType, NotMediaType};

use std::fmt;

use rustc_hash::FxHashSet;

use crate::rows::HttpsUrl;

/// An https URL a profile revalidates with; it takes a [`Fetch`]. Only the core makes one, from
/// a profile's `wanted`:
///
/// ```compile_fail,E0423
/// use siros_openid4vp::effects::Resource;
/// use siros_openid4vp::rows::HttpsUrl;
///
/// fn forged(url: HttpsUrl) -> Resource {
///     Resource(url)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource(HttpsUrl);

impl Resource {
    /// One resource per distinct URL a profile wanted, in the order each URL first appears.
    pub(crate) fn distinct(wanted: Vec<HttpsUrl>) -> Vec<Self> {
        let mut seen = FxHashSet::default();
        wanted
            .into_iter()
            .filter(|url| seen.insert(url.clone()))
            .map(Self)
            .collect()
    }

    /// The URL the caller GETs.
    #[must_use]
    pub const fn url(&self) -> &HttpsUrl {
        &self.0
    }
}

/// The caller's answer to a [`Resource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// The response's content and its `Content-Type`.
    Fetched {
        /// The content.
        content: Vec<u8>,
        /// Its media type.
        media: MediaType,
    },
    /// The fetch failed.
    Unfetched,
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Resource {}
    impl Sealed for super::Evaluation {}
}

/// A kind of question and the answer it takes: a [`Resource`] takes a [`Fetch`], an
/// [`Evaluation`] a [`Decision`]. Sealed: the kinds are the core's.
pub trait Ask: sealed::Sealed + fmt::Debug {
    /// The answer the question takes.
    type Answer: fmt::Debug;
}

impl Ask for Resource {
    type Answer = Fetch;
}

impl Ask for Evaluation {
    type Answer = Decision;
}

/// A step's questions of one kind, one slot per question, in order. Only the step makes them; its
/// continuation fills them.
#[derive(Debug)]
pub struct Slots<Q> {
    questions: Vec<Q>,
}

impl<Q: Ask> Slots<Q> {
    pub(crate) const fn of(questions: Vec<Q>) -> Self {
        Self { questions }
    }

    /// The questions, in order: what the caller performs.
    #[must_use]
    pub fn questions(&self) -> &[Q] {
        &self.questions
    }

    /// Every slot filled, in order: `answer` called once per question.
    pub(crate) fn fill(self, mut answer: impl FnMut(&Q) -> Q::Answer) -> Filled<Q> {
        let replies = self
            .questions
            .into_iter()
            .map(|question| {
                let answer = answer(&question);
                Reply { question, answer }
            })
            .collect();
        Filled { replies }
    }
}

/// A question with the caller's answer to it.
#[derive(Debug)]
pub struct Reply<Q: Ask> {
    question: Q,
    answer: Q::Answer,
}

impl<Q: Ask> Reply<Q> {
    /// The question.
    #[must_use]
    pub const fn question(&self) -> &Q {
        &self.question
    }

    /// The caller's answer.
    #[must_use]
    pub const fn answer(&self) -> &Q::Answer {
        &self.answer
    }
}

/// Each question with its answer, in order, one answer per slot. Only [`Slots`]' continuation
/// makes one; a set built otherwise does not compile:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::effects::{Filled, Resource};
///
/// fn forged() -> Filled<Resource> {
///     Filled { replies: Vec::new() }
/// }
/// ```
#[derive(Debug)]
pub struct Filled<Q: Ask> {
    replies: Vec<Reply<Q>>,
}

impl<Q: Ask> Filled<Q> {
    /// Each question with its answer, in order.
    #[must_use]
    pub fn replies(&self) -> &[Reply<Q>] {
        &self.replies
    }
}

/// A record's resources, one per distinct URL its profile wanted, each with what the caller
/// fetched, in the order the URLs first appear. Only phase 2 makes one, from its filled slots.
#[derive(Debug, Clone, Copy)]
pub struct Resources<'r>(&'r [Reply<Resource>]);

impl<'r> Resources<'r> {
    pub(crate) const fn of(replies: &'r [Reply<Resource>]) -> Self {
        Self(replies)
    }

    /// What the caller fetched at the URL, the one answer every mention of it reads; `None` when
    /// the profile did not want it.
    #[must_use]
    pub fn fetched(&self, url: &HttpsUrl) -> Option<&'r Fetch> {
        self.0
            .iter()
            .find(|reply| reply.question.url() == url)
            .map(|reply| &reply.answer)
    }

    /// Each resource with what the caller fetched, in order.
    #[must_use]
    pub const fn replies(&self) -> &'r [Reply<Resource>] {
        self.0
    }
}
