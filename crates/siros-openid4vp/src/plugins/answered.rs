//! A record phase 2 answers, as its profile reads it, with the response mode it answers in: before
//! its resources are fetched ([`Answered`]), and with them ([`FetchedRecord`]). Only the core's
//! phase 2 makes either.

use super::{Attested, BoundEntries};
use crate::effects::Resources;
use crate::request::Request;
use crate::routing::ModeName;
use crate::wallet::Credential;
use crate::wallet_metadata::Placement;

/// A record phase 2 answers, as a profile reads it.
#[derive(Debug, Clone, Copy)]
pub struct Answered<'r> {
    request: &'r Request<'r>,
    credential: &'r Credential<'r>,
    entries: &'r BoundEntries,
    attested: &'r Attested,
    placement: Option<Placement>,
    mode: ModeName,
}

impl<'r> Answered<'r> {
    pub(crate) const fn of(
        request: &'r Request<'r>,
        credential: &'r Credential<'r>,
        entries: &'r BoundEntries,
        attested: &'r Attested,
        placement: Option<Placement>,
        mode: ModeName,
    ) -> Self {
        Self {
            request,
            credential,
            entries,
            attested,
            placement,
            mode,
        }
    }

    /// The response mode the answer goes in, which the request's rules accepted.
    #[must_use]
    pub const fn mode(&self) -> ModeName {
        self.mode
    }

    /// The request.
    #[must_use]
    pub const fn request(&self) -> &'r Request<'r> {
        self.request
    }

    /// The credential.
    #[must_use]
    pub const fn credential(&self) -> &'r Credential<'r> {
        self.credential
    }

    /// The entries the record authorizes.
    #[must_use]
    pub const fn entries(&self) -> &'r BoundEntries {
        self.entries
    }

    /// What the record attests.
    #[must_use]
    pub const fn attested(&self) -> &'r Attested {
        self.attested
    }

    /// How the presentation's format places the profile's members; `None` for a proof that
    /// carries none.
    #[must_use]
    pub const fn placement(&self) -> Option<Placement> {
        self.placement
    }
}

/// A record with the resources its profile wanted, each with what the caller fetched.
#[derive(Debug, Clone, Copy)]
pub struct FetchedRecord<'r> {
    record: Answered<'r>,
    resources: Resources<'r>,
}

impl<'r> FetchedRecord<'r> {
    pub(crate) const fn of(record: Answered<'r>, resources: Resources<'r>) -> Self {
        Self { record, resources }
    }

    /// The record.
    #[must_use]
    pub const fn record(&self) -> Answered<'r> {
        self.record
    }

    /// The resources its profile wanted, with what the caller fetched.
    #[must_use]
    pub const fn resources(&self) -> Resources<'r> {
        self.resources
    }
}
