//! The wallet's selection: a credential's definitions served by its sources, verified against
//! the trust store and the metadata the host holds, then the first match of [`Selector`]; and
//! what a registration records of those sources.

use siros_codec::date::DateTime;
use siros_credential::Credential;
use siros_display::{DisplayCache, Locale};
use siros_oid4vp::RequestSignature;
use siros_trust::TrustStore;

use crate::entry::Entry;
use crate::error::TransactionDataError;
use crate::image::Channel;
use crate::projection::Projected;
use crate::select::{Incompatibility, Selection, Selector};
use crate::served::ServedTypes;
use crate::sources::{Configuration, CredentialSources, HeldMetadata, NotServed, Verifier};
use crate::type_id::TypeId;

/// What a credential's sources read: the trust store, the metadata the host holds, the
/// configuration, the wallet's language and the time.
#[derive(Clone, Copy)]
pub struct SourceInputs<'c> {
    /// The trust store (H4), against which `x5c` chains are validated.
    pub trust: &'c TrustStore,
    /// The metadata the host holds: signed credential metadata, type metadata, key sets.
    pub held: &'c HeldMetadata,
    /// The display metadata the host holds, which names the PaSO Credentials.
    pub display: &'c DisplayCache,
    /// The host's configured definitions.
    pub configuration: &'c Configuration,
    /// The wallet's language.
    pub language: &'c Locale,
    /// The time.
    pub now: DateTime,
}

/// What the evaluation of an entry for a credential reads.
#[derive(Clone, Copy)]
pub struct Context<'c> {
    /// What the credential's sources read.
    pub sources: SourceInputs<'c>,
    /// How the request reached the wallet, which sets the images it admits.
    pub channel: Channel,
    /// Whether the request arrived signed.
    pub signature: RequestSignature,
}

impl<'c> SourceInputs<'c> {
    /// The sources of `credential`, its own metadata loaded.
    fn of(&self, credential: &'c Credential) -> Result<CredentialSources<'c>, NotServed> {
        let verifier = Verifier {
            trust: self.trust,
            held: self.held,
            now: self.now,
        };
        CredentialSources::load(
            credential,
            verifier,
            self.display,
            self.configuration,
            self.language,
        )
    }

    /// The definition of `type_id` that `credential`'s own metadata or the configuration
    /// gives, in the wallet's language.
    ///
    /// # Errors
    ///
    /// [`Incompatibility`]: why no source serves the type for the credential.
    pub fn served(
        &self,
        type_id: &TypeId,
        credential: &'c Credential,
    ) -> Result<Projected, Incompatibility> {
        self.of(credential)
            .and_then(|sources| sources.served(type_id))
            .map_err(Incompatibility::from)
    }

    /// What `credential`'s own metadata or the configuration serves for each type a source
    /// names, in the wallet's language, and for every other type: what a registration records
    /// (K1). A credential whose sources do not load is served nothing.
    pub fn served_types(&self, credential: &'c Credential) -> ServedTypes<Projected> {
        match self.of(credential) {
            Ok(sources) => sources.record(),
            Err(reason) => ServedTypes::none(reason.recorded()),
        }
    }
}

impl<'c> Context<'c> {
    /// What `credential` takes of `entries`, those that target it in array order (PaSO Core,
    /// Section 7.4.2, steps 2 and 3). A credential whose own metadata is not valid takes none,
    /// each entry with that cause.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::Unsigned`] when the request arrived unsigned and PaSO metadata
    /// serves an entry the credential would take (PaSO Core, Section 3).
    pub fn first_match(
        &self,
        entries: &[&Entry],
        credential: &'c Credential,
    ) -> Result<Selection, TransactionDataError> {
        let selector = Selector {
            channel: self.channel,
            signature: self.signature,
            now: self.sources.now,
        };
        match self.sources.of(credential) {
            Ok(sources) => selector.first_match(entries, &sources),
            Err(cause) => {
                let cause = Incompatibility::from(cause);
                Ok(Selection::Excluded(
                    entries
                        .iter()
                        .map(|entry| (entry.position(), cause.clone()))
                        .collect(),
                ))
            }
        }
    }

    /// Whether a source defines `entry`'s type for `credential` (OpenID4VP 1.0, Section 5.1),
    /// though the entry may not be compatible.
    pub fn knows(&self, entry: &Entry, credential: &'c Credential) -> bool {
        let served = self
            .sources
            .of(credential)
            .map_err(Incompatibility::from)
            .and_then(|sources| crate::select::Definitions::serve(&sources, entry).map(drop));
        served
            .as_ref()
            .err()
            .is_none_or(Incompatibility::type_defined)
    }
}
