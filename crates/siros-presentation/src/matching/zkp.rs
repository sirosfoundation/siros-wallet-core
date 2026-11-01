//! `zkp_req` matching (A2): the options in the Verifier's order, each with the first available
//! system that forms a usable pair for it.

use itertools::Itertools;
use serde_json::Value;
use siros_codec::date::Date;
use siros_dcql::CredentialQuery;
use siros_zkp_req::{
    ErrorCode, PairRefusal, ProofBackend, QueryOption, RequestRule, ZkpFormats, ZkpReqQuery,
};
use siros_zkp_req_nym_auth::catalogue::{CatalogueRule, NymAuthQuery};
use siros_zkp_req_nym_auth::pair::{NymAuthOption, UsablePair};
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::system::{pair_code, NymAuthSystem, Unsupported};

use crate::credential::{KeyHolding, MatchCredential};
use crate::ids::OptionIndex;
use crate::matching::AskedType;

/// A nym_auth query of a request that meets the nym_auth policy, with the options that have a
/// usable pair at the proof date.
#[derive(Debug, Clone)]
pub struct ZkpQuery {
    query: NymAuthQuery,
    formats: ZkpFormats,
    date: Date,
    choices: Vec<ProofChoice>,
}

/// An option of a nym_auth query, and the system and proof backend that form its usable pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofChoice {
    option: OptionIndex,
    system: NymAuthSystem,
    backend: ProofBackend,
}

/// Why a `zkp_req` query has no candidate whatever the wallet holds (`zkp_req.md`, Section 5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ZkpRefusal {
    /// The query breaks a rule of `zkp_req`.
    Query(#[source] RequestRule),
    /// The request has no `client_metadata` to list the Verifier's systems.
    ClientMetadataMissing,
    /// `client_metadata` breaks a rule of `zkp_req`, Section 1.2.
    ClientMetadata(#[source] RequestRule),
    /// The query breaks a rule of the nym_auth catalogue.
    Catalogue(#[source] CatalogueRule),
    /// The query asks for another credential type than nym_auth's.
    OtherType,
    /// The request breaks the nym_auth policy.
    Policy(#[source] RequestRefusal),
    /// No option has a usable pair: the refusal of each system for each option.
    NoUsablePair(Vec<PairRefusal<Unsupported>>),
}

impl ZkpRefusal {
    /// A stable identifier: the code of the rule broken, or `no_usable_pair`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Query(rule) | Self::ClientMetadata(rule) => rule.code(),
            Self::ClientMetadataMissing => "client_metadata_missing",
            Self::Catalogue(rule) => rule.code(),
            Self::OtherType => "other_credential_type",
            Self::Policy(refusal) => refusal.code(),
            Self::NoUsablePair(_) => "no_usable_pair",
        }
    }

    /// The `zkp_req.md`, Section 5 code: `vp_formats_not_supported` for another credential
    /// type or no usable pair, `invalid_request` for a broken rule.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::OtherType | Self::NoUsablePair(_) => ErrorCode::VpFormatsNotSupported,
            Self::Query(_)
            | Self::ClientMetadataMissing
            | Self::ClientMetadata(_)
            | Self::Catalogue(_)
            | Self::Policy(_) => ErrorCode::InvalidRequest,
        }
    }
}

/// Why a [`ProofChoice`] gives no option or usable pair of a query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ChoiceError {
    /// The query has no option at the choice's position: the choice is another query's.
    OptionUnknown(OptionIndex),
    /// The choice's system no longer forms a usable pair for the option.
    Pair(#[source] PairRefusal<Unsupported>),
}

impl ChoiceError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OptionUnknown(_) => "choice_option_unknown",
            Self::Pair(refusal) => pair_code(refusal),
        }
    }
}

impl ProofChoice {
    /// The option's position among the query's options.
    pub fn option(&self) -> OptionIndex {
        self.option
    }

    /// The system.
    pub fn system(&self) -> NymAuthSystem {
        self.system
    }

    /// The proof backend.
    pub fn backend(&self) -> &ProofBackend {
        &self.backend
    }
}

impl ZkpQuery {
    /// The nym_auth query of the Credential Query `query`, at the proof date `date`.
    ///
    /// The query follows `zkp_req` and the catalogue, `client_metadata` lists the Verifier's
    /// systems and proof backends (`zkp_req.md`, Section 1.2), and `policy` holds. Each option,
    /// in the Verifier's order, takes the first of `systems` that forms a usable pair for it.
    ///
    /// # Errors
    ///
    /// [`ZkpRefusal`]: the first rule the query, its metadata or the request breaks, another
    /// credential type, or no option with a usable pair.
    pub(crate) fn read(
        query: &CredentialQuery,
        client_metadata: Option<&Value>,
        policy: Result<(), RequestRefusal>,
        systems: &[NymAuthSystem],
        date: Date,
    ) -> Result<Self, ZkpRefusal> {
        let parsed = ZkpReqQuery::parse(query).map_err(ZkpRefusal::Query)?;
        let metadata = client_metadata.ok_or(ZkpRefusal::ClientMetadataMissing)?;
        let formats =
            ZkpFormats::from_client_metadata(metadata).map_err(ZkpRefusal::ClientMetadata)?;
        let query = NymAuthQuery::from_query(parsed)
            .map_err(ZkpRefusal::Catalogue)?
            .nym_auth()
            .ok_or(ZkpRefusal::OtherType)?;
        policy.map_err(ZkpRefusal::Policy)?;
        let (choices, refusals): (Vec<ProofChoice>, Vec<Vec<PairRefusal<Unsupported>>>) = query
            .options()
            .enumerate()
            .map(|(index, option)| {
                first_pair(OptionIndex::new(index), option, &formats, systems, date)
            })
            .partition_result();
        if choices.is_empty() {
            return Err(ZkpRefusal::NoUsablePair(refusals.concat()));
        }
        Ok(Self {
            query,
            formats,
            date,
            choices,
        })
    }

    /// The nym_auth query.
    pub fn query(&self) -> &NymAuthQuery {
        &self.query
    }

    /// The options with a usable pair, in the Verifier's order, each with its pair.
    pub fn choices(&self) -> &[ProofChoice] {
        &self.choices
    }

    /// The option of `choice`.
    ///
    /// # Errors
    ///
    /// [`ChoiceError::OptionUnknown`] for a choice of another query.
    pub fn option(&self, choice: &ProofChoice) -> Result<&QueryOption, ChoiceError> {
        self.query
            .query()
            .options()
            .get(choice.option.value())
            .ok_or(ChoiceError::OptionUnknown(choice.option))
    }

    /// The usable pair of `choice` again, at the proof date of the matching.
    ///
    /// # Errors
    ///
    /// [`ChoiceError`]: a choice of another query, or a pair no longer usable.
    pub fn pair(&self, choice: &ProofChoice) -> Result<UsablePair<'_>, ChoiceError> {
        self.query
            .options()
            .nth(choice.option.value())
            .ok_or(ChoiceError::OptionUnknown(choice.option))?
            .pair(&self.formats, choice.system, self.date)
            .map_err(ChoiceError::Pair)
    }

    /// The instances of `instances` the query's systems prove over: credentials of the type
    /// [`AskedType::proven`] gives whose key the wallet holds, the catalogue requiring holder
    /// binding.
    pub(crate) fn provable<C: MatchCredential + Clone>(&self, instances: &[&C]) -> Vec<C> {
        let Some(proven) = AskedType::proven(self.query.query().credential_type()) else {
            return Vec::new();
        };
        instances
            .iter()
            .filter(|credential| {
                proven.holds(**credential) && credential.key_holding() == KeyHolding::Held
            })
            .map(|credential| (*credential).clone())
            .collect()
    }
}

/// The choice of `option`, at `index`, with the first of `systems` that forms a usable pair for
/// it at `date`.
///
/// # Errors
///
/// The refusal of each system when none forms one.
fn first_pair(
    index: OptionIndex,
    option: NymAuthOption<'_>,
    formats: &ZkpFormats,
    systems: &[NymAuthSystem],
    date: Date,
) -> Result<ProofChoice, Vec<PairRefusal<Unsupported>>> {
    let (pairs, refusals): (Vec<UsablePair<'_>>, Vec<_>) = systems
        .iter()
        .map(|&system| option.pair(formats, system, date))
        .partition_result();
    pairs
        .into_iter()
        .next()
        .map(|pair| ProofChoice {
            option: index,
            system: pair.system(),
            backend: pair.backend().clone(),
        })
        .ok_or(refusals)
}
