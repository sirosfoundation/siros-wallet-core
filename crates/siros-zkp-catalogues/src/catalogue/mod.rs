//! The nym_auth function catalogue: the `pseudonym` and `age_check` items, and the rules a
//! nym_auth Credential Query follows (nym_auth rulebook, "Presentation" and "Function
//! catalogue").

use serde_json::{Map, Value};
use siros_codec::date::Date;
use siros_dcql::{DocType, HolderBinding};
use siros_zkp_req::{
    CredentialType, FnId, ItemIndex, QueryOption, ReqItem, ReturnHandle, ZkpReqQuery,
};

use crate::age::{AgeRange, Bounds, RangeError};

mod rule;

pub use rule::{CatalogueRule, ContextFault, ParamFault};

/// The `docType` and namespace of the ISO/IEC 18013-5 form.
pub const MDOC_DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
/// [`MDOC_DOCTYPE`], typed.
#[must_use]
pub fn nym_auth_doc_type() -> DocType {
    DocType::new(MDOC_DOCTYPE)
}

/// The schema identifier of the `bbs_cd` form.
pub const BBS_SCHEMA_ID: &str = "eu.europa.ec.eudi.nym_auth.bbs.1";

/// The types of the nym_auth attestations: the `docType` of the ISO/IEC 18013-5 form and the
/// schema identifier of the `bbs_cd` form. No query but `zkp_req` discloses their attributes.
pub const ATTESTATION_TYPES: [&str; 2] = [MDOC_DOCTYPE, BBS_SCHEMA_ID];

/// The attributes of a nym_auth attestation that nothing discloses: the commitments, the seed
/// and the birth date (R-G6).
pub const UNDISCLOSABLE: [&str; 4] = ["ssc", "psc", "secret_seed", "birth_date"];

/// The form of the attestation a query asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form {
    /// `mso_mdoc`, `doctype_value` [`MDOC_DOCTYPE`].
    Mdoc,
    /// `bbs_cd`, `schema_id_value` [`BBS_SCHEMA_ID`].
    BbsCd,
}

/// `verifier_context` of `account-recovery-ssc`: 1 to 64 bytes of UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifierContext(String);

/// Why a text is no `verifier_context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum VerifierContextError {
    /// The text is empty.
    #[error("the text is empty")]
    Empty,
    /// The text has this many bytes, more than 64.
    #[error("the text has {0} bytes, more than 64")]
    TooLong(usize),
}

impl VerifierContext {
    /// The context `text`.
    ///
    /// # Errors
    ///
    /// [`VerifierContextError`]: an empty text, or one of more than 64 bytes.
    pub fn parse(text: &str) -> Result<Self, VerifierContextError> {
        match text.len() {
            0 => Err(VerifierContextError::Empty),
            1..=64 => Ok(Self(text.to_owned())),
            length => Err(VerifierContextError::TooLong(length)),
        }
    }

    /// The context.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A `pseudonym` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Config {
    /// `known-offender-matching-ssc`.
    KnownOffenderMatchingSsc,
    /// `known-offender-matching-psc`.
    KnownOffenderMatchingPsc,
    /// `account-recovery-ssc`, with its `verifier_context`.
    AccountRecoverySsc {
        /// `verifier_context`, as sent.
        verifier_context: VerifierContext,
    },
    /// `user-managed-pseudonym-xsite-ssc`.
    UserManagedPseudonymXsiteSsc,
}

impl Config {
    /// The configuration's identifier.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KnownOffenderMatchingSsc => "known-offender-matching-ssc",
            Self::KnownOffenderMatchingPsc => "known-offender-matching-psc",
            Self::AccountRecoverySsc { .. } => "account-recovery-ssc",
            Self::UserManagedPseudonymXsiteSsc => "user-managed-pseudonym-xsite-ssc",
        }
    }
}

/// The pseudorandom function of a `pseudonym`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prf {
    /// `sha-256`.
    Sha256,
    /// `hashdh-bls12381g1`.
    HashdhBls12381G1,
}

impl Prf {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "sha-256" => Some(Self::Sha256),
            "hashdh-bls12381g1" => Some(Self::HashdhBls12381G1),
            _ => None,
        }
    }

    /// Whether the catalogue defines this PRF for `form` and `config`.
    fn defined_for(self, form: Form, config: &Config) -> bool {
        match (self, form) {
            (Self::Sha256, Form::Mdoc) => true,
            (Self::HashdhBls12381G1, Form::BbsCd) => *config == Config::KnownOffenderMatchingSsc,
            (Self::Sha256, Form::BbsCd) | (Self::HashdhBls12381G1, Form::Mdoc) => false,
        }
    }
}

/// The parameters of a `pseudonym` item: a configuration and a PRF the catalogue defines for
/// it and the query's form. Its `ver` is 1, the only version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pseudonym {
    config: Config,
    prf: Prf,
}

impl Pseudonym {
    /// `config`, with `verifier_context` where the configuration takes one.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// `prf`.
    #[must_use]
    pub fn prf(&self) -> Prf {
        self.prf
    }
}

/// The parameters of an `age_check` item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgeCheck {
    range: AgeRange,
}

impl AgeCheck {
    /// `range`.
    #[must_use]
    pub fn range(&self) -> &AgeRange {
        &self.range
    }
}

/// The `fn_id` of `pseudonym`.
const PSEUDONYM: &str = "pseudonym";
/// The `fn_id` of `age_check`.
const AGE_CHECK: &str = "age_check";

/// Whether the function `fn_id` has a result (`zkp_req`, Section 3): `pseudonym` has a `bstr`,
/// `age_check` none.
#[must_use]
pub fn has_result(fn_id: &FnId) -> bool {
    fn_id.as_str() == PSEUDONYM
}

/// One `_req` item, typed: its function, the function's parameters and its `return`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Item {
    /// `pseudonym`, whose `bstr` result `results` carries under `ret`.
    Pseudonym {
        /// The parameters.
        pseudonym: Pseudonym,
        /// `return`.
        ret: ReturnHandle,
    },
    /// `age_check`, an assertion: `results` carries `true` under its `return`, when it has one.
    AgeCheck {
        /// The parameters.
        check: AgeCheck,
        /// `return`.
        ret: Option<ReturnHandle>,
    },
}

impl Item {
    /// `return`.
    #[must_use]
    pub fn ret(&self) -> Option<&ReturnHandle> {
        match self {
            Self::Pseudonym { ret, .. } => Some(ret),
            Self::AgeCheck { ret, .. } => ret.as_ref(),
        }
    }

    /// The parameters of a `pseudonym`.
    #[must_use]
    pub fn pseudonym(&self) -> Option<&Pseudonym> {
        match self {
            Self::Pseudonym { pseudonym, .. } => Some(pseudonym),
            Self::AgeCheck { .. } => None,
        }
    }

    /// The parameters of an `age_check`.
    #[must_use]
    pub fn age_check(&self) -> Option<&AgeCheck> {
        match self {
            Self::AgeCheck { check, .. } => Some(check),
            Self::Pseudonym { .. } => None,
        }
    }
}

/// The `pseudonym` item of an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PseudonymItem<'q> {
    /// Its `_req` index.
    pub index: ItemIndex,
    /// Its parameters.
    pub pseudonym: &'q Pseudonym,
    /// Its `return`.
    pub ret: &'q ReturnHandle,
}

/// A nym_auth Credential Query: a `zkp_req` query that follows the catalogue's rules.
#[derive(Debug, Clone, PartialEq)]
pub struct NymAuthQuery {
    query: ZkpReqQuery,
    form: Form,
    items: Vec<Item>,
}

/// A `zkp_req` query sorted by the catalogue.
#[derive(Debug, Clone, PartialEq)]
pub enum Catalogued {
    /// A query for a nym_auth attestation.
    NymAuth(NymAuthQuery),
    /// A query for another credential type. The catalogue does not apply to it.
    OtherType(ZkpReqQuery),
}

impl Catalogued {
    /// The query as `zkp_req` reads it.
    #[must_use]
    pub fn into_query(self) -> ZkpReqQuery {
        match self {
            Self::NymAuth(query) => query.query,
            Self::OtherType(query) => query,
        }
    }

    /// The nym_auth query; `None` for a query for another credential type.
    #[must_use]
    pub fn nym_auth(self) -> Option<NymAuthQuery> {
        match self {
            Self::NymAuth(query) => Some(query),
            Self::OtherType(_) => None,
        }
    }
}

impl NymAuthQuery {
    /// Reads `query` against the catalogue. A query for another credential type comes back as
    /// [`Catalogued::OtherType`].
    ///
    /// # Errors
    ///
    /// [`CatalogueRule`]: the first rule the query breaks.
    pub fn from_query(query: ZkpReqQuery) -> Result<Catalogued, CatalogueRule> {
        let Some(form) = form_of(query.credential_type())? else {
            return Ok(Catalogued::OtherType(query));
        };
        if query.holder_binding() == HolderBinding::Optional {
            return Err(CatalogueRule::HolderBindingWaived);
        }
        let items = query
            .items()
            .iter()
            .enumerate()
            .map(|(index, item)| read_item(ItemIndex::new(index), item, form))
            .collect::<Result<Vec<_>, _>>()?;
        query
            .options()
            .iter()
            .try_for_each(|option| check_option(option, &items))?;
        Ok(Catalogued::NymAuth(Self { query, form, items }))
    }

    /// The query as `zkp_req` reads it.
    #[must_use]
    pub fn query(&self) -> &ZkpReqQuery {
        &self.query
    }

    /// The attestation form it asks for.
    #[must_use]
    pub fn form(&self) -> Form {
        self.form
    }

    /// `_req`, typed, in order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The typed items of `option`, with their `_req` indexes.
    pub fn option_items<'a>(
        &'a self,
        option: &'a QueryOption,
    ) -> impl Iterator<Item = (ItemIndex, &'a Item)> + 'a {
        option
            .items()
            .iter()
            .filter_map(move |&index| self.items.get(index.value()).map(|item| (index, item)))
    }

    /// The bounds of `option` at the date `d`: those of its `age_check`, or the widest.
    #[must_use]
    pub fn option_bounds(&self, option: &QueryOption, d: Date) -> Bounds {
        self.option_items(option)
            .find_map(|(_, item)| item.age_check())
            .map_or(Bounds::WIDEST, |check| check.range.bounds(d))
    }

    /// The `pseudonym` item of `option`.
    pub fn option_pseudonym<'a>(&'a self, option: &'a QueryOption) -> Option<PseudonymItem<'a>> {
        self.option_items(option)
            .find_map(|(index, item)| match item {
                Item::Pseudonym { pseudonym, ret } => Some(PseudonymItem {
                    index,
                    pseudonym,
                    ret,
                }),
                Item::AgeCheck { .. } => None,
            })
    }
}

fn form_of(credential_type: &CredentialType) -> Result<Option<Form>, CatalogueRule> {
    match credential_type {
        CredentialType::MsoMdoc { doctype } => {
            Ok((doctype.as_str() == MDOC_DOCTYPE).then_some(Form::Mdoc))
        }
        CredentialType::Profiled {
            source_format,
            meta,
        } if source_format.as_str() == "bbs_cd" => match meta.get("schema_id_value") {
            Some(Value::String(schema)) => Ok((schema == BBS_SCHEMA_ID).then_some(Form::BbsCd)),
            None => Err(CatalogueRule::SchemaIdInvalid(ParamFault::Absent)),
            Some(_) => Err(CatalogueRule::SchemaIdInvalid(ParamFault::WrongType)),
        },
        CredentialType::SdJwt { .. }
        | CredentialType::W3c { .. }
        | CredentialType::Profiled { .. } => Ok(None),
    }
}

fn check_option(option: &QueryOption, items: &[Item]) -> Result<(), CatalogueRule> {
    let functions = option
        .items()
        .iter()
        .filter_map(|index| items.get(index.value()));
    let (pseudonyms, ages) = functions.fold((0_usize, 0_usize), |(p, a), item| match item {
        Item::Pseudonym { .. } => (p + 1, a),
        Item::AgeCheck { .. } => (p, a + 1),
    });
    if pseudonyms > 1 {
        return Err(CatalogueRule::PseudonymRepeated {
            option: option.req_set(),
        });
    }
    if ages > 1 {
        return Err(CatalogueRule::AgeCheckRepeated {
            option: option.req_set(),
        });
    }
    Ok(())
}

fn read_item(index: ItemIndex, item: &ReqItem, form: Form) -> Result<Item, CatalogueRule> {
    match item.fn_id().as_str() {
        PSEUDONYM => {
            let ret = item
                .ret()
                .cloned()
                .ok_or(CatalogueRule::PseudonymReturnMissing { item: index })?;
            let pseudonym = read_pseudonym(index, item.params(), form)?;
            Ok(Item::Pseudonym { pseudonym, ret })
        }
        AGE_CHECK => Ok(Item::AgeCheck {
            check: read_age_check(index, item.params())?,
            ret: item.ret().cloned(),
        }),
        _ => Err(CatalogueRule::FunctionUnknown { item: index }),
    }
}

fn only_params(
    index: ItemIndex,
    params: &Map<String, Value>,
    known: &[&str],
) -> Result<(), CatalogueRule> {
    if params.keys().any(|k| !known.contains(&k.as_str())) {
        return Err(CatalogueRule::ParamUnknown { item: index });
    }
    Ok(())
}

/// The string parameter `name`.
fn text_param<'p>(params: &'p Map<String, Value>, name: &str) -> Result<&'p str, ParamFault> {
    params
        .get(name)
        .ok_or(ParamFault::Absent)?
        .as_str()
        .ok_or(ParamFault::WrongType)
}

fn read_pseudonym(
    index: ItemIndex,
    params: &Map<String, Value>,
    form: Form,
) -> Result<Pseudonym, CatalogueRule> {
    only_params(index, params, &["config", "ver", "prf", "verifier_context"])?;
    let config_invalid = |fault| CatalogueRule::ConfigInvalid { item: index, fault };
    let name = text_param(params, "config").map_err(config_invalid)?;
    let config =
        read_config(name, params.get("verifier_context")).map_err(|fault| match fault {
            ConfigFault::Name => config_invalid(ParamFault::Value),
            ConfigFault::Context(fault) => {
                CatalogueRule::VerifierContextInvalid { item: index, fault }
            }
        })?;
    match params.get("ver").map(Value::as_u64) {
        Some(Some(1)) => {}
        Some(Some(_)) => return Err(ver_invalid(index, ParamFault::Value)),
        Some(None) => return Err(ver_invalid(index, ParamFault::WrongType)),
        None => return Err(ver_invalid(index, ParamFault::Absent)),
    }
    let prf_invalid = |fault| CatalogueRule::PrfInvalid { item: index, fault };
    let prf = Prf::parse(text_param(params, "prf").map_err(prf_invalid)?)
        .ok_or(prf_invalid(ParamFault::Value))?;
    if !prf.defined_for(form, &config) {
        return Err(CatalogueRule::PrfUndefined { item: index, prf });
    }
    Ok(Pseudonym { config, prf })
}

fn ver_invalid(item: ItemIndex, fault: ParamFault) -> CatalogueRule {
    CatalogueRule::VerInvalid { item, fault }
}

/// Why `config` and `verifier_context` name no configuration.
#[derive(Debug, thiserror::Error)]
enum ConfigFault {
    /// `config` names none.
    #[error("`config` names none")]
    Name,
    /// `verifier_context` breaks its rule for the configuration.
    #[error("`verifier_context` breaks its rule for the configuration")]
    Context(#[from] ContextFault),
}

/// The configuration named `name`. `verifier_context` is required for account recovery and
/// forbidden elsewhere.
fn read_config(name: &str, context: Option<&Value>) -> Result<Config, ConfigFault> {
    let config = match name {
        "known-offender-matching-ssc" => Config::KnownOffenderMatchingSsc,
        "known-offender-matching-psc" => Config::KnownOffenderMatchingPsc,
        "user-managed-pseudonym-xsite-ssc" => Config::UserManagedPseudonymXsiteSsc,
        "account-recovery-ssc" => {
            let text = context
                .ok_or(ContextFault::Absent)?
                .as_str()
                .ok_or(ContextFault::WrongType)?;
            let verifier_context = VerifierContext::parse(text).map_err(ContextFault::Invalid)?;
            return Ok(Config::AccountRecoverySsc { verifier_context });
        }
        _ => return Err(ConfigFault::Name),
    };
    match context {
        None => Ok(config),
        Some(_) => Err(ConfigFault::Context(ContextFault::Forbidden)),
    }
}

fn read_age_check(
    index: ItemIndex,
    params: &Map<String, Value>,
) -> Result<AgeCheck, CatalogueRule> {
    only_params(index, params, &["range"])?;
    let syntax = |fault| CatalogueRule::RangeSyntax { item: index, fault };
    let range =
        AgeRange::parse(text_param(params, "range").map_err(syntax)?).map_err(|e| match e {
            RangeError::Syntax => syntax(ParamFault::Value),
            RangeError::Inverted => CatalogueRule::RangeInverted { item: index },
        })?;
    Ok(AgeCheck { range })
}
