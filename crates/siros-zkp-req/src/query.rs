//! A `zkp_req` Credential Query (`zkp_req`, Sections 1.1, 2 and 2.1).

use serde_json::{Map, Value};
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_dcql::{
    CredentialFormat, CredentialQuery, DocType, HolderBinding, Multiplicity, QueryId, Vct,
};

use crate::ids::{FnId, ItemIndex, ReqSetIndex, ReturnHandle, W3cType};
use crate::json::{identifier, non_empty_array, non_empty_strings};
use crate::outcome::{OptionFault, RequestRule, ReturnFault, TypeValueFault};

/// The Credential Format Identifier of a `zkp_req` query.
pub const FORMAT: &str = "zkp_req";

/// One `_req` item (Section 2).
#[derive(Debug, Clone, PartialEq)]
pub struct ReqItem {
    fn_id: FnId,
    ret: Option<ReturnHandle>,
    params: Map<String, Value>,
}

impl ReqItem {
    /// `fn_id`: a function of the catalogue of the credential's type.
    #[must_use]
    pub fn fn_id(&self) -> &FnId {
        &self.fn_id
    }

    /// `return`: the handle of the result. Absent for an assertion.
    #[must_use]
    pub fn ret(&self) -> Option<&ReturnHandle> {
        self.ret.as_ref()
    }

    /// `params`, as sent. Empty when absent: each parameter then takes its default.
    #[must_use]
    pub fn params(&self) -> &Map<String, Value> {
        &self.params
    }
}

/// One option: the `_req` items the Verifier accepts together (Section 2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOption {
    req_set: Option<ReqSetIndex>,
    items: Vec<ItemIndex>,
}

impl QueryOption {
    /// The option's index in `_req_sets`, which the presentation carries as `req_set`. `None`
    /// for the one option of a query without `_req_sets`.
    #[must_use]
    pub fn req_set(&self) -> Option<ReqSetIndex> {
        self.req_set
    }

    /// The `_req` indexes of the option, in the Verifier's order, each once.
    #[must_use]
    pub fn items(&self) -> &[ItemIndex] {
        &self.items
    }
}

/// The credential type a query asks for: `meta`, read for its `source_format`
/// (Section 1.1).
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialType {
    /// `mso_mdoc`, with `doctype_value` (OpenID4VP 1.0, B.2.3).
    MsoMdoc {
        /// `doctype_value`.
        doctype: DocType,
    },
    /// `dc+sd-jwt`, with `vct_values` (OpenID4VP 1.0, B.3.5).
    SdJwt {
        /// `vct_values`.
        vct_values: Vec<Vct>,
    },
    /// `jwt_vc_json` or `ldp_vc`, with `type_values` (OpenID4VP 1.0, B.1.1).
    W3c {
        /// The source format.
        source_format: CredentialFormat,
        /// `type_values`.
        type_values: Vec<Vec<W3cType>>,
    },
    /// A format whose own profile defines its `meta` members, such as `bbs_cd`.
    Profiled {
        /// The source format.
        source_format: CredentialFormat,
        /// `meta`, as sent.
        meta: Map<String, Value>,
    },
}

impl CredentialType {
    /// `meta.source_format`.
    #[must_use]
    pub fn source_format(&self) -> CredentialFormat {
        match self {
            Self::MsoMdoc { .. } => CredentialFormat::new("mso_mdoc"),
            Self::SdJwt { .. } => CredentialFormat::new("dc+sd-jwt"),
            Self::W3c { source_format, .. } | Self::Profiled { source_format, .. } => {
                source_format.clone()
            }
        }
    }
}

/// Whether a query has `_req_sets` (Section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReqSets {
    /// It has none: `_req` is its one option, and a presentation carries no `req_set`.
    Absent,
    /// Its options are its `_req_sets`, and a presentation names one by `req_set`.
    Present,
}

/// A `zkp_req` Credential Query: the DCQL Credential Query and what `zkp_req` reads from it.
#[derive(Debug, Clone, PartialEq)]
pub struct ZkpReqQuery {
    query: CredentialQuery,
    credential_type: CredentialType,
    items: Vec<ReqItem>,
    options: Vec<QueryOption>,
    req_sets: ReqSets,
}

impl ZkpReqQuery {
    /// The `zkp_req` reading of the Credential Query `query`, which DCQL parsed: its `format`,
    /// `meta`, `_req` and `_req_sets`.
    ///
    /// # Errors
    ///
    /// [`RequestRule`]: the first rule of Sections 1.1, 2 and 2.1 the query breaks.
    pub fn parse(query: &CredentialQuery) -> Result<Self, RequestRule> {
        if *query.format() != FORMAT {
            return Err(RequestRule::FormatNotZkpReq);
        }
        if !query.claims().is_empty() {
            return Err(RequestRule::ClaimsPresent);
        }
        let credential_type = CredentialType::of_meta(query.meta())?;
        let items = read_items(query.extension("_req"))?;
        let (options, req_sets) = read_options(query.extension("_req_sets"), items.len())?;
        Ok(Self {
            query: query.clone(),
            credential_type,
            items,
            options,
            req_sets,
        })
    }

    /// The DCQL Credential Query.
    #[must_use]
    pub fn credential_query(&self) -> &CredentialQuery {
        &self.query
    }

    /// `id`.
    #[must_use]
    pub fn id(&self) -> &QueryId {
        self.query.id()
    }

    /// `meta`, read for its source format.
    #[must_use]
    pub fn credential_type(&self) -> &CredentialType {
        &self.credential_type
    }

    /// `_req`, in order. An item's index identifies it.
    #[must_use]
    pub fn items(&self) -> &[ReqItem] {
        &self.items
    }

    /// The item at `index` of `_req`.
    #[must_use]
    pub fn item(&self, index: ItemIndex) -> Option<&ReqItem> {
        self.items.get(index.value())
    }

    /// The options, in the Verifier's order of preference.
    #[must_use]
    pub fn options(&self) -> &[QueryOption] {
        &self.options
    }

    /// Whether the query has `_req_sets`.
    #[must_use]
    pub fn req_sets(&self) -> ReqSets {
        self.req_sets
    }

    /// `require_cryptographic_holder_binding`; required when absent (OpenID4VP 1.0, Section
    /// 6.1).
    #[must_use]
    pub fn holder_binding(&self) -> HolderBinding {
        self.query.holder_binding()
    }

    /// `multiple`: whether several presentations may answer; one when absent (OpenID4VP 1.0,
    /// Section 6.1).
    #[must_use]
    pub fn multiplicity(&self) -> Multiplicity {
        self.query.multiplicity()
    }

    /// The option with index `req_set` of `_req_sets`, or the one option without them.
    #[must_use]
    pub fn option(&self, req_set: Option<ReqSetIndex>) -> Option<&QueryOption> {
        self.options.iter().find(|o| o.req_set == req_set)
    }
}

impl CredentialType {
    /// The credential type `meta` names for its `source_format` (Section 1.1).
    ///
    /// # Errors
    ///
    /// [`RequestRule::SourceFormatInvalid`] and [`RequestRule::TypeValueInvalid`].
    pub fn of_meta(meta: &Map<String, Value>) -> Result<Self, RequestRule> {
        let source_format = match meta.get("source_format") {
            None => Err(MemberFault::Absent),
            Some(Value::String(text)) if text.is_empty() => Err(MemberFault::Empty),
            Some(Value::String(text)) => Ok(text.as_str()),
            Some(_) => Err(MemberFault::WrongType),
        }
        .map_err(RequestRule::SourceFormatInvalid)?;
        let credential_type = match source_format {
            "mso_mdoc" => match meta.get("doctype_value") {
                None => Err(TypeValueFault::Member(MemberFault::Absent)),
                Some(Value::String(doctype)) => Ok(CredentialType::MsoMdoc {
                    doctype: DocType::new(doctype),
                }),
                Some(_) => Err(TypeValueFault::Member(MemberFault::WrongType)),
            },
            "dc+sd-jwt" => non_empty_strings(meta.get("vct_values"), Vct::new)
                .map(|vct_values| CredentialType::SdJwt { vct_values })
                .map_err(TypeValueFault::Member),
            "jwt_vc_json" | "ldp_vc" => {
                type_values(meta.get("type_values")).map(|type_values| CredentialType::W3c {
                    source_format: CredentialFormat::new(source_format),
                    type_values,
                })
            }
            _ => Ok(CredentialType::Profiled {
                source_format: CredentialFormat::new(source_format),
                meta: meta.clone(),
            }),
        };
        credential_type.map_err(RequestRule::TypeValueInvalid)
    }
}

/// `type_values`: a non-empty array of non-empty arrays of strings.
fn type_values(value: Option<&Value>) -> Result<Vec<Vec<W3cType>>, TypeValueFault> {
    let mut lists = Vec::new();
    for (index, entry) in non_empty_array(value)
        .map_err(TypeValueFault::Member)?
        .iter()
        .enumerate()
    {
        let list = non_empty_strings(Some(entry), W3cType::new)
            .map_err(|fault| TypeValueFault::List(ArrayIndex::new(index), fault))?;
        lists.push(list);
    }
    Ok(lists)
}

fn read_items(req: Option<&Value>) -> Result<Vec<ReqItem>, RequestRule> {
    let items = non_empty_array(req).map_err(RequestRule::ReqInvalid)?;
    let mut out: Vec<ReqItem> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let index = ItemIndex::new(index);
        let item = read_item(item, index)?;
        let repeated = item
            .ret
            .as_ref()
            .is_some_and(|handle| out.iter().any(|seen| seen.ret.as_ref() == Some(handle)));
        if repeated {
            return Err(RequestRule::ReturnRepeated { item: index });
        }
        out.push(item);
    }
    Ok(out)
}

fn read_item(item: &Value, index: ItemIndex) -> Result<ReqItem, RequestRule> {
    let item = item
        .as_object()
        .ok_or(RequestRule::ItemNotObject { item: index })?;
    if item
        .keys()
        .any(|k| !matches!(k.as_str(), "fn_id" | "params" | "return"))
    {
        return Err(RequestRule::ItemMemberUnknown { item: index });
    }
    let fn_id = identifier(item.get("fn_id"), FnId::parse)
        .map_err(|fault| RequestRule::FnIdInvalid { item: index, fault })?;
    let params = match item.get("params") {
        None => Map::new(),
        Some(Value::Object(params)) => params.clone(),
        Some(_) => return Err(RequestRule::ParamsNotObject { item: index }),
    };
    let ret = item
        .get("return")
        .map(|value| {
            let text = value.as_str().ok_or(ReturnFault::NotString)?;
            ReturnHandle::parse(text).map_err(ReturnFault::Syntax)
        })
        .transpose()
        .map_err(|fault| RequestRule::ReturnInvalid { item: index, fault })?;
    Ok(ReqItem { fn_id, ret, params })
}

fn read_options(
    sets: Option<&Value>,
    items: usize,
) -> Result<(Vec<QueryOption>, ReqSets), RequestRule> {
    if sets.is_none() {
        let all = QueryOption {
            req_set: None,
            items: (0..items).map(ItemIndex::new).collect(),
        };
        return Ok((vec![all], ReqSets::Absent));
    }
    let options = non_empty_array(sets)
        .map_err(RequestRule::ReqSetsInvalid)?
        .iter()
        .enumerate()
        .map(|(index, set)| {
            let option = ReqSetIndex::new(index);
            read_option(set, items)
                .map(|items| QueryOption {
                    req_set: Some(option),
                    items,
                })
                .map_err(|fault| RequestRule::OptionInvalid { option, fault })
        })
        .collect::<Result<_, _>>()?;
    Ok((options, ReqSets::Present))
}

/// The `_req` indexes of an option of `_req_sets`, for a `_req` of `items` items.
fn read_option(set: &Value, items: usize) -> Result<Vec<ItemIndex>, OptionFault> {
    let set = match set {
        Value::Array(set) if set.is_empty() => return Err(OptionFault::Empty),
        Value::Array(set) => set,
        _ => return Err(OptionFault::NotArray),
    };
    let mut out: Vec<ItemIndex> = Vec::with_capacity(set.len());
    for (position, entry) in set.iter().enumerate() {
        let position = ArrayIndex::new(position);
        let index = entry.as_u64().ok_or(OptionFault::NotInteger(position))?;
        let item = match usize::try_from(index) {
            Ok(index) if index < items => ItemIndex::new(index),
            Ok(_) | Err(_) => return Err(OptionFault::OutOfRange(position)),
        };
        if out.contains(&item) {
            return Err(OptionFault::Repeated(item));
        }
        out.push(item);
    }
    Ok(out)
}
