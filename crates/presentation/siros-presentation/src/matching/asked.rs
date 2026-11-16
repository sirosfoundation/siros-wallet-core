//! The credential types a Credential Query asks for (A1, A2): what the matching reads of a
//! credential before its claims.

use serde_json::Value;
use siros_credential::Format;
use siros_dcql::{CredentialQuery, QueryId};
use siros_zkp_req::CredentialType;

use crate::credential::MatchCredential;

/// A credential type with the format it belongs to: an mdoc's `docType` or an SD-JWT VC's
/// `vct`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AskedType {
    format: Format,
    name: String,
}

/// A Credential Query's `id`, with the credential types its matching reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryTypes {
    pub(crate) query: QueryId,
    pub(crate) types: Vec<AskedType>,
}

impl AskedType {
    /// The format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// The `docType` or the `vct`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether `credential` is of this format and type.
    pub(crate) fn holds(&self, credential: &impl MatchCredential) -> bool {
        credential.format() == self.format && credential.credential_type() == self.name
    }

    /// The types `query` asks for (A1): an mdoc of `doctype_value` for `mso_mdoc`, an SD-JWT VC
    /// of each `vct` of `vct_values` for `dc+sd-jwt`, and for `zkp_req` the type its systems
    /// prove over, which its `meta` names. Any other format asks for none.
    pub(crate) fn of(query: &CredentialQuery) -> Vec<Self> {
        let meta = query.meta();
        match query.format().as_str() {
            "mso_mdoc" => meta
                .get("doctype_value")
                .and_then(Value::as_str)
                .map(|doctype| Self::of_format(Format::Mdoc, doctype))
                .into_iter()
                .collect(),
            "dc+sd-jwt" => meta
                .get("vct_values")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|vct| Self::of_format(Format::SdJwtVc, vct))
                .collect(),
            "zkp_req" => CredentialType::of_meta(meta)
                .ok()
                .and_then(|credential_type| Self::proven(&credential_type))
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The type the systems of a `zkp_req` query of `credential_type` prove over (A2): an mdoc
    /// of its `docType`.
    pub(crate) fn proven(credential_type: &CredentialType) -> Option<Self> {
        match credential_type {
            CredentialType::MsoMdoc { doctype } => {
                Some(Self::of_format(Format::Mdoc, doctype.as_str()))
            }
            CredentialType::SdJwt { .. }
            | CredentialType::W3c { .. }
            | CredentialType::Profiled { .. } => None,
        }
    }

    fn of_format(format: Format, name: &str) -> Self {
        Self {
            format,
            name: name.to_owned(),
        }
    }
}

impl QueryTypes {
    /// The Credential Query's `id`.
    pub fn query(&self) -> &QueryId {
        &self.query
    }

    /// The credential types its matching reads.
    pub fn types(&self) -> &[AskedType] {
        &self.types
    }
}
