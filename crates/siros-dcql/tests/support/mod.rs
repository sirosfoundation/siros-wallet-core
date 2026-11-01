//! The JSON credential and the helpers the selection tests share.

#![allow(dead_code)]

use serde_json::Value;
use siros_dcql::{
    ClaimPath, CredentialFormat, CredentialRef, CryptographicBinding, DcqlQuery, PathError,
    QueryResult, Satisfaction,
};

/// Whether the wallet can satisfy the request.
pub fn satisfiable(result: &QueryResult) -> bool {
    result.satisfaction() == Satisfaction::Satisfiable
}

/// A JSON credential, resolved with the §7.1 rules the crate provides.
pub struct JsonCredential {
    id: CredentialRef,
    format: CredentialFormat,
    body: Value,
    /// Cryptographic holder binding, so §6.1's requirement can be tested from
    /// both sides.
    binding: CryptographicBinding,
}

impl JsonCredential {
    pub fn new(id: &str, format: &str, body: Value) -> Self {
        Self {
            id: CredentialRef::new(id),
            format: CredentialFormat::new(format),
            body,
            binding: CryptographicBinding::Bound,
        }
    }

    /// The same credential, with no cryptographic holder binding.
    pub fn unbound(mut self) -> Self {
        self.binding = CryptographicBinding::Unbound;
        self
    }
}

impl siros_dcql::Credential for JsonCredential {
    fn id(&self) -> &CredentialRef {
        &self.id
    }
    fn format(&self) -> &CredentialFormat {
        &self.format
    }
    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        siros_dcql::resolve_json(&self.body, path).map(|v| v.into_iter().cloned().collect())
    }
    fn binding(&self) -> CryptographicBinding {
        self.binding
    }
}

pub fn pid(body: Value) -> JsonCredential {
    JsonCredential::new("pid-1", "dc+sd-jwt", body)
}

pub fn query(json: &str) -> DcqlQuery {
    DcqlQuery::from_json(json).expect("valid DCQL")
}
