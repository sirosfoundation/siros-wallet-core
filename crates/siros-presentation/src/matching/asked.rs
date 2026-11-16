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
    ///
    /// The type names compare EUDI-URN-spelling-insensitively - a
    /// deliberately SCOPED compat shim, not a general rule: SD-JWT VC's
    /// `vct` is a case-sensitive collision-resistant identifier and
    /// `eudi:eucc:1` vs `urn:eudi:eucc:1` are formally two types. But the
    /// EUDI ARF rulebooks mandate URN-qualified type identifiers
    /// (e.g. PID_14: "a URN within the `urn:eudi:pid:` namespace"), while
    /// issuers in the same ecosystem keep shipping the unprefixed
    /// spelling (Spherity's EUCC SD-JWT metadata declares
    /// `vct: eudi:eucc:1`; Accredify's ACRA UAT request names
    /// `urn:eudi:eucc:1`, found on-device 2026-11-16: the wallet held
    /// exactly the credential the query asked for and the literal
    /// compare 400'd "no matching credential").
    ///
    /// Scope: the `urn:` prefix is stripped ONLY where the remainder
    /// starts `eudi:` - the one namespace this interoperability gap is
    /// actually observed in, and the one the ARF itself defines as
    /// URN-native. A general `urn:` strip would merge identifier
    /// distinctions for every other namespace, which the spec
    /// deliberately draws (and a future ecosystem could rely on).
    /// No case folding anywhere - `vct` is case-sensitive.
    ///
    /// TIME-BOXED: the issuer-side fix exists (Spherity: correct the
    /// `vct`, or add `aka_vcts: ["urn:eudi:eucc:1"]` - SD-JWT VC §2.2.2.2's
    /// own mechanism for "this credential is also of type X"). When the
    /// corrected issuer has landed, re-visit: either drop this shim and
    /// return to literal matching, or keep it as EUDI-ecosystem policy.
    /// The Kotlin SharedDcqlMatcher's reportDifference logs every match
    /// the literal built-in would not have offered - that is this
    /// shim's loud firing record.
    pub(crate) fn holds(&self, credential: &impl MatchCredential) -> bool {
        fn eudi_bare(name: &str) -> &str {
            match name.strip_prefix("urn:") {
                Some(rest) if rest.starts_with("eudi:") => rest,
                _ => name,
            }
        }
        credential.format() == self.format
            && eudi_bare(credential.credential_type()) == eudi_bare(&self.name)
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
