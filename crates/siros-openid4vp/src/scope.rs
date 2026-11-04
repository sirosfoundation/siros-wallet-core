//! Scope values that stand for DCQL queries (§5.5: "The specific scope values, and the mapping
//! between a certain scope value and the respective DCQL query, are out of scope of this
//! specification"): a scope query is a plug-in, which a profile or the app registers. Over the DC
//! API `scope` is no parameter A.2 lists, and the wallet ignores it (reading 12). Scope queries
//! register under the feature `uri`; a build without it holds none, and a URI request's `scope`
//! names no registered query (S3).

use std::fmt;

use serde_json::value::RawValue;

#[cfg(feature = "uri")]
use crate::json::RawObject;
#[cfg(feature = "uri")]
use crate::request::Query;

/// A scope value (RFC 6749 §3.3's `scope-token`): one or more of %x21, %x23-5B, %x5D-7E. A plug-in
/// makes its own with `siros_explain::checked!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeValue(&'static str);

impl ScopeValue {
    /// The value; `None` for an empty text or another character.
    #[must_use]
    pub const fn new(value: &'static str) -> Option<Self> {
        let mut rest = value.as_bytes();
        if rest.is_empty() {
            return None;
        }
        while let [byte, tail @ ..] = rest {
            if !matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e) {
                return None;
            }
            rest = tail;
        }
        Some(Self(value))
    }

    /// The value as `scope` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ScopeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A scope value is named by its text in a message.
impl siros_explain::IntoArg for ScopeValue {
    type Kind = siros_explain::kind::Name;

    fn arg(&self) -> &'static str {
        self.0
    }
}

/// A scope value and the DCQL query it stands for (§5.5; feature `uri`).
///
/// # Implementing
///
/// `scope` and `query` are constants. The registry parses `query` with the core's DCQL reader when
/// it builds and refuses a query it does not read (`RegistryError::ScopeQuery`), a scope value
/// registered twice (`ScopeTwice`), and a Credential Query or claim id two scope values' queries
/// share (`ScopeIds`; §5.5: "MUST be unique"). A request by URI whose `scope` names registered
/// values is read as the union of their queries; a value no query names is S3 (`invalid_scope`).
#[cfg(feature = "uri")]
pub trait ScopeQuery: Send + Sync {
    /// The scope value.
    fn scope(&self) -> ScopeValue;
    /// The DCQL query, as JSON text.
    fn query(&self) -> &'static str;
}

/// A registered scope query as the registry read it: its value, its Credential Queries and its
/// Credential Sets, each as written.
#[derive(Debug, Clone)]
pub(crate) struct ScopeEntry {
    pub(crate) value: ScopeValue,
    pub(crate) credentials: Vec<&'static RawValue>,
    pub(crate) sets: Vec<&'static RawValue>,
    #[cfg_attr(
        not(feature = "uri"),
        expect(dead_code, reason = "the registry of a URI build checks the ids")
    )]
    pub(crate) ids: Vec<String>,
}

impl ScopeEntry {
    /// The entry of a scope query; `None` when the core's DCQL reader refuses its query.
    #[cfg(feature = "uri")]
    pub(crate) fn read(query: &dyn ScopeQuery) -> Option<Self> {
        let raw: &'static RawValue = serde_json::from_str(query.query()).ok()?;
        let queries = Query::read_all(raw).ok()?;
        let object = RawObject::parse(raw.get()).ok()?;
        let list = |name: &str| -> Option<Vec<&'static RawValue>> {
            object
                .get(name)
                .map(|value| serde_json::from_str(value.get()).ok())
                .unwrap_or(Some(Vec::new()))
        };
        let credentials = list("credentials")?;
        let sets = list("credential_sets")?;
        let mut ids: Vec<String> = queries.iter().map(|query| query.id.to_string()).collect();
        for credential in &credentials {
            let claims = RawObject::parse(credential.get())
                .ok()?
                .get("claims")
                .map(|claims| serde_json::from_str::<Vec<&RawValue>>(claims.get()).ok())
                .unwrap_or(Some(Vec::new()))?;
            for claim in claims {
                let id = RawObject::parse(claim.get())
                    .ok()?
                    .get("id")
                    .map(|id| serde_json::from_str::<String>(id.get()).ok());
                if let Some(id) = id {
                    ids.push(format!("claim {}", id?));
                }
            }
        }
        Some(Self {
            value: query.scope(),
            credentials,
            sets,
            ids,
        })
    }
}

/// The registered scope queries, as the request carries them from the registry its envelope was
/// read with.
#[derive(Debug, Clone, Copy)]
pub struct Scopes<'r>(&'r [ScopeEntry]);

impl<'r> Scopes<'r> {
    pub(crate) const fn of(entries: &'r [ScopeEntry]) -> Self {
        Self(entries)
    }

    /// The registered entry of a scope value.
    pub(crate) fn named(&self, value: &str) -> Option<&'r ScopeEntry> {
        self.0.iter().find(|entry| entry.value.as_str() == value)
    }
}
