//! The `zkp_req` entry of `vp_formats_supported` (`zkp_req`, Section 1.2).

use serde_json::Value;
use siros_codec::member::MemberFault;

use crate::ids::{ProofBackend, SystemId};
use crate::json::non_empty_strings;
use crate::outcome::RequestRule;

/// What the Verifier says it can verify.
///
/// Both lists are non-empty. They may name identifiers this Wallet does not know: Section 1.2
/// tells Wallets to ignore those, so they never match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpFormats {
    proof_backends: Vec<ProofBackend>,
    systems: Vec<SystemId>,
}

impl ZkpFormats {
    /// Reads `vp_formats_supported.zkp_req` from a request's `client_metadata`.
    ///
    /// # Errors
    ///
    /// [`RequestRule::FormatsMissing`] when the entry is absent or not an object: Section 1.2
    /// says the Verifier MUST send both lists. The list rules otherwise.
    pub fn from_client_metadata(client_metadata: &Value) -> Result<Self, RequestRule> {
        let entry = match client_metadata
            .get("vp_formats_supported")
            .and_then(|f| f.get("zkp_req"))
        {
            None => return Err(RequestRule::FormatsMissing(MemberFault::Absent)),
            Some(Value::Object(entry)) => entry,
            Some(_) => return Err(RequestRule::FormatsMissing(MemberFault::WrongType)),
        };
        Ok(Self {
            proof_backends: non_empty_strings(entry.get("proof_backend_values"), ProofBackend::new)
                .map_err(RequestRule::ProofBackendValuesInvalid)?,
            systems: non_empty_strings(entry.get("system_id_values"), SystemId::new)
                .map_err(RequestRule::SystemIdValuesInvalid)?,
        })
    }

    /// `proof_backend_values`, in the Verifier's order.
    #[must_use]
    pub fn proof_backends(&self) -> &[ProofBackend] {
        &self.proof_backends
    }

    /// `system_id_values`, in the Verifier's order.
    #[must_use]
    pub fn systems(&self) -> &[SystemId] {
        &self.systems
    }

    /// Whether the Verifier lists `system`.
    #[must_use]
    pub fn lists_system(&self, system: &SystemId) -> bool {
        self.systems.contains(system)
    }

    /// Whether the Verifier lists `backend`.
    #[must_use]
    pub fn lists_backend(&self, backend: &ProofBackend) -> bool {
        self.proof_backends.contains(backend)
    }
}
