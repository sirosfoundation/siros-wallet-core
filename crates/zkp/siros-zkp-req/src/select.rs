//! Choosing a system and a proof backend (`zkp_req`, Section 1.3).

use crate::formats::ZkpFormats;
use crate::ids::{ProofBackend, SystemId};
use crate::query::CredentialType;

/// A system as Section 1.3 judges it.
pub trait System {
    /// The system identifier.
    fn id(&self) -> SystemId;
    /// Whether the system runs on the proof backend `backend`.
    fn runs_on(&self, backend: &ProofBackend) -> bool;
    /// Whether the system proves over the source format and a type that `credential_type`
    /// allows.
    fn proves_over(&self, credential_type: &CredentialType) -> bool;
}

/// Why a system and a proof backend do not form a usable pair for an option (Section 1.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairRefusal<U> {
    /// The Verifier does not list the system in `system_id_values`.
    #[error("the Verifier does not list the system in `system_id_values`")]
    SystemNotListed,
    /// The system runs on no proof backend of `proof_backend_values`.
    #[error("the system runs on no proof backend of `proof_backend_values`")]
    NoListedBackend,
    /// The system proves over another source format or type than `meta` allows.
    #[error("the system proves over another source format or type than `meta` allows")]
    CredentialType,
    /// The system does not support the option's functions or parameter values. The system
    /// rulebook names this outcome `unsupported`.
    #[error("the system does not support the option's functions or parameter values")]
    Unsupported(#[source] U),
}

/// The proof backend of a usable pair of `system` for an option, or why there is none.
///
/// The rules of Section 1.3 apply in its order. `supports` judges the last two: the
/// combination of functions and the parameter values, defaults included. Among the backends
/// the system runs on, the first one the Verifier lists is chosen.
///
/// # Errors
///
/// [`PairRefusal`]: the first rule that fails.
pub fn usable_backend<'f, S, U>(
    formats: &'f ZkpFormats,
    credential_type: &CredentialType,
    system: &S,
    supports: impl FnOnce(&S) -> Result<(), U>,
) -> Result<&'f ProofBackend, PairRefusal<U>>
where
    S: System + ?Sized,
{
    if !formats.lists_system(&system.id()) {
        return Err(PairRefusal::SystemNotListed);
    }
    let backend = formats
        .proof_backends()
        .iter()
        .find(|b| system.runs_on(b))
        .ok_or(PairRefusal::NoListedBackend)?;
    if !system.proves_over(credential_type) {
        return Err(PairRefusal::CredentialType);
    }
    supports(system).map_err(PairRefusal::Unsupported)?;
    Ok(backend)
}
