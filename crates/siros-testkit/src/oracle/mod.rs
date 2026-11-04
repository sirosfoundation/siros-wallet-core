//! The reference model's shapes the repository's tests read: a response member as the model writes
//! it ([`member`]), and the registry a fallback's consent re-runs with ([`informed`]). The
//! harness's siros-oracle compares the port with the model through them.

mod inputs;

use siros_explain::Explain;
use siros_openid4vp::ids::InvalidId;
use siros_openid4vp::plugins::{Fault, ProfileFinding, Registry};
use siros_openid4vp::resolve::Finding;

pub use inputs::{bytes, field, member, missing, text};

/// Why a run could not compare.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "testkit.oracle")]
pub enum OracleError {
    /// The exporter did not run, or failed.
    #[error("the exporter: {0}")]
    Export(#[explain(name = "detail")] String),
    /// The export holds no input of the shape the port reads.
    #[error("the export: {0}")]
    Input(#[explain(name = "detail")] String),
    /// The port failed where the model answered.
    #[error("the port: {0}")]
    Port(#[explain(name = "detail")] String),
}

impl From<InvalidId> for OracleError {
    fn from(error: InvalidId) -> Self {
        Self::Input(error.to_string())
    }
}

impl From<Fault> for OracleError {
    fn from(error: Fault) -> Self {
        Self::Port(error.to_string())
    }
}

/// The registry the wallet re-runs a fallback's consent with: the registry phase 2 ran with, its
/// profiles informed of their findings.
pub fn informed<H>(
    registry: &Registry<H>,
    findings: &[Finding],
) -> Result<Registry<H>, OracleError> {
    let revalidations: Vec<&ProfileFinding> = findings
        .iter()
        .filter_map(|finding| match finding {
            Finding::Revalidation { finding, .. } => Some(finding),
            Finding::Diverged { .. } | Finding::Unusable { .. } | Finding::Format { .. } => None,
        })
        .collect();
    registry
        .informed(&revalidations)
        .map_err(|e| OracleError::Port(e.to_string()))
}
