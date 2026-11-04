//! A JWS signature's algorithm, and the identifiers of `vp_formats_supported` it matches (B.3.4:
//! fully-specified identifiers, RFC 9864).

use std::borrow::Cow;

use siros_openid4vp::json::Node;

/// A JWS signer: the `alg` it signs with, and its key's curve when the view names one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signer<'v> {
    /// The `alg` header value.
    pub(crate) alg: &'v str,
    /// The key's curve.
    pub(crate) curve: Option<&'v str>,
}

impl<'v> Signer<'v> {
    /// Its `alg`, and for EdDSA the fully-specified algorithm of its curve: RFC 9864 §2.2 names
    /// `Ed25519` and `Ed448` after their curves. A JOSE ECDSA algorithm names its curve already.
    pub(crate) fn identifiers(self) -> Vec<Node<'static>> {
        let fully_specified = (self.alg == "EdDSA")
            .then_some(self.curve)
            .flatten()
            .filter(|curve| matches!(*curve, "Ed25519" | "Ed448"));
        std::iter::once(self.alg)
            .chain(fully_specified)
            .map(|name| Node::String(Cow::Owned(name.to_owned())))
            .collect()
    }
}
