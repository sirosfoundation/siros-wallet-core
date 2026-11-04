//! The wallet's ephemeral key for an encrypted Request Object (OpenID4VP §5.10, CS-12 §7.3 item
//! 9): fresh for each POST, posted in `wallet_metadata`'s `jwks`, consumed by the decryption.

use crate::jose::PublicJwk;

/// The decrypting module's reference to the secret of a key it drew; the core holds it and reads
/// nothing of it.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyHandle(u64);

impl KeyHandle {
    /// The module's identifier.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }
}

/// A fresh key the wallet posts: its public JWK, which `jwks` holds with `use` `enc`, and the
/// handle to the secret the decrypting module keeps. The core links no curve arithmetic: it
/// checks that the JWK is public ([`PublicJwk`]) and that its `crv` is one
/// `RequestDecryption::decrypts` states, a `Fault` otherwise. Only [`EphemeralKey::new`] makes
/// one; a pair assembled from parts does not compile:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::host::{EphemeralKey, KeyHandle};
/// use siros_openid4vp::jose::PublicJwk;
///
/// fn pair(public: PublicJwk, handle: KeyHandle) -> EphemeralKey {
///     EphemeralKey { public, handle }
/// }
/// ```
///
/// The `Fetch` owns it until `resume` hands it to `RequestDecryption::decrypt`.
#[derive(Debug)]
pub struct EphemeralKey {
    public: PublicJwk,
    handle: KeyHandle,
}

impl EphemeralKey {
    /// The key `RequestDecryption::ephemeral_key` drew: its public JWK and the handle to its
    /// secret.
    #[must_use]
    pub const fn new(public: PublicJwk, handle: KeyHandle) -> Self {
        Self { public, handle }
    }

    /// The public JWK.
    #[must_use]
    pub const fn public(&self) -> &PublicJwk {
        &self.public
    }

    /// The handle to the secret.
    #[must_use]
    pub const fn handle(&self) -> &KeyHandle {
        &self.handle
    }
}
