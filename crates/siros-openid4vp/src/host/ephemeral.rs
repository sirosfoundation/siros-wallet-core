//! The wallet's ephemeral key for an encrypted Request Object (OpenID4VP §5.10, CS-12 §7.3 item
//! 9): fresh for each POST, posted in `wallet_metadata`'s `jwks`, consumed by the decryption.

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::{Coordinates, ToSec1Point};

use crate::json::{JsonError, Node};

/// A fresh P-256 key pair: p256's secret scalar, non-zero and below the group order, and the
/// public point it derives, which `jwks` holds with `use` `enc`. Only [`EphemeralKey::new`]
/// makes one, from the scalar, so the point is the scalar's; a pair assembled from parts does
/// not compile:
///
/// ```compile_fail,E0451
/// use siros_openid4vp::host::EphemeralKey;
///
/// fn pair(secret: p256::SecretKey, public: p256::PublicKey) -> EphemeralKey {
///     EphemeralKey { secret, public }
/// }
/// ```
///
/// The `Fetch` owns it until `resume` hands it to `RequestDecryption::decrypt`.
#[derive(Debug)]
pub struct EphemeralKey {
    secret: p256::SecretKey,
    public: p256::PublicKey,
}

impl EphemeralKey {
    /// The key pair of the scalar `RequestDecryption::ephemeral_key` drew.
    #[must_use]
    pub fn new(secret: p256::SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// The secret scalar, which `decrypt` agrees the content key with.
    #[must_use]
    pub const fn secret(&self) -> &p256::SecretKey {
        &self.secret
    }

    /// The public point.
    #[must_use]
    pub const fn public(&self) -> &p256::PublicKey {
        &self.public
    }

    /// The public JWK `wallet_metadata`'s `jwks` holds: `kty` `EC`, `crv` `P-256`, `x`, `y`
    /// (RFC 7518 §6.2.1), `use` `enc`, by which WE BUILD's test bed selects it.
    ///
    /// # Errors
    ///
    /// The point is the identity, which a key derived from a scalar of the group never is.
    pub fn jwk(&self) -> Result<Node<'static>, JsonError> {
        let point = self.public.to_sec1_point(false);
        let Coordinates::Uncompressed { x, y } = point.coordinates() else {
            return Err(JsonError::Syntax(
                "the key's point has no coordinates".to_owned(),
            ));
        };
        let text = |value: &str| Node::String(Cow::Owned(value.to_owned()));
        Node::object([
            (Cow::Borrowed("kty"), text("EC")),
            (Cow::Borrowed("crv"), text("P-256")),
            (Cow::Borrowed("x"), text(&URL_SAFE_NO_PAD.encode(x))),
            (Cow::Borrowed("y"), text(&URL_SAFE_NO_PAD.encode(y))),
            (Cow::Borrowed("use"), text("enc")),
        ])
    }
}
