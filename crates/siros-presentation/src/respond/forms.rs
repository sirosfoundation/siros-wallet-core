//! The presentation of each format, from its preparation to its signature: an SD-JWT VC with
//! or without its KB-JWT, an mdoc's `DeviceResponse`, and a nym_auth proof.

use siros_codec::base64url;
use siros_mdoc::Disclosure;
use siros_oid4vp::Presentation;
use siros_sdjwt::KeyBinding;
use siros_zkp_req_nym_auth::presenter::Prepared as NymPrepared;
use siros_zkp_req_nym_auth::prover::NymAuthProver;

use super::sign::{SignId, SigningInput, VerifiedSignature};
use crate::error::PresentationError;

/// A presentation that waits for the signature of its holder key.
pub(crate) trait Unsigned {
    /// The bytes the holder key signs.
    fn signing_input(&self) -> SigningInput;

    /// The presentation, with `signature` of the signing input. `prover` proves a nym_auth
    /// statement.
    fn present(
        self: Box<Self>,
        signature: &VerifiedSignature,
        prover: &dyn NymAuthProver,
    ) -> Result<Presentation, PresentationError>;
}

/// A credential's presentation in its format: complete, or waiting for the signature of its
/// `Sign` effect.
pub(crate) enum Form<'p> {
    /// An SD-JWT VC without key binding.
    Ready(Presentation),
    /// A presentation and the effect whose signature completes it.
    Unsigned(Box<dyn Unsigned + 'p>, SignId),
}

impl<'p> Form<'p> {
    /// The form that waits for the signature of the effect `id`.
    pub(crate) fn unsigned(presentation: impl Unsigned + 'p, id: SignId) -> Self {
        Self::Unsigned(Box::new(presentation), id)
    }

    /// The presentation, completed with the signature `signatures` holds for its effect.
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: the presentation's format refuses it.
    pub(crate) fn present(
        self,
        signatures: &[VerifiedSignature],
        prover: &dyn NymAuthProver,
    ) -> Result<Presentation, PresentationError> {
        match self {
            Self::Ready(presentation) => Ok(presentation),
            Self::Unsigned(unsigned, id) => {
                let signature = signatures
                    .get(id.value())
                    .ok_or(super::sign::SignatureError::Missing(id))?;
                unsigned.present(signature, prover)
            }
        }
    }
}

/// An SD-JWT VC and its KB-JWT, signed by the `cnf` key (RFC 9901, Section 4.3).
impl Unsigned for KeyBinding {
    fn signing_input(&self) -> SigningInput {
        SigningInput::new(KeyBinding::signing_input(self).to_vec())
    }

    fn present(
        self: Box<Self>,
        signature: &VerifiedSignature,
        _prover: &dyn NymAuthProver,
    ) -> Result<Presentation, PresentationError> {
        Ok(Presentation::text(self.assemble(signature.signature())))
    }
}

/// An mdoc's disclosure and the DeviceAuthentication bytes its device key signs over the
/// request's SessionTranscript (ISO/IEC 18013-5, Section 9.1.3).
pub(crate) struct DeviceResponse<'p> {
    pub(crate) disclosure: Disclosure<'p>,
    pub(crate) input: SigningInput,
}

impl Unsigned for DeviceResponse<'_> {
    fn signing_input(&self) -> SigningInput {
        self.input.clone()
    }

    fn present(
        self: Box<Self>,
        signature: &VerifiedSignature,
        _prover: &dyn NymAuthProver,
    ) -> Result<Presentation, PresentationError> {
        let response = self.disclosure.device_response(signature.signature());
        Ok(Presentation::text(base64url::encode(&response).into()))
    }
}

/// A nym_auth statement, whose device signature the prover's job needs.
impl Unsigned for NymPrepared {
    fn signing_input(&self) -> SigningInput {
        SigningInput::new(self.data_to_sign().as_bytes().to_vec())
    }

    fn present(
        self: Box<Self>,
        signature: &VerifiedSignature,
        prover: &dyn NymAuthProver,
    ) -> Result<Presentation, PresentationError> {
        let proof = self.prove(signature.signature(), prover)?;
        Ok(Presentation::cbor_map(proof.encode())?)
    }
}
