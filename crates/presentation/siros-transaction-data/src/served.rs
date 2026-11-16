//! What a credential's sources serve for each transaction data type, as the wallet records it
//! at registration and the credential picker serves entries from it (K1, K2).

use crate::sources::CredentialSource;
use crate::type_id::TypeId;

/// Why a credential's sources serve no definition of a type, as a registration records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unserved {
    /// The credential is no SD-JWT VC.
    Format,
    /// No source defines the type for the credential.
    TypeUnsupported,
    /// The credential's own metadata declares every type it supports, and not this one.
    TypeUndeclared,
    /// The host holds no issuer metadata of the credential's configuration.
    IssuerMetadataNotHeld,
    /// The credential's signed credential metadata is not held or invalid.
    CredentialMetadata,
    /// The credential's TS12 type metadata gives no definition of the type.
    TypeMetadata,
    /// The definition of this source breaks PaSO Proof Metadata, Section 3.
    Definition(CredentialSource),
    /// A localised array of the definition has no entry for the wallet's language.
    Language,
}

impl Unserved {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Format => "transaction_data_format_unsupported",
            Self::TypeUnsupported => "transaction_data_type_unsupported",
            Self::TypeUndeclared => "transaction_data_type_undeclared",
            Self::IssuerMetadataNotHeld => "transaction_data_issuer_metadata_not_held",
            Self::CredentialMetadata => "credential_metadata_invalid",
            Self::TypeMetadata => "type_metadata_invalid",
            Self::Definition(_) => "definition_invalid",
            Self::Language => "language_unmatched",
        }
    }

    /// Whether a source defines the type for the credential, though it serves no definition:
    /// every reason but a format without transaction data and a type no source declares
    /// (OpenID4VP 1.0, Section 5.1).
    #[must_use]
    pub fn type_defined(self) -> bool {
        match self {
            Self::Format | Self::TypeUnsupported | Self::TypeUndeclared => false,
            Self::IssuerMetadataNotHeld
            | Self::CredentialMetadata
            | Self::TypeMetadata
            | Self::Definition(_)
            | Self::Language => true,
        }
    }
}

/// What a credential's own metadata and the configuration serve for it: for each type a source
/// names, the definition in the wallet's language or why there is none, and for every other
/// type one reason. `D` is the definition: the projection, or its place in a registration.
#[derive(Debug, Clone, PartialEq)]
pub struct ServedTypes<D> {
    types: Vec<(TypeId, Result<D, Unserved>)>,
    otherwise: Unserved,
}

/// Why types are no [`ServedTypes`]: this type is named twice.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub struct TypeRepeated(pub TypeId);

impl TypeRepeated {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "served_type_repeated"
    }
}

impl<D> ServedTypes<D> {
    /// What `types` names, each type once, and `otherwise` for every other type.
    ///
    /// # Errors
    ///
    /// [`TypeRepeated`] for a type named twice.
    pub fn new(
        types: Vec<(TypeId, Result<D, Unserved>)>,
        otherwise: Unserved,
    ) -> Result<Self, TypeRepeated> {
        let repeated = types
            .iter()
            .enumerate()
            .find(|(at, (type_id, _))| types.iter().take(*at).any(|(t, _)| t == type_id));
        if let Some((_, (type_id, _))) = repeated {
            return Err(TypeRepeated(type_id.clone()));
        }
        Ok(Self { types, otherwise })
    }

    /// What `serve` gives for each type of `named`, each type once, and `otherwise` for every
    /// other type.
    #[cfg(feature = "wallet")]
    pub(crate) fn collect(
        named: impl IntoIterator<Item = TypeId>,
        mut serve: impl FnMut(&TypeId) -> Result<D, Unserved>,
        otherwise: Unserved,
    ) -> Self {
        let mut types: Vec<(TypeId, Result<D, Unserved>)> = Vec::new();
        for type_id in named {
            if types.iter().all(|(named, _)| *named != type_id) {
                let served = serve(&type_id);
                types.push((type_id, served));
            }
        }
        Self { types, otherwise }
    }

    /// Nothing for any type, for `reason`: a credential whose sources do not load.
    #[must_use]
    pub fn none(reason: Unserved) -> Self {
        Self {
            types: Vec::new(),
            otherwise: reason,
        }
    }

    /// The types a source names, each with its definition or why there is none.
    #[must_use]
    pub fn types(&self) -> &[(TypeId, Result<D, Unserved>)] {
        &self.types
    }

    /// Why no definition serves a type no source names.
    #[must_use]
    pub fn otherwise(&self) -> Unserved {
        self.otherwise
    }

    /// The definition of `type_id`.
    ///
    /// # Errors
    ///
    /// [`Unserved`]: why no definition serves it.
    pub fn serve(&self, type_id: &TypeId) -> Result<&D, Unserved> {
        match self.types.iter().find(|(named, _)| named == type_id) {
            Some((_, served)) => served.as_ref().map_err(|reason| *reason),
            None => Err(self.otherwise),
        }
    }

    /// What `self` serves for the types of `named`, each type once, each definition replaced by
    /// what `f` gives for it, and [`ServedTypes::otherwise`] for every type `named` leaves out.
    ///
    /// # Errors
    ///
    /// The first error of `f`.
    pub fn select<E, X>(
        &self,
        named: &[TypeId],
        mut f: impl FnMut(&D) -> Result<E, X>,
    ) -> Result<ServedTypes<E>, X> {
        let mut types: Vec<(TypeId, Result<E, Unserved>)> = Vec::new();
        for type_id in named {
            if types.iter().all(|(listed, _)| listed != type_id) {
                let served = match self.serve(type_id) {
                    Ok(definition) => Ok(f(definition)?),
                    Err(reason) => Err(reason),
                };
                types.push((type_id.clone(), served));
            }
        }
        Ok(ServedTypes {
            types,
            otherwise: self.otherwise,
        })
    }

    /// The types with each definition replaced by what `f` gives for it.
    ///
    /// # Errors
    ///
    /// The first error of `f`.
    pub fn try_map<E, X>(self, mut f: impl FnMut(D) -> Result<E, X>) -> Result<ServedTypes<E>, X> {
        let types = self
            .types
            .into_iter()
            .map(|(type_id, served)| {
                let served = match served {
                    Ok(definition) => Ok(f(definition)?),
                    Err(reason) => Err(reason),
                };
                Ok((type_id, served))
            })
            .collect::<Result<_, X>>()?;
        Ok(ServedTypes {
            types,
            otherwise: self.otherwise,
        })
    }
}
