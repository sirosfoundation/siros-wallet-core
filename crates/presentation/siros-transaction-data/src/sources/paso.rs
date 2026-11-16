//! The signed credential metadata JWT of a PaSO Credential (PaSO Proof Metadata, Sections 4, 7
//! and 8): the one the host holds for the credential's configuration, verified each time it is
//! loaded (Section 6), and read into a definition per transaction data type. The host admits a
//! JWT with [`HeldJwt::admit`].

use siros_codec::date::DateTime;
use siros_codec::member::MemberFault;
use siros_credential::Credential;
use siros_oid4vp::HttpsUrl;
use siros_trust::TrustStore;

use super::held::{HeldJwt, HeldMetadata, Renewal};
use super::signed::{self, MetadataClaim, SignedFault, Verifier};
use crate::definition::{Definition, DefinitionError, LabelRules};
use crate::json;
use crate::type_id::{EmptyTypeId, TypeId};

/// The `typ` of a signed credential metadata JWT (Section 4).
const TYP: &str = "credential-metadata+jwt";

/// Why a credential's signed credential metadata is invalid. The credential is then excluded
/// from PaSO processing (Section 7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum CredentialMetadataFault {
    /// The host holds no JWT for the credential's configuration.
    NotHeld,
    /// The JWT is invalid (Section 7).
    Invalid(#[source] SignedFault),
    /// `transaction_data_types` has a member with an empty name.
    TypeEmpty,
    /// The JWT's `credential_metadata_uri` claim holds this text, which differs from the URL
    /// that served the JWT (Section 8).
    UriMismatch(String),
}

impl CredentialMetadataFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotHeld => "credential_metadata_not_held",
            Self::Invalid(fault) => fault.code(),
            Self::TypeEmpty => "credential_metadata_type_empty",
            Self::UriMismatch(_) => "credential_metadata_uri_mismatch",
        }
    }
}

/// The transaction data types of a verified signed credential metadata JWT, each with its
/// definition or why the definition breaks Section 3.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CredentialMetadata(Vec<(TypeId, Result<Definition, DefinitionError>)>);

impl CredentialMetadata {
    /// The signed credential metadata the host holds for `credential`, verified: Section 7, and
    /// its `credential_metadata_uri` the URL that served it (Section 8).
    pub(crate) fn load(
        credential: &Credential,
        verifier: Verifier<'_>,
    ) -> Result<Self, CredentialMetadataFault> {
        let held = verifier
            .held
            .jwt(credential)
            .ok_or(CredentialMetadataFault::NotHeld)?;
        served(held.jwt(), held.served_from(), credential, verifier).map(|(metadata, _)| metadata)
    }

    /// The types the metadata lists, in its order.
    pub(crate) fn types(&self) -> impl Iterator<Item = &TypeId> {
        self.0.iter().map(|(type_id, _)| type_id)
    }

    /// The definition of `type_id`, when the metadata lists the type.
    pub(crate) fn definition(
        &self,
        type_id: &TypeId,
    ) -> Option<&Result<Definition, DefinitionError>> {
        self.0
            .iter()
            .find(|(listed, _)| listed == type_id)
            .map(|(_, definition)| definition)
    }
}

impl HeldJwt {
    /// The JWT `jwt` that `served_from` served for `credential`'s configuration: verified
    /// (Section 7), its `credential_metadata_uri` `served_from` (Section 8). `held` holds the
    /// issuer's key set when the credential carries no `x5c` chain.
    ///
    /// # Errors
    ///
    /// [`CredentialMetadataFault`]: why the JWT is invalid. The host keeps the JWT it held.
    pub fn admit(
        jwt: String,
        served_from: &HttpsUrl,
        credential: &Credential,
        trust: &TrustStore,
        held: &HeldMetadata,
        now: DateTime,
    ) -> Result<(Self, Renewal), CredentialMetadataFault> {
        let verifier = Verifier { trust, held, now };
        let (_, renewal) = served(&jwt, served_from, credential, verifier)?;
        let (Some(issuer), Some(configuration)) =
            (credential.issuer(), credential.configuration_id())
        else {
            return Err(CredentialMetadataFault::Invalid(SignedFault::Issuer));
        };
        Ok((
            Self::new(
                issuer.clone(),
                configuration.clone(),
                jwt,
                served_from.clone(),
            ),
            renewal,
        ))
    }
}

/// The metadata of the JWT `jwt` for `credential`, served by `served_from`: verified (Section
/// 7), its `credential_metadata_uri` `served_from` (Section 8).
fn served(
    jwt: &str,
    served_from: &HttpsUrl,
    credential: &Credential,
    verifier: Verifier<'_>,
) -> Result<(CredentialMetadata, Renewal), CredentialMetadataFault> {
    let (metadata, renewal) = verified(jwt, credential, verifier)?;
    if renewal.from != *served_from {
        return Err(CredentialMetadataFault::UriMismatch(
            renewal.from.as_str().to_owned(),
        ));
    }
    Ok((metadata, renewal))
}

/// The metadata of the JWT `jwt` for `credential`, verified (Section 7), and how the host
/// renews it.
fn verified(
    jwt: &str,
    credential: &Credential,
    verifier: Verifier<'_>,
) -> Result<(CredentialMetadata, Renewal), CredentialMetadataFault> {
    let invalid = CredentialMetadataFault::Invalid;
    let signed::Verified {
        mut claims,
        expires,
    } = signed::verify(jwt.trim(), TYP, credential, verifier).map_err(invalid)?;
    let uri =
        signed::text_claim(&mut claims, MetadataClaim::CredentialMetadataUri).map_err(invalid)?;
    let from = HttpsUrl::parse(&uri).ok_or(CredentialMetadataFault::Invalid(
        SignedFault::Claim(MetadataClaim::CredentialMetadataUri, MemberFault::WrongType),
    ))?;
    let member = |claim: MetadataClaim| {
        move |fault| CredentialMetadataFault::Invalid(SignedFault::Claim(claim, fault))
    };
    let mut metadata = claims
        .require(MetadataClaim::CredentialMetadata.as_str())
        .and_then(json::object)
        .map_err(member(MetadataClaim::CredentialMetadata))?;
    let types = metadata
        .require(MetadataClaim::TransactionDataTypes.as_str())
        .and_then(json::object)
        .map_err(member(MetadataClaim::TransactionDataTypes))?
        .rest()
        .into_iter()
        .map(|(name, value)| {
            let type_id =
                TypeId::parse(&name).map_err(|EmptyTypeId| CredentialMetadataFault::TypeEmpty)?;
            Ok((type_id, Definition::parse(value, LabelRules::Paso)))
        })
        .collect::<Result<Vec<_>, CredentialMetadataFault>>()?;
    Ok((CredentialMetadata(types), Renewal { expires, from }))
}
