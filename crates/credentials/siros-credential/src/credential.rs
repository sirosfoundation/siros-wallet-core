//! A credential of the wallet state, read through its format component (C1).

use siros_dcql::{CredentialFormat, CredentialRef, DocType, Vct};
use siros_mdoc::{Mdoc, P256Key};
use siros_sdjwt::SdJwt;
#[cfg(feature = "chain")]
use siros_trust::{ChainError, IssuerChain};
use siros_wallet_state::{
    BatchId, ConfigurationId, CredentialEntry, CredentialId, InstanceId, IssuerIdentifier, KeyId,
    MetadataValue,
};

use crate::error::CredentialError;
use crate::sd_jwt_vc::SdJwtVc;
use crate::usable::Validity;
use crate::value;

/// The `metadata` type of the data an issuer delivers with a credential (privatedata 3.1,
/// Section 5A.2).
const AUXILIARY_DATA: &str = "auxiliary_data";

/// A wallet state entry whose `data` its format component reads.
pub struct Credential {
    entry: EntryRef,
    id: CredentialRef,
    format: CredentialFormat,
    issuer: Option<IssuerIdentifier>,
    configuration_id: Option<ConfigurationId>,
    key_id: Option<KeyId>,
    auxiliary_data: Vec<MetadataValue>,
    validity: Validity,
    #[cfg(feature = "chain")]
    issuer_chain: Option<IssuerChain>,
    pub(crate) body: Body,
}

/// The parsed format value.
pub(crate) enum Body {
    SdJwtVc(Box<SdJwtVc>),
    Mdoc(Box<Mdoc>),
}

impl Body {
    fn format(&self) -> Format {
        match self {
            Self::SdJwtVc(_) => Format::SdJwtVc,
            Self::Mdoc(_) => Format::Mdoc,
        }
    }

    /// The issuer chain: the mdoc's `x5chain`, or the SD-JWT VC issuer JWT's `x5c` when it has
    /// one.
    #[cfg(feature = "chain")]
    fn issuer_chain(&self) -> Result<Option<IssuerChain>, ChainError> {
        match self {
            Self::SdJwtVc(vc) => vc.sd_jwt().x5c().map(IssuerChain::parse).transpose(),
            Self::Mdoc(mdoc) => IssuerChain::parse(mdoc.issuer_auth().x5chain()).map(Some),
        }
    }
}

/// The entry a credential is read from: its `credentialId`, `batchId` and `instanceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryRef {
    credential_id: CredentialId,
    batch_id: BatchId,
    instance_id: InstanceId,
}

impl EntryRef {
    /// The entry of `credentialId` `credential_id` in batch `batch_id`, instance `instance_id`,
    /// as a registration projection records it.
    pub fn new(credential_id: CredentialId, batch_id: BatchId, instance_id: InstanceId) -> Self {
        Self {
            credential_id,
            batch_id,
            instance_id,
        }
    }

    /// `credentialId`.
    pub fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// `batchId`.
    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    /// `instanceId`.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }
}

/// A credential format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// SD-JWT VC, stored as `dc+sd-jwt` or, by earlier wallets, as `vc+sd-jwt`.
    SdJwtVc,
    /// ISO/IEC 18013-5 mdoc, stored as `mso_mdoc`.
    Mdoc,
}

impl Format {
    /// The format identifier of OpenID4VP 1.0, Appendix B: `dc+sd-jwt` or `mso_mdoc`.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::SdJwtVc => "dc+sd-jwt",
            Self::Mdoc => "mso_mdoc",
        }
    }
}

/// The type of a credential: the SD-JWT VC's `vct`, or the mdoc's `docType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType<'a> {
    /// An SD-JWT VC's `vct`.
    Vct(&'a Vct),
    /// An mdoc's `docType`.
    DocType(&'a DocType),
}

impl<'a> CredentialType<'a> {
    /// The type's text.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        match self {
            Self::Vct(vct) => vct.as_str(),
            Self::DocType(doc_type) => doc_type.as_str(),
        }
    }
}

/// The parsed format value of a credential.
#[derive(Clone, Copy)]
pub enum Parsed<'a> {
    /// The SD-JWT of an SD-JWT VC.
    SdJwtVc(&'a SdJwt),
    /// The mdoc.
    Mdoc(&'a Mdoc),
}

impl Credential {
    /// The credential of `entry`.
    ///
    /// `format` selects the reader: `dc+sd-jwt` and `vc+sd-jwt` read as SD-JWT VC, `mso_mdoc`
    /// as mdoc. An SD-JWT VC has a string `vct`; `iss`, `nbf`, `exp`, `cnf`, `vct`,
    /// `vct#integrity`, `aka_vcts` and `status` are permanently disclosed; `cnf`, when present,
    /// is a JSON object; `nbf` and `exp` are NumericDates. Every mdoc element value, at every
    /// depth, has one of the ten types of [`TypedValue`](crate::TypedValue): its tags are 0
    /// over a `tdate` and 1004 over a `full-date`, its map keys are text, and it holds no
    /// `undefined`. With the feature `chain`, the issuer chain (TR2), the mdoc's `x5chain` or
    /// the SD-JWT VC issuer JWT's `x5c`, parses.
    ///
    /// # Errors
    ///
    /// [`CredentialError`]: the first rule `entry` breaks.
    pub fn parse(entry: &CredentialEntry) -> Result<Self, CredentialError> {
        let (body, validity) = match entry.format().as_str() {
            "dc+sd-jwt" | "vc+sd-jwt" => {
                let vc = SdJwtVc::read(entry.data().as_str())?;
                let validity = vc.validity();
                (Body::SdJwtVc(Box::new(vc)), validity)
            }
            "mso_mdoc" => {
                let mdoc = Box::new(Mdoc::parse(entry.data().as_str())?);
                value::typed(&mdoc)?;
                let mso = mdoc.mso().validity();
                let validity = Validity::new(Some(mso.valid_from()), Some(mso.valid_until()));
                (Body::Mdoc(mdoc), validity)
            }
            _ => return Err(CredentialError::UnsupportedFormat),
        };
        Ok(Self {
            entry: EntryRef {
                credential_id: entry.credential_id(),
                batch_id: entry.batch_id(),
                instance_id: entry.instance_id(),
            },
            id: CredentialRef::new(&entry.credential_id().to_string()),
            format: CredentialFormat::new(body.format().identifier()),
            issuer: entry.issuer().cloned(),
            configuration_id: entry.configuration_id().cloned(),
            key_id: entry.key_id().cloned(),
            auxiliary_data: entry
                .metadata()
                .iter()
                .filter(|m| m.kind() == AUXILIARY_DATA)
                .map(|m| m.value().clone())
                .collect(),
            validity,
            #[cfg(feature = "chain")]
            issuer_chain: body.issuer_chain()?,
            body,
        })
    }

    /// The entry the credential is read from.
    pub fn entry(&self) -> EntryRef {
        self.entry
    }

    /// The format.
    #[must_use]
    pub fn format(&self) -> Format {
        self.body.format()
    }

    /// The parsed format value.
    pub fn parsed(&self) -> Parsed<'_> {
        match &self.body {
            Body::SdJwtVc(vc) => Parsed::SdJwtVc(vc.sd_jwt()),
            Body::Mdoc(mdoc) => Parsed::Mdoc(mdoc),
        }
    }

    /// The type: the SD-JWT VC's `vct`, or the mdoc's `docType`.
    #[must_use]
    pub fn credential_type(&self) -> CredentialType<'_> {
        match &self.body {
            Body::SdJwtVc(vc) => CredentialType::Vct(vc.vct()),
            Body::Mdoc(mdoc) => CredentialType::DocType(mdoc.doc_type()),
        }
    }

    /// The entry's `credentialIssuerIdentifier`. `None` when the wallet did not know it.
    #[must_use]
    pub fn issuer(&self) -> Option<&IssuerIdentifier> {
        self.issuer.as_ref()
    }

    /// The entry's `credentialConfigurationId`. `None` when the wallet did not know it.
    #[must_use]
    pub fn configuration_id(&self) -> Option<&ConfigurationId> {
        self.configuration_id.as_ref()
    }

    /// The validity: the MSO's `validFrom` and `validUntil`, or the SD-JWT VC's `nbf` and
    /// `exp`.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// The public key a presentation of the credential proves possession of: the P-256 key of
    /// an SD-JWT VC's `cnf.jwk`, or an mdoc's `deviceKey`. `None` for an SD-JWT VC without
    /// `cnf`, which is bound to no key.
    pub fn holder_key(&self) -> Option<P256Key> {
        match &self.body {
            Body::SdJwtVc(vc) => vc.holder_key(),
            Body::Mdoc(mdoc) => Some(*mdoc.mso().device_key()),
        }
    }

    /// The issuer chain (TR2): the mdoc's `x5chain`, or the SD-JWT VC issuer JWT's `x5c`. `None`
    /// for an SD-JWT VC without `x5c`.
    #[cfg(feature = "chain")]
    pub fn issuer_chain(&self) -> Option<&IssuerChain> {
        self.issuer_chain.as_ref()
    }

    /// The entry's `kid`: the key pair the credential is bound to.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// The value of each `metadata` entry of type `auxiliary_data`, in their order: the
    /// Auxiliary Data Entries the issuer delivered (privatedata 3.1, Section 5A.2).
    pub fn auxiliary_data(&self) -> &[MetadataValue] {
        &self.auxiliary_data
    }

    /// The decimal `credentialId`: the identifier DCQL evaluation echoes.
    pub(crate) fn id(&self) -> &CredentialRef {
        &self.id
    }

    /// The format identifier DCQL evaluation compares with a query's `format`.
    pub(crate) fn format_identifier(&self) -> &CredentialFormat {
        &self.format
    }
}
