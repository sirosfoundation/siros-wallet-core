//! OpenID4VCI display metadata of one credential configuration, and the merger (D1).

use serde_json::{Map, Value};
use siros_codec::url::HttpsUrl;
use siros_wallet_state::{ConfigurationId, EmptyIdentifier, IssuerIdentifier};

use crate::claims::{self, ClaimDescription, Label};
use crate::entry::DisplayEntry;
use crate::error::{DisplayError, EntryFault};
use crate::json::{self, Entries};
use crate::locale::Localized;

/// The Credential Response member that carries delivered secrets (privatedata 3.1, Section
/// 5A.1).
const AUXILIARY_DATA: &str = "auxiliary_data";

/// The configuration member that locates its signed credential metadata (PaSO Proof Metadata,
/// Section 2).
const METADATA_URI: &str = "credential_metadata_uri";

/// The display metadata of one credential configuration of a Credential Issuer, as the display
/// cache holds it.
///
/// Its JSON form, which [`IssuerMetadata::to_json`] gives and [`IssuerMetadata::parse`] reads:
///
/// ```json
/// {
///   "credential_issuer": "https://issuer.example",
///   "credential_configuration_id": "pid",
///   "display": [{"name": "Example Issuer", "locale": "en"}],
///   "credential_metadata": {"display": [{"name": "PID", "locale": "en"}], "claims": []},
///   "credential_metadata_uri": "https://issuer.example/credential-metadata/pid"
/// }
/// ```
///
/// `display` is the Credential Issuer's own (OpenID4VCI 1.0, Section 12.2.4). `credential_metadata`
/// is the configuration's, merged with the Credential Response's ([`IssuerMetadata::merge`]); it
/// holds no `auxiliary_data`. `credential_metadata_uri` is the configuration's (PaSO Proof
/// Metadata, Section 2). All three are optional; the first two keep all their members.
#[derive(Debug, Clone)]
pub struct IssuerMetadata {
    record: Value,
    issuer: IssuerIdentifier,
    configuration_id: ConfigurationId,
    issuer_display: Vec<Label>,
    display: Vec<DisplayEntry>,
    claims: Vec<ClaimDescription>,
    metadata_uri: Option<HttpsUrl>,
}

impl IssuerMetadata {
    /// D1: the display metadata of configuration `configuration_id` of the Credential Issuer
    /// Metadata `issuer_metadata`, merged with the `credential_metadata` of a Credential
    /// Response (privatedata 3.1, Section 5A.3).
    ///
    /// `auxiliary_data` leaves the response's object first. Each remaining member then replaces
    /// the configuration's member of the same name. A configuration whose `credential_metadata`
    /// holds `auxiliary_data` is malformed (Section 5A.3).
    ///
    /// # Errors
    ///
    /// [`DisplayError`]: the first rule the inputs or the merged metadata break.
    pub fn merge(
        issuer_metadata: &Value,
        configuration_id: &str,
        response: Option<&Value>,
    ) -> Result<Self, DisplayError> {
        let document = json::object(issuer_metadata)?;
        let issuer = json::string(
            document,
            "credential_issuer",
            DisplayError::IssuerIdentifier,
        )?
        .ok_or(DisplayError::IssuerIdentifier)?;
        let configuration = document
            .get("credential_configurations_supported")
            .and_then(Value::as_object)
            .and_then(|configurations| configurations.get(configuration_id))
            .and_then(Value::as_object)
            .ok_or(DisplayError::ConfigurationUnknown)?;
        let mut merged = match configuration.get("credential_metadata") {
            None => Map::new(),
            Some(metadata) => json::object(metadata)?.clone(),
        };
        if merged.contains_key(AUXILIARY_DATA) {
            return Err(DisplayError::AuxiliaryDataPublished);
        }
        if let Some(response) = response {
            let response = response
                .as_object()
                .ok_or(DisplayError::ResponseMetadataNotObject)?;
            merged.extend(
                response
                    .iter()
                    .filter(|(name, _)| name.as_str() != AUXILIARY_DATA)
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
        let record: Map<String, Value> = [
            Some(("credential_issuer", Value::from(issuer))),
            Some(("credential_configuration_id", configuration_id.into())),
            document
                .get("display")
                .map(|display| ("display", display.clone())),
            Some(("credential_metadata", merged.into())),
            configuration
                .get(METADATA_URI)
                .map(|uri| (METADATA_URI, uri.clone())),
        ]
        .into_iter()
        .flatten()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        Self::parse(&record.into())
    }

    /// The display metadata of `record`, the form [`IssuerMetadata::to_json`] gives.
    ///
    /// `display` is a non-empty array of objects, each with an optional string `name` and an
    /// optional `locale`, one per locale. `credential_metadata_uri` is an `https` URL. `credential_metadata` is an object without
    /// `auxiliary_data`. Its `display` is a non-empty array of objects with a string `name`, an
    /// optional `locale` (one per locale), `logo`, `background_color` and `text_color`; its
    /// `claims` are claims descriptions (Appendix B.2 and B.3).
    ///
    /// # Errors
    ///
    /// [`DisplayError`]: the first rule `record` breaks.
    pub fn parse(record: &Value) -> Result<Self, DisplayError> {
        let object = json::object(record)?;
        let known = [
            "credential_issuer",
            "credential_configuration_id",
            "display",
            "credential_metadata",
            METADATA_URI,
        ];
        if object.keys().any(|name| !known.contains(&name.as_str())) {
            return Err(DisplayError::RecordMemberUnknown);
        }
        let issuer = json::string(object, "credential_issuer", DisplayError::IssuerIdentifier)?
            .ok_or(DisplayError::IssuerIdentifier)?;
        let configuration_id = json::string(
            object,
            "credential_configuration_id",
            DisplayError::ConfigurationId,
        )?
        .ok_or(DisplayError::ConfigurationId)?;
        let empty = Map::new();
        let metadata = match object.get("credential_metadata") {
            None => &empty,
            Some(metadata) => json::object(metadata)?,
        };
        if metadata.contains_key(AUXILIARY_DATA) {
            return Err(DisplayError::AuxiliaryDataPublished);
        }
        let claims = match json::array(
            metadata,
            "claims",
            Entries::AtLeastOne,
            DisplayError::Claims,
        )? {
            None => Vec::new(),
            Some(claims) => claims::issuer_claims(claims)?,
        };
        Ok(Self {
            record: record.clone(),
            issuer: IssuerIdentifier::parse(issuer)
                .map_err(|EmptyIdentifier| DisplayError::IssuerIdentifier)?,
            configuration_id: ConfigurationId::parse(configuration_id)
                .map_err(|EmptyIdentifier| DisplayError::ConfigurationId)?,
            issuer_display: claims::named_labels(object, DisplayError::Display)?,
            display: credential_display(metadata)?,
            claims,
            metadata_uri: json::string(object, METADATA_URI, DisplayError::CredentialMetadataUri)?
                .map(|uri| HttpsUrl::parse(uri).ok_or(DisplayError::CredentialMetadataUri))
                .transpose()?,
        })
    }

    /// The JSON form, for the display cache.
    pub fn to_json(&self) -> Value {
        self.record.clone()
    }

    /// The Credential Issuer Identifier.
    pub fn credential_issuer(&self) -> &IssuerIdentifier {
        &self.issuer
    }

    /// The credential configuration identifier.
    pub fn configuration_id(&self) -> &ConfigurationId {
        &self.configuration_id
    }

    /// `credential_metadata_uri`: where the configuration's signed credential metadata JWT is
    /// served (PaSO Proof Metadata, Section 2).
    pub fn credential_metadata_uri(&self) -> Option<&HttpsUrl> {
        self.metadata_uri.as_ref()
    }

    /// The names of the issuer `display` entries that have one.
    pub(crate) fn issuer_display(&self) -> &[Label] {
        &self.issuer_display
    }

    /// The `credential_metadata.display` entries.
    pub(crate) fn display(&self) -> &[DisplayEntry] {
        &self.display
    }

    /// The `credential_metadata.claims` descriptions.
    pub(crate) fn claims(&self) -> &[ClaimDescription] {
        &self.claims
    }
}

/// The `display` entries of `credential_metadata`.
fn credential_display(metadata: &Map<String, Value>) -> Result<Vec<DisplayEntry>, DisplayError> {
    let malformed = DisplayError::Display;
    let entries = json::array(metadata, "display", Entries::AtLeastOne, malformed)?;
    let display = entries
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let entry = json::entry(entry, malformed)?;
            let locale = json::locale(entry, malformed(EntryFault::MemberType))?;
            let name = json::label(entry, "name", malformed(EntryFault::MemberType))?
                .ok_or(malformed(EntryFault::MemberMissing))?;
            DisplayEntry::read(locale, name, entry)
        })
        .collect::<Result<Vec<_>, DisplayError>>()?;
    json::distinct_locales(display.iter().map(Localized::locale))?;
    Ok(display)
}
