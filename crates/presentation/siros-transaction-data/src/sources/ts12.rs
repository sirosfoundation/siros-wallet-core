//! The SD-JWT VC Type Metadata of an SCA Attestation (EC TS12 v1.0.1, Sections 3 and 4.1): the
//! document at the credential's `vct` and the documents it references, each one the host holds,
//! read into definitions.

use std::str::Utf8Error;

use siros_codec::json::{Json, JsonFault};
use siros_codec::member::MemberFault;
use siros_credential::{Credential, Format, TypedValue};
use siros_dcql::{ClaimPath, PathError};
use siros_oid4vp::HttpsUrl;

use super::held::{HeldMetadata, Holding};
use super::ts12_map;
use crate::definition::{Definition, DefinitionError};
use crate::integrity::{Integrity, IntegrityFault};
use crate::json::{self, Fields};
use crate::type_id::{Ts12Type, TypeId};

/// The `category` of an SCA Attestation (Section 3).
const SCA_CATEGORY: &str = "urn:eu:europa:ec:eudi:sua:sca";

/// A member of TS12 type metadata, of a `transaction_data_types` entry, or of its documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ts12Member {
    /// `vct`.
    Vct,
    /// `category`.
    Category,
    /// `transaction_data_types`.
    TransactionDataTypes,
    /// A `transaction_data_types` entry.
    Entry,
    /// `schema` or `schema_uri`.
    Schema,
    /// `claims` or `claims_uri`.
    Claims,
    /// `ui_labels` or `ui_labels_uri`.
    UiLabels,
    /// A claim's `path`.
    Path,
    /// A claim's `display`.
    Display,
    /// A display entry's `lang` or `locale`.
    Lang,
    /// A display entry's `label`.
    Label,
    /// A UI elements catalogue entry.
    UiEntry,
}

/// Why TS12 type metadata gives no definition of a type (Sections 3.2, 3.3 and 4.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Ts12Fault {
    /// The claims path processing of the credential's `vct#integrity` or a
    /// `transaction_data_types[…]#integrity` claim gives this error.
    PinPath(#[source] PathError),
    /// The credential's `vct#integrity` or a `transaction_data_types[…]#integrity` claim is no
    /// integrity metadata this wallet reads (SD-JWT VC, Section 7).
    PinValue(#[source] IntegrityFault),
    /// The credential's `vct#integrity` pins Type Metadata at a `vct` that is no `https` URL,
    /// which no host holds.
    VctNotHttps,
    /// The host neither holds the document of this URL nor records it as absent: the Type
    /// Metadata of an `https` `vct`, or a document an entry references.
    NotHeld(HttpsUrl),
    /// The host records the document of this URL as absent, which the credential pins or an
    /// entry references.
    Absent(HttpsUrl),
    /// A document's bytes are no UTF-8 text.
    NotUtf8(#[source] Utf8Error),
    /// A document's text is no JSON document the strict reader holds.
    NotJson(#[source] JsonFault),
    /// A document does not match its `#integrity` claim (SD-JWT VC, Section 7).
    Integrity(#[source] IntegrityFault),
    /// A member breaks its rule.
    Member(Ts12Member, #[source] MemberFault),
    /// The document describes another `vct` than the credential's (SD-JWT VC, Section 6.3).
    VctMismatch,
    /// An entry gives both or neither of a member and its `_uri` form (Section 4.1).
    OneOf(Ts12Member),
    /// A referenced document's URL is no `https` URL.
    DocumentNotHttps(String),
    /// `schema` embeds a JSON Schema; the wallet validates payloads against the schemas of
    /// Section 4.3.
    SchemaEmbedded,
    /// `schema` names no schema of Section 4.3.
    SchemaUnknown(String),
    /// `schema` names another type's schema than the entry's built-in type.
    SchemaMismatch(Ts12Type),
    /// A claim's `path` is not rooted at `payload` (Section 2.3).
    PathOutsidePayload,
    /// The catalogue has no `affirmative_action_label` (Section 3.3.3).
    AffirmativeAbsent,
    /// The mapped definition breaks PaSO Proof Metadata, Section 3.
    Definition(#[source] DefinitionError),
}

impl Ts12Fault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PinPath(_) | Self::PinValue(_) => "type_metadata_pin_malformed",
            Self::VctNotHttps => "type_metadata_vct_not_https",
            Self::NotHeld(_) => "type_metadata_not_held",
            Self::Absent(_) => "type_metadata_absent",
            Self::NotUtf8(_) | Self::NotJson(_) | Self::Member(..) | Self::OneOf(_) => {
                "type_metadata_malformed"
            }
            Self::Integrity(fault) => fault.code(),
            Self::VctMismatch => "type_metadata_vct_mismatch",
            Self::DocumentNotHttps(_) => "type_metadata_document_not_https",
            Self::SchemaEmbedded => "type_metadata_schema_embedded",
            Self::SchemaUnknown(_) => "type_metadata_schema_unknown",
            Self::SchemaMismatch(_) => "type_metadata_schema_mismatch",
            Self::PathOutsidePayload => "type_metadata_path_outside_payload",
            Self::AffirmativeAbsent => "type_metadata_affirmative_absent",
            Self::Definition(error) => error.code(),
        }
    }
}

/// The transaction metadata of a credential's type metadata: its `transaction_data_types`
/// entries, every type the credential supports (Section 3.2, steps 1 and 2). Type metadata of
/// another category than the SCA one supports no type.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TypeMetadata(Vec<(String, Json)>);

/// A document held inline, or referenced by URL with the credential's pin.
enum Document {
    Inline(Json),
    Referenced(HttpsUrl, Option<Integrity>),
}

impl TypeMetadata {
    /// The transaction metadata of `credential`, an SD-JWT VC: that of the document at its
    /// `vct` (SD-JWT VC, Section 6.3.1), as the host holds it, when the document declares
    /// `transaction_data_types`. The SCA `category` requires them. A `vct` that is no `https`
    /// URL locates no document, and the host's record that the document is absent stands for
    /// none, unless `vct#integrity` pins one.
    pub(crate) fn load(
        credential: &Credential,
        held: &HeldMetadata,
    ) -> Result<Option<Self>, Ts12Fault> {
        let Some((url, pin)) = located(credential)? else {
            return Ok(None);
        };
        let body = match (held.document(&url), &pin) {
            (Holding::Body(body), _) => body,
            (Holding::Absent, None) => return Ok(None),
            (Holding::Absent, Some(_)) => return Err(Ts12Fault::Absent(url)),
            (Holding::NotHeld, _) => return Err(Ts12Fault::NotHeld(url)),
        };
        let mut fields = json::object(document_of(body, pin.as_ref())?)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::Vct, fault))?;
        match fields.require("vct").and_then(json::text) {
            Ok(vct) if vct == credential.credential_type().as_str() => {}
            Ok(_) => return Err(Ts12Fault::VctMismatch),
            Err(fault) => return Err(Ts12Fault::Member(Ts12Member::Vct, fault)),
        }
        let category = fields
            .optional("category", json::text)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::Category, fault))?;
        let types = fields
            .optional("transaction_data_types", json::object)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::TransactionDataTypes, fault))?;
        match (category.as_deref() == Some(SCA_CATEGORY), types) {
            (true, Some(types)) => Ok(Some(Self(types.rest()))),
            (true, None) => Err(Ts12Fault::Member(
                Ts12Member::TransactionDataTypes,
                MemberFault::Absent,
            )),
            (false, Some(_)) => Ok(Some(Self(Vec::new()))),
            (false, None) => Ok(None),
        }
    }

    /// The URLs of the documents of `credential`'s type metadata: the document at its `vct`,
    /// and, once the host holds that, each document its entries reference.
    ///
    /// # Errors
    ///
    /// [`Ts12Fault`] for held type metadata that does not read.
    pub(crate) fn documents(
        credential: &Credential,
        held: &HeldMetadata,
    ) -> Result<Vec<HttpsUrl>, Ts12Fault> {
        let Some((url, _)) = located(credential)? else {
            return Ok(Vec::new());
        };
        let mut urls = vec![url.clone()];
        if !matches!(held.document(&url), Holding::Body(_)) {
            return Ok(urls);
        }
        let Some(metadata) = Self::load(credential, held)? else {
            return Ok(urls);
        };
        for (_, entry) in &metadata.0 {
            for member in ["claims_uri", "ui_labels_uri"] {
                if let Some(Json::String(text)) = entry.member(member) {
                    urls.push(
                        HttpsUrl::parse(text)
                            .ok_or_else(|| Ts12Fault::DocumentNotHttps(text.clone()))?,
                    );
                }
            }
        }
        Ok(urls)
    }

    /// The types the metadata lists, in its order. A member with an empty name lists no type an
    /// entry names: an entry's `type` is never empty.
    pub(crate) fn types(&self) -> impl Iterator<Item = TypeId> + '_ {
        self.0
            .iter()
            .filter_map(|(name, _)| TypeId::parse(name).ok())
    }

    /// The definition of `type_id` and the built-in schema its payloads follow, when the
    /// metadata lists the type.
    pub(crate) fn definition(
        &self,
        type_id: &TypeId,
        credential: &Credential,
        held: &HeldMetadata,
    ) -> Option<Result<(Definition, Ts12Type), Ts12Fault>> {
        let (_, entry) = self.0.iter().find(|(name, _)| name == type_id.as_str())?;
        Some(entry_definition(type_id, entry.clone(), credential, held))
    }
}

/// The URL of the Type Metadata of `credential` and its `vct#integrity` pin: its `vct`, when
/// the credential is an SD-JWT VC and the `vct` an `https` URL.
///
/// # Errors
///
/// [`Ts12Fault::PinPath`] or [`Ts12Fault::PinValue`] for a pin that does not read, and [`Ts12Fault::VctNotHttps`] for a pin
/// of a `vct` that is no `https` URL.
fn located(credential: &Credential) -> Result<Option<(HttpsUrl, Option<Integrity>)>, Ts12Fault> {
    match credential.format() {
        Format::SdJwtVc => {}
        Format::Mdoc => return Ok(None),
    }
    let pin = pin(credential, "vct#integrity")?;
    match (HttpsUrl::parse(credential.credential_type().as_str()), pin) {
        (Some(url), pin) => Ok(Some((url, pin))),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(Ts12Fault::VctNotHttps),
    }
}

/// The definition of the `transaction_data_types` entry `entry` of `type_id`.
fn entry_definition(
    type_id: &TypeId,
    entry: Json,
    credential: &Credential,
    held: &HeldMetadata,
) -> Result<(Definition, Ts12Type), Ts12Fault> {
    let mut fields =
        json::object(entry).map_err(|fault| Ts12Fault::Member(Ts12Member::Entry, fault))?;
    let schema = schema(type_id, &mut fields)?;
    let claims = source(
        type_id,
        &mut fields,
        "claims",
        Ts12Member::Claims,
        credential,
    )?;
    let labels = source(
        type_id,
        &mut fields,
        "ui_labels",
        Ts12Member::UiLabels,
        credential,
    )?;
    let definition = ts12_map::definition(resolve(claims, held)?, resolve(labels, held)?)?;
    Ok((definition, schema))
}

/// The built-in schema `schema` or `schema_uri` names (Sections 3.2 and 4.1), one of the two:
/// the payload rulebook of the type. It agrees with the built-in type of `type_id`.
fn schema(type_id: &TypeId, fields: &mut Fields) -> Result<Ts12Type, Ts12Fault> {
    let named = match (fields.take("schema"), fields.take("schema_uri")) {
        (Some(Json::String(name)), None) | (None, Some(Json::String(name))) => name,
        (Some(Json::Object(_)), None) => return Err(Ts12Fault::SchemaEmbedded),
        (Some(_), None) | (None, Some(_)) => {
            return Err(Ts12Fault::Member(
                Ts12Member::Schema,
                MemberFault::WrongType,
            ))
        }
        (Some(_), Some(_)) | (None, None) => return Err(Ts12Fault::OneOf(Ts12Member::Schema)),
    };
    let schema = Ts12Type::schema(&named).ok_or(Ts12Fault::SchemaUnknown(named))?;
    match type_id.rulebook() {
        Some(builtin) if builtin != schema => Err(Ts12Fault::SchemaMismatch(builtin)),
        Some(_) | None => Ok(schema),
    }
}

/// The document of member `name` of the entry of `type_id`: inline in `name`, or referenced by
/// `<name>_uri`, exactly one of them. The credential's
/// `transaction_data_types['<type>'].<name>_uri#integrity` claim pins a referenced document
/// (Section 4.1.2).
fn source(
    type_id: &TypeId,
    fields: &mut Fields,
    name: &str,
    member: Ts12Member,
    credential: &Credential,
) -> Result<Document, Ts12Fault> {
    let uri = format!("{name}_uri");
    match (fields.take(name), fields.take(&uri)) {
        (Some(inline), None) => Ok(Document::Inline(inline)),
        (None, Some(Json::String(url))) => {
            let pinned = format!("transaction_data_types['{type_id}'].{uri}#integrity");
            Ok(Document::Referenced(
                HttpsUrl::parse(&url).ok_or(Ts12Fault::DocumentNotHttps(url))?,
                pin(credential, &pinned)?,
            ))
        }
        (None, Some(_)) => Err(Ts12Fault::Member(member, MemberFault::WrongType)),
        (Some(_), Some(_)) | (None, None) => Err(Ts12Fault::OneOf(member)),
    }
}

/// The JSON value of `document`: inline, or held for its URL.
fn resolve(document: Document, held: &HeldMetadata) -> Result<Json, Ts12Fault> {
    match document {
        Document::Inline(value) => Ok(value),
        Document::Referenced(url, pin) => match held.document(&url) {
            Holding::Body(body) => document_of(body, pin.as_ref()),
            Holding::Absent => Err(Ts12Fault::Absent(url)),
            Holding::NotHeld => Err(Ts12Fault::NotHeld(url)),
        },
    }
}

/// The JSON document `body` holds, checked against `pin` when the credential pins it.
fn document_of(body: &[u8], pin: Option<&Integrity>) -> Result<Json, Ts12Fault> {
    if let Some(pin) = pin {
        pin.check(body).map_err(Ts12Fault::Integrity)?;
    }
    let text = std::str::from_utf8(body).map_err(Ts12Fault::NotUtf8)?;
    Json::parse_unique(text.as_bytes()).map_err(Ts12Fault::NotJson)
}

/// The integrity metadata of the credential's top-level claim `name`, when it has the claim.
fn pin(credential: &Credential, name: &str) -> Result<Option<Integrity>, Ts12Fault> {
    match credential.claims(&ClaimPath::key(name)).as_deref() {
        Err(PathError::Empty) => Ok(None),
        Err(error) => Err(Ts12Fault::PinPath(error.clone())),
        Ok([TypedValue::Text(text)]) => Integrity::parse(text)
            .map(Some)
            .map_err(Ts12Fault::PinValue),
        Ok(_) => Err(Ts12Fault::PinValue(IntegrityFault::Malformed)),
    }
}
