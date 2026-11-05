//! CSC §6.4: the approval rendered for the End-User, in the profile's own strings.
//!
//! First a full-text row: what the approval creates, signatures or seals, under which framework.
//! Then the number of signatures, and per document, in a section of its own: its full label or
//! that it has none, its one-time password, its link, and whether its integrity was checked.

use rustc_hash::FxHashMap;
use siros_explain::Explain;
use siros_openid4vp::consent::Header;
use siros_openid4vp::detail;
use siros_openid4vp::plugins::{Exclude, Fault, NoCandidate};
use siros_openid4vp::rows::{
    Env, HttpsUrl, Label, NotHttpsUrl, Parsed, Row, TableLocale, Value, WalletText,
};

use crate::FAULT;
use crate::approval::{
    ApprovalRequest, Creation, DocumentInfo, Framework, Link, SignatureQualifier,
};
use crate::documents::Fetched;
use crate::rules::Excluded;

/// A text of the profile's own: a message of the crate's module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "qes.approval")]
pub enum QesText {
    /// The consent title of signatures.
    #[error("Approve qualified signatures")]
    TitleSignatures,
    /// The consent title of seals.
    #[error("Approve qualified seals")]
    TitleSeals,
    /// The confirm action.
    #[error("Approve")]
    Confirm,
    /// What an `eu_eidas_qes` approval creates.
    #[error("Creates qualified electronic signatures under the EU eIDAS regulation")]
    CreatesEidasSignatures,
    /// What an `eu_eidas_qeseal` approval creates.
    #[error("Creates qualified electronic seals under the EU eIDAS regulation")]
    CreatesEidasSeals,
    /// The label of the number of signatures.
    #[error("Signatures")]
    Count,
    /// The label of a document's label.
    #[error("Name")]
    Name,
    /// The row of a document without a label.
    #[error("This document has no name")]
    NoName,
    /// The label of a document's one-time password.
    #[error("One-time password")]
    OneTimePassword,
    /// The label of a document's link.
    #[error("Document link")]
    Link,
    /// A link other than https: the document came with the request.
    #[error("Included in the request")]
    Embedded,
    /// The label of a document's integrity.
    #[error("Integrity")]
    Integrity,
    /// The integrity checked against the document the wallet holds.
    #[error("Checked automatically")]
    Verified,
    /// The integrity not checked.
    #[error("Not checked")]
    Unverified,
    /// The section of the document at a position, from 1.
    #[error("Document {document}")]
    Section {
        /// The position.
        document: usize,
    },
}

impl QesText {
    /// The consent title of an approval.
    const fn title(qualifier: SignatureQualifier) -> Self {
        match qualifier.creation() {
            Creation::Signature => Self::TitleSignatures,
            Creation::Seal => Self::TitleSeals,
        }
    }

    /// What an approval creates, under its framework.
    const fn creates(qualifier: SignatureQualifier) -> Self {
        match (qualifier.creation(), qualifier.framework()) {
            (Creation::Signature, Framework::Eidas) => Self::CreatesEidasSignatures,
            (Creation::Seal, Framework::Eidas) => Self::CreatesEidasSeals,
        }
    }

    fn in_locale(self, locale: TableLocale) -> String {
        let text = match (locale, self) {
            (_, Self::Section { document }) => {
                return match locale {
                    TableLocale::En => format!("Document {document}"),
                    TableLocale::De => format!("Dokument {document}"),
                };
            }
            (TableLocale::En, Self::TitleSignatures) => "Approve qualified signatures",
            (TableLocale::En, Self::TitleSeals) => "Approve qualified seals",
            (TableLocale::En, Self::Confirm) => "Approve",
            (TableLocale::En, Self::CreatesEidasSignatures) => {
                "Creates qualified electronic signatures under the EU eIDAS regulation"
            }
            (TableLocale::En, Self::CreatesEidasSeals) => {
                "Creates qualified electronic seals under the EU eIDAS regulation"
            }
            (TableLocale::En, Self::Count) => "Signatures",
            (TableLocale::En, Self::Name) => "Name",
            (TableLocale::En, Self::NoName) => "This document has no name",
            (TableLocale::En, Self::OneTimePassword) => "One-time password",
            (TableLocale::En, Self::Link) => "Document link",
            (TableLocale::En, Self::Embedded) => "Included in the request",
            (TableLocale::En, Self::Integrity) => "Integrity",
            (TableLocale::En, Self::Verified) => "Checked automatically",
            (TableLocale::En, Self::Unverified) => "Not checked",
            (TableLocale::De, Self::TitleSignatures) => "Qualifizierte Signaturen freigeben",
            (TableLocale::De, Self::TitleSeals) => "Qualifizierte Siegel freigeben",
            (TableLocale::De, Self::Confirm) => "Freigeben",
            (TableLocale::De, Self::CreatesEidasSignatures) => {
                "Erstellt qualifizierte elektronische Signaturen nach der EU-eIDAS-Verordnung"
            }
            (TableLocale::De, Self::CreatesEidasSeals) => {
                "Erstellt qualifizierte elektronische Siegel nach der EU-eIDAS-Verordnung"
            }
            (TableLocale::De, Self::Count) => "Signaturen",
            (TableLocale::De, Self::Name) => "Name",
            (TableLocale::De, Self::NoName) => "Dieses Dokument hat keinen Namen",
            (TableLocale::De, Self::OneTimePassword) => "Einmalpasswort",
            (TableLocale::De, Self::Link) => "Dokument-Link",
            (TableLocale::De, Self::Embedded) => "In der Anfrage enthalten",
            (TableLocale::De, Self::Integrity) => "Integrität",
            (TableLocale::De, Self::Verified) => "Automatisch geprüft",
            (TableLocale::De, Self::Unverified) => "Nicht geprüft",
        };
        text.to_owned()
    }
}

/// The rows the approval shows and its consent header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The rows, shown before the credential's.
    pub(crate) rows: Vec<Row>,
    /// The header.
    pub(crate) header: Header,
}

/// A plain-text value.
fn text(text: &str) -> Value {
    Value::Formatted {
        parsed: Parsed::Text,
        text: text.to_owned(),
    }
}

/// The approval in the wallet's first locale. Excluded when a linked document the wallet holds
/// fails its checksum (§6.3, abort): the first such document in array order.
pub(crate) fn render(
    approval: &ApprovalRequest<'_>,
    held: &FxHashMap<String, Fetched>,
    env: &Env,
) -> Result<Rendered, NoCandidate> {
    let locale = env.first().table;
    let say = |key: QesText| key.in_locale(locale);
    let qualifier = approval.qualifier;
    let mut rows = vec![
        Row::full_text(Label::text(say(QesText::creates(qualifier)))),
        Row::new(
            Label::text(say(QesText::Count)),
            text(approval.count.as_str()),
        ),
    ];
    for (k, document) in approval.documents.iter().enumerate() {
        let n = k + 1;
        let section = say(QesText::Section { document: n });
        for row in document_rows(document, n, held, env)? {
            rows.push(row.in_section(section.clone()));
        }
    }
    Ok(Rendered {
        rows,
        header: Header {
            title: Label::text(say(QesText::title(qualifier))),
            confirm: Label::text(say(QesText::Confirm)),
            cancel: Label::text(env.first().text(WalletText::Deny)),
        },
    })
}

/// The rows of the document at position `n`: its label or that it has none, its one-time
/// password, its link, and with a checksum whether its integrity was checked.
fn document_rows(
    document: &DocumentInfo<'_>,
    n: usize,
    held: &FxHashMap<String, Fetched>,
    env: &Env,
) -> Result<Vec<Row>, NoCandidate> {
    let locale = env.first().table;
    let say = |key: QesText| key.in_locale(locale);
    let mut rows = vec![match document.label {
        Some(label) => Row::new(Label::text(say(QesText::Name)), text(label)),
        None => Row::full_text(Label::text(say(QesText::NoName))),
    }];
    if let Some(password) = document.one_time_password {
        rows.push(Row::new(
            Label::text(say(QesText::OneTimePassword)),
            text(password),
        ));
    }
    let Some(Link { href, checksum }) = document.link else {
        return Ok(rows);
    };
    let link = match HttpsUrl::parse(href) {
        Ok(url) => Value::url(url),
        Err(e @ NotHttpsUrl::ALabel { .. }) => {
            return Err(Fault::caused(FAULT, detail!("QES document {n}: its link"), e).into());
        }
        Err(_) => text(&say(QesText::Embedded)),
    };
    rows.push(Row::new(Label::text(say(QesText::Link)), link));
    if let Some(checksum) = checksum {
        let checked = match held.get(href) {
            Some(fetched) if fetched.verifies(checksum) => QesText::Verified,
            Some(_) => {
                return Err(Exclude::new(Excluded::Checksum { document: n }).into());
            }
            None => QesText::Unverified,
        };
        rows.push(Row::new(
            Label::text(say(QesText::Integrity)),
            text(&say(checked)),
        ));
    }
    Ok(rows)
}
