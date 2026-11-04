//! CSC §6.4: the approval rendered for the End-User, in the profile's own strings.
//!
//! First a full-text row: what the approval creates, signatures or seals, under which framework.
//! Then the number of signatures, and per document, in a section of its own: its full label or
//! that it has none, its one-time password, its link, and whether its integrity was checked.

use rustc_hash::FxHashMap;
use siros_openid4vp::consent::Header;
use siros_openid4vp::detail;
use siros_openid4vp::plugins::{Exclude, Fault, NoCandidate};
use siros_openid4vp::rows::{
    Env, HttpsUrl, Label, NotHttpsUrl, Parsed, Row, TableLocale, Value, WalletText,
};

use crate::FAULT;
use crate::approval::{ApprovalRequest, Creation, DocumentInfo, Framework, Link};
use crate::documents::Fetched;
use crate::rules::Excluded;

/// A string of the profile's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Text {
    /// The consent title.
    Title(Creation),
    /// The confirm action.
    Confirm,
    /// What the approval creates.
    Creates(Creation),
    /// The framework it is qualified under.
    Under(Framework),
    /// The label of the number of signatures.
    Count,
    /// The label of a document's label.
    Name,
    /// The row of a document without a label.
    NoName,
    /// The label of a document's one-time password.
    OneTimePassword,
    /// The label of a document's link.
    Link,
    /// A link other than https: the document came with the request.
    Embedded,
    /// The label of a document's integrity.
    Integrity,
    /// The integrity checked against the document the wallet holds.
    Verified,
    /// The integrity not checked.
    Unverified,
}

impl Text {
    const fn in_locale(self, locale: TableLocale) -> &'static str {
        match (locale, self) {
            (TableLocale::En, Self::Title(Creation::Signature)) => "Approve qualified signatures",
            (TableLocale::En, Self::Title(Creation::Seal)) => "Approve qualified seals",
            (TableLocale::En, Self::Confirm) => "Approve",
            (TableLocale::En, Self::Creates(Creation::Signature)) => {
                "Creates qualified electronic signatures"
            }
            (TableLocale::En, Self::Creates(Creation::Seal)) => {
                "Creates qualified electronic seals"
            }
            (TableLocale::En, Self::Under(Framework::Eidas)) => "under the EU eIDAS regulation",
            (TableLocale::En, Self::Count) => "Signatures",
            (TableLocale::En, Self::Name) => "Name",
            (TableLocale::En, Self::NoName) => "This document has no name",
            (TableLocale::En, Self::OneTimePassword) => "One-time password",
            (TableLocale::En, Self::Link) => "Document link",
            (TableLocale::En, Self::Embedded) => "Included in the request",
            (TableLocale::En, Self::Integrity) => "Integrity",
            (TableLocale::En, Self::Verified) => "Checked automatically",
            (TableLocale::En, Self::Unverified) => "Not checked",
            (TableLocale::De, Self::Title(Creation::Signature)) => {
                "Qualifizierte Signaturen freigeben"
            }
            (TableLocale::De, Self::Title(Creation::Seal)) => "Qualifizierte Siegel freigeben",
            (TableLocale::De, Self::Confirm) => "Freigeben",
            (TableLocale::De, Self::Creates(Creation::Signature)) => {
                "Erstellt qualifizierte elektronische Signaturen"
            }
            (TableLocale::De, Self::Creates(Creation::Seal)) => {
                "Erstellt qualifizierte elektronische Siegel"
            }
            (TableLocale::De, Self::Under(Framework::Eidas)) => "nach der EU-eIDAS-Verordnung",
            (TableLocale::De, Self::Count) => "Signaturen",
            (TableLocale::De, Self::Name) => "Name",
            (TableLocale::De, Self::NoName) => "Dieses Dokument hat keinen Namen",
            (TableLocale::De, Self::OneTimePassword) => "Einmalpasswort",
            (TableLocale::De, Self::Link) => "Dokument-Link",
            (TableLocale::De, Self::Embedded) => "In der Anfrage enthalten",
            (TableLocale::De, Self::Integrity) => "Integrität",
            (TableLocale::De, Self::Verified) => "Automatisch geprüft",
            (TableLocale::De, Self::Unverified) => "Nicht geprüft",
        }
    }
}

/// The section of the document at position `n`, from 1.
fn section(locale: TableLocale, n: usize) -> String {
    match locale {
        TableLocale::En => format!("Document {n}"),
        TableLocale::De => format!("Dokument {n}"),
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
    let say = |key: Text| key.in_locale(locale);
    let creation = approval.qualifier.creation();
    let mut rows = vec![
        Row::full_text(Label::text(format!(
            "{} {}",
            say(Text::Creates(creation)),
            say(Text::Under(approval.qualifier.framework()))
        ))),
        Row::new(Label::text(say(Text::Count)), text(approval.count.as_str())),
    ];
    for (k, document) in approval.documents.iter().enumerate() {
        let n = k + 1;
        let section = section(locale, n);
        for row in document_rows(document, n, held, env)? {
            rows.push(row.in_section(section.clone()));
        }
    }
    Ok(Rendered {
        rows,
        header: Header {
            title: Label::text(say(Text::Title(creation))),
            confirm: Label::text(say(Text::Confirm)),
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
    let say = |key: Text| key.in_locale(locale);
    let mut rows = vec![match document.label {
        Some(label) => Row::new(Label::text(say(Text::Name)), text(label)),
        None => Row::full_text(Label::text(say(Text::NoName))),
    }];
    if let Some(password) = document.one_time_password {
        rows.push(Row::new(
            Label::text(say(Text::OneTimePassword)),
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
        Err(_) => text(say(Text::Embedded)),
    };
    rows.push(Row::new(Label::text(say(Text::Link)), link));
    if let Some(checksum) = checksum {
        let checked = match held.get(href) {
            Some(fetched) if fetched.verifies(checksum) => Text::Verified,
            Some(_) => {
                return Err(Exclude::new(Excluded::Checksum { document: n }).into());
            }
            None => Text::Unverified,
        };
        rows.push(Row::new(
            Label::text(say(Text::Integrity)),
            text(say(checked)),
        ));
    }
    Ok(rows)
}
