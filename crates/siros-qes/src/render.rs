//! CSC §6.4: the approval rendered for the End-User, in the profile's own strings.
//!
//! First a full-text row: what the approval creates, signatures or seals, under which framework.
//! Then the number of signatures, and per document, in a section of its own: its full label or
//! that it has none, its one-time password, its link, and whether its integrity was checked.

use rustc_hash::FxHashMap;
use siros_explain::Explain;
use siros_explain::Text;
use siros_openid4vp::consent::Header;
use siros_openid4vp::detail;
use siros_openid4vp::plugins::{Exclude, Fault, NoCandidate};
use siros_openid4vp::rows::{HttpsUrl, NotHttpsUrl, Row, Value, WalletText};

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
}

/// The rows the approval shows and its consent header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The rows, shown before the credential's.
    pub(crate) rows: Vec<Row>,
    /// The header.
    pub(crate) header: Header,
}

/// A value the request wrote, shown as written.
fn written(text: &str) -> Value {
    Value::Text(Text::Raw(text.to_owned()))
}

/// A value of the profile's own: a message of its module.
fn own(text: QesText) -> Value {
    Value::Text(Text::of(&text))
}

/// The approval's rows and header. Excluded when a linked document the wallet holds
/// fails its checksum (§6.3, abort): the first such document in array order.
pub(crate) fn render(
    approval: &ApprovalRequest<'_>,
    held: &FxHashMap<String, Fetched>,
) -> Result<Rendered, NoCandidate> {
    let qualifier = approval.qualifier;
    let mut rows = vec![
        Row::full_text(Text::of(&QesText::creates(qualifier))),
        Row::new(Text::of(&QesText::Count), written(approval.count.as_str())),
    ];
    for (k, document) in approval.documents.iter().enumerate() {
        let n = k + 1;
        let section = Text::of(&QesText::Section { document: n });
        for row in document_rows(document, n, held)? {
            rows.push(row.in_section(section.clone()));
        }
    }
    Ok(Rendered {
        rows,
        header: Header {
            title: Text::of(&QesText::title(qualifier)),
            confirm: Text::of(&QesText::Confirm),
            cancel: Text::of(&WalletText::Deny),
        },
    })
}

/// The rows of the document at position `n`: its label or that it has none, its one-time
/// password, its link, and with a checksum whether its integrity was checked.
fn document_rows(
    document: &DocumentInfo<'_>,
    n: usize,
    held: &FxHashMap<String, Fetched>,
) -> Result<Vec<Row>, NoCandidate> {
    let mut rows = vec![match document.label {
        Some(label) => Row::new(Text::of(&QesText::Name), written(label)),
        None => Row::full_text(Text::of(&QesText::NoName)),
    }];
    if let Some(password) = document.one_time_password {
        rows.push(Row::new(
            Text::of(&QesText::OneTimePassword),
            written(password),
        ));
    }
    let Some(Link { href, checksum }) = document.link else {
        return Ok(rows);
    };
    let link = match HttpsUrl::parse(href) {
        Ok(url) => Value::url(&url),
        Err(e @ NotHttpsUrl::ALabel { .. }) => {
            return Err(Fault::caused(FAULT, detail!("QES document {n}: its link"), e).into());
        }
        Err(_) => own(QesText::Embedded),
    };
    rows.push(Row::new(Text::of(&QesText::Link), link));
    if let Some(checksum) = checksum {
        let checked = match held.get(href) {
            Some(fetched) if fetched.verifies(checksum) => QesText::Verified,
            Some(_) => {
                return Err(Exclude::new(Excluded::Checksum { document: n }).into());
            }
            None => QesText::Unverified,
        };
        rows.push(Row::new(Text::of(&QesText::Integrity), own(checked)));
    }
    Ok(rows)
}
