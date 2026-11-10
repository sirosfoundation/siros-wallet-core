//! CSC §6.4: the approval rendered for the End-User, each text the context's wording of a
//! statement.
//!
//! First a full-text row: what the approval creates, signatures or seals, under which framework.
//! Then the number of signatures, and per document, in a section of its own: its full label or
//! that it has none, its one-time password, its link, and whether its integrity was checked.

use rustc_hash::FxHashMap;
use siros_i18n::{Context, Message, Text};
use siros_openid4vp::consent::Header;
use siros_openid4vp::detail;
use siros_openid4vp::plugins::{Exclude, Fault, NoCandidate};
use siros_openid4vp::rows::{
    ClaimText, ExactNumber, HttpsUrl, NotHttpsUrl, Row, Value, WalletText,
};

use crate::approval::{
    ApprovalRequest, Creation, DocumentInfo, DocumentNumber, Framework, Link, SignatureQualifier,
};
use crate::documents::{DocumentHref, Fetched};
use crate::rules::Excluded;

/// The consent header's texts of the profile's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
pub enum QesTitle {
    /// The consent title of signatures.
    #[message(id = "approval.title_signatures")]
    TitleSignatures,
    /// The consent title of seals.
    #[message(id = "approval.title_seals")]
    TitleSeals,
    /// The confirm action.
    #[message(id = "approval.confirm")]
    Confirm,
}

impl QesTitle {
    /// The consent title of an approval.
    const fn of(qualifier: SignatureQualifier) -> Self {
        match qualifier.creation() {
            Creation::Signature => Self::TitleSignatures,
            Creation::Seal => Self::TitleSeals,
        }
    }
}

/// The texts of the approval's rows of the profile's own, which its overlay shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Message)]
pub enum QesText {
    /// What an `eu_eidas_qes` approval creates.
    #[message(id = "approval.creates_eidas_signatures")]
    CreatesEidasSignatures,
    /// What an `eu_eidas_qeseal` approval creates.
    #[message(id = "approval.creates_eidas_seals")]
    CreatesEidasSeals,
    /// The label of the number of signatures.
    #[message(id = "approval.count")]
    Count,
    /// The label of a document's label.
    #[message(id = "approval.name")]
    Name,
    /// The row of a document without a label.
    #[message(id = "approval.no_name")]
    NoName,
    /// The label of a document's one-time password.
    #[message(id = "approval.one_time_password")]
    OneTimePassword,
    /// The label of a document's link.
    #[message(id = "approval.link")]
    Link,
    /// A link other than https: the document came with the request.
    #[message(id = "approval.embedded")]
    Embedded,
    /// The label of a document's integrity.
    #[message(id = "approval.integrity")]
    Integrity,
    /// The integrity checked against the document the wallet holds.
    #[message(id = "approval.verified")]
    Verified,
    /// The integrity not checked.
    #[message(id = "approval.unverified")]
    Unverified,
    /// The heading of the rows of a document of the approval.
    #[message(id = "approval.section")]
    Section {
        /// The document.
        document: DocumentNumber,
    },
}

impl QesText {
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

/// A linked document's link as the approval shows it, and with a checksum whether its integrity
/// was checked.
struct Linked {
    /// Where the link leads.
    target: Target,
    /// Whether the integrity was checked, for a document with a checksum.
    integrity: Option<Integrity>,
}

/// Where a document's link leads.
enum Target {
    /// An https URL, shown in its ASCII form.
    Url(HttpsUrl),
    /// A link other than https: the document came with the request.
    Embedded,
}

/// Whether a document's integrity was checked.
#[derive(Clone, Copy)]
enum Integrity {
    /// Checked against the document the wallet holds.
    Verified,
    /// Not checked.
    Unverified,
}

impl Integrity {
    /// Its row's value.
    const fn text(self) -> QesText {
        match self {
            Self::Verified => QesText::Verified,
            Self::Unverified => QesText::Unverified,
        }
    }
}

/// The text `context` words for a message; the profile's fault, caused by the
/// `siros_i18n::ResolveError`, when it words none.
fn resolve(context: &Context, message: &dyn Message) -> Result<Text, Fault> {
    context
        .resolve(message)
        .map_err(|e| crate::caused(detail!("{id}: no text", id = message.id().to_owned()), e))
}

/// A value the request wrote, shown as written.
fn written(context: &Context, text: &str) -> Result<Value, Fault> {
    resolve(
        context,
        &ClaimText::Text {
            value: text.to_owned(),
        },
    )
    .map(Value::Text)
}

/// The approval's rows and header, each text resolved by `context`. Excluded when a linked
/// document the wallet holds fails its checksum (§6.3, abort): the first such document in array
/// order, decided before any text resolves.
pub(crate) fn render(
    approval: &ApprovalRequest<'_>,
    held: &FxHashMap<DocumentHref, Fetched>,
    context: &Context,
) -> Result<Rendered, NoCandidate> {
    let documents = approval
        .numbered_documents()
        .map(|(n, document)| {
            let linked = document
                .link
                .map(|link| linked(link, n, held))
                .transpose()?;
            Ok((n, document, linked))
        })
        .collect::<Result<Vec<_>, NoCandidate>>()?;
    let text = |message: &dyn Message| resolve(context, message);
    let qualifier = approval.qualifier;
    let mut rows = vec![
        Row::full_text(text(&QesText::creates(qualifier))?),
        Row::new(
            text(&QesText::Count)?,
            Value::Text(text(&ClaimText::Number {
                value: ExactNumber::Count(approval.count.count()),
            })?),
        ),
    ];
    for (n, document, linked) in documents {
        let section = text(&QesText::Section { document: n })?;
        for row in document_rows(document, linked, context)? {
            rows.push(row.in_section(section.clone()));
        }
    }
    Ok(Rendered {
        rows,
        header: Header {
            title: text(&QesTitle::of(qualifier))?,
            confirm: text(&QesTitle::Confirm)?,
            cancel: text(&WalletText::Deny)?,
        },
    })
}

/// Document `n`'s link as the approval shows it. Excluded when the wallet holds the document and
/// it fails its checksum (§6.3, abort).
fn linked(
    link: Link<'_>,
    n: DocumentNumber,
    held: &FxHashMap<DocumentHref, Fetched>,
) -> Result<Linked, NoCandidate> {
    let target = match HttpsUrl::parse(link.href) {
        Ok(url) => Target::Url(url),
        Err(e @ (NotHttpsUrl::LabelOverflow | NotHttpsUrl::NotRegName)) => {
            return Err(crate::caused(detail!("QES document {n}: its link"), e).into());
        }
        Err(_) => Target::Embedded,
    };
    let integrity = match link.checksum {
        None => None,
        Some(checksum) => Some(match held.get(link.href) {
            Some(fetched) if fetched.verifies(checksum) => Integrity::Verified,
            Some(_) => {
                return Err(Exclude::new(Excluded::Checksum { document: n }).into());
            }
            None => Integrity::Unverified,
        }),
    };
    Ok(Linked { target, integrity })
}

/// The rows of a document: its label or that it has none, its one-time password, its link, and
/// with a checksum whether its integrity was checked.
fn document_rows(
    document: &DocumentInfo<'_>,
    linked: Option<Linked>,
    context: &Context,
) -> Result<Vec<Row>, Fault> {
    let text = |message: &dyn Message| resolve(context, message);
    let mut rows = vec![match document.label {
        Some(label) => Row::new(text(&QesText::Name)?, written(context, label)?),
        None => Row::full_text(text(&QesText::NoName)?),
    }];
    if let Some(password) = document.one_time_password {
        rows.push(Row::new(
            text(&QesText::OneTimePassword)?,
            written(context, password)?,
        ));
    }
    let Some(Linked { target, integrity }) = linked else {
        return Ok(rows);
    };
    let link = match target {
        Target::Url(url) => written(context, url.ascii())?,
        Target::Embedded => Value::Text(text(&QesText::Embedded)?),
    };
    rows.push(Row::new(text(&QesText::Link)?, link));
    if let Some(integrity) = integrity {
        rows.push(Row::new(
            text(&QesText::Integrity)?,
            Value::Text(text(&integrity.text())?),
        ));
    }
    Ok(rows)
}
