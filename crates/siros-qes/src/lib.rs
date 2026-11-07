//! The CSC QES approval profile (CSC data model bindings 1.0.0 §7): the transaction data type
//! [`TYPE`], whose entry asks the End-User to approve the creation of qualified electronic
//! signatures or seals over linked documents.
//!
//! - The type's rules (OpenID4VP §5.1 `invalid_transaction_data`): §7.1.1's members and its
//!   example's, and one entry per Credential Query, since one presentation approves one request.
//! - The binding (§6.3; §7.2.1 Note 22): a credential approves the entry when its rulebook lets it
//!   approve the entry's `signatureQualifier` and its presentation can carry the approval.
//! - The rendering (§6.4): what the approval creates and under which framework, then per document
//!   its label, its one-time password, its link and whether its integrity was checked.
//! - The documents' checksums (§6.3): a linked document the wallet holds is verified against its
//!   checksum when the entry is bound; phase 2 fetches and verifies each other one.
//! - The response (§7.2, §7.2.1): `qesApproval`, the digest of the entry by its
//!   `hashAlgorithmOID`, as the [`NAMESPACE`] element `qesApproval` of an mdoc's `DeviceSigned`
//!   data, or as the Key Binding JWT claim [`CLAIM`].
//!
//! [`register`] registers a [`QesProfile`] for the type.

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

mod approval;
mod binding;
mod documents;
mod render;
mod rules;

use rustc_hash::FxHashMap;
use siros_explain::{AllOf, Message, Messages};
use siros_openid4vp::consent::Overlay;
use siros_openid4vp::detail;
use siros_openid4vp::ids::{InvalidId, TransactionType};
use siros_openid4vp::plugins::{
    Attested, Binding, Bound, BoundEntries, Build, Carriage, Exclude, Fault, FaultDomain,
    HostedProfile, Member, NoCandidate, Profile, RegistryBuilder,
};
use siros_openid4vp::refusal::Refusal;
use siros_openid4vp::request::{Entry, EntryIndex, Request};
use siros_openid4vp::rows::Env;
use siros_openid4vp::wallet_metadata::Placement;
#[cfg(feature = "resolve")]
use siros_openid4vp::{
    effects::Fetch,
    host::{Authentication, AuthenticationNeed, ProfileHost},
    plugins::{Answered, FetchedRecord, Members},
    rows::HttpsUrl,
};

pub use approval::{DocumentAt, DocumentNumber, Problem, SignatureQualifier};

use approval::ApprovalRequest;
use binding::Encoding;
pub use documents::{DocumentHref, FailedDocument, FailedDocuments, Fetched};
pub use render::{QesText, QesTitle};
pub use rules::{EntryPosition, Positions, QesRule};

use rules::Excluded;

/// The profile's domain, as its fault message.
pub(crate) const FAULT: FaultDomain = siros_explain::checked!(FaultDomain, "qes.fault");

/// The crate's module, `qes`: the messages of the texts the End-User sees. The wallet provides
/// their text in each of its languages, checked against this declaration when it loads.
pub struct CrateModule;

impl CrateModule {
    /// The module's identity.
    pub const ID: siros_explain::ModuleId =
        siros_explain::ModuleId::Crate(siros_explain::checked!(siros_explain::Domain, "qes"));
}

impl Messages for CrateModule {
    fn messages() -> Vec<Message> {
        [render::QesTitle::messages(), render::QesText::messages()].concat()
    }
}

/// Its request messages are the approval's rows' texts.
impl siros_explain::DeclaredModule for CrateModule {
    const ID: siros_explain::ModuleId = Self::ID;
    type Requested = render::QesText;
}

/// The profile's messages: those its rules and exclusions declare, and its fault's.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        [
            approval::Problem::messages(),
            QesRule::messages(),
            Excluded::messages(),
            vec![FAULT.message()],
        ]
        .concat()
    }
}

/// The transaction data type identifier (CSC §7.1).
pub const TYPE: &str = "https://cloudsignatureconsortium.org/2025/qes-approval";

macro_rules! namespace {
    () => {
        "org.cloudsignatureconsortium.dm.1"
    };
}

/// The name space of the `qesApproval` data element in an mdoc's `DeviceSigned` data (CSC
/// §7.2.1.1).
pub const NAMESPACE: &str = namespace!();

/// The Key Binding JWT claim holding `qesApproval` (CSC §7.2.1.2).
pub const CLAIM: &str = concat!(namespace!(), ".qesApproval");

/// The key of a credential's QES document in its registration: `{"signature_qualifiers"?:
/// [string, ...]}`, the CSC API `signatureQualifier` values its rulebook lets it approve (CSC
/// §7.2.1 Note 22). A credential without the document approves none.
pub const DOCUMENT: &str = "qes";

/// The QES approval profile, with the linked documents the wallet holds by URL.
///
/// A held document is verified against its checksum when an entry is bound: a mismatch or a
/// failed fetch excludes the credential (CSC §6.3, abort), a match shows its integrity checked.
/// Phase 2 fetches each document with a checksum the profile does not hold; the profile informed
/// of the documents that failed holds them too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QesProfile {
    held: FxHashMap<DocumentHref, Fetched>,
}

impl QesProfile {
    /// The profile holding the documents; a URL given twice holds the later one.
    pub fn new(held: impl IntoIterator<Item = (DocumentHref, Fetched)>) -> Self {
        Self {
            held: held.into_iter().collect(),
        }
    }
}

#[cfg(feature = "resolve")]
/// A linked document phase 2 checks: its `href` and its checksum (W3C SRI metadata).
struct Unheld<'a> {
    href: &'a str,
    checksum: &'a str,
}

#[cfg(feature = "resolve")]
impl QesProfile {
    /// The entry's linked documents with a checksum the profile does not hold, in the
    /// entry's order: those phase 2 checks.
    fn unheld<'a>(&'a self, approval: &'a ApprovalRequest<'a>) -> impl Iterator<Item = Unheld<'a>> {
        approval
            .documents
            .iter()
            .filter_map(|document| document.link)
            .filter(|link| !self.held.contains_key(link.href))
            .filter_map(|link| {
                link.checksum.map(|checksum| Unheld {
                    href: link.href,
                    checksum,
                })
            })
    }
}

/// Registers the profile for [`TYPE`], by its exact identifier.
pub fn register<H>(builder: &mut RegistryBuilder<H>, profile: QesProfile) -> Result<(), InvalidId>
where
    H: Build,
    QesProfile: HostedProfile<H>,
{
    let kind = TransactionType::parse(TYPE)?;
    let handle = builder.profile(profile);
    builder.exact(kind, handle);
    Ok(())
}

/// The one entry of the type naming a query, and its approval request; a fault when the entries
/// are not one entry of the request that keeps the type's rules, which the rules guarantee.
fn approval_of<'r>(
    request: &'r Request<'_>,
    entries: &[EntryIndex],
) -> Result<(EntryIndex, &'r Entry<'r>, ApprovalRequest<'r>), Fault> {
    let [index] = entries else {
        return Err(Fault::new(
            FAULT,
            detail!(
                "QES entries {entries:?}: one presentation approves one entry",
                entries = entries.to_vec()
            ),
        ));
    };
    let entry = request.entry(*index).ok_or_else(|| {
        Fault::new(
            FAULT,
            detail!("QES entry {entry}: not in the request", entry = index.get()),
        )
    })?;
    let approval = ApprovalRequest::parse(entry.members()).map_err(|problems| {
        let entry = index.get();
        Fault::new(FAULT, move |f| {
            write!(f, "QES entry {entry}: breaks the type's rules (")?;
            for (k, problem) in problems.iter().enumerate() {
                if k > 0 {
                    f.write_str("; ")?;
                }
                write!(f, "{problem}")?;
            }
            f.write_str(")")
        })
    })?;
    Ok((*index, entry, approval))
}

impl Profile for QesProfile {
    type Finding = FailedDocuments;

    /// Each entry keeps the type's rules; no two entries name one query.
    fn refusals(&self, request: &Request<'_>, entries: &[EntryIndex]) -> Vec<Refusal> {
        let own: Vec<(EntryIndex, &Entry<'_>)> = request
            .indexed_entries()
            .filter(|(index, _)| entries.contains(index))
            .collect();
        let mut refusals: Vec<Refusal> = own
            .iter()
            .filter_map(|(index, entry)| {
                ApprovalRequest::parse(entry.members())
                    .err()
                    .map(|problems| (index, problems))
            })
            .flat_map(|(index, problems)| {
                problems.into_iter().map(move |problem| {
                    Refusal::new(QesRule::Entry {
                        entry: EntryPosition::of(*index),
                        problem,
                    })
                })
            })
            .collect();
        refusals.extend(one_request_per_presentation(&own));
        refusals
    }

    /// §7.2.1: `qesApproval` as a claim or as a name space's element.
    fn members(&self, placement: Placement) -> Option<&[Member]> {
        Some(Encoding::of(placement).members())
    }

    /// Binds the query's entry when the credential's rulebook lets it approve the entry's
    /// qualifier (§6.3; §7.2.1 Note 22), its presentation can carry the approval (§7.2.1), and no
    /// linked document it holds fails its checksum (§6.3); rendered by §6.4, attesting nothing
    /// beyond the entry, which the approval hashes.
    fn bind(&self, binding: Binding<'_>, _env: &Env) -> Result<Bound, NoCandidate> {
        let (index, _, approval) = approval_of(binding.request, binding.entries)?;
        if !binding::approves(binding.credential, approval.qualifier)? {
            return Err(Exclude::new(Excluded::Qualifier {
                qualifier: approval.qualifier,
            })
            .into());
        }
        if binding.carriage == Carriage::Uncarried {
            return Err(Exclude::new(Excluded::Carriage).into());
        }
        let rendered = render::render(&approval, &self.held)?;
        let entries = BoundEntries::select(binding.entries, vec![index])
            .map_err(|e| Fault::caused(FAULT, detail!("QES bound entries"), e))?;
        Ok(Bound {
            entries,
            header: rendered.header,
            attested: Attested::default(),
            overlay: Overlay {
                rows: rendered.rows,
                header: None,
                hint: None,
            },
            selected: None,
        })
    }
}

/// One presentation approves one request: no two of the profile's entries name one query. The
/// queries in the order the entries first name them.
fn one_request_per_presentation(own: &[(EntryIndex, &Entry<'_>)]) -> Vec<Refusal> {
    let mut named: Vec<&str> = Vec::new();
    for id in own.iter().flat_map(|(_, entry)| entry.credential_ids()) {
        if !named.contains(&id.as_str()) {
            named.push(id.as_str());
        }
    }
    named
        .into_iter()
        .filter_map(|id| {
            let naming: Vec<EntryPosition> = own
                .iter()
                .filter(|(_, entry)| entry.credential_ids().iter().any(|named| *named == *id))
                .map(|(index, _)| EntryPosition::of(*index))
                .collect();
            AllOf::new(naming)
                .filter(|entries| entries.items().len() > 1)
                .map(|entries| {
                    Refusal::new(QesRule::OneRequest {
                        entries: Positions::new(entries),
                        query: id.to_owned(),
                    })
                })
        })
        .collect()
}

#[cfg(feature = "resolve")]
/// Needs no module.
impl<H> ProfileHost<H> for QesProfile {
    /// CSC §6.3: each linked document with a checksum the profile does not hold, whose
    /// `href` is an https URL.
    fn wanted(&self, record: Answered<'_>, _host: &H) -> Result<Vec<HttpsUrl>, Fault> {
        let (_, _, approval) = approval_of(record.request(), record.entries().entries())?;
        Ok(self
            .unheld(&approval)
            .filter_map(|document| HttpsUrl::parse(document.href).ok())
            .collect())
    }

    /// The profile holding the failed documents too: binding then excludes the credential
    /// (§6.3, abort).
    fn informed(&self, findings: &[&FailedDocuments]) -> Self {
        let failed = findings
            .iter()
            .flat_map(|finding| finding.documents())
            .map(|document| (document.href().clone(), document.fetched().clone()));
        Self::new(self.held.clone().into_iter().chain(failed))
    }

    /// Presence.
    fn authentication(&self, _record: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }

    /// CSC §6.3: each linked document with a checksum the profile does not hold, as the
    /// caller fetched it; the finding lists those whose fetch failed or whose content does
    /// not match.
    fn revalidate(
        &self,
        record: FetchedRecord<'_>,
        _host: &H,
    ) -> Result<Option<FailedDocuments>, Fault> {
        let answered = record.record();
        let resources = record.resources();
        let (_, _, approval) = approval_of(answered.request(), answered.entries().entries())?;
        let failed = self
            .unheld(&approval)
            .map(|document| {
                let fetched = match HttpsUrl::parse(document.href) {
                    Ok(url) => match resources.fetched(&url) {
                        Some(Fetch::Fetched { content, .. }) => Fetched::Content(content.clone()),
                        Some(Fetch::Unfetched) => Fetched::Failed,
                        None => {
                            return Err(Fault::new(
                                FAULT,
                                detail!("a document the profile wanted is unanswered"),
                            ));
                        }
                    },
                    Err(_) => Fetched::Failed,
                };
                Ok((!fetched.verifies(document.checksum))
                    .then(|| FailedDocument::new(DocumentHref::new(document.href), fetched)))
            })
            .filter_map(Result::transpose)
            .collect::<Result<Vec<_>, Fault>>()?;
        Ok(FailedDocuments::of(failed))
    }

    /// `qesApproval` (CSC §7.2, §7.2.1) in the presentation's format.
    fn respond(
        &self,
        record: Answered<'_>,
        _host: &H,
        _authentication: &Authentication,
    ) -> Result<Members, Fault> {
        let (_, entry, approval) = approval_of(record.request(), record.entries().entries())?;
        let encoding = record.placement().map(Encoding::of).ok_or_else(|| {
            Fault::new(
                FAULT,
                detail!("QES binds no presentation whose proof carries no members"),
            )
        })?;
        encoding
            .approval(approval.hash, entry)
            .map_err(|e| Fault::caused(FAULT, detail!("qesApproval"), e))
    }
}
