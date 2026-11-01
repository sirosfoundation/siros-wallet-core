//! The response of a chosen offer: the signatures parsed against their `Sign` effects (A5), the
//! presentations, one `vp_token` (A8), its submission (P4) and the presentation record (W4).

use itertools::Itertools;
use rand_core::CryptoRngCore;
use siros_codec::signature::Es256Signature;
use siros_dcql::QueryId;
use siros_oid4vp::{Presentation, Submission};
use siros_wallet_state::{CredentialId, PresentationId, PresentationRecord, TransactionId};
use siros_zkp_req_nym_auth::prover::NymAuthProver;

use super::prepare::{audience, PendingMember, Prepared};
use super::sign::{verified, Sign, SignId, VerifiedSignature};
use crate::error::PresentationError;

/// What the wallet sends, and what it records.
pub struct Response {
    submission: Submission,
    record: PresentationRecord,
}

impl Response {
    /// The submission in the form of the request's Response Mode (P4).
    pub fn submission(&self) -> &Submission {
        &self.submission
    }

    /// The record the host appends as a `new_presentation` event (H5).
    pub fn record(&self) -> &PresentationRecord {
        &self.record
    }

    /// The submission and the record.
    pub fn into_parts(self) -> (Submission, PresentationRecord) {
        (self.submission, self.record)
    }
}

impl Prepared<'_, '_> {
    /// The `Sign` effects, each of which the host answers with a signature.
    pub fn signs(&self) -> &[Sign] {
        &self.signs
    }

    /// The response, with `signatures` the host made for [`Prepared::signs`], each `r ‖ s`.
    ///
    /// Each signature answers one `Sign` effect and verifies under the key it names, and every
    /// effect has one (A5). `prover` proves each nym_auth statement in-process. One `vp_token`
    /// answers every member, keyed by query id (A8). `rng` gives the response encryption's
    /// ephemeral key and IV, then the record's `presentationId` and `transactionId`. The record
    /// names exactly the instances the presentations use, its `data` is the `vp_token` as JSON
    /// text, its time the plan's, and its `audience` that of the KB-JWT (A6).
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: a signature that names no effect, two that answer one effect, an
    /// effect without a signature, a signature that does not verify, a proof that failed, or a
    /// `vp_token` or submission that could not be built.
    pub fn finish(
        self,
        signatures: Vec<(SignId, Es256Signature)>,
        prover: &dyn NymAuthProver,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Response, PresentationError> {
        let signatures = verified(&self.signs, signatures)?;
        let used = used(&self.members);
        let entries: Vec<(QueryId, Vec<Presentation>)> = self
            .members
            .into_iter()
            .map(|member| presentations(member, &signatures, prover))
            .try_collect()?;
        let planned = self.chosen.planned;
        let request = planned.input.request;
        let token = request.vp_token(entries)?;
        let submission = token.submission(rng)?;
        let record = PresentationRecord::new(
            PresentationId::new(rng.next_u64()),
            TransactionId::new(rng.next_u64()),
            token.json().to_string(),
            used,
            planned.input.now,
            audience(request)?.as_str().to_owned(),
        );
        Ok(Response { submission, record })
    }
}

/// The `vp_token` entry of `member`: its query id and the presentation of each of its
/// credentials.
fn presentations(
    member: PendingMember<'_>,
    signatures: &[VerifiedSignature],
    prover: &dyn NymAuthProver,
) -> Result<(QueryId, Vec<Presentation>), PresentationError> {
    let presentations = member
        .credentials
        .into_iter()
        .map(|(_, form)| form.present(signatures, prover))
        .try_collect()?;
    Ok((member.query_id, presentations))
}

/// The instances `members` present, each once, in order.
fn used(members: &[PendingMember<'_>]) -> Vec<CredentialId> {
    members
        .iter()
        .flat_map(|member| member.credentials.iter().map(|(id, _)| *id))
        .fold(Vec::new(), |mut used, id| {
            if !used.contains(&id) {
                used.push(id);
            }
            used
        })
}
