//! The plan's digest (A4): SHA-256 of the canonical CBOR of the request and of every offer the
//! user can choose.

use std::fmt;

use sha2::{Digest, Sha256};
use siros_codec::cbor::Value;
use siros_codec::{base64url, Base64Error};
use siros_dcql::PathComponent;
use siros_oid4vp::VerifiedRequest;
use siros_zkp_req_nym_auth::verifier_id::VerifierId;

use super::view::{AdditionView, BoundTransaction, CredentialView, MemberView, OfferView};
use crate::display_rule::WalletDisplay;
use siros_dcql::HolderBinding;
use siros_transaction_data::EntryPosition;

use crate::matching::Answer;

/// The domain of the digest, which names this encoding.
const DOMAIN: &str = "siros-presentation plan 2";

/// The digest of a plan: what the user consents to, and what the selection returns (A4). Its
/// text is unpadded base64url.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlanDigest([u8; 32]);

/// Why a selection's plan digest does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum DigestError {
    /// The text is not unpadded base64url.
    Encoding(#[source] Base64Error),
    /// The text decodes to this many bytes; a digest has 32.
    Length(usize),
}

impl DigestError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Encoding(_) => "selection_digest_encoding",
            Self::Length(_) => "selection_digest_length",
        }
    }
}

impl PlanDigest {
    /// The digest of the text `text`, as the view gave it.
    ///
    /// # Errors
    ///
    /// [`DigestError`]: text that is not unpadded base64url, or not of 32 bytes.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        let bytes = base64url::decode(text).map_err(DigestError::Encoding)?;
        let length = bytes.len();
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| DigestError::Length(length))
    }

    /// The digest of the plan of `request`, whose nym_auth `verifier_id` is `verifier_id`, and
    /// whose offers the user sees as `views`.
    ///
    /// It covers the request's response mode, Client Identifier, trust verdict, origin,
    /// response URI, `nonce`, `state`, `dcql_query` as sent, `transaction_data` and the
    /// nym_auth `verifier_id`; and for each offer its members with every candidate's
    /// `credentialId`, instance and answer and the position of the entry bound to it, its
    /// additions with theirs, and whether it needs the wallet's display.
    pub(crate) fn of(
        request: &VerifiedRequest,
        verifier_id: Option<&VerifierId>,
        views: &[OfferView],
    ) -> Self {
        let plan = Value::Array(vec![
            Value::text(DOMAIN),
            request_part(request, verifier_id),
            list(views),
        ]);
        Self(Sha256::digest(plan.encode()).into())
    }
}

impl fmt::Display for PlanDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(base64url::encode(&self.0).as_str())
    }
}

/// The request's part of the digest.
fn request_part(request: &VerifiedRequest, verifier_id: Option<&VerifierId>) -> Value {
    let verifier = request.verifier();
    let transaction_data = request
        .transaction_data()
        .iter()
        .map(|entry| Value::text(entry.as_str()))
        .collect();
    Value::Array(vec![
        Value::text(request.response_mode().as_str()),
        optional(verifier.client_id().map(|c| c.as_str())),
        Value::Bool(verifier.verdict().into()),
        optional(request.origin().map(|origin| origin.as_str())),
        optional(request.response_uri().map(|u| u.as_str())),
        Value::text(request.nonce().as_str()),
        optional(request.state().map(|state| state.as_str())),
        Value::text(&request.dcql_query_json().to_string()),
        Value::Array(transaction_data),
        optional(verifier_id.map(VerifierId::as_str)),
    ])
}

/// A part of the plan in the digest's CBOR.
trait Encode {
    fn encode(&self) -> Value;
}

/// The CBOR array of each of `items`.
fn list<T: Encode>(items: &[T]) -> Value {
    Value::Array(items.iter().map(Encode::encode).collect())
}

/// A text, or `null`.
fn optional(text: Option<&str>) -> Value {
    text.map_or(Value::Null, Value::text)
}

/// Its members, its additions, and whether it needs the wallet's display.
impl Encode for OfferView {
    fn encode(&self) -> Value {
        Value::Array(vec![
            list(self.members()),
            list(self.additions()),
            Value::Bool(self.wallet_display() == WalletDisplay::Needed),
        ])
    }
}

/// Its credential set, and its members.
impl Encode for AdditionView {
    fn encode(&self) -> Value {
        Value::Array(vec![
            Value::Unsigned(self.set().value() as u64),
            list(self.members()),
        ])
    }
}

/// Its query's `id`, and its credentials.
impl Encode for MemberView {
    fn encode(&self) -> Value {
        Value::Array(vec![
            Value::text(self.query_id().as_str()),
            list(self.credentials()),
        ])
    }
}

/// Its `credentialId` and instance, its answer, and the entry bound to it, in an array of none
/// or one.
impl Encode for CredentialView {
    fn encode(&self) -> Value {
        let entry = self.entry();
        Value::Array(vec![
            Value::text(&entry.credential_id().to_string()),
            Value::text(&entry.instance_id().to_string()),
            self.answer().encode(),
            Value::Array(self.transaction().map(Encode::encode).into_iter().collect()),
        ])
    }
}

/// The entry's position, the source of the definition that renders it, and its payload's
/// rulebook, which decides the KB-JWT's TS12 claims.
impl Encode for BoundTransaction {
    fn encode(&self) -> Value {
        let view = self.view();
        Value::Array(vec![
            self.entry().encode(),
            Value::text(view.source().as_str()),
            Value::text(view.rulebook().as_str()),
        ])
    }
}

impl Encode for EntryPosition {
    fn encode(&self) -> Value {
        Value::Unsigned(self.value() as u64)
    }
}

/// `[0, holder binding, pointers]` for claims; `[1, option, system, proof backend]` for a
/// proof.
impl Encode for Answer {
    fn encode(&self) -> Value {
        match self {
            Self::Claims(claims) => Value::Array(vec![
                Value::Unsigned(0),
                Value::Bool(claims.holder_binding() == HolderBinding::Required),
                Value::Array(
                    claims
                        .pointers()
                        .iter()
                        .map(|pointer| list(pointer.components()))
                        .collect(),
                ),
            ]),
            Self::Proof(choice) => Value::Array(vec![
                Value::Unsigned(1),
                Value::Unsigned(choice.option().value() as u64),
                Value::text(choice.system().id().as_str()),
                Value::text(choice.backend().as_str()),
            ]),
        }
    }
}

impl Encode for PathComponent {
    fn encode(&self) -> Value {
        match self {
            Self::Key(key) => Value::text(key),
            Self::Index(index) => Value::Unsigned(*index),
            Self::Null => Value::Null,
        }
    }
}
