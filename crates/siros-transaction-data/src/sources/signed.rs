//! The verification a signed credential metadata JWT (PaSO Proof Metadata, Section 7) and an
//! ad-hoc metadata JWT (Section 5.3) share: `typ`, the signature, the signing key's trust,
//! `iss`, `exp`, and the binding to the credential.

use siros_codec::base64;
use siros_codec::chain::CertificateChain;
use siros_codec::date::DateTime;
use siros_codec::json::Json;
use siros_codec::member::MemberFault;
use siros_credential::Credential;
use siros_trust::{Certificate, ChainError, IssuerChain, TrustStore, Unanchored};

use super::held::HeldMetadata;
use super::issuer_keys::{self, KeySetFault};
use super::jws::{Jws, JwsFault, VerifyingKey};
use crate::json::{self, Fields};

/// The device-signed namespace of PaSO Core, Section 6.3, which no `sub` names (Section 7,
/// step 6).
const SCA_NAMESPACE: &str = "urn:paso:sca:1";

/// A claim of a metadata JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataClaim {
    /// `iss`.
    Iss,
    /// `sub`.
    Sub,
    /// `format`.
    Format,
    /// `iat`.
    Iat,
    /// `exp`.
    Exp,
    /// `credential_metadata_uri` of a signed credential metadata JWT.
    CredentialMetadataUri,
    /// `credential_metadata` of a signed credential metadata JWT.
    CredentialMetadata,
    /// `transaction_data_types` of `credential_metadata`.
    TransactionDataTypes,
    /// `transaction_data_type` of an ad-hoc metadata JWT.
    TransactionDataType,
    /// `metadata` of an ad-hoc metadata JWT.
    Metadata,
}

impl MetadataClaim {
    /// The claim's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iss => "iss",
            Self::Sub => "sub",
            Self::Format => "format",
            Self::Iat => "iat",
            Self::Exp => "exp",
            Self::CredentialMetadataUri => "credential_metadata_uri",
            Self::CredentialMetadata => "credential_metadata",
            Self::TransactionDataTypes => "transaction_data_types",
            Self::TransactionDataType => "transaction_data_type",
            Self::Metadata => "metadata",
        }
    }
}

/// Why a metadata JWT is invalid (Sections 5.3 and 7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum SignedFault {
    /// The text is no JWS this wallet verifies.
    Jws(#[source] JwsFault),
    /// `typ` is absent or other than the JWT's type (step 1).
    Typ,
    /// The header names its key by neither `x5c` nor `kid`.
    KeyAbsent,
    /// `kid` is no string.
    Kid,
    /// The header names its key by `kid` alone, and the credential's issuer keys are an `x5c`
    /// chain; or by `x5c`, and the credential carries no chain (Section 4).
    KeyKind,
    /// `x5c` is no non-empty array of base64 certificates.
    X5c,
    /// A certificate of `x5c` does not parse.
    Chain(#[source] ChainError),
    /// The leaf key is no P-256 or P-384 key.
    LeafKey,
    /// The `x5c` chain has no path to the trust store (step 3).
    Untrusted(#[source] Unanchored),
    /// The issuer's key set gives no key of the `kid` (step 3).
    KeySet(#[source] KeySetFault),
    /// The signature does not verify (step 2).
    Signature,
    /// A claim is absent or of the wrong type.
    Claim(MetadataClaim, #[source] MemberFault),
    /// `iss` is not the credential's Credential Issuer Identifier, or the wallet does not know
    /// it (step 4).
    Issuer,
    /// `exp` has passed (step 5).
    Expired,
    /// `sub` is not the credential's type, or names PaSO's device-signed namespace (step 6).
    Subject,
    /// `format` is not the credential's format.
    Format,
    /// The credential's own chain has no path to the trust store, so it names no root (step
    /// 6).
    CredentialUntrusted(#[source] Unanchored),
    /// The JWT's chain ends at another root than the credential's (step 6).
    Root,
    /// The JWT's leaf has another Subject than the credential's leaf (step 6).
    LeafSubject,
    /// An ad-hoc JWT's `transaction_data_type` is not the entry's `type` (Section 5.3, step 7).
    TransactionDataType,
}

impl SignedFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Jws(fault) => fault.code(),
            Self::Typ => "metadata_jwt_typ",
            Self::KeyAbsent => "metadata_jwt_key_absent",
            Self::Kid => "metadata_jwt_kid",
            Self::KeyKind => "metadata_jwt_key_kind",
            Self::X5c => "metadata_jwt_x5c",
            Self::Chain(error) => error.code(),
            Self::LeafKey => "metadata_jwt_leaf_key",
            Self::Untrusted(_) => "metadata_jwt_untrusted",
            Self::KeySet(fault) => fault.code(),
            Self::Signature => "metadata_jwt_signature",
            Self::Claim(..) => "metadata_jwt_claim",
            Self::Issuer => "metadata_jwt_issuer",
            Self::Expired => "metadata_jwt_expired",
            Self::Subject => "metadata_jwt_subject",
            Self::Format => "metadata_jwt_format",
            Self::CredentialUntrusted(_) => "metadata_jwt_credential_untrusted",
            Self::Root => "metadata_jwt_root",
            Self::LeafSubject => "metadata_jwt_leaf_subject",
            Self::TransactionDataType => "metadata_jwt_transaction_data_type",
        }
    }
}

/// What a verification reads with: the trust store, the metadata the host holds, and the time.
#[derive(Clone, Copy)]
pub(crate) struct Verifier<'v> {
    pub(crate) trust: &'v TrustStore,
    pub(crate) held: &'v HeldMetadata,
    pub(crate) now: DateTime,
}

/// The claims of a verified metadata JWT that the steps both verifications share leave, and its
/// `exp`.
pub(crate) struct Verified {
    pub(crate) claims: Fields,
    pub(crate) expires: DateTime,
}

/// The metadata JWT `text` of type `typ` for `credential`, after the steps both verifications
/// share: `iss`, `sub`, `format`, `iat` and `exp` taken, the other claims left.
pub(crate) fn verify(
    text: &str,
    typ: &str,
    credential: &Credential,
    verifier: Verifier<'_>,
) -> Result<Verified, SignedFault> {
    let mut jws = Jws::parse(text).map_err(SignedFault::Jws)?;
    // Step 1.
    match jws.header.take("typ") {
        Some(Json::String(found)) if found == typ => {}
        _ => return Err(SignedFault::Typ),
    }
    // Steps 2 and 3, and the root and leaf of step 6.
    let key = signing_key(&mut jws.header, credential, verifier)?;
    if !jws.verified_by(&key) {
        return Err(SignedFault::Signature);
    }
    let mut claims = jws.payload;
    // Step 4.
    let iss = text_claim(&mut claims, MetadataClaim::Iss)?;
    if credential.issuer().map(|issuer| issuer.as_str()) != Some(iss.as_str()) {
        return Err(SignedFault::Issuer);
    }
    // Step 5.
    let exp = date_claim(&mut claims, MetadataClaim::Exp)?;
    let expires = DateTime::from_unix(exp).ok_or(SignedFault::Claim(
        MetadataClaim::Exp,
        MemberFault::WrongType,
    ))?;
    if exp <= verifier.now.unix() {
        return Err(SignedFault::Expired);
    }
    // The type of step 6.
    let sub = text_claim(&mut claims, MetadataClaim::Sub)?;
    if sub == SCA_NAMESPACE || sub != credential.credential_type().as_str() {
        return Err(SignedFault::Subject);
    }
    if text_claim(&mut claims, MetadataClaim::Format)? != credential.format().identifier() {
        return Err(SignedFault::Format);
    }
    date_claim(&mut claims, MetadataClaim::Iat).map(drop)?;
    Ok(Verified { claims, expires })
}

/// The key that signed the JWT of `header`, trusted and bound to `credential` (steps 3 and 6).
///
/// A credential with an `x5c` chain takes the JWT's `x5c` chain, a `kid` beside it unused: the
/// chain has a path to the trust store at the same root as the credential's, and the two leaves
/// have one Subject. A credential without a chain takes the `kid` alone, the key of its issuer's
/// key set, the set that verifies the credential (Section 4; step 6).
fn signing_key(
    header: &mut Fields,
    credential: &Credential,
    verifier: Verifier<'_>,
) -> Result<VerifyingKey, SignedFault> {
    let x5c = header.take("x5c");
    let kid = header
        .optional("kid", json::text)
        .map_err(|_| SignedFault::Kid)?;
    match (x5c, kid, credential.issuer_chain()) {
        (Some(x5c), _, Some(own)) => {
            let chain = chain(x5c)?;
            let root = verifier
                .trust
                .anchor(&chain, verifier.now)
                .map_err(SignedFault::Untrusted)?;
            let own_root = verifier
                .trust
                .anchor(own, verifier.now)
                .map_err(SignedFault::CredentialUntrusted)?;
            if root != own_root {
                return Err(SignedFault::Root);
            }
            if chain.leaf().subject() != own.leaf().subject() {
                return Err(SignedFault::LeafSubject);
            }
            leaf_key(chain.leaf())
        }
        (None, Some(kid), None) => {
            let issuer = credential.issuer().ok_or(SignedFault::Issuer)?;
            issuer_keys::key(issuer, &kid, verifier.held).map_err(SignedFault::KeySet)
        }
        (Some(_), _, None) | (None, Some(_), Some(_)) => Err(SignedFault::KeyKind),
        (None, None, _) => Err(SignedFault::KeyAbsent),
    }
}

/// The certificate chain of an `x5c` header value (RFC 7515, Section 4.1.6).
fn chain(x5c: Json) -> Result<IssuerChain, SignedFault> {
    let certificates = json::array(x5c)
        .map_err(|_| SignedFault::X5c)?
        .into_iter()
        .map(|item| match item {
            Json::String(text) => base64::decode(&text).map_err(|_| SignedFault::X5c),
            _ => Err(SignedFault::X5c),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut certificates = certificates.into_iter();
    let first = certificates.next().ok_or(SignedFault::X5c)?;
    IssuerChain::parse(&CertificateChain::new(first, certificates.collect()))
        .map_err(SignedFault::Chain)
}

/// The key of the leaf `certificate`.
fn leaf_key(certificate: &Certificate) -> Result<VerifyingKey, SignedFault> {
    VerifyingKey::of_certificate(certificate).ok_or(SignedFault::LeafKey)
}

/// The string claim `claim`.
pub(crate) fn text_claim(claims: &mut Fields, claim: MetadataClaim) -> Result<String, SignedFault> {
    claims
        .require(claim.as_str())
        .and_then(json::text)
        .map_err(|fault| SignedFault::Claim(claim, fault))
}

/// The NumericDate claim `claim`, in whole seconds (RFC 7519, Section 2).
fn date_claim(claims: &mut Fields, claim: MetadataClaim) -> Result<i64, SignedFault> {
    let number = claims
        .require(claim.as_str())
        .and_then(json::number)
        .map_err(|fault| SignedFault::Claim(claim, fault))?;
    let number = number.number();
    number
        .as_i64()
        .or_else(|| number.as_f64().map(|seconds| seconds.floor() as i64))
        .ok_or(SignedFault::Claim(claim, MemberFault::WrongType))
}
