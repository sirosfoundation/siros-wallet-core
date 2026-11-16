//! A signed Request Object authenticated under the rule of its Client Identifier Prefix
//! (OpenID4VP 1.0, Section 5.9.3).

use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::date::DateTime;

use super::trust::{self, KeyMaterial, MetadataAnswer, TrustSubject, Verdict};
use super::{attestation, Answers, Halt, IntakeError, JwsFault};
use crate::client_id::{ClientId, ClientIdPrefix};
use crate::jose::Signed;
use crate::jws_rules;
use crate::parameters::{strings, Metadata};
use crate::values::{Kid, TrustChain};
use crate::verified::AccessCertificate;
use crate::x509::Chain;

/// Who sent a request, as intake established it.
pub(super) struct Verifier {
    pub(super) client_id: ClientId,
    pub(super) trusted: Verdict,
    /// The access certificate of an `x509_san_dns` or `x509_hash` client.
    pub(super) certificate: Option<AccessCertificate>,
    pub(super) metadata: Metadata,
    pub(super) response_uri: UriRule,
}

/// What the `response_uri` of a redirect request must be, beyond an `https` URL.
pub(super) enum UriRule {
    /// Any.
    Any,
    /// Exactly the value of the Client Identifier, which a request may omit (`redirect_uri`
    /// prefix).
    IsClientIdValue,
    /// A URL whose host is the DNS name the Client Identifier's value is (untrusted
    /// `x509_san_dns` client).
    HostIsClientIdValue,
    /// One of these (`redirect_uris` of a Verifier Attestation JWT).
    OneOf(Vec<String>),
}

/// Authenticates the Request Object `signed` of `client_id`: its `typ`, the binding of its key
/// to the Client Identifier, its signature, and the host's trust verdict.
pub(super) fn authenticate(
    signed: &Signed,
    client_id: ClientId,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    if !jws_rules::is_request_object(signed.header()) {
        return Err(IntakeError::TypMismatch.into());
    }
    match client_id.prefix() {
        ClientIdPrefix::RedirectUri => Err(IntakeError::SignedRedirectUri.into()),
        ClientIdPrefix::X509SanDns => {
            let chain = Chain::parse(signed.header().get("x5c"))?;
            if !chain.names_dns(client_id.value()) {
                return Err(IntakeError::SanMismatch.into());
            }
            signed.verify(chain.key())?;
            let (trusted, certificate) = certified(chain, &client_id, answers)?;
            // Section 5.9.3: without trust in the Client Identifier, the FQDN of the Response
            // URI is the DNS name.
            let response_uri = match trusted {
                Verdict::Trusted => UriRule::Any,
                Verdict::Untrusted => UriRule::HostIsClientIdValue,
            };
            Ok(Verifier {
                certificate: Some(certificate),
                ..by_request(client_id, trusted, response_uri)
            })
        }
        ClientIdPrefix::X509Hash => {
            let chain = Chain::parse(signed.header().get("x5c"))?;
            let hash = base64url::encode(&Sha256::digest(chain.leaf().as_bytes()));
            if hash != client_id.value() {
                return Err(IntakeError::CertificateHashMismatch.into());
            }
            signed.verify(chain.key())?;
            let (trusted, certificate) = certified(chain, &client_id, answers)?;
            Ok(Verifier {
                certificate: Some(certificate),
                ..by_request(client_id, trusted, UriRule::Any)
            })
        }
        ClientIdPrefix::DecentralizedIdentifier => {
            // The key is a verification method of the DID: `kid` is a DID URL of it.
            let kid = signed
                .text("kid")
                .filter(|kid| {
                    kid.strip_prefix(client_id.value())
                        .is_some_and(|fragment| fragment.len() > 1 && fragment.starts_with('#'))
                })
                .map(Kid::new)
                .ok_or(IntakeError::KidNotOfClient)?;
            let resolved = trust::resolve(
                answers,
                TrustSubject::Client(client_id.clone()),
                Some(kid),
                None,
                MetadataAnswer::Refused,
            )?;
            signed.verify(&resolved.key)?;
            Ok(by_request(client_id, resolved.trusted, UriRule::Any))
        }
        ClientIdPrefix::VerifierAttestation => {
            attestation::authenticate(signed, client_id, now, answers)
        }
        ClientIdPrefix::OpenidFederation => {
            let trust_chain = match signed.header().get("trust_chain") {
                None => None,
                Some(chain) => Some(TrustChain::new(
                    strings(chain).ok_or(IntakeError::JwsMalformed(JwsFault::TrustChain))?,
                )),
            };
            let resolved = trust::resolve(
                answers,
                TrustSubject::Client(client_id.clone()),
                signed.kid(),
                trust_chain,
                MetadataAnswer::Taken,
            )?;
            signed.verify(&resolved.key)?;
            Ok(Verifier {
                client_id,
                trusted: resolved.trusted,
                certificate: None,
                metadata: Metadata::TrustChain(resolved.metadata),
                response_uri: UriRule::Any,
            })
        }
    }
}

/// The host's verdict on `client_id` with the `x5c` chain that signed its request, and the
/// chain's leaf as its access certificate.
fn certified(
    chain: Chain,
    client_id: &ClientId,
    answers: &mut Answers<'_>,
) -> Result<(Verdict, AccessCertificate), Halt> {
    let certificate = chain.access_certificate();
    let trusted = trust::verdict(
        answers,
        TrustSubject::Client(client_id.clone()),
        KeyMaterial::X509Chain(chain.into_certificates()),
    )?;
    Ok((trusted, certificate))
}

/// A Verifier whose metadata is the request's `client_metadata`.
pub(super) fn by_request(client_id: ClientId, trusted: Verdict, response_uri: UriRule) -> Verifier {
    Verifier {
        client_id,
        trusted,
        certificate: None,
        metadata: Metadata::Request,
        response_uri,
    }
}
