//! The SD-JWT VC format plug-in (OpenID4VP 1.0 B.3, Credential Format Identifier `dc+sd-jwt`):
//! `meta.vct_values` (B.3.5), the card and rows from SD-JWT VC Type Metadata (§7, §8), the
//! Verifier's JWS algorithms (B.3.4), Key Binding JWT claims as transaction response members
//! (B.3.3), and the presentation: the disclosures, then a Key Binding JWT (B.3.6).
//!
//! A credential's view is the claims kit's (`type`, `metadata`, `values`, `issuer`) with `jwt`,
//! the Issuer-signed JWT; `alg` and `curve`, its algorithm and key curve; `key_alg` and
//! `key_curve`, the holder key's; `extends`, when its type extends another, each type the chain
//! the wallet resolved at registration names, nearest first (§6.4). `vct_values` matches the
//! credential's `vct` or one of them (B.3.5). The view holds values where an issued SD-JWT holds
//! disclosures: a disclosure is the base64url JSON array `[salt, name, value]`, its salt a digest
//! of the claim's path.
//!
//! [`type_metadata`] gives the effective Type Metadata of a type that extends another, which the
//! wallet registers the view's `metadata` from.

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

mod jose;
pub mod type_metadata;
mod view;

#[cfg(feature = "resolve")]
mod presentation;

use siros_explain::{AllOf, Explain, Explained, Message, Messages};
use siros_openid4vp::claims::kit::{self, ClaimsFormat, ClaimsPlugin, ClaimsView, Constraint};
use siros_openid4vp::claims::{Claim, ClaimPath};
use siros_openid4vp::ids::{FormatId, InvalidId};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{Fault, FaultDomain, Format, FormatQuery, Member, ViewAdditions};
use siros_openid4vp::refusal::{ErrorCode, Refusal, RequestRule};
use siros_openid4vp::request::{AgreeableKey, HolderBinding, Query};
use siros_openid4vp::wallet::{Credential, Holder};
use siros_openid4vp::wallet_metadata::Placement;

use view::SdJwtMembers;

/// The Credential Format Identifier.
const ID: &str = "dc+sd-jwt";

/// The plug-in's domain, as its fault message.
pub(crate) const FAULT: FaultDomain = siros_explain::checked!(FaultDomain, "sdjwt.fault");

/// B.3.5's rule on a `dc+sd-jwt` query's `meta`, which the kit reports under the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.rules")]
pub enum SdJwtRule {
    /// `meta.vct_values` is no non-empty array of strings.
    #[error("meta.vct_values is not a non-empty array of strings (B.3.5)")]
    VctValues,
}

/// B.3.3: transaction data names a query that waives holder binding: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "sdjwt.rules", id = "holder_binding")]
#[error("dc+sd-jwt {query}: transaction data on a query without holder binding (B.3.3)")]
pub struct HolderBindingWaived {
    /// The query's id.
    pub query: String,
}

impl RequestRule for HolderBindingWaived {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
    }
}

/// The plug-in's messages: those its error types and rules declare, and its fault's.
pub struct CrateMessages;

impl Messages for CrateMessages {
    fn messages() -> Vec<Message> {
        let declared: &[fn() -> Vec<Message>] = &[
            SdJwtRule::messages,
            HolderBindingWaived::messages,
            type_metadata::ExtendError::messages,
        ];
        declared
            .iter()
            .flat_map(|messages| messages())
            .chain([FAULT.message()])
            .collect()
    }
}

/// The Key Binding JWT's own claims (B.3.6, RFC 9901 §4.3).
static RESERVED: [Member; 4] = [
    Member::claim("iat"),
    Member::claim("aud"),
    Member::claim("nonce"),
    Member::claim("sd_hash"),
];

/// The SD-JWT VC format plug-in. A transaction's response members are Key Binding JWT claims.
#[derive(Debug, Clone)]
pub struct SdJwtVc {
    id: FormatId<'static>,
}

impl SdJwtVc {
    /// The plug-in.
    pub fn new() -> Result<Self, InvalidId> {
        Ok(Self {
            id: FormatId::parse(ID)?,
        })
    }
}

impl Format for SdJwtVc {
    fn id(&self) -> FormatId<'_> {
        self.id.borrowed()
    }

    /// The Key Binding JWT's own claims: `iat`, `aud`, `nonce`, `sd_hash`.
    fn reserved(&self) -> &[Member] {
        &RESERVED
    }

    /// ES256 for the Issuer-signed JWT and the Key Binding JWT (B.3.4; HAIP §7).
    fn wallet_formats(&self) -> Result<Node<'static>, Fault> {
        Node::parse(r#"{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}"#)
            .map_err(|e| Fault::caused(FAULT, siros_openid4vp::detail!("the formats member"), e))
    }

    /// The Key Binding JWT carries a profile's members as claims (B.3.3.1).
    fn placement(&self) -> Option<Placement> {
        Some(Placement::Claims)
    }

    /// The credential's `vct`, then the types it extends, nearest first (§6.4).
    fn additions<'c>(
        &self,
        credential: &'c Credential<'c>,
    ) -> Result<Box<dyn ViewAdditions + 'c>, Fault> {
        kit::additions(self, credential)
    }

    fn query<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::routing::QueryContext<'q>,
    ) -> Result<Box<dyn FormatQuery + 'q>, AllOf<Refusal>> {
        kit::query(self, query, &context)
    }
}

impl ClaimsFormat for SdJwtVc {
    fn id(&self) -> &'static str {
        ID
    }

    /// SD-JWT VC §8.2: a claim's display entry holds its `label`.
    fn label_key(&self) -> &'static str {
        "label"
    }

    fn appendix(&self) -> &'static str {
        "B.3"
    }

    /// B.3.4: a JWS algorithm identifier is a string.
    fn is_algorithm(&self, value: &Node<'_>) -> bool {
        value.as_str().is_some()
    }

    /// SD-JWT VC §7.1.1.1: the display entry's `rendering.simple.logo.uri`.
    fn logo<'n>(&self, entry: &'n Node<'n>) -> Option<&'n str> {
        entry
            .get("rendering")?
            .get("simple")?
            .get("logo")?
            .get("uri")?
            .as_str()
    }

    /// B.3.5: `meta.vct_values` is a non-empty array of strings.
    fn read_meta<'n, 'm>(
        &self,
        meta: Option<&'n Node<'m>>,
    ) -> Result<&'n Node<'m>, Box<dyn Explained>> {
        meta.filter(|meta| {
            meta.get("vct_values")
                .and_then(Node::as_array)
                .is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|v| v.as_str().is_some())
                })
        })
        .ok_or_else(|| Box::new(SdJwtRule::VctValues) as Box<dyn Explained>)
    }

    /// The view's `type`, then each type of its `extends`, nearest first (§6.4).
    fn types<'n>(&self, view: &'n Node<'n>) -> Result<Vec<&'n str>, Fault> {
        let fault = || {
            Fault::new(
                FAULT,
                siros_openid4vp::detail!("a view whose type or extends is no text"),
            )
        };
        let own = view.get("type").and_then(Node::as_str).ok_or_else(fault)?;
        let extended = match view.get("extends") {
            None => &[][..],
            Some(extends) => extends.as_array().ok_or_else(fault)?,
        };
        std::iter::once(Some(own))
            .chain(extended.iter().map(Node::as_str))
            .map(|kind| kind.ok_or_else(fault))
            .collect()
    }

    /// B.3.5: one of `vct_values` names the credential's type or a type it inherits from.
    fn meta_matches(&self, meta: &Node<'_>, types: &[&str]) -> bool {
        meta.get("vct_values")
            .and_then(Node::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str().is_some_and(|value| types.contains(&value)))
            })
    }

    /// A Key Binding JWT claim is no claim of the credential.
    fn written(&self, _claim: &Claim<'_>, _provided: &[Member]) -> bool {
        false
    }

    /// §7.1: every claims path pointer addresses a JSON-based credential.
    fn pointer_refusal(&self, _path: &ClaimPath<'_>) -> Option<Box<dyn Explained>> {
        None
    }
}

impl ClaimsPlugin for SdJwtVc {
    /// B.3.3: transaction data needs a Key Binding JWT, so a query transaction data names
    /// requires holder binding.
    fn rules(&self, query: &Query<'_>, named: bool) -> Vec<Refusal> {
        if named && query.holder_binding == HolderBinding::Waived {
            vec![Refusal::new(HolderBindingWaived {
                query: query.id.to_string(),
            })]
        } else {
            Vec::new()
        }
    }

    /// B.3.4: the Issuer-signed JWT's algorithm under `sd-jwt_alg_values`, and the Key Binding
    /// JWT's under `kb-jwt_alg_values` when the credential is bound to a key.
    fn algorithms<'v>(
        &self,
        view: &ClaimsView<'v>,
        _keys: &[AgreeableKey<'_>],
    ) -> Result<Vec<Constraint<'v>>, Fault> {
        let members = SdJwtMembers::of(view);
        let mut constraints = vec![Constraint {
            member: "sd-jwt_alg_values",
            matched: members.issuer()?.identifiers(),
        }];
        if view.credential().facts.holder == Holder::Bound {
            constraints.push(Constraint {
                member: "kb-jwt_alg_values",
                matched: members.holder()?.identifiers(),
            });
        }
        Ok(constraints)
    }

    /// A presentation with a Key Binding JWT carries any claim: the query requires holder
    /// binding and the credential is bound to a key. A data element is no claim.
    fn carries(
        &self,
        query: &Query<'_>,
        view: &ClaimsView<'_>,
        members: &[Member],
    ) -> Result<bool, Fault> {
        Ok(query.holder_binding == HolderBinding::Required
            && view.credential().facts.holder == Holder::Bound
            && members
                .iter()
                .all(|member| matches!(member, Member::Claim(_))))
    }
}

#[cfg(feature = "resolve")]
/// Signs the Key Binding JWT with HAIP's keystore, its `iat` the platform's clock.
impl<H> siros_openid4vp::host::FormatHost<H> for SdJwtVc
where
    H: siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip>
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::Platform>,
{
    fn answer<'q>(
        &'q self,
        query: &'q Query<'q>,
        context: siros_openid4vp::host::AnsweredContext<'q>,
    ) -> Result<Box<dyn siros_openid4vp::host::AnsweredQuery<H> + 'q>, AllOf<Refusal>> {
        kit::answer(self, query, context)
    }
}

#[cfg(feature = "resolve")]
impl<H> kit::ClaimsPresent<H> for SdJwtVc
where
    H: siros_openid4vp::host::Has<dyn siros_openid4vp::host::Haip>
        + siros_openid4vp::host::Has<dyn siros_openid4vp::host::Platform>,
{
    /// Nothing: the presentation needs only required modules, and its key binding reads
    /// the view phase 2 derived again.
    fn revalidate(
        &self,
        _revalidating: kit::Revalidating<'_>,
        _host: &H,
    ) -> Result<Option<Box<dyn siros_openid4vp::plugins::FindingData>>, Fault> {
        Ok(None)
    }

    fn present(
        &self,
        presenting: kit::Presenting<'_>,
        host: &H,
    ) -> Result<siros_openid4vp::host::Presentation, siros_openid4vp::host::PresentError> {
        presentation::present(presenting, host)
    }
}
