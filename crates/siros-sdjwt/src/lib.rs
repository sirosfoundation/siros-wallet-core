//! The SD-JWT VC format plug-in (OpenID4VP 1.0 B.3, Credential Format Identifier `dc+sd-jwt`):
//! `meta.vct_values` (B.3.5), the card and rows from SD-JWT VC Type Metadata (§7, §8), the
//! Verifier's JWS algorithms (B.3.4), Key Binding JWT claims as transaction response members
//! (B.3.3), and the presentation: the disclosures, then a Key Binding JWT (B.3.6).
//!
//! A credential's view is the claims kit's (`type`, `metadata`, `values`, `issuer`) with `alg` and
//! `curve`, the Issuer-signed JWT's algorithm and key curve; `key_alg` and `key_curve`, the holder
//! key's; `extends`, when its type extends another, each type the chain the wallet resolved at
//! registration names, nearest first (§6.4); `validity`, `not_before` and `not_after` from `nbf`
//! and `exp`. `vct_values` matches the credential's `vct` or one of them (B.3.5).
#![cfg_attr(
    feature = "resolve",
    doc = "[`Registered`] builds the view from the issued SD-JWT, held as the [`DOCUMENT`] \
           document phase 2 presents from,"
)]
#![cfg_attr(
    not(feature = "resolve"),
    doc = "`Registered`, with the feature `resolve`, builds the view from the issued SD-JWT, held \
           as the `DOCUMENT` document phase 2 presents from,"
)]
//! and gives its `Facts::holder`; `values` is its processed payload at the issued array
//! positions, `{"...": digest}` where it holds no value.
//!
//! [`type_metadata`] gives the effective Type Metadata of a type that extends another, which the
//! wallet registers the view's `metadata` from. The claims kit shows its display texts as written,
//! each entry picked by the End-User's language priority.

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
mod alg;
#[cfg(feature = "resolve")]
mod error;
#[cfg(feature = "resolve")]
mod key_binding;
#[cfg(feature = "resolve")]
mod presentation;
#[cfg(feature = "resolve")]
mod process;
#[cfg(feature = "resolve")]
mod registration;
#[cfg(feature = "resolve")]
mod sd_jwt;
#[cfg(feature = "resolve")]
mod select;
#[cfg(feature = "resolve")]
mod tree;

use std::error::Error;

use siros_explain::Explain;
use siros_openid4vp::claims::kit::{
    self, ClaimsFormat, ClaimsPlugin, ClaimsView, Constraint, VpFormatsMember,
};
use siros_openid4vp::claims::{Claim, ClaimPath};
use siros_openid4vp::ids::{CredentialType, FormatId, FormatName, InvalidId, QueryId};
use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::{
    Carriage, Clause, Detail, Fault, Format, FormatQuery, Member, ViewAdditions,
};
use siros_openid4vp::refusal::{ErrorCode, Refusal, RequestRule};
use siros_openid4vp::request::{AgreeableKey, HolderBinding, Query};
use siros_openid4vp::routing::EntryNaming;
use siros_openid4vp::wallet::{Credential, Holder};
use siros_openid4vp::wallet_metadata::Placement;
use siros_syntax::AllOf;

use view::SdJwtMembers;

#[cfg(feature = "resolve")]
pub use {
    alg::{Digest, SigningAlg},
    error::{
        DisclosureFault, EncodedJsonFault, HolderKeyFault, IssuerJwtFault, JwkCoordinate,
        KeyBindingError, Misplaced, ParseError, PermanentClaim, PresentFault, RegistrationError,
        ReservedFault, ResolvedCurve, SdAlgFault, SelectError, ValidityClaim, X5cError,
    },
    key_binding::{
        Audience, Binding, KbNonce, KbSignature, KbSigningInput, KeyBinding, NumericDate,
        Presentation, SdJwtKb,
    },
    process::MAX_DEPTH,
    registration::{DOCUMENT, Registered, Resolved},
    sd_jwt::{IssuerJwt, JwtType, SdJwt},
    tree::{ClaimValue, Disclosure, DisclosureId, Element, IssuedClaim, Object},
};

siros_explain::scope!("sdjwt");

/// The Credential Format Identifier.
const NAME: FormatName = siros_syntax::checked!(FormatName, "dc+sd-jwt");
const ID: &str = NAME.as_str();
/// The claim display member holding the label (SD-JWT VC §8.2).
const LABEL: &str = "label";

/// The plug-in's fault error: the log line, and the error that caused the fault.
#[derive(Debug, thiserror::Error, Explain)]
#[error("{detail}")]
#[explain(id = "fault")]
struct SdJwtFault {
    #[explain(skip)]
    detail: Detail,
    #[source]
    cause: Option<Box<dyn Error + Send + Sync>>,
}

/// The plug-in's fault, its log line written by `detail`.
pub(crate) fn fault(detail: Detail) -> Fault {
    Fault::new(SdJwtFault {
        detail,
        cause: None,
    })
}

/// The plug-in's fault caused by an error, its log line written by `detail`.
pub(crate) fn caused(detail: Detail, cause: impl Error + Send + Sync + 'static) -> Fault {
    Fault::new(SdJwtFault {
        detail,
        cause: Some(Box::new(cause)),
    })
}

/// B.3.5's rule on a `dc+sd-jwt` query's `meta`, which the kit reports under the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
pub enum SdJwtRule {
    /// `meta.vct_values` is no non-empty array of strings.
    #[error("meta.vct_values is not a non-empty array of strings (B.3.5)")]
    #[explain(id = "rules.vct_values")]
    VctValues,
}

/// B.3.3: transaction data names a query that waives holder binding: `invalid_transaction_data`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(id = "rules.holder_binding")]
#[error("dc+sd-jwt {query}: transaction data on a query without holder binding (B.3.3)")]
pub struct HolderBindingWaived {
    /// The query's id.
    pub query: QueryId<'static>,
}

impl RequestRule for HolderBindingWaived {
    fn code(&self) -> ErrorCode {
        ErrorCode::INVALID_TRANSACTION_DATA
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
            .map_err(|e| caused(siros_openid4vp::detail!("the formats member"), e))
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
    fn id(&self) -> FormatName {
        NAME
    }

    /// SD-JWT VC §8.2: a claim's display entry holds its `label`.
    fn label_key(&self) -> &'static str {
        LABEL
    }

    fn vp_formats_clause(&self) -> Clause {
        Clause::cited("OpenID4VP B.3 vp_formats_supported")
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
    ) -> Result<&'n Node<'m>, Box<dyn Explain>> {
        meta.filter(|meta| {
            meta.get("vct_values")
                .and_then(Node::as_array)
                .is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|v| v.as_str().is_some())
                })
        })
        .ok_or_else(|| Box::new(SdJwtRule::VctValues) as Box<dyn Explain>)
    }

    /// The view's `type`, then each type of its `extends`, nearest first (§6.4).
    fn types<'n>(&self, view: &'n Node<'n>) -> Result<Vec<CredentialType<'n>>, Fault> {
        let fault = || {
            crate::fault(siros_openid4vp::detail!(
                "a view whose type or extends is no text"
            ))
        };
        let own = view.get("type").and_then(Node::as_str).ok_or_else(fault)?;
        let extended = match view.get("extends") {
            None => &[][..],
            Some(extends) => extends.as_array().ok_or_else(fault)?,
        };
        std::iter::once(Some(own))
            .chain(extended.iter().map(Node::as_str))
            .map(|kind| {
                kind.and_then(|kind| CredentialType::parse(kind).ok())
                    .ok_or_else(fault)
            })
            .collect()
    }

    /// B.3.5: one of `vct_values` names the credential's type or a type it inherits from.
    fn meta_matches(&self, meta: &Node<'_>, types: &[CredentialType<'_>]) -> bool {
        meta.get("vct_values")
            .and_then(Node::as_array)
            .is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| types.iter().any(|kind| *kind == *value))
                })
            })
    }

    /// A Key Binding JWT claim is no claim of the credential.
    fn written(&self, _claim: &Claim<'_>, _provided: &[Member]) -> bool {
        false
    }

    /// RFC 9901 §4.2.4.2: `{"...": digest}` keeps the position of an element the credential does
    /// not hold; S1 refuses `...` elsewhere.
    fn withheld(&self, element: &Node<'_>) -> bool {
        element
            .as_object()
            .is_some_and(|object| matches!(object.members(), [only] if only.name == "..."))
    }

    /// §7.1: every claims path pointer addresses a JSON-based credential.
    fn pointer_refusal(&self, _path: &ClaimPath<'_>) -> Option<Box<dyn Explain>> {
        None
    }
}

impl ClaimsPlugin for SdJwtVc {
    /// B.3.3: transaction data needs a Key Binding JWT, so a query transaction data names
    /// requires holder binding.
    fn rules(&self, query: &Query<'_>, naming: EntryNaming) -> Vec<Refusal> {
        if naming == EntryNaming::Named && query.holder_binding() == HolderBinding::Waived {
            vec![Refusal::new(HolderBindingWaived {
                query: query.id().clone().into_owned(),
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
            member: VpFormatsMember::new("sd-jwt_alg_values"),
            matched: members.issuer()?.identifiers(),
            also: Vec::new(),
        }];
        if view.credential().facts.holder == Holder::Bound {
            constraints.push(Constraint {
                member: VpFormatsMember::new("kb-jwt_alg_values"),
                matched: members.holder()?.identifiers(),
                also: Vec::new(),
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
    ) -> Result<Carriage, Fault> {
        Ok(
            if query.holder_binding() == HolderBinding::Required
                && view.credential().facts.holder == Holder::Bound
                && members
                    .iter()
                    .all(|member| matches!(member, Member::Claim(_)))
            {
                Carriage::Carried
            } else {
                Carriage::Uncarried
            },
        )
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
