//! The Response URI's answer to a direct post (§8.2): `redirect_uri`, which the core reads, and
//! the members registered readers declare.

use dyn_clone::DynClone;
use siros_explain::{Explain, Explained};

use super::RedirectTarget;
use crate::json::{Node, Object};
use crate::plugins::Registry;
use crate::wallet_metadata::ParameterName;

/// Members of the Response URI's answer a profile or a deployment defines (§8.2: "Additional
/// parameters MAY be defined and used in the response from the Response Endpoint to the
/// Wallet"), and the outcome the wallet shows the End-User.
///
/// # Implementing
///
/// `names` is a constant: the registry refuses a name another reader declares (`NameTwice`) and
/// `redirect_uri` (`NameReserved`). `read` receives the answer's members of declared names alone,
/// as the core parsed them, and returns the outcome it reads, nothing, or its rule's refusal,
/// which the core returns as [`AnswerError::Reader`]. `siros-testkit`'s `TestAnswerReader` is the
/// double.
pub trait AnswerReader: DynClone + Send + Sync {
    /// The member names it reads.
    fn names(&self) -> &'static [ParameterName];

    /// The outcome its members state.
    ///
    /// # Errors
    ///
    /// Its rule's refusal of the members.
    fn read(
        &self,
        members: &AnswerMembers<'_>,
    ) -> Result<Option<Box<dyn Explained>>, Box<dyn Explained>>;
}

dyn_clone::clone_trait_object!(AnswerReader);

/// The members of a Response URI answer that one reader declares, as received. Only
/// [`ResponseUriAnswer::parse`] makes them.
#[derive(Debug, Clone, Copy)]
pub struct AnswerMembers<'a> {
    object: &'a Object<'a>,
    names: &'static [ParameterName],
}

impl<'a> AnswerMembers<'a> {
    /// A declared member, when the answer holds it; `None` for a name the reader did not
    /// declare.
    #[must_use]
    pub fn get(&self, name: ParameterName) -> Option<&'a Node<'a>> {
        if self.names.contains(&name) {
            self.object.get(name.as_str())
        } else {
            None
        }
    }
}

/// The Response URI's answer to a direct post (§8.2): a JSON object with unique member names at
/// every level; `redirect_uri`, when present, a [`RedirectTarget`]; the outcomes the registered
/// [`AnswerReader`]s read from their members. A member no reader declares is ignored (§8.2:
/// "Additional parameters MAY be defined").
#[derive(Debug)]
pub struct ResponseUriAnswer {
    redirect: Option<RedirectTarget>,
    outcomes: Vec<Box<dyn Explained>>,
}

/// A Response URI answer the wallet cannot read.
#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.response_uri")]
pub enum AnswerError {
    /// No JSON object with unique member names.
    #[error("the answer is no JSON object with unique member names")]
    NotObject,
    /// `redirect_uri` is no URI with a scheme.
    #[error("redirect_uri is no URI with a scheme")]
    RedirectUri,
    /// A registered reader refuses its members: its rule.
    #[error("{0}")]
    Reader(#[explain(skip)] Box<dyn Explained>),
}

impl ResponseUriAnswer {
    /// Parses the body the Response URI answered with, and runs each registered reader over its
    /// members, in registration order.
    ///
    /// # Errors
    ///
    /// [`AnswerError`]: no JSON object with unique member names, a `redirect_uri` that is no
    /// string holding a URI with a scheme, or a reader's refusal.
    pub fn parse<H>(body: &str, registry: &Registry<H>) -> Result<Self, AnswerError> {
        let node = Node::parse(body).map_err(|_| AnswerError::NotObject)?;
        let object = node.as_object().ok_or(AnswerError::NotObject)?;
        let redirect = object
            .get("redirect_uri")
            .map(|uri| {
                uri.as_str()
                    .ok_or(AnswerError::RedirectUri)
                    .and_then(|uri| {
                        RedirectTarget::parse(uri.to_owned()).map_err(|_| AnswerError::RedirectUri)
                    })
            })
            .transpose()?;
        let mut outcomes = Vec::new();
        for reader in registry.answer_readers() {
            let members = AnswerMembers {
                object,
                names: reader.names(),
            };
            if let Some(outcome) = reader.read(&members).map_err(AnswerError::Reader)? {
                outcomes.push(outcome);
            }
        }
        Ok(Self { redirect, outcomes })
    }

    /// Where the wallet sends the user agent (§8.2; HAIP §5.1).
    #[must_use]
    pub const fn redirect(&self) -> Option<&RedirectTarget> {
        self.redirect.as_ref()
    }

    /// The outcomes the readers read, in their registration order.
    #[must_use]
    pub fn outcomes(&self) -> &[Box<dyn Explained>] {
        &self.outcomes
    }
}
