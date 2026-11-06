//! What a registration's package was built from beside its modules: the End-User's priority list, the app's fallback list, the rendering
//! options, each credential with its candidate languages, and each transaction type with its
//! module. The matcher reads its lists and options from it, and a package whose inputs differ
//! from the app's is stale.

use siros_explain::{IntoArg, ModuleId, kind};

#[cfg(feature = "load")]
use super::codec::write_list;
use super::codec::{EntryReader, list, tag, text};
use super::manifest::{ModuleRecord, StoredId};
#[cfg(feature = "load")]
use crate::bytes::Writer;
use crate::error::PackageError;
use crate::locale::LocaleTag;
use crate::render::{Amounts, Bidi, OnRenderError, RenderOptions};

/// A credential's candidate languages: the tags of the priority list that every module of its
/// card matches, in the list's order, and the tags of the fallback list that every one matches.
/// Only a registration's builder computes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidates {
    understood: Vec<LocaleTag>,
    fallback: Vec<LocaleTag>,
}

impl Candidates {
    /// The candidates over modules whose locale entries have these tags, by RFC 4647 basic
    /// filtering.
    #[cfg(feature = "load")]
    pub(crate) fn of(
        modules: &[&[LocaleTag]],
        priority: &[LocaleTag],
        fallback: &[LocaleTag],
    ) -> Self {
        let served = |list: &[LocaleTag]| {
            list.iter()
                .filter(|range| {
                    modules
                        .iter()
                        .all(|tags| tags.iter().any(|tag| range.filters(tag)))
                })
                .cloned()
                .collect()
        };
        Self {
            understood: served(priority),
            fallback: served(fallback),
        }
    }

    /// The priority list's tags every module of the card matches, in its order.
    #[must_use]
    pub fn understood(&self) -> &[LocaleTag] {
        &self.understood
    }

    /// The fallback list's tags every module of the card matches, in its order.
    #[must_use]
    pub fn fallback(&self) -> &[LocaleTag] {
        &self.fallback
    }
}

/// A credential's name in a registration: the identifier its query or its wallet's configuration
/// gives it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialName(String);

impl CredentialName {
    /// The credential of this name.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self(name)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl IntoArg for CredentialName {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}

/// A transaction data type in a registration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionKind(String);

impl TransactionKind {
    /// The transaction type of this name.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self(name)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl IntoArg for TransactionKind {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        &self.0
    }
}

/// A credential the registration serves: its name, its card's modules and its candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub(crate) name: CredentialName,
    pub(crate) modules: Vec<StoredId>,
    pub(crate) candidates: Candidates,
}

impl CredentialRecord {
    /// Its candidate languages.
    #[must_use]
    pub const fn candidates(&self) -> &Candidates {
        &self.candidates
    }

    /// Whether its card draws from exactly `modules`, in any order.
    #[must_use]
    pub fn draws_from(&self, modules: &[ModuleId]) -> bool {
        self.modules.len() == modules.len()
            && modules
                .iter()
                .all(|id| self.modules.iter().any(|module| module.is(*id)))
    }
}

/// A transaction type the registration serves: its name and the module its metadata converts
/// to, whose languages and policy the package's module record holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransactionRecord {
    pub(crate) kind: TransactionKind,
    pub(crate) module: StoredId,
}

/// What a registration's package was built from beside its modules. Only a registration's
/// builder writes one, and [`super::Package::registration`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub(crate) priority: Vec<LocaleTag>,
    pub(crate) fallback: Vec<LocaleTag>,
    pub(crate) options: RenderOptions,
    pub(crate) credentials: Vec<CredentialRecord>,
    pub(crate) transactions: Vec<TransactionRecord>,
}

impl Registration {
    /// The End-User's priority list, as the app gave it.
    #[must_use]
    pub fn priority(&self) -> &[LocaleTag] {
        &self.priority
    }

    /// The app's fallback list.
    #[must_use]
    pub fn fallback(&self) -> &[LocaleTag] {
        &self.fallback
    }

    /// The app's rendering options.
    #[must_use]
    pub const fn options(&self) -> RenderOptions {
        self.options
    }

    /// The credential `name`; `None` for a credential the registration does not serve.
    #[must_use]
    pub fn credential(&self, name: &CredentialName) -> Option<&CredentialRecord> {
        self.credentials
            .iter()
            .find(|credential| credential.name == *name)
    }

    /// Whether `module` is the module of a transaction type the registration serves.
    #[must_use]
    pub fn transacts(&self, module: ModuleId) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.module.is(module))
    }

    /// The registration's bytes.
    #[cfg(feature = "load")]
    pub(super) fn encode(&self, writer: &mut Writer) {
        let tags = |writer: &mut Writer, tags: &[LocaleTag]| {
            write_list(writer, tags, |writer, tag| writer.text(tag.as_str()));
        };
        tags(writer, &self.priority);
        tags(writer, &self.fallback);
        writer.flag(self.options.amounts == Amounts::Written);
        writer.flag(self.options.bidi == Bidi::None);
        writer.flag(self.options.on_error == OnRenderError::Rendered);
        write_list(writer, &self.credentials, |writer, credential| {
            writer.text(credential.name.as_str());
            write_list(writer, &credential.modules, |writer, module| {
                writer.raw(module.encoded());
            });
            tags(writer, &credential.candidates.understood);
            tags(writer, &credential.candidates.fallback);
        });
        write_list(writer, &self.transactions, |writer, transaction| {
            writer.text(transaction.kind.as_str());
            writer.raw(transaction.module.encoded());
        });
    }

    /// A registration over the package's `modules`: refused when its credentials or transaction
    /// types are out of order or repeated, or name a module the package does not hold.
    pub(super) fn decode(
        reader: &mut EntryReader<'_>,
        modules: &[ModuleRecord],
    ) -> Result<Self, PackageError> {
        let priority = list(reader, tag)?;
        let fallback = list(reader, tag)?;
        let options = RenderOptions {
            amounts: if reader.flag()? {
                Amounts::Written
            } else {
                Amounts::Formatted
            },
            bidi: if reader.flag()? {
                Bidi::None
            } else {
                Bidi::Default
            },
            on_error: if reader.flag()? {
                OnRenderError::Rendered
            } else {
                OnRenderError::NoEntry
            },
        };
        let held = |reader: &EntryReader<'_>, id: StoredId| {
            if modules.iter().any(|module| module.id == id) {
                Ok(id)
            } else {
                Err(reader.malformed())
            }
        };
        let credentials = list(reader, |reader| {
            let name = CredentialName::new(text(reader)?);
            let modules = list(reader, |reader| {
                let id = StoredId::decode(reader)?;
                held(reader, id)
            })?;
            let understood = list(reader, tag)?;
            let fallback = list(reader, tag)?;
            Ok(CredentialRecord {
                name,
                modules,
                candidates: Candidates {
                    understood,
                    fallback,
                },
            })
        })?;
        let transactions = list(reader, |reader| {
            let kind = TransactionKind::new(text(reader)?);
            let id = StoredId::decode(reader)?;
            Ok(TransactionRecord {
                kind,
                module: held(reader, id)?,
            })
        })?;
        let ascending = |names: &mut dyn Iterator<Item = &str>| {
            let names: Vec<&str> = names.collect();
            names.windows(2).all(|pair| match pair {
                [a, b] => a < b,
                _ => true,
            })
        };
        if !ascending(&mut credentials.iter().map(|c| c.name.as_str()))
            || !ascending(&mut transactions.iter().map(|t| t.kind.as_str()))
        {
            return Err(reader.malformed());
        }
        Ok(Self {
            priority,
            fallback,
            options,
            credentials,
            transactions,
        })
    }
}
