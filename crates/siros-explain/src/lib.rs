//! Texts as messages. Every text a crate produces for the End-User, an error or a statement,
//! implements [`Explain`]: a stable identifier, which its crate's module keys its message by, and
//! named arguments, which the messages interpolate. An argument is an i18n query (a nested
//! message), a typed [`Value`] the renderer formats in the display locale, a name the code fixes,
//! and as a last resort a raw text from the outside.
//!
//! Nothing is formatted before a text is displayed. A message travels as its own value: an error
//! boxed as [`Explained`] across a plug-in boundary, and as a [`Text`] where it is stored. A type's
//! [`Messages`] declare its module's keys and each argument's [`ArgKind`], against which the
//! module's messages in every locale are checked when they load. An error's `Display` stays the
//! English text, written when a log line or a Verifier's error response is.
//!
//! A value's kind is its type's: [`IntoArg::Kind`] fixes what the value gives, and only
//! [`Arg::of`] makes an argument. A message's argument names are [`Names`], which refuse a repeated
//! name when the crate builds. A message that names another message holds it as one argument, whose
//! own arguments stay in its own query.
//!
//! The crate imposes the trait alone: a type keeps its own shape, and `#[derive(Explain)]`
//! (feature `derive`) writes the implementation beside `#[derive(thiserror::Error)]`, as miette's
//! `Diagnostic` does.
//!
//! ```
//! use siros_explain::{ArgValue, Count, Explain, Value};
//!
//! #[derive(Debug, thiserror::Error, Explain)]
//! #[explain(domain = "openid4vp.routing")]
//! pub enum RoutingRule {
//!     #[error("P1 response_type is absent")]
//!     #[explain(id = "p1_absent")]
//!     ResponseTypeAbsent,
//!     #[error("C5 response_mode {mode} is no mode the wallet answers in on this channel")]
//!     #[explain(id = "c5")]
//!     Mode { mode: String },
//!     #[error("P6 state holds a character outside URL-safe ASCII at {0}")]
//!     #[explain(id = "p6")]
//!     State(#[explain(name = "at")] usize),
//! }
//!
//! let rule = RoutingRule::Mode { mode: "fragment".to_owned() };
//! assert_eq!(rule.id().as_str(), "openid4vp.routing.c5");
//! let args = rule.args();
//! let [named] = args.as_slice() else { panic!("one argument") };
//! assert_eq!((named.name().as_str(), named.arg().value()), ("mode", &ArgValue::Raw("fragment")));
//! let args = RoutingRule::State(7).args();
//! let [named] = args.as_slice() else { panic!("one argument") };
//! let seven = ArgValue::Value(Value::Count(Count::of(7)));
//! assert_eq!((named.name().as_str(), named.arg().value()), ("at", &seven));
//! ```
//!
//! A value without [`IntoArg`] cannot be an argument, so a secret never reaches a message:
//!
//! ```compile_fail,E0277
//! use siros_explain::Explain;
//!
//! #[derive(Debug)]
//! pub struct Secret([u8; 16]);
//!
//! #[derive(Debug, thiserror::Error, Explain)]
//! #[explain(domain = "example")]
//! #[error("the seed does not open the commitment")]
//! pub struct Opening { seed: Secret }
//! ```
//!
//! A message that names an argument twice does not build:
//!
//! ```compile_fail,E0080
//! use siros_explain::Explain;
//!
//! #[derive(Debug, thiserror::Error, Explain)]
//! #[explain(domain = "example")]
//! #[error("{0} to {1}")]
//! pub struct Between(#[explain(name = "age")] u64, #[explain(name = "age")] u64);
//! ```
//!
//! A value gives the argument of its declared kind alone:
//!
//! ```compile_fail,E0308
//! use siros_explain::{IntoArg, Kind, kind};
//!
//! pub struct Age(String);
//!
//! impl IntoArg for Age {
//!     type Kind = kind::Count;
//!
//!     fn arg(&self) -> <Self::Kind as Kind>::Of<'_> {
//!         self.0.as_str()
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use, unused_results)]
#![deny(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::disallowed_types
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

mod arg;
mod calendar;
mod checked;
mod into_arg;
mod iso4217;
mod keyed;
pub mod kind;
mod list;
mod message;
mod text;
mod value;

pub use arg::{Arg, ArgKind, ArgName, ArgValue, Args, IntoArg, Kind, Named, Names, Presence};
pub use calendar::{Date, DateTime, Fraction, Offset, OffsetTime, Second, Time};
pub use iso4217::Currency;
pub use keyed::{Entry, Keyed, Repeated};
pub use list::{AllOf, AnyOf, ListKind, Listed};
pub use message::{Domain, Explain, Explained, Message, MessageId, Messages, Param, ParamKind};
#[cfg(feature = "derive")]
pub use siros_explain_derive::Explain;
pub use text::{DefinedKey, DefinedModule, Key, ModuleId, Query, Text};
pub use value::{Amount, Count, Decimal, Value};
