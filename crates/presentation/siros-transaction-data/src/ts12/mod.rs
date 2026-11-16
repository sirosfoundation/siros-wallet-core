//! The built-in rulebooks: the four transaction data types of EC TS12 v1.0.1 (Section 4.3).
//!
//! Each payload parses into the typed value its schema describes (`docs/technical-specifications/api/`
//! of the TS12 repository): `additionalProperties: false` at the top, open nested objects, and
//! `format` an annotation only, as JSON Schema 2020-12 has it.

mod leaves;
mod payloads;
mod payment;
pub(crate) mod read;
mod rules;

use siros_codec::date::DateTime;
use siros_codec::json::Json;

use crate::type_id::Ts12Type;
use read::{Fields, MemberPath, Members, Ts12PayloadFault};

pub(crate) use leaves::Leaves;
use payloads::{AccountAccess, Emandate, LoginRisk};
use payment::Payment;

/// The `payload` of one TS12 type.
pub(crate) trait Payload: Sized {
    /// The payload of the members of the `payload` object, at the time `now`.
    fn parse(fields: Fields, now: DateTime) -> Result<Self, Ts12PayloadFault>;

    /// Adds its leaf parameters to `leaves`, in the order of its schema (Section 3.3.1).
    fn leaves(&self, leaves: &mut Leaves);
}

/// A payload of a built-in type.
pub(crate) enum Ts12Payload {
    Payment(Payment),
    LoginRisk(LoginRisk),
    AccountAccess(AccountAccess),
    Emandate(Emandate),
}

impl Ts12Payload {
    /// The payload `payload` of the type `rulebook`, at the time `now`.
    pub(crate) fn parse(
        rulebook: Ts12Type,
        payload: &Json,
        now: DateTime,
    ) -> Result<Self, Ts12PayloadFault> {
        let fields = match payload {
            Json::Object(members) => Fields::new(members.clone()),
            _ => {
                return Err(Ts12PayloadFault::Member(
                    PAYLOAD,
                    siros_codec::member::MemberFault::WrongType,
                ))
            }
        };
        Ok(match rulebook {
            Ts12Type::Payment => Self::Payment(Payment::parse(fields, now)?),
            Ts12Type::LoginRisk => Self::LoginRisk(LoginRisk::parse(fields, now)?),
            Ts12Type::AccountAccess => Self::AccountAccess(AccountAccess::parse(fields, now)?),
            Ts12Type::Emandate => Self::Emandate(Emandate::parse(fields, now)?),
        })
    }

    /// Its leaf parameters, in the order of its schema.
    pub(crate) fn leaves(&self) -> Leaves {
        let mut leaves = Leaves::payload();
        match self {
            Self::Payment(payload) => payload.leaves(&mut leaves),
            Self::LoginRisk(payload) => payload.leaves(&mut leaves),
            Self::AccountAccess(payload) => payload.leaves(&mut leaves),
            Self::Emandate(payload) => payload.leaves(&mut leaves),
        }
        leaves
    }
}

/// The path of the payload member `name`: its name.
pub(crate) const fn member(name: &'static str) -> MemberPath {
    MemberPath::new(name)
}

/// The `payload` member of every TS12 entry (Section 4.2).
const PAYLOAD: MemberPath = MemberPath::new("payload");

/// `transaction_id`: 1 to 36 characters, required in every payload (Section 4.3).
type TransactionId = rules::Text<1, 36>;

/// The `transaction_id` of the payload `fields`.
fn transaction_id(fields: &mut Fields) -> Result<TransactionId, Ts12PayloadFault> {
    const PATH: MemberPath = MemberPath::new("transaction_id");
    TransactionId::parse(fields.require_member("transaction_id", PATH)?, PATH)
}
