//! The kinds, as types: a value's [`IntoArg::Kind`](crate::IntoArg::Kind) names one. Each is
//! uninhabited.

use std::convert::Infallible;
use std::marker::PhantomData;

use crate::arg::{Arg, ArgKind, ArgValue, Kind, Presence, sealed::Sealed, sealed::Token};
use crate::list::Listed;
use crate::message::Explain;
use crate::value::Value;

/// An i18n query: a message.
#[derive(Debug)]
pub enum Message {}
/// A count.
#[derive(Debug)]
pub enum Count {}
/// An exact decimal.
#[derive(Debug)]
pub enum Decimal {}
/// A date.
#[derive(Debug)]
pub enum Date {}
/// A time of day.
#[derive(Debug)]
pub enum Time {}
/// A date and a time.
#[derive(Debug)]
pub enum DateTime {}
/// An amount.
#[derive(Debug)]
pub enum Amount {}
/// A currency.
#[derive(Debug)]
pub enum Currency {}
/// A name the code fixes.
#[derive(Debug)]
pub enum Name {}
/// Several values, each of its own type's kind.
#[derive(Debug)]
pub enum List {}
/// A stored text.
#[derive(Debug)]
pub enum Text {}
/// A text from the outside.
#[derive(Debug)]
pub enum Raw {}
/// A value of kind `K` the input may leave out.
#[derive(Debug)]
pub struct Optional<K>(PhantomData<K>, Infallible);

macro_rules! valued {
    ($($marker:ident: $of:ty => $kind:ident, $value:expr;)*) => {
        $(
            impl Sealed for $marker {}

            impl Kind for $marker {
                const KIND: ArgKind = ArgKind::$kind;
                type Of<'a> = $of;

                fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
                    Arg::held(ArgValue::Value($value(value)))
                }
            }
        )*
    };
}

valued! {
    Count: crate::Count => Count, Value::Count;
    Decimal: crate::Decimal => Decimal, Value::Decimal;
    Date: crate::Date => Date, Value::Date;
    Time: crate::OffsetTime => Time, |time: crate::OffsetTime| Value::Time { at: time.at(), offset: time.offset() };
    DateTime: crate::DateTime => DateTime, Value::DateTime;
    Amount: crate::Amount => Amount, Value::Amount;
    Currency: crate::Currency => Currency, Value::Currency;
}

impl Sealed for Message {}

impl Kind for Message {
    const KIND: ArgKind = ArgKind::Message;
    type Of<'a> = &'a dyn Explain;

    fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
        Arg::held(ArgValue::Message(value))
    }
}

impl Sealed for Name {}

impl Kind for Name {
    const KIND: ArgKind = ArgKind::Name;
    type Of<'a> = &'static str;

    fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
        Arg::held(ArgValue::Name(value))
    }
}

impl Sealed for List {}

impl Kind for List {
    const KIND: ArgKind = ArgKind::List;
    type Of<'a> = Listed<'a>;

    fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
        value.into_arg()
    }
}

impl Sealed for Text {}

impl Kind for Text {
    const KIND: ArgKind = ArgKind::Text;
    type Of<'a> = &'a crate::text::Text;

    fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
        Arg::held(ArgValue::Held(value))
    }
}

impl Sealed for Raw {}

impl Kind for Raw {
    const KIND: ArgKind = ArgKind::Raw;
    type Of<'a> = &'a str;

    fn arg<'a>(value: Self::Of<'a>, _token: Token) -> Arg<'a> {
        Arg::held(ArgValue::Raw(value))
    }
}

impl<K: Kind> Sealed for Optional<K> {}

impl<K: Kind> Kind for Optional<K> {
    const KIND: ArgKind = K::KIND;
    const PRESENCE: Presence = Presence::Optional;
    type Of<'a> = Option<K::Of<'a>>;

    fn arg<'a>(value: Self::Of<'a>, token: Token) -> Arg<'a> {
        value.map_or(Arg::held(ArgValue::Absent), |value| K::arg(value, token))
    }
}
