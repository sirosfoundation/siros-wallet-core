//! The values a message can name: std's and the crate's.

use std::num::NonZeroUsize;

use crate::arg::{IntoArg, Kind};
use crate::calendar::{Date, DateTime, OffsetTime, Time};
use crate::iso4217::Currency;
use crate::kind;
use crate::message::Explain;
use crate::text::Text;
use crate::value::{Amount, Count, Decimal};

impl IntoArg for String {
    type Kind = kind::Raw;

    fn arg(&self) -> &str {
        self
    }
}

impl IntoArg for &'static str {
    type Kind = kind::Name;

    fn arg(&self) -> &'static str {
        self
    }
}

const _: () = assert!(usize::BITS <= u64::BITS, "a usize count fits a u64");

impl IntoArg for usize {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(*self as u64)
    }
}

impl IntoArg for NonZeroUsize {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(self.get() as u64)
    }
}

impl IntoArg for u64 {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(*self)
    }
}

impl IntoArg for u8 {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(u64::from(*self))
    }
}

impl IntoArg for u16 {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        Count::of(u64::from(*self))
    }
}

impl IntoArg for Count {
    type Kind = kind::Count;

    fn arg(&self) -> Count {
        self.clone()
    }
}

impl IntoArg for Decimal {
    type Kind = kind::Decimal;

    fn arg(&self) -> Decimal {
        *self
    }
}

impl IntoArg for Date {
    type Kind = kind::Date;

    fn arg(&self) -> Date {
        *self
    }
}

impl IntoArg for Time {
    type Kind = kind::Time;

    fn arg(&self) -> OffsetTime {
        OffsetTime::new(*self, None)
    }
}

impl IntoArg for OffsetTime {
    type Kind = kind::Time;

    fn arg(&self) -> OffsetTime {
        *self
    }
}

impl IntoArg for DateTime {
    type Kind = kind::DateTime;

    fn arg(&self) -> DateTime {
        *self
    }
}

impl IntoArg for Amount {
    type Kind = kind::Amount;

    fn arg(&self) -> Amount {
        *self
    }
}

impl IntoArg for Currency {
    type Kind = kind::Currency;

    fn arg(&self) -> Currency {
        *self
    }
}

impl IntoArg for Text {
    type Kind = kind::Text;

    fn arg(&self) -> &Text {
        self
    }
}

impl<T: IntoArg> IntoArg for Option<T> {
    type Kind = kind::Optional<T::Kind>;

    fn arg(&self) -> Option<<T::Kind as Kind>::Of<'_>> {
        self.as_ref().map(IntoArg::arg)
    }
}

impl<T: Explain> IntoArg for T {
    type Kind = kind::Message;

    fn arg(&self) -> &dyn Explain {
        self
    }
}
