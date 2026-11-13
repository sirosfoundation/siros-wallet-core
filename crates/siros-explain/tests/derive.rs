//! What `#[derive(Explain)]` gives, by the rules siros-explain states: the scoped id, each named
//! field under its name, `""` for `None`, no causes or skipped fields, a transparent error's
//! field's id and arguments, and a boxed error's. A `#[backtrace]` field has no fixture:
//! thiserror implements `Error::provide` for it, which the stable toolchain refuses (E0658).

use std::any::Any;
use std::error::Error;
use std::fmt::Debug;

use siros_explain::Explain;

siros_explain::scope!("derive");

#[derive(Debug, thiserror::Error, Explain)]
#[error("the channel closed")]
#[explain(id = "closed")]
struct Closed;

#[derive(Debug, thiserror::Error, Explain)]
#[error("the read failed")]
#[explain(id = "unread")]
struct Unread;

/// Each way to leave a field out, beside the arguments.
#[derive(Debug, thiserror::Error, Explain)]
enum Refused {
    #[error("response_mode {mode} at {at:?}")]
    #[explain(id = "request.mode")]
    Mode {
        mode: String,
        r#type: u8,
        at: Option<u16>,
        #[explain(skip)]
        secret: Vec<u8>,
        #[source]
        cause: Closed,
    },
    #[error("the read failed")]
    #[explain(id = "request.unread")]
    Unread(#[from] Unread),
    #[error("{length} bytes")]
    #[explain(id = "request.bytes")]
    Bytes { length: usize, source: Closed },
    #[error(transparent)]
    Closed(Closed),
    #[error(transparent)]
    Boxed(Box<dyn Explain>),
}

#[derive(Debug, thiserror::Error, Explain)]
#[error(transparent)]
struct Wrapped {
    refused: Refused,
}

#[derive(Debug, thiserror::Error, Explain)]
#[error("{value} beyond {limit:?}")]
#[explain(id = "beyond")]
struct Beyond<T: Debug> {
    value: T,
    limit: Option<T>,
}

/// Every field name of the fixtures, as a key: an error gives an argument under those of its
/// arguments alone.
const NAMES: [&str; 12] = [
    "mode", "type", "r#type", "at", "secret", "cause", "source", "length", "refused", "value",
    "limit", "0",
];

/// An error, the id it gives, and the arguments it gives, each a key and a value's `Display`.
type Row<'e> = (
    &'e dyn Explain,
    &'static str,
    &'static [(&'static str, &'static str)],
);

#[test]
fn a_derived_error_gives_its_id_and_its_arguments() {
    let mode = |at| Refused::Mode {
        mode: "fragment".to_owned(),
        r#type: 2,
        at,
        secret: vec![7],
        cause: Closed,
    };
    let bytes = || Refused::Bytes {
        length: 9,
        source: Closed,
    };
    let beyond: Box<dyn Explain> = Box::new(Beyond {
        value: 12_u64,
        limit: Some(10),
    });
    let rows: [Row<'_>; 9] = [
        (&Closed, "err.derive.closed", &[]),
        (
            &mode(Some(7)),
            "err.derive.request.mode",
            &[("mode", "fragment"), ("type", "2"), ("at", "7")],
        ),
        (
            &mode(None),
            "err.derive.request.mode",
            &[("mode", "fragment"), ("type", "2"), ("at", "")],
        ),
        (&Refused::Unread(Unread), "err.derive.request.unread", &[]),
        (&bytes(), "err.derive.request.bytes", &[("length", "9")]),
        (&Refused::Closed(Closed), "err.derive.closed", &[]),
        (&Refused::Boxed(Box::new(Unread)), "err.derive.unread", &[]),
        (
            &Wrapped { refused: bytes() },
            "err.derive.request.bytes",
            &[("length", "9")],
        ),
        (
            &beyond,
            "err.derive.beyond",
            &[("value", "12"), ("limit", "10")],
        ),
    ];
    let given = |error: &dyn Explain| -> Vec<(&'static str, String)> {
        NAMES
            .into_iter()
            .filter_map(|name| Some((name, error.arg(name)?.to_string())))
            .collect()
    };
    for (error, id, args) in rows {
        let args: Vec<_> = args
            .iter()
            .map(|&(key, value)| (key, value.to_owned()))
            .collect();
        assert_eq!((error.id(), given(error)), (id, args), "{error:?}");
    }

    let unbounded = Beyond::<u8> {
        value: 3,
        limit: None,
    };
    assert_eq!(
        given(&unbounded),
        [("value", "3".to_owned()), ("limit", String::new())]
    );
    let value: &dyn Any = unbounded.arg("value").expect("the field `value`");
    assert!(value.is::<u8>(), "an argument's value is its field");

    let boxed: Box<dyn Explain> = Box::new(bytes());
    assert_eq!(
        Error::source(&boxed).map(ToString::to_string),
        Some("the channel closed".to_owned())
    );
}
