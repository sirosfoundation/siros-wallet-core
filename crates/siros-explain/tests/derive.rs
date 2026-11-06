//! The derive beside thiserror: one type's identifiers, arguments and catalogue, a transparent
//! cause, a struct, a nested message held by value, and the declaration of each argument's kind.
//! Then the identifier grammar, a name given twice, the calendar rule of a date, a key given
//! twice, and where RFC 3339 places a leap second.

use siros_explain::{
    ArgKind, ArgName, ArgValue, Count, Date, DateTime, DefinedKey, Domain, Entry, Explain,
    Fraction, Key, Keyed, MessageId, Messages, Names, Offset, ParamName, Presence, Repeated,
    Second, Text, Value, checked,
};

#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.routing")]
enum RoutingRule {
    #[error("P1 response_type is absent")]
    #[explain(id = "p1_absent")]
    ResponseTypeAbsent,
    #[error("C5 response_mode {mode} is no mode the wallet answers in on this channel")]
    #[explain(id = "c5")]
    Mode { mode: String },
    #[error("P6 state holds a character outside URL-safe ASCII at {0}")]
    #[explain(id = "p6")]
    State(#[explain(name = "at")] usize),
}

#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.request_object")]
enum RequestObjectRule {
    #[error("U11 an encrypted Request Object answers a GET")]
    JweAfterGet,
    #[error(transparent)]
    Routing(#[from] RoutingRule),
    #[error("U11 the decrypted Request Object, {plaintext_len} bytes: {cause}")]
    Decrypted {
        cause: RoutingRule,
        #[explain(skip)]
        plaintext_len: usize,
    },
}

#[derive(Debug, thiserror::Error, Explain)]
#[explain(domain = "openid4vp", id = "fault")]
#[error("the plug-in broke its contract: {detail}")]
struct Fault {
    #[explain(skip)]
    detail: String,
}

#[test]
fn errors_explain_beside_thiserror() {
    let mode = RoutingRule::Mode {
        mode: "fragment".to_owned(),
    };
    let cases: [(&dyn Explain, &str, usize); 6] = [
        (
            &RoutingRule::ResponseTypeAbsent,
            "openid4vp.routing.p1_absent",
            0,
        ),
        (&mode, "openid4vp.routing.c5", 1),
        (&RoutingRule::State(7), "openid4vp.routing.p6", 1),
        (
            &RequestObjectRule::JweAfterGet,
            "openid4vp.request_object.jwe_after_get",
            0,
        ),
        (
            &RequestObjectRule::Routing(RoutingRule::State(3)),
            "openid4vp.routing.p6",
            1,
        ),
        (
            &Fault {
                detail: "a member twice".to_owned(),
            },
            "openid4vp.fault",
            0,
        ),
    ];
    for (error, id, args) in cases {
        assert_eq!(
            (error.id().as_str(), error.args().as_slice().len()),
            (id, args),
            "{error:?}"
        );
    }
    let state = RoutingRule::State(7);
    let args = state.args();
    let [named] = args.as_slice() else {
        panic!("one argument")
    };
    assert_eq!(
        (named.name().as_str(), named.arg().value()),
        ("at", &ArgValue::Value(Value::Count(Count::of(7))))
    );

    let decrypted = RequestObjectRule::Decrypted {
        cause: RoutingRule::ResponseTypeAbsent,
        plaintext_len: 9,
    };
    let Text::Query(held) = Text::of(&decrypted) else {
        panic!("a message is held as a query")
    };
    assert_eq!(
        held.key(),
        &Key::Message(checked!(MessageId, "openid4vp.request_object.decrypted"))
    );
    let [cause] = held.args() else {
        panic!("one argument: {held:?}")
    };
    let Text::Query(query) = cause.value() else {
        panic!("a query: {cause:?}")
    };
    assert_eq!(
        (cause.key().as_str(), query.key(), query.args()),
        (
            "cause",
            &Key::Message(checked!(MessageId, "openid4vp.routing.p1_absent")),
            &[][..]
        )
    );

    let boxed: Box<dyn siros_explain::Explained> = Box::new(decrypted);
    assert_eq!(boxed.id().as_str(), "openid4vp.request_object.decrypted");

    let declared: Vec<_> = RequestObjectRule::messages()
        .iter()
        .map(|message| {
            let params: Vec<_> = message
                .params()
                .iter()
                .map(|param| {
                    (
                        param.name().as_str(),
                        param.kind().kind(),
                        param.kind().presence(),
                    )
                })
                .collect();
            (message.id().as_str(), message.text(), params)
        })
        .collect();
    let required = Presence::Required;
    assert_eq!(
        declared,
        vec![
            (
                "openid4vp.request_object.jwe_after_get",
                Some("U11 an encrypted Request Object answers a GET"),
                vec![]
            ),
            (
                "openid4vp.routing.p1_absent",
                Some("P1 response_type is absent"),
                vec![]
            ),
            (
                "openid4vp.routing.c5",
                Some("C5 response_mode {mode} is no mode the wallet answers in on this channel"),
                vec![("mode", ArgKind::Raw, required)]
            ),
            (
                "openid4vp.routing.p6",
                Some("P6 state holds a character outside URL-safe ASCII at {0}"),
                vec![("at", ArgKind::Count, required)]
            ),
            (
                "openid4vp.request_object.decrypted",
                Some("U11 the decrypted Request Object, {plaintext_len} bytes: {cause}"),
                vec![("cause", ArgKind::Message, required)]
            ),
        ]
    );
}

/// The grammar `MessageId` states: tokens separated by `.`, each a lowercase ASCII letter, then
/// lowercase letters, digits and underscores. A message identifier holds two or more tokens; a
/// domain, an argument name and a defined key one or more. Each case is a text and the number of
/// tokens it holds, `None` outside the grammar.
#[test]
fn an_identifier_follows_the_grammar() {
    let cases = [
        ("openid4vp", Some(1)),
        ("fn_id", Some(1)),
        ("openid4vp.routing", Some(2)),
        ("openid4vp.routing.c5", Some(3)),
        ("", None),
        (".openid4vp", None),
        ("openid4vp..routing", None),
        ("openid4vp.", None),
        ("openid4vp.Host", None),
        ("4vp", None),
        ("_id", None),
        ("fnId", None),
        ("fn-id", None),
        ("é", None),
    ];
    for (text, tokens) in cases {
        let at_least = |min| tokens.is_some_and(|count| count >= min);
        assert_eq!(
            (
                MessageId::new(text).is_some(),
                Domain::new(text).is_some(),
                ArgName::new(text).is_some(),
                DefinedKey::parse(text.to_owned()).is_some(),
                ParamName::parse(text.to_owned()).is_some(),
            ),
            (
                at_least(2),
                at_least(1),
                at_least(1),
                at_least(1),
                at_least(1)
            ),
            "{text:?}"
        );
    }
}

/// A message's names: each an argument name, none twice.
#[test]
fn names_refuse_a_repeated_name() {
    let cases = [
        (["from", "to", "at"], true),
        (["from", "to", "from"], false),
        (["from", "to", "To"], false),
    ];
    for (names, valid) in cases {
        assert_eq!(Names::new(names).is_some(), valid, "{names:?}");
    }
}

/// The Gregorian rule: February has 29 days in years divisible by 4, except centuries not
/// divisible by 400.
#[test]
fn a_date_is_a_calendar_date() {
    let cases = [
        ((2024, 2, 29), true),
        ((2023, 2, 29), false),
        ((1900, 2, 29), false),
        ((2000, 2, 29), true),
        ((2026, 4, 31), false),
        ((2026, 13, 1), false),
        ((2026, 1, 0), false),
        ((2026, 12, 31), true),
    ];
    for ((year, month, day), valid) in cases {
        assert_eq!(
            Date::new(year, month, day).is_some(),
            valid,
            "{year}-{month}-{day}"
        );
    }
}

/// `Keyed` holds each key once: a repeated key is refused with the key, and distinct keys keep
/// their order.
#[test]
fn keyed_refuses_a_repeated_key() {
    let entries = |pairs: &[(&'static str, u8)]| {
        pairs
            .iter()
            .map(|&(key, value)| Entry::new(key, value))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        Keyed::new(entries(&[("en", 1), ("de", 2), ("en", 3)])),
        Err(Repeated("en"))
    );
    let keyed = Keyed::new(entries(&[("en", 1), ("de", 2)])).expect("distinct keys");
    assert_eq!(
        (keyed.get(&"de"), keyed.entries()),
        (Some(&2), &entries(&[("en", 1), ("de", 2)])[..])
    );
}

/// RFC 3339 §5.7 and Appendix D: second 60 only at 23:59:60 UTC on a month's last day, which an
/// offset shifts to its local time; §5.8's two examples hold, and a time of day alone holds none.
#[test]
fn a_leap_second_stands_where_rfc_3339_places_it() {
    let on = |year, month, day| Date::new(year, month, day).expect("a calendar date");
    let at = |minutes| Offset::new(minutes).expect("an offset");
    let cases = [
        ((1990, 12, 31), 23, 59, 0, true),
        ((1990, 12, 31), 15, 59, -480, true),
        ((1972, 6, 30), 23, 59, 0, true),
        ((1991, 1, 1), 0, 59, 60, true),
        ((1990, 12, 30), 23, 59, 0, false),
        ((1990, 12, 31), 23, 58, 0, false),
        ((1990, 12, 31), 23, 59, 60, false),
        ((1990, 12, 31), 15, 59, 0, false),
    ];
    for ((year, month, day), hour, minute, offset, stands) in cases {
        let leap = DateTime::leap(
            on(year, month, day),
            hour,
            minute,
            Fraction::NONE,
            at(offset),
        );
        assert_eq!(
            leap.is_some(),
            stands,
            "{year}-{month}-{day}T{hour}:{minute}:60 at {offset}"
        );
        if let Some(leap) = leap {
            assert_eq!((leap.second(), leap.offset()), (Some(60), Some(at(offset))));
        }
    }
    assert_eq!(Second::new(60, Fraction::NONE), None);
}
