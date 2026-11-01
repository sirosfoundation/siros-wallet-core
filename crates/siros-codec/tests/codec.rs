//! Known answers of the codec: RFC 4648, Section 10; RFC 8949, Appendix A; day numbers counted
//! by hand; and the refusals of each reader.

use siros_codec::cbor::{self, CborError, Unsupported, Value, MAX_DEPTH};
use siros_codec::date::{Date, DateTime};
use siros_codec::{base64url, Base64Error};

/// RFC 4648, Section 10, in the URL alphabet without padding, and the rejections.
#[test]
fn rfc4648_vectors() {
    let cases = [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in cases {
        assert_eq!(base64url::encode(plain.as_bytes()).as_str(), encoded);
        assert_eq!(base64url::decode(encoded).as_deref(), Ok(plain.as_bytes()));
    }
    assert_eq!(base64url::encode(&[0xfb, 0xff]).as_str(), "-_8");
    let refused = [
        ("Zg==", Base64Error::Alphabet(2)),
        ("Zh", Base64Error::TrailingBits),
        ("Z", Base64Error::Length),
        ("Zm9v+A", Base64Error::Alphabet(4)),
        ("Zm9v/A", Base64Error::Alphabet(4)),
    ];
    for (bad, error) in refused {
        assert_eq!(base64url::decode(bad), Err(error), "{bad}");
    }
}

/// RFC 8949, Appendix A: encodings this writer must produce and the reader must read.
#[test]
fn rfc8949_appendix_a() {
    let cases: [(Value, &str); 9] = [
        (Value::Unsigned(0), "00"),
        (Value::Unsigned(23), "17"),
        (Value::Unsigned(24), "1818"),
        (Value::Unsigned(1_000_000), "1a000f4240"),
        (Value::Negative(999), "3903e7"),
        (Value::text("IETF"), "6449455446"),
        (
            Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
            "820102",
        ),
        (
            Value::Tag(0, Box::new(Value::text("2013-03-21T20:04:00Z"))),
            "c074323031332d30332d32315432303a30343a30305a",
        ),
        (
            Value::Map(vec![
                (Value::Unsigned(1), Value::Unsigned(2)),
                (Value::Unsigned(3), Value::Unsigned(4)),
            ]),
            "a201020304",
        ),
    ];
    for (value, hex) in cases {
        let encoded = value.encode();
        assert_eq!(to_hex(&encoded), hex);
        assert_eq!(
            cbor::decode(&encoded).map(|i| i.raw().to_vec()),
            Ok(encoded)
        );
    }
}

/// The refusals: each input breaks one rule of the reader.
#[test]
fn refusals() {
    let cases: [(&[u8], CborError); 6] = [
        (&[0x82, 0x01], CborError::Truncated),
        (&[0x01, 0x02], CborError::TrailingBytes),
        (
            &[0x9f, 0xff],
            CborError::Unsupported(Unsupported::IndefiniteLength),
        ),
        (
            &[0xfa, 0, 0, 0, 0],
            CborError::Unsupported(Unsupported::Float),
        ),
        (
            &[0x62, 0xff, 0xfe],
            CborError::InvalidUtf8(
                std::str::from_utf8(std::hint::black_box(&[0xff, 0xfe])).unwrap_err(),
            ),
        ),
        (&[0xa2, 0x01, 0x02, 0x01, 0x03], CborError::DuplicateKey),
    ];
    for (bytes, error) in cases {
        assert_eq!(cbor::decode(bytes), Err(error), "{bytes:02x?}");
    }
    let deep = [vec![0x81; MAX_DEPTH + 1], vec![0x00]].concat();
    assert_eq!(cbor::decode(&deep), Err(CborError::TooDeep));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Round trips at the ends of the range and across the leap days of 1900, 2000 and 2024,
/// against day numbers counted by hand from 1970-01-01.
#[test]
fn day_numbers() {
    let cases = [
        ("1970-01-01", 0),
        ("2000-02-29", 11_016),
        ("2000-03-01", 11_017),
        ("1900-03-01", -25_508),
        ("2024-02-29", 19_782),
        ("0000-01-01", -719_528),
        ("9999-12-31", 2_932_896),
    ];
    for (text, days) in cases {
        let date = Date::parse(text);
        assert_eq!(date.map(Date::days), Some(days), "{text}");
        assert_eq!(Some(Date::from_days(days)), date, "{text}");
        assert_eq!(date.and_then(Date::to_full_date).as_deref(), Some(text));
    }
    for bad in [
        "1900-02-29",
        "2023-02-29",
        "2024-13-01",
        "2024-04-31",
        "24-01-01",
    ] {
        assert_eq!(Date::parse(bad), None, "{bad}");
    }
}

/// The 20-character form: its range ends, and the forms it refuses.
#[test]
fn date_times() {
    for text in [
        "0000-01-01T00:00:00Z",
        "2026-10-09T12:34:56Z",
        "9999-12-31T23:59:59Z",
    ] {
        let t = DateTime::parse(text);
        assert_eq!(t.map(|t| t.to_string()).as_deref(), Some(text));
    }
    assert_eq!(
        DateTime::parse("0000-01-01T00:00:00Z").map(DateTime::unix),
        Some(DateTime::MIN_UNIX)
    );
    assert_eq!(
        DateTime::parse("9999-12-31T23:59:59Z").map(DateTime::unix),
        Some(DateTime::MAX_UNIX)
    );
    for bad in [
        "2026-10-09T24:00:00Z",
        "2026-10-09T12:34:56.1Z",
        "2026-10-09T12:34:56+00:00",
        "2026-10-09t12:34:56Z",
        "2026-02-30T00:00:00Z",
    ] {
        assert_eq!(DateTime::parse(bad), None, "{bad}");
    }
}
