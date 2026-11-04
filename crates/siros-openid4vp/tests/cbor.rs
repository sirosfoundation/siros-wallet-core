//! RFC 8949 §5.6.1's distinct keys at every depth, RFC 9052 §3's header buckets, RFC 8949 §6's
//! conversions between JSON and CBOR over export_formats.py's `json_value` grammar, and RFC 8949
//! §4.2.1's deterministic encoding.

use siros_openid4vp::cbor::cose::{CoseShape, coset, read_sign1};
use siros_openid4vp::cbor::{
    CborError, Value, decode, encode, encode_deterministic, of_json, to_json,
};
use siros_openid4vp::json::Node;
use siros_testkit::reading::model_value;

use coset::{AsCborValue, CoseSign1};

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn embedded(bytes: Vec<u8>) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(bytes)))
}

#[test]
fn a_key_twice_is_refused_at_every_depth() {
    let repeated = |e: &CborError| matches!(e, CborError::RepeatedKey(_));
    let deep = format!("{}00", "81".repeat(300));
    let keyed = format!("{}00{}", "a1".repeat(200), "00".repeat(200));
    // (name, CBOR, the refusal expected, if any).
    type Fixture<'a> = (&'a str, &'a str, Option<fn(&CborError) -> bool>);
    let cases: [Fixture<'_>; 20] = [
        ("one key", "a1616101", None),
        ("a key twice", "a2616101616102", Some(repeated)),
        (
            "twice one level down",
            "a16161a2616201616202",
            Some(repeated),
        ),
        ("twice inside an array", "81a201000100", Some(repeated)),
        ("twice inside a tag", "c1a201000100", Some(repeated)),
        (
            "twice inside an indefinite map",
            "bf616101616102ff",
            Some(repeated),
        ),
        ("1 and 1.0 are distinct", "a20100f93c0000", None),
        (
            "0.0 and -0.0 are one key",
            "a2f9000000f9800000",
            Some(repeated),
        ),
        ("text and bytes are distinct", "a2616100416100", None),
        ("equal map keys", "a2a1010200a1010201", Some(repeated)),
        ("equal array keys", "a28201020082010201", Some(repeated)),
        (
            "a tagged key and its content are distinct",
            "a2c101000100",
            None,
        ),
        (
            "a bignum and its integer are distinct",
            "a20101c2410102",
            None,
        ),
        (
            "undefined has no value",
            "a2f601f702",
            Some(|e| matches!(e, CborError::Simple(23))),
        ),
        ("200 maps nested in keys", keyed.as_str(), None),
        ("a repeat inside a key", "a1a2010001000a", Some(repeated)),
        (
            "a byte after the item",
            "a161610100",
            Some(|e| matches!(e, CborError::Trailing(1))),
        ),
        (
            "a cut item",
            "a2616101",
            Some(|e| matches!(e, CborError::Truncated)),
        ),
        ("indefinite text", "7f61616162ff", None),
        (
            "300 nested arrays",
            deep.as_str(),
            Some(|e| matches!(e, CborError::Depth(256))),
        ),
    ];
    let mut held = 0;
    for (name, text, refused) in cases {
        let result = decode(&unhex(text));
        match (refused, &result) {
            (None, Ok(_)) => {}
            (Some(expected), Err(error)) if expected(error) => {}
            _ => panic!("{name}: {result:?}"),
        }
        held += 1;
    }
    // An embedded item is a byte string to the outer reading; its own reading refuses the repeat.
    let inner = unhex("a2616101616102");
    let outer = encode(&embedded(inner.clone())).unwrap();
    assert!(decode(&outer).is_ok());
    assert!(matches!(decode(&inner), Err(CborError::RepeatedKey(_))));
    held += 1;
    assert_eq!(held, 21);
}

#[test]
fn a_bignum_keeps_its_tag() {
    // RFC 8949 §3.4.3: 2(h'01') is 1 and 3(h'00') is -1; §6.1 writes them as base64url text.
    for (text, json) in [("c24101", r#""AQ""#), ("c34100", r#""~AA""#)] {
        let bytes = unhex(text);
        let item = decode(&bytes).unwrap();
        assert!(
            matches!(&item, Value::Tag(2 | 3, inner) if inner.is_bytes()),
            "{text}"
        );
        assert_eq!(encode(&item).unwrap(), bytes, "{text}");
        assert_eq!(
            to_json(&item).unwrap(),
            Node::parse(json).unwrap(),
            "{text}"
        );
    }
}

#[test]
fn a_cose_label_sits_in_one_bucket_once() {
    let alg = |value: i64| (Value::Integer(1.into()), Value::Integer(value.into()));
    let kid = |byte: u8| (Value::Integer(4.into()), Value::Bytes(vec![byte]));
    let sign1 = |protected: Vec<(Value, Value)>, unprotected: Vec<(Value, Value)>| {
        Value::Array(vec![
            Value::Bytes(if protected.is_empty() {
                Vec::new()
            } else {
                encode(&Value::Map(protected)).unwrap()
            }),
            Value::Map(unprotected),
            Value::Bytes(b"payload".to_vec()),
            Value::Bytes(b"signature".to_vec()),
        ])
    };
    let mut held = 0;
    // A label in both buckets: coset accepts it, the wallet refuses it (RFC 9052 §3).
    let both = sign1(vec![alg(-7)], vec![alg(-7)]);
    assert!(CoseSign1::from_cbor_value(both.clone()).is_ok());
    held += 1;
    assert!(matches!(read_sign1(both), Err(CoseShape::BothBuckets(_))));
    held += 1;
    // A label twice in the unprotected bucket: coset refuses it.
    let twice = sign1(vec![alg(-7)], vec![kid(1), kid(2)]);
    assert!(matches!(
        CoseSign1::from_cbor_value(twice.clone()),
        Err(coset::CoseError::DuplicateMapKey)
    ));
    held += 1;
    assert!(matches!(
        read_sign1(twice),
        Err(CoseShape::Cose(coset::CoseError::DuplicateMapKey))
    ));
    held += 1;
    // A label twice in the protected bucket's bytes: the decoder refuses it first.
    let twice = Value::Array(vec![
        Value::Bytes(unhex("a201260126")),
        Value::Map(vec![]),
        Value::Null,
        Value::Bytes(vec![]),
    ]);
    assert!(matches!(
        read_sign1(twice),
        Err(CoseShape::Protected(CborError::RepeatedKey(_)))
    ));
    held += 1;
    // Disjoint buckets, and an empty protected bucket, read.
    assert!(read_sign1(sign1(vec![alg(-7)], vec![kid(1)])).is_ok());
    held += 1;
    assert!(read_sign1(sign1(vec![], vec![alg(-7)])).is_ok());
    held += 1;
    assert_eq!(held, 7);
}

/// A linear congruential draw in `0..n`.
fn draw(seed: &mut u64, n: usize) -> usize {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    usize::try_from((*seed >> 33) % n as u64).unwrap()
}

/// export_formats.py's `json_value`, seeded: its scalars, arrays and objects to depth 2.
fn json_value(seed: &mut u64, depth: u32) -> String {
    let texts = [
        r#""plain""#,
        r#""Grüße""#,
        r#""a\"quote'""#,
        r#""back\\slash""#,
        r#""tab\there""#,
        r#""line\nbreak""#,
        "\"\u{202e}\"",
        "\"😀\"",
        r#""""#,
        r#""\u007f\u0001""#,
    ];
    let doubles = ["0.5", "-1.25", "1e+16", "1e-05", "3.0", "49.99"];
    if depth > 2 || draw(seed, 2) == 0 {
        return match draw(seed, 6) {
            0 => texts[draw(seed, texts.len())].to_owned(),
            1 => (i64::try_from(draw(seed, 1 << 41)).unwrap() - (1 << 40)).to_string(),
            2 => doubles[draw(seed, doubles.len())].to_owned(),
            3 => "true".into(),
            4 => "false".into(),
            _ => "null".into(),
        };
    }
    if draw(seed, 2) == 0 {
        let items: Vec<String> = (0..draw(seed, 4))
            .map(|_| json_value(seed, depth + 1))
            .collect();
        return format!("[{}]", items.join(","));
    }
    let mut names = vec!["a", "b", "c", "type", "value", "ü"];
    let mut members = Vec::new();
    for _ in 0..draw(seed, 4) {
        let name = names.remove(draw(seed, names.len()));
        members.push(format!("\"{name}\":{}", json_value(seed, depth + 1)));
    }
    format!("{{{}}}", members.join(","))
}

#[test]
fn json_converts_to_cbor_and_back() {
    let mut seed = 7u64;
    for _ in 0..10_000 {
        let text = json_value(&mut seed, 0);
        let node = Node::parse(&text).unwrap();
        let item = of_json(&node).unwrap();
        assert_eq!(decode(&encode(&item).unwrap()).unwrap(), item, "{text}");
        // The reading writes the item as the model's Python writes the JSON.
        assert_eq!(
            model_value(&item).unwrap().python_compact().to_string(),
            node.python_compact().to_string(),
            "{text}"
        );
        assert_eq!(to_json(&item).unwrap(), node, "{text}");
    }
}

/// RFC 8949 §4.2.1's example key order (10, 100, -1, "z", "aa", [100], [-1], false), given
/// scrambled, and Appendix A's shortest float for 1.5.
#[test]
fn the_deterministic_encoding_is_rfc_8949_s4_2_1() {
    let int = |n: i64| Value::Integer(n.into());
    let keys = [
        Value::Bool(false),
        Value::Text("aa".into()),
        int(-1),
        Value::Array(vec![int(-1)]),
        int(100),
        Value::Text("z".into()),
        Value::Array(vec![int(100)]),
        int(10),
    ];
    let map = Value::Map(keys.into_iter().map(|key| (key, int(0))).collect());
    assert_eq!(
        encode_deterministic(&map).unwrap(),
        unhex("a8 0a00 186400 2000 617a00 62616100 81186400 812000 f400")
    );
    assert_eq!(
        encode_deterministic(&Value::Float(1.5)).unwrap(),
        unhex("f93e00")
    );
}
