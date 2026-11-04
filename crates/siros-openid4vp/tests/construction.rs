//! What cannot exist is refused at construction: a registry whose profile writes a member
//! twice, a name given twice where each is given once, bound entries outside those offered,
//! identifiers breaking their rule; and the protocol values the core writes: the error codes,
//! the registry's profile lookup, random identifiers.

mod common;

use siros_testkit::TestHost;
use siros_testkit::rules::TestExclusion;
use std::borrow::Cow;

use siros_openid4vp::host::{Authentication, AuthenticationNeed, ProfileHost};
use siros_openid4vp::ids::{
    AuthorityType, CredentialId, DocumentKey, FormatId, Origin, TransactionType,
};
use siros_openid4vp::json::{JsonError, Node};
use siros_openid4vp::plugins::{
    Answered, Attested, AttestedTwice, Binding, Bound, BoundEntries, Exclude, Fault, FetchedRecord,
    Member, MemberTwice, MemberValue, Members, NoCandidate, NoHost, Profile, Registry,
    RegistryError,
};
use siros_openid4vp::refusal::{ErrorCode, Refusal};
use siros_openid4vp::request::{EntryIndex, Request};
use siros_openid4vp::rows::{Env, HttpsUrl};
use siros_openid4vp::wallet::{
    Credential, Document, Facts, HeldAuthority, Holder, RegistrationError, Wallet,
};
use siros_testkit::{Binds, TestFormat, TestProfile};

use common::{entry, test_queries};

/// A profile declaring the members it is given.
#[derive(Clone)]
struct Writes(Vec<Member>);

impl Profile for Writes {
    type Finding = ();

    fn refusals(&self, _: &Request<'_>, _: &[EntryIndex]) -> Vec<Refusal> {
        Vec::new()
    }
    fn members(&self, _: &FormatId<'_>) -> Option<&[Member]> {
        (!self.0.is_empty()).then_some(self.0.as_slice())
    }
    fn bind(&self, _: Binding<'_>, _: &Env) -> Result<Bound, NoCandidate> {
        Err(Exclude::new(TestExclusion::new("binds nothing")).into())
    }
    fn wanted(&self, _: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        Ok(Vec::new())
    }
    fn informed(&self, _: &[&()]) -> Self {
        self.clone()
    }

    fn authentication(&self, _: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }
}

impl<H> ProfileHost<H> for Writes {
    fn revalidate(&self, _: FetchedRecord<'_>, _: &H) -> Result<Option<()>, Fault> {
        Ok(None)
    }

    fn respond(&self, _: Answered<'_>, _: &H, _: &Authentication) -> Result<Members, Fault> {
        Ok(Members::none())
    }
}

#[test]
fn what_cannot_exist_is_refused_at_construction() {
    let build = |members: Vec<Member>| {
        let mut builder = Registry::<NoHost>::builder();
        builder.format(TestFormat::new().expect("format"));
        let profile = builder.profile(Writes(members));
        builder.exact(TransactionType::parse("t1").expect("type"), profile);
        builder.build().map(drop)
    };
    // A profile that would write a member twice into one presentation: one it declares twice,
    // or one the format's proof writes itself. A profile binding nothing in a format writes
    // nothing there.
    assert!(matches!(
        build(vec![Member::claim("x"), Member::claim("x")]),
        Err(RegistryError::MemberTwice { .. })
    ));
    assert!(matches!(
        build(vec![Member::claim("nonce")]),
        Err(RegistryError::MemberTwice { .. })
    ));
    assert_eq!(build(vec![Member::claim("x")]), Ok(()));
    assert_eq!(build(Vec::new()), Ok(()));
    // A data element is its name space and identifier: one identifier in two name spaces is two
    // members.
    assert_eq!(
        build(vec![Member::element("a", "x"), Member::element("b", "x")]),
        Ok(())
    );
    assert!(matches!(
        build(vec![Member::element("a", "x"), Member::element("a", "x")]),
        Err(RegistryError::MemberTwice { .. })
    ));
    // A response's members, the names a response attests, and an object's members: each once.
    let text = |value: &str| MemberValue::Text(value.to_owned());
    assert_eq!(
        Members::new(vec![
            (Member::claim("x"), text("1")),
            (Member::claim("x"), text("2"))
        ]),
        Err(MemberTwice(Member::claim("x")))
    );
    assert_eq!(
        Attested::new(vec![
            ("a".to_owned(), "1".to_owned()),
            ("a".to_owned(), "2".to_owned())
        ]),
        Err(AttestedTwice("a".to_owned()))
    );
    assert_eq!(
        Node::object([
            (Cow::Borrowed("a"), Node::Null),
            (Cow::Borrowed("a"), Node::Null)
        ]),
        Err(JsonError::DuplicateMember("a".to_owned()))
    );
    // The wallet's registration: a credential's facts list a Trusted Authorities type once, its
    // documents a key once, the wallet a credential id once.
    let authority = |kind: &'static str| HeldAuthority {
        kind: AuthorityType::parse(kind).expect("type"),
        values: Vec::new(),
    };
    assert_eq!(
        Facts::new(Holder::Bound, vec![authority("aki"), authority("aki")]),
        Err(RegistrationError::AuthorityTwice("aki".to_owned()))
    );
    let document = |key: &'static str| Document {
        key: DocumentKey::parse(key).expect("key"),
        content: b"{}",
    };
    let credential = |documents: Vec<Document<'static>>| {
        Credential::new(
            CredentialId::parse("c").expect("id"),
            FormatId::parse("test").expect("format"),
            b"{}",
            documents,
            Facts::new(Holder::Bound, Vec::new()).expect("facts"),
        )
    };
    assert_eq!(
        credential(vec![document("test"), document("test")]),
        Err(RegistrationError::DocumentTwice {
            credential: "c".to_owned(),
            key: "test".to_owned()
        })
    );
    let held = credential(vec![document("test")]).expect("credential");
    assert_eq!(
        Wallet::new(vec![held.clone(), held]),
        Err(RegistrationError::CredentialTwice("c".to_owned()))
    );
    // Bound entries are a non-empty ascending subset of those offered.
    let offered: Vec<EntryIndex> = request_entries(3);
    assert!(BoundEntries::select(&offered, Vec::new()).is_err());
    assert!(BoundEntries::select(&offered, vec![offered[2], offered[1]]).is_err());
    assert!(BoundEntries::select(&offered[..1], vec![offered[1]]).is_err());
    assert!(BoundEntries::select(&offered, vec![offered[0], offered[2]]).is_ok());
}

/// The positions of a request's entries.
fn request_entries(count: usize) -> Vec<EntryIndex> {
    let entries: Vec<String> = (0..count)
        .map(|_| {
            format!(
                "\"{}\"",
                entry(r#"{"type": "t1", "credential_ids": ["q"]}"#)
            )
        })
        .collect();
    let text = format!(
        r#"{{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","dcql_query":{},"transaction_data":[{}]}}"#,
        test_queries(&["q"]),
        entries.join(",")
    );
    let received = siros_testkit::fixtures::unsigned(&text).expect("received");
    let request = siros_testkit::fixtures::request_of(&received).expect("request");
    request.indexed_entries().map(|(index, _)| index).collect()
}

#[test]
fn constrained_strings_are_refused_when_they_break_their_rule() {
    use siros_openid4vp::ids::{LocaleTag, Nonce, QueryId, TypePrefix};
    // OpenID4VP §6.1: a query id is non-empty, of letters, digits, _ and -.
    assert!(QueryId::parse("a_b-1").is_ok());
    for invalid in ["", "a b", "a.b", "é"] {
        assert!(QueryId::parse(invalid).is_err(), "{invalid:?}");
    }
    assert!(FormatId::parse("").is_err());
    assert!(CredentialId::parse("").is_err());
    assert!(Nonce::parse("").is_err());
    assert!(Origin::parse("").is_err());
    assert!(TypePrefix::parse("").is_err());
    assert!(LocaleTag::parse("").is_err());
}

#[test]
fn error_codes_are_written_as_section_8_5_names_them() {
    let codes = [
        (ErrorCode::InvalidRequest, "invalid_request"),
        (
            ErrorCode::UnsupportedResponseType,
            "unsupported_response_type",
        ),
        (ErrorCode::InvalidRequestUri, "invalid_request_uri"),
        (ErrorCode::InvalidRequestObject, "invalid_request_object"),
        (ErrorCode::RequestNotSupported, "request_not_supported"),
        (ErrorCode::InvalidScope, "invalid_scope"),
        (
            ErrorCode::InvalidRequestUriMethod,
            "invalid_request_uri_method",
        ),
        (
            ErrorCode::InvalidTransactionData,
            "invalid_transaction_data",
        ),
        (ErrorCode::VpFormatsNotSupported, "vp_formats_not_supported"),
        (ErrorCode::AccessDenied, "access_denied"),
    ];
    for (code, name) in codes {
        assert_eq!((code.as_str(), code.to_string()), (name, name.to_owned()));
    }
}

#[test]
fn profiles_are_found_by_exact_type_then_longest_prefix() {
    use siros_openid4vp::ids::TypePrefix;
    let mut builder = Registry::<TestHost>::builder();
    builder.format(TestFormat::new().expect("format"));
    let profiles: Vec<_> = (0..4)
        .map(|_| builder.profile(TestProfile::new(Binds::First)))
        .collect();
    let kind = |text: &str| TransactionType::parse(text.to_owned()).expect("type");
    builder.exact(kind("urn:paso:sca:global:payment:1"), profiles[0]);
    builder.prefix(
        TypePrefix::parse("urn:paso:sca:").expect("prefix"),
        profiles[1],
    );
    builder.prefix(
        TypePrefix::parse("urn:paso:sca:global:generic:").expect("prefix"),
        profiles[2],
    );
    builder.prefix(
        TypePrefix::parse("urn:paso:sca:global:mandate:").expect("prefix"),
        profiles[3],
    );
    let registry = builder.build().expect("registry");
    let cases = [
        ("urn:paso:sca:global:payment:1", Some(profiles[0])),
        ("urn:paso:sca:global:payment:2", Some(profiles[1])),
        ("urn:paso:sca:global:generic:x:1", Some(profiles[2])),
        ("urn:paso:sca:global:mandate:agentic:1", Some(profiles[3])),
        ("urn:other:1", None),
    ];
    for (type_id, want) in cases {
        assert_eq!(registry.profile(&kind(type_id)), want, "{type_id}");
    }
    // A type or prefix registered twice is refused.
    let mut twice = Registry::<TestHost>::builder();
    let profile = twice.profile(TestProfile::new(Binds::First));
    twice.exact(kind("t1"), profile);
    twice.exact(kind("t1"), profile);
    assert!(matches!(twice.build(), Err(RegistryError::TypeTwice(_))));
}

#[test]
fn a_random_id_is_a_version_4_uuid() {
    use siros_openid4vp::host::RandomId;
    // RFC 9562 Appendix A.3's example.
    assert_eq!(
        RandomId::from_bytes([
            0x91, 0x91, 0x08, 0xf7, 0x52, 0xd1, 0x33, 0x20, 0x5b, 0xac, 0xf8, 0x47, 0xdb, 0x41,
            0x48, 0xa8
        ])
        .to_string(),
        "919108f7-52d1-4320-9bac-f847db4148a8"
    );
    // RFC 9562 §5.4: version 4 in the version field, the variant bits 10.
    assert_eq!(
        RandomId::from_bytes([0; 16]).to_string(),
        "00000000-0000-4000-8000-000000000000"
    );
    assert_eq!(
        RandomId::from_bytes([0xff; 16]).to_string(),
        "ffffffff-ffff-4fff-bfff-ffffffffffff"
    );
    assert!(RandomId::parse("00000000-0000-4000-9abc-000000000001").is_ok());
    for invalid in [
        "00000000-0000-1000-8000-000000000000",
        "00000000-0000-4000-c000-000000000000",
        "00000000-0000-4000-8000-00000000000A",
        "00000000-0000-4000-8000-0000000000000",
        "000000000000-4000-8000-000000000000",
    ] {
        assert!(RandomId::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn a_modules_ciphertext_of_another_form_is_refused() {
    use siros_openid4vp::host::{NotSealed, SealedCose, SealedJwe};
    // RFC 7516 §7.1: a compact JWE has five parts, the first a protected header that is a JSON
    // object; `{"alg":"ECDH-ES"}` is eyJhbGciOiJFQ0RILUVTIn0.
    let header = "eyJhbGciOiJFQ0RILUVTIn0";
    assert!(SealedJwe::parse(format!("{header}..AAAA.AAAA.AAAA")).is_ok());
    assert!(matches!(
        SealedJwe::parse(format!("{header}..AAAA.AAAA")),
        Err(NotSealed::JweParts { parts: 4 })
    ));
    // RFC 9052 §5.1: a COSE_Encrypt is tag 96 around [protected, unprotected, ciphertext,
    // recipients]; d8 60 is tag 96, 80 an empty array.
    assert!(SealedCose::parse(vec![0xd8, 0x60, 0x84, 0x40, 0xa0, 0x40, 0x80]).is_ok());
    assert!(matches!(
        SealedCose::parse(vec![0x84, 0x40, 0xa0, 0x40, 0x80]),
        Err(NotSealed::Untagged)
    ));
    // 96([]): the tagged content lacks the structure's four items.
    assert!(matches!(
        SealedCose::parse(vec![0xd8, 0x60, 0x80]),
        Err(NotSealed::Structure(_))
    ));
}
