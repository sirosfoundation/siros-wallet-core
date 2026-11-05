//! What cannot exist is refused at construction: a registry whose profile writes a member
//! twice or one its format's proof does not hold, a name given twice where each is given once, bound entries outside those offered,
//! identifiers breaking their rule; and the protocol values the core writes: the error codes,
//! the registry's profile lookup, the modules' ciphertexts.

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
use siros_openid4vp::wallet_metadata::Placement;
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
    fn members(
        &self,
        _placement: siros_openid4vp::wallet_metadata::Placement,
    ) -> Option<&[Member]> {
        (!self.0.is_empty()).then_some(self.0.as_slice())
    }
    fn bind(&self, _: Binding<'_>, _: &Env) -> Result<Bound, NoCandidate> {
        Err(Exclude::new(TestExclusion::new("binds nothing")).into())
    }
}

impl<H> ProfileHost<H> for Writes {
    fn wanted(&self, _: Answered<'_>) -> Result<Vec<HttpsUrl>, Fault> {
        Ok(Vec::new())
    }

    fn informed(&self, _: &[&()]) -> Self {
        self.clone()
    }

    fn authentication(&self, _: Answered<'_>) -> Result<AuthenticationNeed, Fault> {
        Ok(AuthenticationNeed::Presence)
    }

    fn revalidate(&self, _: FetchedRecord<'_>, _: &H) -> Result<Option<()>, Fault> {
        Ok(None)
    }

    fn respond(&self, _: Answered<'_>, _: &H, _: &Authentication) -> Result<Members, Fault> {
        Ok(Members::none())
    }
}

#[test]
fn what_cannot_exist_is_refused_at_construction() {
    let build_placing = |placement: Placement, members: Vec<Member>| {
        let mut builder = Registry::<NoHost>::builder();
        siros_testkit::fixtures::hashes(&mut builder);
        builder.format(TestFormat::placing(placement).expect("format"));
        let profile = builder.profile(Writes(members));
        builder.exact(TransactionType::parse("t1").expect("type"), profile);
        builder.build().map(drop)
    };
    let build = |members: Vec<Member>| build_placing(Placement::Claims, members);
    let elements = |members: Vec<Member>| build_placing(Placement::NameSpaces, members);
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
        elements(vec![Member::element("a", "x"), Member::element("b", "x")]),
        Ok(())
    );
    assert!(matches!(
        elements(vec![Member::element("a", "x"), Member::element("a", "x")]),
        Err(RegistryError::MemberTwice { .. })
    ));
    // A member of another kind than the format's proof holds (Placement): a data element where
    // it holds claims, a claim where it holds name-space elements.
    assert!(matches!(
        build(vec![Member::claim("x"), Member::element("a", "x")]),
        Err(RegistryError::MemberPlacement { .. })
    ));
    assert!(matches!(
        elements(vec![Member::claim("x")]),
        Err(RegistryError::MemberPlacement { .. })
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

/// The codes as RFC 6749 §4.1.2.1, RFC 9101 §7 and OpenID4VP §8.5 name them; a code is one or
/// more of RFC 6749 Appendix A.7's `NQSCHAR` (`%x20-21 / %x23-5B / %x5D-7E`).
#[test]
fn error_codes_are_the_specifications_names_in_appendix_a_7s_syntax() {
    let codes = [
        (ErrorCode::INVALID_REQUEST, "invalid_request"),
        (ErrorCode::UNAUTHORIZED_CLIENT, "unauthorized_client"),
        (ErrorCode::ACCESS_DENIED, "access_denied"),
        (
            ErrorCode::UNSUPPORTED_RESPONSE_TYPE,
            "unsupported_response_type",
        ),
        (ErrorCode::INVALID_SCOPE, "invalid_scope"),
        (ErrorCode::SERVER_ERROR, "server_error"),
        (
            ErrorCode::TEMPORARILY_UNAVAILABLE,
            "temporarily_unavailable",
        ),
        (ErrorCode::INVALID_REQUEST_URI, "invalid_request_uri"),
        (ErrorCode::INVALID_REQUEST_OBJECT, "invalid_request_object"),
        (ErrorCode::REQUEST_NOT_SUPPORTED, "request_not_supported"),
        (
            ErrorCode::REQUEST_URI_NOT_SUPPORTED,
            "request_uri_not_supported",
        ),
        (ErrorCode::INVALID_CLIENT, "invalid_client"),
        (
            ErrorCode::VP_FORMATS_NOT_SUPPORTED,
            "vp_formats_not_supported",
        ),
        (
            ErrorCode::INVALID_REQUEST_URI_METHOD,
            "invalid_request_uri_method",
        ),
        (
            ErrorCode::INVALID_TRANSACTION_DATA,
            "invalid_transaction_data",
        ),
        (ErrorCode::WALLET_UNAVAILABLE, "wallet_unavailable"),
    ];
    for (code, name) in codes {
        assert_eq!((code.as_str(), code.to_string()), (name, name.to_owned()));
        assert_eq!(ErrorCode::new(name), Some(code));
    }
    assert!(ErrorCode::new(" !#[]~").is_some());
    for refused in ["", "a\"b", "a\\b", "a\u{7f}", "a\tb", "caf\u{e9}"] {
        assert_eq!(ErrorCode::new(refused), None, "{refused:?}");
    }
}

#[test]
fn a_refusals_description_keeps_appendix_a_8s_characters_alone() {
    use siros_openid4vp::refusal::ErrorDescription;
    // RFC 6749 Appendix A.8: %x20-21 / %x23-5B / %x5D-7E; the wallet writes `?` for any other
    // character, one per character.
    let a_8: String = (0x20u8..=0x7e)
        .filter(|byte| !matches!(byte, b'"' | b'\\'))
        .map(char::from)
        .collect();
    let cases = [
        (a_8.as_str(), Some(a_8.as_str())),
        (
            "C5 response_mode 'x\"y' \\",
            Some("C5 response_mode 'x?y' ?"),
        ),
        ("caf\u{e9} \u{1f600}\tend\n", Some("caf? ??end?")),
        ("\u{7f}", Some("?")),
        ("", None),
    ];
    for (text, sanitized) in cases {
        let description = ErrorDescription::sanitized(text);
        assert_eq!(
            description.as_ref().map(ErrorDescription::as_str),
            sanitized,
            "{text:?}"
        );
        assert_eq!(
            description,
            sanitized.and_then(|text| ErrorDescription::parse(text.to_owned())),
            "{text:?}"
        );
    }
}

#[test]
fn profiles_are_found_by_exact_type_then_longest_prefix() {
    use siros_openid4vp::ids::TypePrefix;
    let mut builder = Registry::<TestHost>::builder();
    siros_testkit::fixtures::openid4vp(&mut builder);
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
    // A registration under a handle another builder gave names no profile this one holds.
    let mut other = Registry::<TestHost>::builder();
    let elsewhere = other.profile(TestProfile::new(Binds::First));
    let mut unheld = Registry::<TestHost>::builder();
    unheld.exact(kind("t1"), elsewhere);
    assert!(matches!(
        unheld.build(),
        Err(RegistryError::UnknownProfile(registration)) if registration == "t1"
    ));
}

#[test]
fn each_routing_conflict_is_refused_when_the_registry_builds() {
    use siros_openid4vp::hash::{HashAlgorithm, Sha2};
    use siros_openid4vp::scope::{ScopeQuery, ScopeValue};
    use siros_testkit::fixtures::TestScope;

    /// A scope value's query, given.
    struct Scoped(&'static str, &'static str);

    impl ScopeQuery for Scoped {
        fn scope(&self) -> ScopeValue {
            ScopeValue::new(self.0).expect("a scope value")
        }

        fn query(&self) -> &'static str {
            self.1
        }
    }
    use siros_openid4vp::modes::{DcApi, DcApiJwt, DirectPostJwt};
    use siros_openid4vp::routing::{ChannelKind, Mode, ModeName, ResponseType, VpToken};
    use siros_openid4vp::wallet_metadata::ParameterName;
    use siros_testkit::{TestHash, TestMode, TestResponseType};

    const MEMBER: ParameterName = siros_explain::checked!(ParameterName, "test_member");
    const JWKS: ParameterName = siros_explain::checked!(ParameterName, "jwks");
    // A mode in the clear of a name and channel, declaring `wallet_metadata` members.
    let declares = |name: &'static str, channel, names: &'static [ParameterName]| TestMode {
        declares: names,
        ..TestMode::new(ModeName::new(name).expect("a mode name"), channel)
    };
    // The core's cases are peers of an extension's: an extension of the name of one of them is
    // that name twice. A response type twice (RFC 6749 §3.1.1 keys it by its name).
    let mut builder = Registry::<TestHost>::builder();
    builder.response_type(VpToken);
    builder.response_type(TestResponseType(VpToken.name()));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::ResponseTypeTwice(VpToken.name()))
    );
    // A mode twice on one channel, whatever its sealing.
    let mut builder = Registry::<TestHost>::builder();
    builder.mode(TestMode::new(DcApiJwt.name(), ChannelKind::DcApi));
    builder.jwe_mode(DcApiJwt);
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::ModeTwice {
            name: DcApiJwt.name(),
            channel: ChannelKind::DcApi
        })
    );
    // An error mode twice.
    let mut builder = Registry::<TestHost>::builder();
    builder.error_mode(DirectPostJwt);
    builder.error_mode(DirectPostJwt);
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::ModeTwice {
            name: DirectPostJwt.name(),
            channel: ChannelKind::Uri
        })
    );
    // A hash algorithm twice; a transaction data profile without B.3.3.1's default sha-256.
    let mut builder = Registry::<TestHost>::builder();
    builder.hash(Sha2::Sha256);
    builder.hash(TestHash {
        name: Sha2::Sha256.name(),
        octets: Sha2::Sha256.octets(),
        writes: 32,
    });
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::HashTwice(Sha2::Sha256.name()))
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.hash(Sha2::Sha384);
    let profile = builder.profile(TestProfile::new(Binds::First));
    builder.exact(TransactionType::parse("t1").expect("t1"), profile);
    assert_eq!(builder.build().map(drop), Err(RegistryError::Sha256Absent));
    // A scope value twice; a query the DCQL reader refuses; an id two scope values' queries
    // share (§5.5: "MUST be unique").
    let mut builder = Registry::<TestHost>::builder();
    builder.scope(TestScope);
    builder.scope(TestScope);
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::ScopeTwice(TestScope.scope()))
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.scope(Scoped("org.example.broken", r#"{"credentials":[]}"#));
    assert!(matches!(
        builder.build().map(drop),
        Err(RegistryError::ScopeQuery(_))
    ));
    let mut builder = Registry::<TestHost>::builder();
    builder.scope(TestScope);
    builder.scope(Scoped(
        "org.example.again",
        r#"{"credentials":[{"id":"scoped","format":"test","meta":{}}]}"#,
    ));
    assert!(matches!(
        builder.build().map(drop),
        Err(RegistryError::ScopeIds { id, .. }) if id == "scoped"
    ));
    // A DC API mode that declares wallet_metadata members; a name two modes declare; a name the
    // core writes.
    let mut builder = Registry::<TestHost>::builder();
    builder.mode(declares("dc_api.test", ChannelKind::DcApi, &[MEMBER]));
    assert!(matches!(
        builder.build().map(drop),
        Err(RegistryError::MetadataChannel(_))
    ));
    let mut builder = Registry::<TestHost>::builder();
    builder.mode(declares("post.one", ChannelKind::Uri, &[MEMBER]));
    builder.mode(declares("post.two", ChannelKind::Uri, &[MEMBER]));
    assert!(matches!(
        builder.build().map(drop),
        Err(RegistryError::NameTwice { name, .. }) if name.as_str() == "test_member"
    ));
    let mut builder = Registry::<TestHost>::builder();
    builder.mode(declares("post.one", ChannelKind::Uri, &[JWKS]));
    assert!(matches!(
        builder.build().map(drop),
        Err(RegistryError::NameReserved { name, .. }) if name.as_str() == "jwks"
    ));
    // A POST contribution's member a mode declares too; its parameter the core owns; a reader's
    // member another reader declares; the answer member the core reads.
    use siros_openid4vp::wallet_metadata::{NamePlace, PostContent};
    use siros_testkit::{TestAnswerReader, TestPostContribution};
    const NONCE: ParameterName = siros_explain::checked!(ParameterName, "wallet_nonce");
    const REDIRECT: ParameterName = siros_explain::checked!(ParameterName, "redirect_uri");
    let contribution = |members, parameters| TestPostContribution {
        members,
        parameters,
        content: PostContent::default(),
    };
    let mut builder = Registry::<TestHost>::builder();
    builder.mode(declares("post.one", ChannelKind::Uri, &[MEMBER]));
    builder.post_contribution(contribution(&[MEMBER], &[]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameTwice {
            place: NamePlace::WalletMetadata,
            name: MEMBER
        })
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.post_contribution(contribution(&[], &[NONCE]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameReserved {
            place: NamePlace::PostParameter,
            name: NONCE
        })
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.answer_reader(TestAnswerReader(&[MEMBER]));
    builder.answer_reader(TestAnswerReader(&[MEMBER]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameTwice {
            place: NamePlace::AnswerMember,
            name: MEMBER
        })
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.answer_reader(TestAnswerReader(&[REDIRECT]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameReserved {
            place: NamePlace::AnswerMember,
            name: REDIRECT
        })
    );
    // An Authorization Response parameter two parts declare; one the core writes (§8.1).
    use siros_testkit::TestResponseParameters;
    const ISS: ParameterName = siros_explain::checked!(ParameterName, "iss");
    const STATE: ParameterName = siros_explain::checked!(ParameterName, "state");
    let parameters = |names| TestResponseParameters {
        names,
        writes: Vec::new(),
    };
    let mut builder = Registry::<TestHost>::builder();
    builder.response_parameters(parameters(&[ISS]));
    builder.response_parameters(parameters(&[ISS]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameTwice {
            place: NamePlace::ResponseParameter,
            name: ISS
        })
    );
    let mut builder = Registry::<TestHost>::builder();
    builder.response_parameters(parameters(&[STATE]));
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::NameReserved {
            place: NamePlace::ResponseParameter,
            name: STATE
        })
    );
    // The POST twice; encrypted Request Objects twice, or without the POST (§5.10: the key
    // travels in the POST's `jwks`).
    use siros_openid4vp::uri::{EncryptedRequests, RequestPost};
    let mut builder = Registry::<TestHost>::builder();
    builder.request_post(RequestPost);
    builder.request_post(RequestPost);
    assert_eq!(builder.build().map(drop), Err(RegistryError::PostTwice));
    let mut builder = Registry::<TestHost>::builder();
    builder.request_post(RequestPost);
    builder.request_encryption(EncryptedRequests);
    builder.request_encryption(EncryptedRequests);
    assert_eq!(builder.build().map(drop), Err(RegistryError::PostTwice));
    let mut builder = Registry::<TestHost>::builder();
    builder.request_encryption(EncryptedRequests);
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::DecryptionWithoutPost)
    );
    // An error mode on the DC API, whose errors A.4 fixes.
    let dc_api_errors = TestMode::new(DcApi.name(), ChannelKind::DcApi);
    let mut builder = Registry::<TestHost>::builder();
    builder.error_mode(dc_api_errors);
    assert_eq!(
        builder.build().map(drop),
        Err(RegistryError::ErrorModeChannel(DcApi.name()))
    );
}

#[test]
fn a_modules_ciphertext_of_another_form_is_refused() {
    use siros_openid4vp::host::{NotSealed, SealedJwe};
    // RFC 7516 §7.1: a compact JWE has five parts, the first a protected header that is a JSON
    // object; `{"alg":"ECDH-ES"}` is eyJhbGciOiJFQ0RILUVTIn0.
    let header = "eyJhbGciOiJFQ0RILUVTIn0";
    assert!(SealedJwe::parse(format!("{header}..AAAA.AAAA.AAAA")).is_ok());
    assert!(matches!(
        SealedJwe::parse(format!("{header}..AAAA.AAAA")),
        Err(NotSealed::JweParts { parts: 4 })
    ));
}

#[test]
fn a_body_of_another_form_than_its_channels_is_refused() {
    use siros_openid4vp::media::MediaType;
    use siros_openid4vp::resolve::{DcApiData, FormMedia, NotObject, PostBody};
    use siros_openid4vp::uri::{FormBody, NotForm};
    // RFC 6749 Appendix B holds flat name-value pairs, each name once.
    #[derive(serde::Serialize)]
    struct Nested {
        response: [u8; 1],
    }
    assert!(matches!(
        FormBody::of(&Nested { response: [1] }),
        Err(NotForm::Serializer(_))
    ));
    assert_eq!(
        FormBody::of(&[("response", "a"), ("response", "b")]),
        Err(NotForm::Repeated("response".to_owned()))
    );
    // A.4: the DigitalCredential's data is a JSON object.
    assert_eq!(DcApiData::of("[]".to_owned()), Err(NotObject));
    assert_eq!(DcApiData::of(r#"{"a":1,"a":2}"#.to_owned()), Err(NotObject));
    // A form comes from FormBody::of alone.
    let form = MediaType::parse("application/x-www-form-urlencoded; charset=UTF-8").expect("media");
    assert_eq!(PostBody::of(form, b"a=1".to_vec()), Err(FormMedia));
}
