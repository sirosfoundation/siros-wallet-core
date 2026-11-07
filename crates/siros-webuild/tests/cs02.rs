//! CS-02 §8.2's Request Object claims and CS-02 §8.3's error answer, as RFC 6749 §5.2 writes it.

use siros_openid4vp::json::Node;
use siros_openid4vp::plugins::Registry;
use siros_openid4vp::refusal::ErrorCode;
use siros_openid4vp::uri::{AnswerError, ResponseUriAnswer};
use siros_testkit::TestHost;
use siros_webuild::{ClaimAbsent, Cs02Claims, Cs02ErrorAnswer, ErrorAnswerForm, VerifierError};

#[test]
fn a_request_object_holds_exp_and_aud() {
    use siros_openid4vp::authenticate::ObjectRule;
    // CS-02 §8.2: "The Presentation Request Object MUST include" both; RFC 9101 §6.2's code.
    let cases = [
        (r#"{"exp": 1, "aud": "https://self-issued.me/v2"}"#, None),
        (r#"{"aud": "https://self-issued.me/v2"}"#, Some("exp")),
        (r#"{"exp": 1}"#, Some("aud")),
    ];
    for (claims, absent) in cases {
        let node = Node::parse(claims).expect("claims");
        let refusal = Cs02Claims.check(node.as_object().expect("an object"));
        let rule = refusal.as_ref().map(|refusal| {
            let rule = (refusal.rule() as &dyn std::error::Error).downcast_ref::<ClaimAbsent>();
            (rule.map(|rule| rule.claim().name()), refusal.code())
        });
        assert_eq!(
            rule,
            absent.map(|claim| (Some(claim), ErrorCode::INVALID_REQUEST_OBJECT)),
            "{claims}"
        );
    }
}

#[test]
fn the_verifiers_error_answer_reads_as_rfc_6749_writes_it() {
    let mut builder = Registry::<TestHost>::builder();
    builder.answer_reader(Cs02ErrorAnswer);
    let registry = builder.build().expect("registry");
    let answer = ResponseUriAnswer::parse(
        r#"{"error": "access_denied", "error_description": "Declined by the user"}"#,
        &registry,
    )
    .expect("an answer");
    let [outcome] = answer.outcomes() else {
        panic!("one outcome")
    };
    let error = (outcome.as_ref() as &dyn std::error::Error)
        .downcast_ref::<VerifierError>()
        .expect("the Verifier's error");
    assert_eq!(
        (
            error.code().as_str(),
            error.description().map(|d| d.as_str())
        ),
        ("access_denied", Some("Declined by the user"))
    );
    // No error, no outcome; an `error` outside Appendix A.7, an `error_description` outside
    // Appendix A.8, or a description without an error: the reader's refusal.
    assert!(
        ResponseUriAnswer::parse("{}", &registry)
            .expect("an answer")
            .outcomes()
            .is_empty()
    );
    for body in [
        r#"{"error": "a\"b"}"#,
        r#"{"error": "access_denied", "error_description": "café"}"#,
        r#"{"error": 1}"#,
        r#"{"error_description": "Declined"}"#,
    ] {
        match ResponseUriAnswer::parse(body, &registry) {
            Err(AnswerError::Reader(rule)) => assert_eq!(
                (rule.as_ref() as &dyn std::error::Error).downcast_ref::<ErrorAnswerForm>(),
                Some(&ErrorAnswerForm),
                "{body}"
            ),
            other => panic!("{body}: {other:?}"),
        }
    }
}
