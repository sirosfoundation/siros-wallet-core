//! The Cleverbase onboarding authorization request through the parser —
//! the live nonce-refusal repro (found 2026-11-24: the device refused
//! "nonce is required but absent" against a request whose JWT payload
//! carries nonce=vuKlapXh7WwF_HCRhVLjqwL-yV0Unozj).

use engine_core::oid4vp::request::parse_request;

/// The http port stub: the fetch never runs (the test passes the JWT's
/// URI but asserts on the parse-time error, which happens before any
/// fetch of a *second* object).
#[tokio::test]
async fn the_cleverbase_onboarding_request_parses() {
    let jwt = std::fs::read_to_string("/tmp/opencode/echo-probe/auth-request.jwt")
        .expect("the saved onboarding JWT");
    let jwt = jwt.trim().to_owned();
    // The link form the device consumed: the request_uri query form.
    let link = "openid4vp://?client_id=x509_hash%3AKh5otZVorg9029W8m40wPRa0azxV8f-rA7NNI8_HgVY&request_uri=https%3A%2F%2Ferds-wb.business-sandbox.cleverbase.io%2Fwmp%2Fonboarding%2Fonb-e6149183fdfdd51090570782de605cff%2Frequest".to_owned();
    let params = serde_json::json!(link);
    // The http port stub: the request_uri fetch answers the JWT itself.
    struct StaticHttp(String);
    #[async_trait::async_trait]
    impl engine_ports::HttpClient for StaticHttp {
        async fn send(
            &self,
            _request: engine_ports::HttpRequest,
        ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
            Ok(engine_ports::HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.0.clone().into_bytes(),
            })
        }
    }
    let http = StaticHttp(jwt.clone());
    let parsed = parse_request(&http, &params).await;
    match parsed {
        Ok(req) => {
            println!("PARSED: client_id={}, nonce={:?}", req.client_id, req.nonce);
            assert!(!req.client_id.is_empty());
        }
        Err(err) => {
            panic!("the parse refused: {err}");
        }
    }
}
