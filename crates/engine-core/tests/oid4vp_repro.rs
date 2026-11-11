//! The on-device reproduction: the flow-core GDC link + the real signed
//! request object, driven through parse_request on the host.

use engine_core::oid4vp::request::parse_request;
use engine_ports::HttpClient;
use std::sync::Mutex;

struct OneShotHttp {
    body: String,
    hits: Mutex<u32>,
}

#[async_trait::async_trait]
impl HttpClient for OneShotHttp {
    async fn send(
        &self,
        _request: engine_ports::HttpRequest,
    ) -> Result<engine_ports::HttpResponse, engine_ports::HttpError> {
        *self.hits.lock().unwrap() += 1;
        Ok(engine_ports::HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: self.body.clone().into_bytes(),
        })
    }
}

#[tokio::test]
async fn the_gdc_flow_core_link_parses() {
    let object =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gdc-repro/reqobj"))
        .expect("the fetched request object");
    let http = OneShotHttp {
        body: object,
        hits: Mutex::new(0),
    };
    let link = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gdc-repro/link.txt"))
        .expect("the link")
        .trim()
        .to_owned();
    let parsed = parse_request(&http, &serde_json::Value::String(link)).await;
    match parsed {
        Ok(req) => {
            println!(
                "PARSED client_id={} response_uri={}",
                req.client_id, req.response_uri
            );
        }
        Err(e) => panic!("REFUSED: {e}"),
    }
}
