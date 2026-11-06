//! The examples of RFC 9901, Section 5 and Appendices A.1 to A.4.
//!
//! SOURCE: RFC 9901 (November 2025), https://www.rfc-editor.org/rfc/rfc9901.txt. The files
//! under `rfc9901/` are its blocks verbatim, without the three-space indent:
//!
//! - `input.json`: the input JWT Claims Set;
//! - `issued.txt`: the issued SD-JWT (Sections 5.1, A.3, A.4);
//! - `disclosures.txt`: every Disclosure the example lists (A.1, A.2);
//! - `presentation.txt`: the presentation, with its KB-JWT where the example binds a key;
//! - `processed.json`: the Processed SD-JWT Payload the verifier gets from the presentation.

use siros_sdjwt::SdJwt;

use crate::common::{compact_fixture, issued, json_fixture, processed};

const EXAMPLES: [&str; 5] = ["s5", "a1", "a2", "a3", "a4"];

/// The issued SD-JWT holds every input claim; a presentation's processed payload equals the RFC's.
#[test]
fn rfc9901_examples() {
    for dir in EXAMPLES {
        let sd_jwt = SdJwt::parse(&issued(dir)).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let full = processed(sd_jwt.claims());
        let input = json_fixture(&format!("{dir}/input.json"));
        for member in input.as_object().unwrap().members() {
            assert_eq!(
                full.get(&member.name),
                Some(&member.value),
                "{dir}: {}",
                member.name
            );
        }

        let stated = compact_fixture(&format!("{dir}/presentation.txt"));
        let (sent, _) = stated.split_at(stated.rfind('~').unwrap() + 1);
        let shown = SdJwt::parse(sent).unwrap_or_else(|e| panic!("{dir}: {e}"));
        let expected = json_fixture(&format!("{dir}/processed.json"));
        assert_eq!(processed(shown.claims()), expected, "{dir}");
    }
}
