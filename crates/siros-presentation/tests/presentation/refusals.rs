//! A4 and A5: a selection parses only against the plan it was made on, and the signatures only
//! against the `Sign` effects they answer, each under the key its effect names.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::Signature;
use serde_json::json;
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_codec::signature::Es256Signature;
use siros_presentation::{
    AdditionIndex, DigestError, Fulfilment, OfferIndex, PlanDigest, PresentationError, Selection,
    Sign, SignId, SignatureError,
};
use siros_zkp_req_nym_auth::testing::{self, TestProver};

use crate::verifier::{b64, redirect_unsigned, Rng, NONCE, STATE};
use crate::wallet::{mdoc, ready, sd_jwt, sign_all, Held, Wallet, MDL, MDL_NS, VCT};

#[test]
fn selections_and_signatures_parse_against_the_plan() {
    let wallet = Wallet::new(vec![
        Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        ),
        Held::new(
            2,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
        ),
    ]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": NONCE,
        "state": STATE,
        "dcql_query": {
            "credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                 "claims": [{"path": ["given_name"]}]},
                {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
                 "claims": [{"path": [MDL_NS, "family_name"]}]}
            ],
            "credential_sets": [
                {"options": [["pid"]]},
                {"options": [["mdl"]], "required": false}
            ]
        }
    }));
    let input = wallet.input(&request);
    let planned = ready(&input).unwrap();
    let digest = planned.view().digest().to_string();
    let set = planned.view().offers()[0].additions()[0].set();
    let other = b64(&[0; 32]);

    // A4: (case, digest, offer, additions, refusal)
    type Case<'d> = (
        &'d str,
        &'d str,
        usize,
        Vec<usize>,
        Option<PresentationError>,
    );
    let selections: [Case<'_>; 7] = [
        ("the plan's offer and addition", &digest, 0, vec![0], None),
        (
            "a digest not of base64url",
            "AA=A",
            0,
            vec![],
            Some(PresentationError::Digest(DigestError::Encoding(
                base64url::decode("AA=A").unwrap_err(),
            ))),
        ),
        (
            "a digest not of 32 bytes",
            "AAAA",
            0,
            vec![],
            Some(PresentationError::Digest(DigestError::Length(3))),
        ),
        (
            "another plan",
            &other,
            0,
            vec![],
            Some(PresentationError::DigestMismatch),
        ),
        (
            "an unknown offer",
            &digest,
            1,
            vec![],
            Some(PresentationError::OfferUnknown(OfferIndex::new(1))),
        ),
        (
            "an unknown addition",
            &digest,
            0,
            vec![1],
            Some(PresentationError::AdditionUnknown(AdditionIndex::new(1))),
        ),
        (
            "an addition twice",
            &digest,
            0,
            vec![0, 0],
            Some(PresentationError::AdditionSetRepeated(set)),
        ),
    ];
    for (case, digest, offer, additions, refusal) in selections {
        let additions = additions.into_iter().map(AdditionIndex::new).collect();
        let chosen = PlanDigest::parse(digest)
            .map_err(PresentationError::from)
            .and_then(|digest| {
                let selection =
                    Selection::new(digest, OfferIndex::new(offer), additions, Vec::new());
                planned.choose(&selection, Fulfilment::WalletUi).map(drop)
            });
        assert_eq!(chosen.err(), refusal, "{case}");
    }

    // A5: (case, the signatures from the honest ones, refusal); the first effect is 0, the
    // second 1.
    type Edit = fn(&[Sign], &mut Vec<(SignId, Es256Signature)>);
    let first = SignId::new(0);
    let signatures: [(&str, Edit, Option<SignatureError>); 5] = [
        ("every signature once", |_, _| {}, None),
        (
            "the second missing",
            |_, s| s.truncate(1),
            Some(SignatureError::Missing(SignId::new(1))),
        ),
        (
            "the first twice",
            |_, s| s.push(s[0]),
            Some(SignatureError::Repeated(first)),
        ),
        (
            "one of no effect",
            |_, s| s.push((SignId::new(2), s[0].1)),
            Some(SignatureError::Unknown(SignId::new(2))),
        ),
        (
            "the first under another key",
            |signs, s| {
                let other: Signature = testing::key(0x55).sign(signs[0].input());
                s[0].1 = Es256Signature::new(other.to_bytes().into());
            },
            Some(SignatureError::Invalid(first)),
        ),
    ];
    let parsed = PlanDigest::parse(&digest).unwrap();
    for (case, edit, refusal) in signatures {
        let selection = Selection::new(
            parsed,
            OfferIndex::new(0),
            vec![AdditionIndex::new(0)],
            Vec::new(),
        );
        let chosen = planned.choose(&selection, Fulfilment::WalletUi).unwrap();
        let mut rng = Rng(3);
        let prepared = chosen.prepare(&mut rng).unwrap();
        assert_eq!(
            prepared.signs().len(),
            2,
            "the KB-JWT and the DeviceAuthentication"
        );
        let mut signed = sign_all(prepared.signs());
        edit(prepared.signs(), &mut signed);
        let response = prepared.finish(signed, &TestProver { fail: None }, &mut rng);
        assert_eq!(
            response.err(),
            refusal.map(PresentationError::Signature),
            "{case}"
        );
    }
}
