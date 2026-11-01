# nym_auth vectors

| Path | Cases | Runner |
| :-- | :-- | :-- |
| `request/` | the rules of the nym_auth catalogue 0.5 on top of the protocol's | `tests/request_vectors.rs` |
| `presentation/` | a `ZkpPresentation` in a JSON `vp_token`, against the Verifier's own request | `tests/presentation_vectors.rs` |
| `proof_time.json` | the 20-character `proof_time` and the Verifier's tolerance | `tests/proof_time_vectors.rs` |
| `session.json` | the `SessionTranscript` of both channels and e2 | `tests/known_answers.rs` |
| `pseudonym.json` | `verifier_input` and the `sha-256` pseudonym | `tests/known_answers.rs` |
| `readdit.json` | readdit's values for a credential, a session and a v0.4 presentation | `tests/readdit.rs` |

The rulebook is the nym_auth rulebook repository at commit `e65861c`. `scripts/vectors_digest.sh`
prints the digest of the whole set, with the protocol's request vectors.

## `request/`

The format of `crates/siros-zkp-req/tests/vectors/request/README.md`, with
`"expect": {"valid": {"catalogue": true}}` when the catalogue applies to the query and `false` when
the query asks for another credential type. Error codes are those of
`siros_zkp_req::RequestRule::code` and `siros_zkp_req_nym_auth::catalogue::CatalogueRule::code`.
The set ports the matcher's v0.4 unsatisfiable-request vectors and the planner vectors whose rule
the catalogue now owns; `v0_4` says what changed. The v0.4 rules on `ge`, `le` and the 365-day
span are gone with those parameters.

## `presentation/`

```json
{
  "description": "what the case shows",
  "query": { }, "client_metadata": { },
  "vp_token": { },               // or "vp_token_text" for raw text
  "expect": { "valid": true },   // or { "error": "<code>" }
  "v0_4": "what changed from the v0.4 vector, and why"
}
```

Codes: the `vp_token` reader's (`response_not_object`, `duplicate_member`, `query_id_missing`,
`presentations_not_array`, `presentations_empty`, `presentations_multiple_not_allowed`,
`presentation_not_string`, `presentation_not_base64url`), the CBOR reader's (`cbor_truncated`,
`cbor_trailing_bytes`, `cbor_unsupported`, `cbor_invalid_utf8`, `cbor_duplicate_key`,
`cbor_too_deep`), the presentation's (`presentation_not_map`, `presentation_unknown_member`,
`presentation_member_missing`, `presentation_member_wrong_type`), the steps of Section 4.1
(`system_not_listed`, `backend_not_listed`, `system_not_on_backend`, `req_set_missing`,
`req_set_extra`, `req_set_unknown`, `result_keys`, `result_not_true`), and the system rulebooks'
Section 9 (`request`, `proof_encoding`, `issuer_key_set`, `proof_time`, `results`). The Verifier's
clock, its `trust_anchors` and the proof are not judged here. The set ports v0.11.0's v0.4
response vectors without the BBS-CD cases, since no wallet proves `urn:mms:bbs-cd:nym_auth:v1`
yet, and without the v0.4 orders of checks the draft does not make.

## `session.json`, `pseudonym.json`

Copied from zk-cred-vega `6bc2622`, `test-vectors/nymauth/` (BSD-2-Clause), which shares them
byte for byte with zk-cred-longfellow; an independent Python encoder generated the session
vectors there. Each file names its provenance.

## `readdit.json`

What readdit-demo `1cf3f26` computes with `native/longfellow/nym-longfellow` and
`native/vega/nym-vega`, the reference code of the system rulebooks' Section 10, for a credential of
the test issuer and the redirect session of `CLIENT_ID`, `NONCE` and `RESPONSE_URI`:
`SessionTranscript`, the device's `Sig_structure`, e2, the fields of the mdoc, the issuer key,
`verifier_input` and the pseudonym, and for Longfellow a v0.4 presentation of fixed parts.
`scripts/readdit-differential` regenerates it. readdit has no license, so the repository holds its
computed values only.
