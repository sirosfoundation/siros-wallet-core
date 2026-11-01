# zkp_req request vectors: the protocol

One JSON file per case: a rule of `zkp_req`, Sections 1.1, 1.2, 2 and 2.1 (draft 0.1, rulebook
repository commit `e65861c`), or a query that follows them all. The nym_auth catalogue's rules
have their own set in `crates/siros-zkp-req-nym-auth/tests/vectors/request/`. Spec summary:
`docs/zkp_req_request.md`.

```json
{
  "description": "what the case shows",
  "query": { },                  // the Credential Query; or "query_text" for text that is not JSON
  "client_metadata": { },        // or "client_metadata_text"
  "expect": { "valid": { "options": [[0, 1], [0]], "req_sets": true } },
                                 // or { "error": "<code>", "item": n, "option": n }
  "v0_4": "what changed from the v0.4 vector, and why"
}
```

Text that is not JSON reads as `null`. `options` lists each option's `_req` indexes in the
Verifier's order; `req_sets` says whether the query has `_req_sets`. DCQL parses the query
first: a rule of OpenID4VP 1.0, Section 6 has the code of `siros_dcql::QueryError::code`, and a
rule of `zkp_req` that of `siros_zkp_req::RequestRule::code`.

## Provenance

The set ports the matcher's v0.4 planner vectors (`tests/vectors/zkp_req` of
siros-dc-matcher-core at v0.11.0) to the draft, and adds cases for the draft's own rules
(`_req_sets`, `return` syntax). Every ported vector carries the draft's `client_metadata`, since
Section 1.2 requires both lists, and `age_check` takes `range` where v0.4 took `ge` and `le`;
these input migrations apply to every vector. `v0_4` names each further change to an input or an
expectation. Vectors whose subject the draft removed (the `full-date` parameters `ge` and `le`)
are gone: their syntax rules are now the `range` vectors of the catalogue set.
