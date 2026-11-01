# `zkp_req` requests

The request side of the `zkp_req` draft 0.1 and the nym_auth catalogue 0.5 (rulebook repository,
commit `e65861c`). Code: `crates/siros-zkp-req` (the protocol) and `crates/siros-zkp-req-nym-auth`
(the catalogue). Vectors: `crates/siros-zkp-req/tests/vectors/request/` and
`crates/siros-zkp-req-nym-auth/tests/vectors/request/`.

```json
{ "id": "nym_attestation", "format": "zkp_req",
  "meta": { "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" },
  "_req": [
    { "fn_id": "pseudonym", "return": "nym",
      "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } },
    { "fn_id": "age_check", "params": { "range": "13-17" } } ],
  "_req_sets": [ [0, 1], [0] ] }
```

The Verifier's `client_metadata.vp_formats_supported.zkp_req` holds `proof_backend_values` and
`system_id_values`, both required and non-empty (Section 1.2).

## The protocol's rules (`zkp_req`, Sections 1.1, 1.2, 2, 2.1)

`siros-dcql` parses the Credential Query first and refuses what OpenID4VP 1.0, Section 6 forbids,
with its own codes (`dcql_malformed`, `query_id_empty`, `claim_sets_without_claims`, …): a query
that is no object, an `id` outside Section 6.1, an absent or non-object `meta`, a member of DCQL's
of the wrong type. `ZkpReqQuery::parse` reads the `CredentialQuery` DCQL gives; `_req` and
`_req_sets` are its extension members. Each rule below makes the request invalid
(`invalid_request`). Codes:

| Code | Rule |
| :-- | :-- |
| `format_not_zkp_req` | `format` is `zkp_req` |
| `claims_present` | `claims` is absent, and with it `claim_sets` |
| `source_format_invalid`, `type_value_invalid` | `meta` has `source_format` and the type member DCQL defines for it |
| `req_invalid`, `item_not_object`, `item_member_unknown` | `_req` is a non-empty array of objects with only `fn_id`, `params` and `return` |
| `fn_id_invalid`, `params_not_object` | `fn_id` is a non-empty string, `params` an object |
| `return_invalid`, `return_repeated` | `return` is ASCII letters, digits, `_` and `-`, unique in the query |
| `req_sets_invalid`, `option_invalid` | `_req_sets` is a non-empty array of non-empty arrays of `_req` indexes, each once |
| `formats_missing`, `proof_backend_values_invalid`, `system_id_values_invalid` | the Verifier sends both lists |

`trusted_authorities` follows OpenID4VP 1.0, Section 6.1.1: `siros-dcql` parses it with the
query, and `siros-trust` resolves it against the credential's issuer chain and the trust store.
An issuer it does not admit matches nothing; a malformed `aki` value makes the request invalid.

## The nym_auth catalogue's rules

| Code | Rule |
| :-- | :-- |
| `schema_id_invalid` | a `bbs_cd` query has a string `schema_id_value` |
| `holder_binding_waived` | `require_cryptographic_holder_binding` is absent or `true` |
| `function_unknown`, `param_unknown` | `fn_id` is `pseudonym` or `age_check`, with only their parameters |
| `pseudonym_return_missing` | `pseudonym` has a `return` |
| `config_invalid`, `ver_invalid`, `prf_invalid` | `config` is a configuration, `ver` is 1, `prf` is defined for the source format and configuration |
| `verifier_context_invalid` | `verifier_context` is present exactly for `account-recovery-ssc`, 1 to 64 bytes |
| `range_syntax`, `range_inverted` | `range` is `A-B`, `A+` or `B-`, ages of ASCII digits, A at most B |
| `pseudonym_repeated`, `age_check_repeated` | an option holds at most one of each |

A query of another credential type is valid: the catalogue does not apply, and no nym_auth
credential matches it.

## Choosing a system (`zkp_req`, Section 1.3)

For each option in the Verifier's order, a system and a proof backend form a usable pair when the
Verifier lists both, the system runs on the backend, proves over the query's type, and supports the
option's functions and parameter values. The system rulebooks' Section 2 says what each supports:
the Longfellow and Vega systems need a `pseudonym` item with `known-offender-matching-ssc` and
`sha-256`, and E and C from 0000-01-01 to 9999-12-31. When no option has a usable pair, the Wallet
sends `vp_formats_not_supported`.

The picker reads the systems the registration names, the nym_auth systems whose circuits the
wallet loaded, in its order of preference. The FFI matching reads a registered circuit as a
system: its `system_id` param is the system, its `system` the proof backend, and its
`capabilities` (or `functions` and `credential_type`) say what it supports.

## Non-disclosure

`ssc`, `psc`, `secret_seed` and `birth_date` of a nym_auth attestation
(`eu.europa.ec.eudi.nym_auth.1`, `eu.europa.ec.eudi.nym_auth.bbs.1`) are never disclosed. A request
through any format other than `zkp_req` that names one of them, uses a wildcard path, or has no
`claims` at all does not match that attestation. `birth_date` of any other credential is an
ordinary claim.
