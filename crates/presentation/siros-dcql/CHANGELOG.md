# Changelog

`siros-dcql` is published to [crates.io](https://crates.io/crates/siros-dcql)
and versioned independently of the matcher repository it lives in. This file
records changes to *this crate's* public API.

Pre-1.0, a breaking change bumps the minor version, per
[Cargo's interpretation](https://doc.rust-lang.org/cargo/reference/semver.html)
of [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for 0.1.0 and 0.2.0 are reconstructed from git history, which predates
this file.

## Unreleased

### Changed

- **BREAKING:** `CredentialQuery::id`, `QueryMatch::query_id`, `QueryError::DuplicateCredentialId`
  and `QueryError::DuplicateClaimId::credential` are a `QueryId`: "a non-empty string consisting
  of alphanumeric, underscore (_), or hyphen (-) characters" (§6.1). `DcqlQuery::from_json`
  refuses another id with `QueryError::Id`, which holds the `QueryIdError`; a dotted id is
  refused.
  `QueryError::EmptyCredentialId` is gone: `QueryIdError::Empty` covers it. The version is
  0.12.0.
- **BREAKING:** a query is constructed only by parsing. The fields of `DcqlQuery`,
  `CredentialQuery`, `ClaimsQuery` and `CredentialSetQuery` are private and read through
  accessors of the same names (`credentials()`, `id()`, `format()`, `meta()`, `claims()`,
  `claim_sets()`, `path()`, `values()`, `options()`, `purpose()`); `DcqlQuery::validate` is
  gone. `DcqlQuery::parse` reads a JSON value in one pass, and `Deserialize` runs it. A member
  of the wrong form is `QueryError::Form`, which names the `Member` and its `FormFault`.
- **BREAKING:** the parse refuses an empty `credentials` (`QueryError::Form` with
  `FormFault::Empty`), a `claim_sets` option naming an id no claims query has
  (`QueryError::UnknownClaimId`), a `credential_sets` option naming an id no Credential Query
  has (`QueryError::UnknownCredentialId`), `claim_sets` without claims
  (`QueryError::ClaimSetsWithoutClaims`), a claims `path` that is no claims path pointer
  (`QueryError::ClaimPath` with its `ClaimPathError`), and an `mso_mdoc` claims path other than
  two strings (`QueryError::MdocPath`).
- **BREAKING:** a claims path pointer is a `ClaimPath`, at least one `PathComponent`:
  `ClaimsQuery::path`, `SelectedClaim::path` and `into_path`, `Credential::claim`, `resolve`,
  `resolve_json` and `mdoc_components` take or give one. `PathError::Malformed` is gone;
  `PathError::MdocElement` is the error of §7.2.1, with the code `path_malformed`.
  `PathComponent` has no `Deserialize`; `ClaimPath` deserializes through `ClaimPath::parse`.
- **BREAKING:** `select_claims` gives `Result<Option<Vec<SelectedClaim>>, PathError>`: a
  claims path processing error other than an empty selection is an error. With `claim_sets`,
  the next option is tried, and the first error is given when no option is satisfied.
  `execute` keeps such a credential out of the candidates and records it in
  `QueryMatch::refusals`, a `ClaimPathRefusal` each.
- **BREAKING:** `CredentialQuery::claim_sets` gives the `ClaimOption`s, each with the `ids()`
  and the `claims()` it names.
- **BREAKING:** the parse enforces the rest of §6. It refuses a Credential Query without `meta`
  (REQUIRED, §6.1; `QueryError::Form` with `FormFault::Absent`), and `CredentialQuery::meta`
  gives the object as sent. It refuses an empty `claims`, `claim_sets` (§6.1), `credential_sets`
  (§6), `options` (§6.2) or `values` (§6.3), each `FormFault::Empty`; a `values` element other
  than a string, an integer or a boolean (§6.3, `FormFault::Entry` with its `Position`); and a
  claims query without `id` in a Credential Query with `claim_sets` (§6.3, `FormFault::Absent`
  of `ClaimMember::Id`). An absent `claims` asks for no claim; an empty one is refused. A
  `credential_sets` option that is an empty array is `FormFault::Entry` of
  `SetMember::Options` (§6.2). `null` is a member of the wrong JSON type wherever §6 defines
  one (`FormFault::WrongType`, `TrustedAuthorityError::NotArray`); `CredentialSetQuery::purpose`
  gives the `purpose` as sent, `null` included, since §6.2 defines no such member.
- **BREAKING:** `DcqlQuery::parse` refuses with a `QueryError`, which is `Clone`, `Eq` and
  `Hash`; `DcqlQuery::from_json` refuses with a `QueryTextError`: the serde_json error of text
  that is no JSON, or the `QueryError` of its value. `QueryError::Json` is gone.
- The text values (`CredentialFormat`, `CredentialRef`, `DocType`, `Vct`, `AuthorityType`,
  `AuthorityValue`) implement `Borrow<str>`, for map lookups by text.
- **BREAKING:** `trusted_authorities` parses into `TrustedAuthorities`: a non-empty array of
  `TrustedAuthority`, each an `AuthorityType` and a non-empty list of `AuthorityValue`s
  (§6.1.1). A malformed one is `QueryError::TrustedAuthorities` with its
  `TrustedAuthorityError`; `null` is `NotArray`. An entry's `type` is absent
  (`TypeAbsent`) or no string (`TypeNotString`); its `values` is absent (`ValuesAbsent`), no
  array (`ValuesNotArray`), empty (`ValuesEmpty`), or holds a non-string at a `Position`
  (`ValueNotString`). `TrustedAuthorities` has no `Deserialize`.
- **BREAKING:** a claims query id, and an id a `claim_sets` option names, is a `ClaimId` (§6.3);
  another is `QueryError::ClaimId`. A `credential_sets` option names `QueryId`s; another id is
  `QueryError::Id`. `QueryError::DuplicateClaimId::claim` is a `ClaimId`.
- **BREAKING:** `multiple`, `require_cryptographic_holder_binding` and `required` read as
  `CredentialQuery::multiplicity()` (`Multiplicity`), `holder_binding()` (`HolderBinding`) and
  `CredentialSetQuery::requirement()` (`SetRequirement`); the format is a `CredentialFormat`.
- **BREAKING:** `Credential::has_cryptographic_holder_binding` is `Credential::binding`, a
  `CryptographicBinding`.
- **BREAKING:** the results of `execute` keep their fields private, read through accessors:
  `QueryResult::matches()`, `satisfaction()` (a `Satisfaction`), `credential_sets()`;
  `QueryMatch::query_id()`, `candidates()`, `multiplicity()`; `Candidate::credential_id()`,
  `claims()`; `SelectedClaim::claim_id()` (a `ClaimId`), `path()`, `into_path()`;
  `Combinations::combinations()`, `dropped()`; `Combination::members()` (keyed by `QueryId`),
  `purposes()`.
- **BREAKING:** `PathError::TypeMismatch::at` is a `ComponentIndex`.
- **BREAKING:** `Credential::id` gives a `CredentialRef` and `Credential::format` a
  `CredentialFormat`; `Candidate::credential_id` is a `CredentialRef`.
- Every error has a stable code, which its `Display` writes. The parse finds a repeated id, and
  resolves the ids a `claim_sets` or `credential_sets` option names, with rustc-hash's
  `FxHashMap`.
- `QueryResult::combinations` walks the candidates of each query as an odometer, the first
  query turning fastest: the order of the combinations is unchanged.
- The crate depends on `rustc-hash`, `serde`, `serde_json` and `thiserror` only.
- Every error type derives `Display` and `Error` with `thiserror`, a new dependency, and keeps
  its text: `PathError`, `QueryIdError`, `ClaimIdError`, `ClaimPathError`,
  `TrustedAuthorityError`, `QueryError` and `QueryTextError`. `FormFault` and
  `ClaimPathRefusal` implement `Error`, with the first sentence of their documentation as text.
  `QueryError::Form` returns its `FormFault` from `source()`, and `ClaimPathRefusal` its
  `PathError`. `QueryTextError::Query` is transparent: its text and source are its
  `QueryError`'s.
- The error texts now print the value they name: `FormFault::Entry`, `ClaimPathRefusal`, and
  `QueryError`'s `DuplicateClaimId`, `ClaimPath`, `UnknownClaimId` and `MdocPath`.

### Added

- `QueryId`, `QueryIdError` and `QueryError::Id`.
- `CredentialQuery::parse`, the Credential Query of a JSON value alone, its errors naming it at
  position 0; and `CredentialQuery::extension`, a member §6.1 leaves undefined, as sent, for
  the profile of the query's format, such as `zkp_req`'s `_req`. A Credential Query serializes
  with its extension members.
- `ClaimId`, `ClaimIdError`, `AuthorityType`, `AuthorityValue`, `TrustedAuthority`,
  `TrustedAuthorities`, `TrustedAuthorityError`, `CredentialFormat`, `Multiplicity`,
  `HolderBinding`, `SetRequirement`, `CryptographicBinding`, `Satisfaction`, `ComponentIndex`,
  `QueryError::code` and `select_claims` at the crate root.
- `CredentialRef`, `DocType` and `Vct`, the text values a held credential and `meta` carry.
- `QueryTextError`, `ClaimPath`, `ClaimPathError`, `ClaimOption`, `ClaimPathRefusal`,
  `Position`, `Member`, `CredentialMember`, `ClaimMember`, `SetMember`, `FormFault`, and
  `QueryError::Form`, `ClaimPath`, `UnknownClaimId`, `UnknownCredentialId`,
  `ClaimSetsWithoutClaims` and `MdocPath`.
- `resolve`, the §7.1.1 processing over any claim tree that implements `ClaimNode` (with
  `Lookup`); `resolve_json` runs on it. `PathError::code`.
- `PathError` implements `std::error::Error`.

### Fixed

- The crate hashes with `rustc-hash`, whose hasher takes no seed: a `wasm32-wasip1` build runs on
  a host that lacks WASI `random_get`.

## 0.11.0 — 2026-10-20

No change to this crate: version bump only, to stay in step with the workspace
(matcher release v0.11.0). There is nothing to migrate.

## 0.10.0 — 2026-10-15

No change to this crate: version bump only, to stay in step with the workspace
(matcher release v0.10.0). There is nothing to migrate.

## 0.9.1 — 2026-10-15

No change to this crate: version bump only, to stay in step with the workspace
(matcher release v0.9.1). There is nothing to migrate.

## 0.9.0 — 2026-10-14

No API change. The version is aligned with the matcher release (v0.9.0), which
it ships with; there is nothing to migrate.

## 0.3.0 — 2026-09-19

This release contains breaking changes, which pre-1.0 means a minor version
bump. They are listed under *Changed* below; every caller of
`DcqlQuery::from_json` is affected.

### Added

- `CredentialSetQuery::purpose` (§6.2) — why the verifier wants a combination,
  as a `Value`, because the spec permits a string, an integer or an object.
- `Combination::purposes`, carrying the reasons of the credential sets a
  combination satisfies. Held per combination rather than only on the query,
  because a request with several sets offers several combinations and the
  reason shown beside one belongs to *its* set.
- `DcqlQuery::validate`, and `QueryError` describing why a query is unusable.
- `Credential::has_cryptographic_holder_binding`, and `QueryMatch::multiple`.
- `Dropped`, with `count`, `is_exact` and `any`.

### Changed

- **Breaking.** `DcqlQuery::from_json` now returns `Result<Self, QueryError>`
  rather than `Result<Self, serde_json::Error>`, and validates identifiers on
  the way through. Validation is on the parse path rather than beside it so a
  caller cannot hold a query whose ids are ambiguous. `QueryError::Json` wraps
  what the old signature returned, and `QueryError` implements `Display` and
  `std::error::Error`, so a caller that only formatted the error needs no
  change.
- **Breaking.** `Combination` and `QueryMatch` each gained a field, so neither
  can be constructed with a struct literal from outside the crate.
- **Breaking.** `Combinations::dropped` is a `Dropped` rather than a `usize`.
  A caller wanting the old value calls `count()` on it — and should check
  `is_exact()` before showing it to anyone.
- **Breaking.** `Credential` gained a required method,
  `has_cryptographic_holder_binding`, deliberately without a default. A blanket
  `true` would let an implementor who never considered the question assert a
  security property on their credentials' behalf, and the failure mode is a
  verifier being handed exactly what it said it would not accept.

### Fixed

- `require_cryptographic_holder_binding` (§6.1) is enforced. It was parsed and
  never read, so a verifier that required holder binding — which is the
  *default*, so also every verifier that said nothing — was offered unbound
  credentials regardless. Checked before format and claims, because an unbound
  credential is disqualified rather than a weaker match.
- `multiple` (§6.1) is evaluated. A query that sets it is now answered by every
  matching credential at once, rather than the flag being parsed and ignored.
  This is the reading under which it does anything: "multiple Credentials can
  be returned for this Credential Query". It also collapses the combination
  count where enumerating each credential as its own alternative would multiply
  it. `multiple: false` — the default — is unchanged and still yields at most
  one credential per query, as §6.4 requires.
- `Combinations::dropped` no longer reports a precise-looking figure it cannot
  know. The combination count is a product of the per-query widths, and once
  that product overflows `usize` the number not built is unknowable; the old
  code returned `total - take` over a saturated total, so a request with enough
  candidates reported 18446744073709551551 combinations dropped. The value was
  a true lower bound, but nothing said so, and a figure that precise gets
  believed. `Dropped` now distinguishes `Exact` from `AtLeast`, so a caller
  cannot read the number without meeting the question.
- Duplicate identifiers are rejected instead of resolving to whichever came
  first. §6.1 requires a credential query `id` to be unique across the query
  and §6.3 requires a claims `id` to be unique within its array; without the
  check, a reference from `credential_sets` or `claim_sets` to a duplicated id
  named two different things and answered one, silently dropping the other. An
  empty credential query `id` is rejected for the same reason.

  The character restrictions §6.1 and §6.3 also place on an `id` are
  deliberately *not* enforced: they carry no meaning for matching, and failing
  a request over a dot in an identifier would reject a request that is
  perfectly well understood.

## 0.2.0 — 2026-08-30

### Added

- `QueryResult::combinations(limit)`, enumerating the ways a wallet can satisfy
  a request as sets of credentials presented *together* — what a picker offers
  as one selectable option.
- `Combination` and `Combinations`. The combination count is a product of the
  per-query candidate counts, so it is bounded by `limit` and computed by index
  arithmetic rather than by building the full product and discarding most of
  it. What is not built is reported in `Combinations::dropped` rather than
  silently omitted.
- `QueryResult::credential_sets`, so combinations can be enumerated from a
  result without also passing the query it came from.

## 0.1.0 — 2026-08-30

First release.

### Added

- The DCQL query model (OpenID4VP 1.0 §6): `DcqlQuery`, `CredentialQuery`,
  `ClaimsQuery`, `CredentialSetQuery`, faithful to the wire format, ignoring
  unknown properties as §6 instructs.
- Claims path pointers (§7): `PathComponent` and resolution against a
  credential, iteratively, so path depth cannot exhaust the stack.
- `execute`, applying §6.4 selection: a credential that cannot deliver every
  requested claim is not a match, and an absent `credential_sets` means every
  query must be satisfied rather than none.
- The `Credential` and `Policy` traits. `Policy` exists because §6.1 defines
  `meta` per credential format, so a generic engine cannot interpret it;
  `ExactFormat` covers the standalone case.
- `select_claims`, honouring `claims`, `claim_sets` and `values` exactly,
  including the type-strict comparison §6.3 requires.
