# Implementation Plan: Rust WMP Engine as a Separate Repository

Nov 1, 2026. Companion to the specification document ([`engine-spec.md`](engine-spec.md), exported from the artifact of Oct 28). This plan adds what the spec leaves open on purpose: where the code lives, how the repository is bootstrapped, and in what order the work runs. It follows the conventions of the sibling repos in the SIROS workspace (verified against `siros-verifier-core`, `siros-wscd-manager`, `siros-dc-matcher`, `wmp`, `go-wmp` and `sirosfoundation/.github`).

## 1. State of the start condition

The spec gates the spike on go-wmp **v0.12.0** and the rework of go-wallet-backend **PR 163** landing in the current Go engine. Status as of Nov 1, 2026: go-wmp has shipped **v0.13.0** (v0.12.0, v0.12.1 and v0.13.0 are all tagged), so the go-wmp half of the gate is **met** — and the spec's own text ("v0.11.0 released, v0.12.0 in progress") is already stale and gets refreshed in P0.3. The PR 163 rework is merged on go-wallet-backend's `integration/wmp-test` branch but has **not reached `main`**; that landing is the trigger. Therefore:

- Everything in **Phase 0** below (library evaluation, spec verification, repository scaffolding, UniFFI async smoke test, vector schema) can start now. None of it needs a Go change.
- The spike proper (S0 slice, vector generation from Go) starts when the PR 163 rework lands on `main`. Vectors generated earlier would be generated from a moving reference, which the spec forbids.
- When the gate opens, the generator pins go-wallet-backend `main` + go-wmp **v0.13.0**, not the v0.12.0 the spec names. Reference-table verification (P0.6) must use current checkouts — local ones may be behind (the local go-wmp clone was 134 commits behind at the time of writing).

## 2. Repositories

### 2.1 Main workspace repo

| Item | Decision | Notes |
| --- | --- | --- |
| GitHub repo | **`sirosfoundation/siros-wallet-core`** | Decided by the owner, 2026-11-01. Also hosts the presentation-side wallet core ported from the closed dc-matcher PRs #54/#55 (see §11); the engine crates join it in the same workspace. |
| Local path | `/home/leifj/work/siros.org/siros-wallet-core` | Exists; scaffolded and green (P0.2 done). |
| Remote | `git@github.com:sirosfoundation/siros-wallet-core.git` | Git over SSH only, per the standing rules. |
| License | BSD-2-Clause, `Copyright (c) 2026, SIROS Foundation` | Same as every repo in the org. `license = "BSD-2-Clause"`, `authors = ["SIROS Foundation"]` in `workspace.package`. |
| Visibility | To match the other repos (currently public); confirm with the owner at creation time. |  |

### 2.2 Companion vectors repo

- `sirosfoundation/engine-vectors` (name per the spec's own example), local path `/home/leifj/work/siros.org/engine-vectors`.
- Language-neutral, owned by neither engine, following the `wmp` repo's pattern: a `vectors/` directory, a `vector-schema.json` (JSON Schema 2020-12), and a documented runner contract. WMP wire vectors stay in the `wmp` repo; this repo holds engine-level HTTP/host transcripts.
- Both runners (Go, Rust) load a sibling checkout with a CI fallback checkout, exactly as the `wmp` vectors are consumed today.

### 2.3 Repos this work must not touch

- `go-wallet-backend`: the Phase A generator is **test-only** (`test/vectorgen`). Any engine bug found becomes an issue, not a production patch.
- `go-wmp`, `wmp`, `wmp-js`: consumed as references only, through their published vectors.

## 3. Workspace layout

Cargo workspace, `resolver = "2"`, `edition = "2021"`, `rust-toolchain.toml` pinned like `siros-verifier-core` (stable + rustfmt + clippy). `#![forbid(unsafe_code)]` in core and runtime crates.

```
siros-wallet-engine/
├── Cargo.toml                 # workspace: crates/* (model: siros-dc-matcher)
├── deny.toml                  # cargo-deny, from day one
├── rust-toolchain.toml
├── LICENSE                    # BSD-2-Clause, SIROS Foundation
├── Makefile                   # bindings / ios / xcframework / android / aar (from siros-wscd-manager)
├── uniffi-bindgen.rs
├── README.md
├── AGENTS.md                  # org convention (see siros-verifier-core): scope, invariants, read-first, build/test recipe
├── docs/
│   ├── engine-spec.md         # the specification document, corrected as tables are verified (authoritative copy)
│   ├── DEPENDENCIES.md        # published list of direct deps with the reason for each (spec requirement)
│   └── RELEASING.md           # only when first release approaches; copy the siros-verifier-core model
├── scripts/
│   ├── audit.sh               # cargo audit + cargo deny (from siros-verifier-core)
│   ├── mutate.py              # mutation anchors for security checks (from siros-verifier-core)
│   └── repro.sh               # two-clean-builds byte-identical check (musl static)
├── fuzz/                      # cargo-fuzz targets for offer/request parsing and metadata decoding
├── .github/workflows/         # ci.yml; docker-build-push + sbom via org reusable workflows
└── crates/
    ├── siros-codec/           # the presentation core, ported from dc-matcher #54/#55 (Nov 1):
    ├── siros-dcql/            #   codec, dcql, sdjwt, mdoc, oid4vp, trust, wallet-state, credential,
    ├── siros-sdjwt/           #   display, transaction-data, zkp-req, zkp-req-nym-auth, presentation —
    ├── siros-mdoc/            #   with docs/wallet-core-architecture.md as their contract
    ├── siros-oid4vp/
    ├── siros-trust/
    ├── siros-wallet-state/
    ├── siros-credential/
    ├── siros-display/
    ├── siros-transaction-data/
    ├── siros-zkp-req/
    ├── siros-zkp-req-nym-auth/
    ├── siros-presentation/
    ├── wmp-core/              # engine stubs until the spike opens (S0):
    ├── engine-ports/          #   ports, core, adapters, conformance
    ├── engine-core/
    ├── engine-adapter-sdk/
    ├── engine-adapter-server/
    └── engine-conformance/
```

Notes on crate names: keep the spec's logical names as workspace member names. Decide crates.io-publishable names (`siros-wmp-core`, etc.) before any release; the spike needs no registry names since org cross-deps are git-rev pinned (`siros-verifier-core` pins `siros-dc-matcher-core` by rev). `wmp-core` is the one crate meant to outgrow this workspace (the shared base of the native WMP clients — spec open question 7); if it becomes a separate work stream it moves to its own repo later, unchanged.

## 4. Conventions to inherit, not reinvent

1. **Verification stack from `siros-verifier-core`:** `jose-rs` 0.10 + `kryptering` 0.7 (rustcrypto provider, `default-features = false`), RustCrypto crates, `zeroize`, `thiserror`, `url`. The spec's library evaluation (Kushal Das crates) has a live in-org reference implementation — evaluate against what `siros-verifier-core` already learned, not from READMEs alone.
2. **UniFFI pattern from `siros-wscd-manager`:** `crate-type = ["lib","cdylib","staticlib"]`, `uniffi-bindgen.rs` + `bindgen` feature, Makefile targets for Swift/Kotlin/XCFramework/AAR, `async-trait` ports with tokio on native.
3. **Security-test pattern from `siros-verifier-core`:** `scripts/mutate.py` disables each security check and requires a test to fail; CI fails on missing anchors and surviving mutants. This is the org's enforcement of the spec's rule that every test must be shown to fail when its fix is reverted.
4. **CI from `sirosfoundation/.github`:** `cargo fmt --check`, `clippy --workspace --all-targets --all-features -D warnings`, `cargo test --workspace`, `scripts/audit.sh`, `scripts/mutate.py`; Docker image and SBOM via the reusable `docker-build-push.yml` and `sbom.yml` workflows; `workflow-templates/conformance.yml` exists for Phase B.
5. **Standing rules from the spec:** SSH only; signed commits; no force-push; no merges, tags or publishes without the owner's go; every review finding fixed including its whole class; report full URLs.

## 5. Phase 0 — start now (no Go dependency)

Status after the first working session (2026-11-01): **P0.1, P0.2, P0.3 and P0.9 are done.** The repo exists — this repository — local path `/home/leifj/work/siros.org/siros-wallet-core`, first commit signed and pushed to `main`. The presentation core (13 crates, the architecture contract, the zkp_req specs, the proving workspace) is ported and green: fmt, clippy `-D warnings`, panic-site check and all 32 test suites on the pinned toolchain 1.99.1. The engine crates exist as stubs. Remaining in Phase 0: P0.4 (the UniFFI head-to-head), P0.5 (library evaluation, now including the ported crates), P0.6 (verify the spec's reference tables), P0.7/P0.8 (the vectors repo).

| # | Task | Output |
| --- | --- | --- |
| P0.1 | Confirm repo names, crate names, visibility (owner decision) | **Done 2026-11-01**: `sirosfoundation/siros-wallet-core`, created private; engine crate names as in the spec |
| P0.2 | Create both repos, scaffold the workspace exactly as §3; wire CI; empty AGENTS.md | **Done 2026-11-01**: workspace + CI (test/fmt/clippy/msrv/proving/browser) + AGENTS.md/README/CHANGELOG/deny.toml/Makefile; the `engine-vectors` repo is still to create (P0.7) |
| P0.3 | Move the spec into `docs/engine-spec.md` as the authoritative copy | **Done 2026-11-01**: in the first commit of the new repo |
| P0.4 | **UniFFI async smoke test, day one** (moved up from "measurements" per the review): a minimal async `HttpClient`/`Host` callback over UniFFI, JVM and Swift, plus the wasm32 check that `wscd-manager` needed | Go/no-go on the async-ports design **before** S0 is built on it; if it fails, switch to the sans-I/O state-machine core and rewrite the affected spec sections |
| P0.5 | Library evaluation write-up (jose-rs, kryptering, grindvakt) against the spec's question list, cross-checked with `siros-verifier-core`'s existing usage and its `docs/RELEASING.md` dependency rules | `docs/DEPENDENCIES.md` draft; gaps recorded for the spike report |
| P0.6 | Verify the spec's behavioural reference tables against `go-wallet-backend` code (the spec's own first task); correct `docs/engine-spec.md`; enumerate the OIDF wallet plans and write the plan mapping into the spec (Phase B §"Which plans") | Corrections PR per repo finding; issues in `go-wallet-backend` where Go is wrong (no patches) |
| P0.7 | `engine-vectors` schema: `vector-schema.json` with `id`, `provenance` (`spec`/`oidf`/`policy`/`go-observed`), `generator {repo, commit, date}`, `review_by`, `spec_refs`, `config`, `setup`, `script` (steps: `wmp_in`/`wmp_out`/`http_out`/`host_ask`/`must_refuse`) — modeled on `wmp/vectors/vector-schema.json` | Schema + runner contract doc |
| P0.8 | Write the Phase A generator **design** (test-only `test/vectorgen` in go-wallet-backend) so it can land the day the gate opens | Design note in the vectors repo |
| P0.9 | Salvage from the closed wallet-core PRs (dc-matcher #54/#55, see §11): extract `docs/wallet-core-architecture.md` from the `wallet-core/phase-2` branch into `docs/presentation-core-reference.md`; inventory the format crates for reuse; decide the engine/wallet-core boundary in writing | **Done 2026-11-01, superseded by the better outcome**: the 13 crates, the contract (as `docs/wallet-core-architecture.md`, now authoritative in its home repo), the zkp_req docs and the `proving/` workspace were ported into `siros-wallet-core` outright; the boundary is written into its README and AGENTS.md |

Phase 0 needs no more than a small constant of days and is the only work that should be AI-pushed without the Go reference being still.

## 6. Spike S0–S4 (gated on the PR 163 rework reaching go-wallet-backend `main`; go-wmp v0.13.0 has already shipped)

Sequence, slice content and acceptance criteria are as specified in the spec document (§"Spike scope"); this plan adds the repository mechanics per step:

- **One PR per step, S0→S3**, plus the parallel server-adapter track. Each PR: vectors from `engine-vectors` running green in CI, `mutate.py` anchors for any new security check, and the divergence table updated.
- **S0:** port traits, in-memory fakes, vector runner, minimal `wmp-core`, the second non-OpenID4 flow (minimal MCP integration flow — confirm with the owner which one; keep it trivial). Acceptance includes: the second flow registers with **zero** changes to the runtime crate, and the UniFFI smoke test from P0.4 is wired into CI.
- **S1:** offer parsing, issuer + AS metadata resolution. The serde-vs-Go decoding decisions are recorded per document type in the vectors. Includes the blind-encryption seam decision (see §8, D2) before S2 starts.
- **S2:** pre-authorized-code issuance end to end; DPoP/attestation if the gdc issuer requires them.
- **S3:** trust via `BackendProxy`, fail closed; live gdc run recorded.
- **S4 (stretch):** authorization code with PAR/PKCE, or a basic OID4VP `direct_post`.
- **Report:** measurements exactly as the spec lists them (lines vs Go, time per step, divergence table, binary sizes, `cargo tree` counts, two-clean-builds reproducibility, crypto crate list). Ends with go/no-go on the full port.

## 7. Phase B (post-spike, outline only)

As specified: OIDF conformance suite in Docker (pinned release), headless wallet driver in `engine-conformance`, Go baseline first then Rust, promote vectors to `oidf` provenance, hard sunset of `go-observed`, nightly + on-demand CI using the org's conformance workflow template. B1 closes the go-observed era for good.

## 8. Amendments from the artifact review, baked into this plan

These correct the spec where the review found issues; each becomes a PR against `docs/engine-spec.md` in P0.3:

- **D1 — UniFFI smoke test moved to day one** (P0.4). It gates the whole design; it is not a measurement.
- **D2 — Blind-encryption seam decision before S2.** The `Host` trait as sketched has sign/consent but no client-crypto sub-flows, while the Go engine has the *client* decrypt issuance responses and build the encrypted VP response (PRs 469/471). Either add `request_decrypt`/`request_encrypt` sub-flows (or a generic crypto sub-flow) to `Host`, or state that in encrypted modes the core treats payloads as opaque and S2 exercises transport, not decryption. Unresolved, S2 proves the wrong seam for the container/TEE deployment.
- **D3 — go-observed vectors assert `purpose` as inferred, not observed.** The Go generator cannot see `FetchPurpose`; purpose/limit assertions become hard requirements only on `spec`/`oidf` vectors. Recorded in the vector schema (P0.7).
- **D4 — Cancellation in the ports.** A flow-abort/timeout interface and ephemeral-key cleanup (per-flow DPoP keys) must be specified before the runtime is written; add it to the S0 port set.
- **D5 — `wmp-core` is driven from `wmp/vectors/*.json`, never from go-wmp source**, same referee-substitution principle as Phase B.
- **D6 — Pre-register the size gate.** Define "reasonable multiple of the Go size" numerically before the spike starts (suggestion: ≤1.5× non-test lines for the ported areas; owner to fix the number in P0.1).
- **D7 — `AuthzenDirect` ships only when the PDP both authenticates (go-tokenauth JWTs) and enforces an SPOCP-equivalent query gate.** Not spike work; write the precondition into the spec now.
- **D8 — Sans-I/O is co-equal, not fallback (from §11).** The P0.4 smoke test compares both shapes head-to-head and the spike report weighs the wallet-core precedent before the async-ports default is confirmed.

## 9. Open items for the owner (blocking P0 only)

1. Repo and crate names, and repo visibility (P0.1–P0.2).
2. The size-multiple number for the gate (D6).
3. Which minimal MCP flow plays the S0 second-flow role (the spec says "confirm which minimal MCP flow is meant").
4. Spec open questions 1, 6 and 7 (code location is settled by this plan, but the owner should ratify it; decoding policy; wmp-core ownership).

Everything else (PDP token details, TEE platform, OIDF plan list) can stay open until it blocks, exactly as the spec schedules them.

## 10. First two weeks, concretely

1. Owner ratifies names and the D6 number.
2. `gh repo create` both repos; scaffold per §3; CI green; spec lands as `docs/engine-spec.md`.
3. UniFFI async smoke test running on JVM and Swift, in CI, with the verdict recorded.
4. Library evaluation written; `docs/DEPENDENCIES.md` drafted.
5. Reference tables verified against `internal/engine`; corrections and `go-wallet-backend` issues filed.
6. `engine-vectors` schema + runner contract merged; generator design note written.
7. Stop and wait for the PR 163 rework to land on go-wallet-backend `main` (go-wmp v0.13.0 is already out). When it lands: pin `main` + go-wmp v0.13.0, generator PR in go-wallet-backend (test-only), then S0.

## 11. Lessons from the closed wallet-core PRs (siros-dc-matcher #54, #55)

Two stacked PRs (closed 2026-11-01, "I won't put a wallet core in dc-matcher — it doesn't belong here") carried a nearly complete sans-I/O wallet core for OpenID4VP presentation: ~97k lines, a 508-line requirements contract, passing gates, real-proof CI. They were right in content and wrong in home. The branches survive on the dc-matcher remote (`wallet-core/*`); the groundwork (android-credman host ABI crates, #53) already merged and shipped in release 0.12.0.

What the engine work takes from them:

1. **The architecture contract is reference material for post-spike OID4VP.** `docs/wallet-core-architecture.md` on `wallet-core/phase-2` decides presentation in more depth than the engine spec's OID4VP table: DCQL §6 enforcement-by-parsing, RFC 9901, mdoc handovers and `KeyAuthorizations`, transaction data (PaSO draft-2 + TS12), display/locale, response encryption (JWE and `direct_post.cwt`), trust with RFC 5280 path validation, the picker registration. Extract in P0.9; treat as the requirements source when full OID4VP starts.
2. **Sans-I/O is validated in-org (decision D8).** The wallet core chose effects-in/results-out for the stated reason "one shape for UniFFI, the browser, the WASI module and the picker" — and it worked across all four bindings. This dissolves the async-over-UniFFI problem the engine spec worries about. P0.4 compares both shapes; the spike report cites this precedent.
3. **wazero/WASI is a proven Go-integration seam.** "Go runs a WASI module under wazero because go-wallet-backend builds with CGO_ENABLED=0." During the two-engine overlap this lets the Go engine consume Rust components with no CGO — an overlap strategy the spec lacks.
4. **Format crates to evaluate before rewriting anything.** `siros-codec` (strict CBOR/JSON, bounded inputs, one-sort duplicate detection), `siros-sdjwt`, `siros-mdoc`, `siros-oid4vp`, `siros-dcql` 0.12 overlap heavily with S2/S4; their constraints (deny `unwrap`/`expect`/indexing/`panic`, no interior mutability, construction-guards-validity witnesses) match engine-core's rules. P0.5 scores them alongside jose-rs/kryptering.
5. **F5's HTTP rules upgrade `engine-ports::HttpClient` policy:** https-only, 10s timeout, no wallet-identifying headers, no redirects on request-object fetches (RFC 9101 §10.4.1) or submissions (307/308 body replay), media-type enforcement, 256 KiB request-object / 64 KiB reply caps, "the final URL is the URL that served it" for held metadata.
6. **The boundary, in writing.** The wallet core is a candidate implementation of the engine's `Host` on the SDK side (it is what answers `request_match`/`request_consent`), not a competing engine. The engine core must not grow wallet responsibilities (credential storage, display, picker registration) — that scope creep is what put those PRs in the wrong repo. One tension to reconcile: wallet-core built local trust evaluation (TR1–TR5); the engine keeps trust remote — keep the guarantee-level enum extensible so both fit.
7. **Verification patterns to adopt:** one vector suite asserted byte-identical through UniFFI, browser, WASI and picker (adapter parity); differential testing (picker offers equal wallet offers, 512 runs); zero-reference greps proving platform copies deleted; RFC example vectors; a panic-site checker.
8. **Process rule:** repo placement and the architecture contract land **before** large-scale code generation. A 1017-file stack was closed at the finish line for a decision that cost nothing on day one.
