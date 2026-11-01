# Agent guide: siros-wallet-core

## Scope and invariants

This workspace holds the Rust wallet core: the presentation-side crates ported
from siros-dc-matcher PRs #54/#55, and the planned WMP engine core. Keep changes
small and protocol-specific.

- **`docs/wallet-core-architecture.md` is the contract** for the presentation
  crates: responsibilities, requirements (A/K/D/M/N/P/Q/S/T/TR/W rules), the
  layer table and the boundary contracts. Read it before touching a crate; when
  a change contradicts it, fix the document in the same pull request or raise
  it with the owner.
- **Logic lives in the core.** Every rule about requests, credentials, matching,
  disclosure, proof choice, transaction data, display content and response
  construction has its only implementation here. Platforms must not keep a copy.
- **The core is pure and offline.** No networking, storage, clock, randomness or
  key operations inside; effects in, results out (R-G2). Every error carries a
  stable code.
- **Construction guards validity.** Data enters through a parser whose output
  type can only hold valid states; no separate `validate()` beside a parser.
  Witness types carry runtime checks (trust, time, selection) between steps.
- **`zkp_req` is protocol; proof systems are catalogues.** `siros-zkp-req`
  extends DCQL so a verifier can state a zero-knowledge request and a wallet
  can answer it; it holds no prover and no system. nym_auth is the first of
  many catalogues (`siros-zkp-req-nym-auth`); a new ZKP system adds a
  catalogue on top of the protocol layer — never a change to `zkp_req`
  itself, and never a second copy of the protocol.
- **Nothing panics outside the tests.** No `unwrap`, `expect`, indexing or
  `panic!` in library code; CI enforces it with clippy and
  `scripts/check_panic_sites.py`.
- **Multipaz is an oracle only.** See CONTRIBUTING.md §Provenance before
  writing matching code: no Apache-2.0 expression enters this tree.
- **The engine crates are stubs.** Do not start them; the spike is gated on the
  PR 163 rework landing on go-wallet-backend `main` (go-wmp v0.13.0 has
  shipped). Library evaluation, spec verification and the UniFFI async
  smoke test can proceed — see `docs/engine-spec.md` and the implementation
  plan.
- **Trust decisions.** The presentation core resolves `trusted_authorities`
  locally (TR1–TR5); the engine core evaluates issuer and verifier trust through
  the PDP. Keep both: the `Pdp` seam is shaped so a local evaluator can plug in
  without a redesign.

## Read first

- `docs/wallet-core-architecture.md` — the contract, especially §3
  (cross-cutting requirements), §4 (components) and §5 (boundary contracts).
- `docs/engine-spec.md` — the WMP engine specification and spike plan.
- `docs/zkp_req_core.md`, `docs/zkp_req_request.md`, `docs/zkp_req_response.md`
  — the `zkp_req` specifications.
- `CONTRIBUTING.md` — provenance rule, MSRV policy, review expectations.

## Build and test

Run all checks before committing:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check_panic_sites.py Cargo.toml
```

Rust 1.82 is the floor of every library crate; the `msrv` CI job checks it.
The toolchain itself is pinned exactly in `rust-toolchain.toml`.

## Working rules

- Git over SSH only. Commits are signed. No force-push. No merges, tags or
  publishes without the owner's explicit go.
- Every test must be shown to fail when its fix is reverted.
- Fix every review finding and every instance of the same class of bug.
- Cite the spec, not the implementation: every non-obvious rule carries a doc
  comment naming its source (`OpenID4VP 1.0 §6.4.2`, `RFC 9901 §7.1`). An
  uncited behavioural rule is a review comment; structural resemblance to the
  oracle is a blocker.
- Report in full URLs for every pull request and issue.
