# Agent guide: siros-wallet-core

## Scope and invariants

This workspace holds the Rust wallet core: the presentation core and the WMP
engine core. Keep changes small and protocol-specific.

- **`docs/wallet-core-design.md` is the contract** of the presentation core's
  crates: who owns what, the signatures, the rules, the acceptance gates and the
  decisions. Read it before touching a crate; when a change contradicts it, fix
  the document in the same pull request or raise it with the owner.
- **The core is modular** (decision 20). Each mechanism a specification leaves
  open is an extension point: its inputs are core-made, the core checks its
  outputs. A build compiles what it uses. The core names no plug-in.
- **Tests check behaviour an external source defines**: a specification,
  published vectors, an independent implementation or a property. Delete a
  test whose expected value comes from the code it tests.
- **Logic lives in the core.** Every rule about requests, credentials, matching,
  disclosure, proof choice, transaction data, display content and response
  construction has its only implementation here. Platforms must not keep a copy.
- **The core is pure and offline.** No networking, storage, clock, randomness or
  key operations inside; effects in, results out (R-G2). Every error carries a
  stable code.
- **Construction guards validity.** Data enters through a parser whose output
  type can only hold valid states; no separate `validate()` beside a parser.
  Witness types carry runtime checks (trust, time, selection) between steps.
- **`zkp_req` is protocol; nym_auth is a credential capability.**
  `siros-zkp-req` extends DCQL so a verifier can state a zero-knowledge
  request and a wallet can answer it; it holds no prover and no system.
  nym_auth (`siros-zkp-catalogues`) is a normal credential — an mdoc,
  stored in the wallet state, matched, displayed and consented like any
  other — that happens to carry the capability of doing pseudonyms; its
  rulebook defines the functions (`pseudonym`, `age_check`) and the
  Longfellow and Vega systems that prove them. New capabilities and systems
  add crates on top of the protocol layer — never a change to `zkp_req`
  itself, and never a second copy of the protocol.
- **The ZK stack is two crates, permanently.** `siros-zkp-req` is the
  protocol: DCQL extensions, no prover, no system, format-neutral.
  `siros-zkp-catalogues` holds every rulebook — an independently specified
  capability — as modules and features. nym_auth is the first; a new
  credential form (the nym_auth form of an mdoc today, of an SD-JWT VC
  tomorrow) and a new system (Longfellow, Vega, BBS-CD) land inside the
  existing crates. A new rulebook lands in `siros-zkp-catalogues` too.
  Capability growth never adds a crate. The catalogue crate exists because
  the rulebooks cross the layers (protocol, credential form, request
  policy, trust at once) and its consumers cut along its features: the
  picker links it without `credential`, the wallet with it, and the 1.95
  provers sit behind its prover interface in `proving/`. When a second
  rulebook arrives, namespace its internals (`src/nym_auth/`,
  `src/<rulebook>/`) in the same change.
- **Nothing panics outside the tests.** No `unwrap`, `expect`, indexing or
  `panic!` in library code; CI enforces it with clippy and
  `scripts/check_panic_sites.py`.
- **Multipaz is an oracle only.** See CONTRIBUTING.md §Provenance before
  writing matching code: no Apache-2.0 expression enters this tree.
- **The engine performs the core's effects.** It keeps its runtime, ports and
  transport; every OpenID4VP rule is the core's.
- **Trust decisions.** The core matches `trusted_authorities` against
  registered facts, which siros-trust computes locally at registration. A
  Verifier's trust is an AuthZEN evaluation the caller answers.

## Read first

- `docs/wallet-core-design.md` — the contract, especially §4 (design), §8
  (acceptance gates) and §10 (the repository).
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

Rust 1.89 is the floor of every crate; the `msrv` CI job checks it.
The toolchain itself is pinned exactly in `rust-toolchain.toml`.

## Working rules

- Git over SSH only. Commits are signed. No force-push. No merges, tags or
  publishes without the owner's explicit go.
- A test that guards a guarantee must fail when its fix is reverted.
- Fix every review finding and every instance of the same class of bug.
- Cite the spec, not the implementation: every non-obvious rule carries a doc
  comment naming its source (`OpenID4VP 1.0 §6.4.2`, `RFC 9901 §7.1`). An
  uncited behavioural rule is a review comment; structural resemblance to the
  oracle is a blocker.
- Report in full URLs for every pull request and issue.
