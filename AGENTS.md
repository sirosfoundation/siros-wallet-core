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
  outputs, and the core's own cases implement it as peers. A build compiles
  what it uses: each mechanism sits behind a feature the crates that use it
  turn on (design §4.11), a feature adds items and changes no signature, and a
  plug-in gates its phase 2 on its own `resolve`. A new feature or dependency
  edge updates `xtask/builds.json`. The core names no plug-in.
- **Logic lives in the core.** Every rule about requests, credentials, matching,
  disclosure, proof choice, transaction data, display content and response
  construction has its only implementation here. Platforms must not keep a copy.
- **The core is pure and offline.** No networking, storage, clock, randomness or
  key operations inside; effects in, results out. Every error carries a
  stable code.
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

## Tests

- **Tests live outside the source files**, in each crate's `tests/` directory,
  and check the crate through its public API: no `#[test]` or `#[cfg(test)]`
  under `src/`, and no visibility widened for a test.
- **A crate's `test-util` feature holds doubles of the extension points the
  crate defines, written with its public API alone.** No constructor sits behind
  `test-util`: tests reach restricted values through
  `crates/siros-testkit/src/probe.rs`. `cargo xtask layout` refuses an inherent
  `impl` of a type outside the gate, any item that makes a value of a type with
  private fields, and a free `pub fn`, a `pub const` or a `pub static`.
- **Every test enforces a source of truth outside the code it tests**: a
  specification, published vectors, an independent implementation, or a
  property that must hold. Delete a test whose expected value comes from the
  code it tests: a snapshot, a digest or a count copied from a run, a constant
  of the code under test.
- **Trust the dependencies.** A library the crate uses is tested by its own
  project. Delete a test of its guarantees, such as a JSON parser parsing or a
  hash crate hashing; a dependency may still serve as an independent oracle.
- **Leave to the compiler what it enforces.** Delete a test of an invariant
  the type system already guarantees: a type that cannot be built invalid, an
  exhaustive match, a trait bound, a visibility, or a compile-fail check of any
  of them.
- **One test per guarantee and one fixture per refusal rule**, known answers in
  one table. A test of wording is no test.

## Types

- **Parse, don't validate.** Every type carries a meaning and its guarantees,
  and no value of it is invalid. Checking happens once, at construction: data
  enters through a parser whose output can only hold valid states, with no
  `validate()` beside it. Witness types carry runtime checks (trust, time,
  selection) between steps.
- **Newtypes give general primitives their meaning.** A value with a
  constraint or a role (an identifier, a tag, an amount, a path, a key) is its
  own type, so a wrong use does not compile.

## Wording

- **The core gets no say on what gets said.** A crate ships no End-User text in
  any language. It declares its messages (keys, typed arguments, the situation
  each reports), and the wallet implementation provides every text. `#[error]`
  templates stay English, for logs and the Verifier's `error_description`.

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
cargo xtask layout
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --workspace --lib --no-default-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --all-features
cargo test --locked --workspace --all-features
python3 scripts/check_panic_sites.py Cargo.toml proving/Cargo.toml
cargo xtask builds
cargo xtask alone
```

Rust 1.89 is the floor of every crate; the `msrv` CI job checks it.
The toolchain itself is pinned exactly in `rust-toolchain.toml`.

## Working rules

- Git over SSH only. Commits are signed. No force-push. No merges, tags or
  publishes without the owner's explicit go.
- A test that guards a guarantee fails when its fix is reverted.
- Fix every review finding and every instance of the same class of bug.
- Cite the spec, not the implementation: every non-obvious rule carries a doc
  comment naming its source (`OpenID4VP 1.0 §6.4.2`, `RFC 9901 §7.1`). An
  uncited behavioural rule is a review comment; structural resemblance to the
  oracle is a blocker.
- Report in full URLs for every pull request and issue.
