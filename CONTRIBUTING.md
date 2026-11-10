# Contributing

## Provenance

**Read this before writing any matching code.** It is committed ahead of the
implementation on purpose — a provenance rule written after someone has read the
source it governs is worth nothing.

This repository is an independent implementation of the OpenID4VP presentation
stack — the DCQL query language, SD-JWT VC, ISO mdoc, transaction data and the
`zkp_req` proof protocol. It is licensed BSD-2-Clause.

The OpenWallet Foundation's [Multipaz](https://github.com/openwallet-foundation/multipaz)
project ships an Apache-2.0 credential matcher that solves the same problem
(`multipaz-dcapi-credman/src/androidMain/matcher/`). We use it as a **conformance
oracle** and nothing else.

This is not a formal clean-room procedure. Clean-room exists for
reverse-engineering undocumented interfaces, and nothing here is undocumented —
DCQL is a public specification. What follows is the narrower rule that BSD-2
licensing actually requires: no Apache-2.0 *expression* enters this codebase.

Two implementations of DCQL will converge on **behaviour**, because the
specification dictates it. That convergence is expected and fine. What must not
converge is **expression**: file decomposition, type structure, algorithm shape
carried over line by line, or comments.

### You may

- Run Multipaz's matcher binary and compare its output against ours.
- Commit behaviour observed that way as test vectors. A vector describing what a
  program does is a fact about it.
- Consult their source to answer "what does the host actually accept here?" when
  the specification is silent. Write the *fact* down, in your own words, in the
  code comment — never the passage that revealed it.

### You may not

- Copy or transliterate their source into Rust, in whole or in part. This
  applies with full force to `dcql.cpp`, `CredentialDatabase.cpp` and
  `Request.cpp`, which cover exactly the ground our core crates cover.
- Port their file or type decomposition structurally. This is the same problem
  as copying, and considerably harder to catch in review.
- Copy their comments, or adopt their identifier set wholesale.
- Vendor their binaries into this repository. Redistributing an Apache-2.0
  artifact from a BSD-2 tree drags in notice obligations for no benefit.

### Cite the spec, not the implementation

Every non-obvious matching rule carries a doc comment naming the section it
comes from — `OpenID4VP 1.0 §6.4.2`, `ISO/IEC 18013-7`, `W3C Digital
Credentials API`. A rule you cannot cite is a rule you should not be writing
yet: you have not finished reading.

Reviewers: treat an uncited behavioural rule as a review comment, and a
structural resemblance to the oracle as a blocker.

## Development

The [README's build section](README.md#build-and-test) lists what CI checks.

[AGENTS.md](AGENTS.md)'s [Tests](AGENTS.md#tests), [Types](AGENTS.md#types)
and [Wording](AGENTS.md#wording) sections bind every change: tests live in each
crate's `tests/` and enforce a source of truth outside the code they test,
types parse once at construction, and the crates ship no End-User text: each
declares its errors and statements as an id and named arguments, and
siros-testkit's `locales/` word every one in English and German for the tests.
`cargo xtask layout` checks the layout these rules give.

`proving/` is a second workspace: the proof backends and the browser presenter,
whose dependencies need Rust 1.95, above the root workspace's floor. Run its
commands from there.

Rust 1.89 is the floor of every crate in this workspace. The MSRV job checks
the workspace on 1.89, then each crate with its default features and with
`--no-default-features`. If you raise a floor, raise it in the manifest that
owns it and say why there.

A build compiles what it registers. `cargo xtask builds` checks each build of
`xtask/builds.json`, the design's section 4.11, against the crates it must not
compile, the siros-i18n features it compiles, and the count of crates it stays
below; `cargo xtask alone` builds and documents each crate alone, and checks the
workspace crates it names. A change that adds a feature or a dependency edge
updates the table in the same pull request.

Nothing panics outside the tests: a type makes the impossible state
unrepresentable, or the caller receives an error. CI holds each crate to it with
clippy and `scripts/check_panic_sites.py`, which fails on a new crate until its
root denies the panic lints outside the tests, as the other roots do.


## Changelog

Changes that a user or a downstream consumer would notice go in
[`CHANGELOG.md`](CHANGELOG.md), under `Unreleased`, in the same PR.

Releasing renames `Unreleased` to the version and dates it; that is the only
time the heading changes.

## Pull requests

Branch from `main`, open a PR, keep the history linear. Every PR must be green on
CI. Commits are signed; Git over SSH only; no force-push; no merges, tags or
publishes without the owner's explicit go.
