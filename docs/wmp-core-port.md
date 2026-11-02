# wmp-core: mirroring go-wmp v0.13.0 in Rust

**Status (Nov 2, 2026):** the foundation, methods, session, session service,
request context, handler, registry, peer, profiles, transport, the async flow
driver (`flowcontext.rs`) and the sub-flow machinery (`subflow.rs`) are
ported and green — 33 tests, including the vector referee. Remaining:
`channel_transport.go`, `mls/` (interface + noop), and the stage-3 modules
(`evidence.go`, `invitation.go`, `discovery.go`, `resolve.go`).

`wmp-core` is the Rust WMP library: messages, session state, peer, flows,
validators and error codes — the future base of the native WMP clients. It is
written by mirroring [go-wmp](https://github.com/sirosfoundation/go-wmp) at
**v0.13.0** (pinned; the tag, not a branch) against the
[wmp](https://github.com/sirosfoundation/wmp) specification and its vectors.

## Referee

The vectors in `wmp/vectors/*.json` are the referee, never go-wmp's source:
behaviour they fix is fixed. `tests/conformance.rs` mirrors go-wmp's
`conformance_test.go`: `WMP_VECTORS_DIR` overrides the search, the sibling
checkout `../../../wmp/vectors` (three levels up from `crates/wmp-core`) is
the local-dev default, `wmp-spec/vectors` the CI fallback. A vector whose
method the current code does not dispatch is counted as *pending*, never
silently passed; the port is done when the pending count is zero across all
six files (22 vectors).

## Module map

| go-wmp `pkg/wmp` (v0.13.0) | `wmp-core` | Notes |
| --- | --- | --- |
| `errors.go` | `error.rs` | WMP + JSON-RPC error codes, standard messages, `RpcError` |
| `jsonrpc.go` | `jsonrpc.rs` | Request/Response/Message over `RawValue`; 1 MiB size cap, depth cap 32, strict end-of-input, batch |
| `version.go` | `version.rs` | `MAJOR.MINOR` parse (no leading zeros, ≤6 digits), negotiation, the `-32602`/`-31013` rejection split |
| `token.go` | `token.rs` | 192-bit resumption token; **entropy is injected by the caller** (no ambient RNG), base64url unpadded; constant-time compare |
| `principal.go` | `principal.rs` | Subject/tenant, opaque claims, the `owner key`; Rust has no request context — the `Principal` is passed explicitly |
| `types.go` | `types.rs` | The `wmp` envelope (`Metadata`), identity assertions, trust hints, relay entries, delegates, security mode, capabilities and their parameter types |
| `methods.go` | `methods.rs` | Method-name constants and every params/result type |
| `session.go` | `session.rs` | `Session`, `SessionStore`, the in-memory store, token rotation |
| `sessionservice.go` | `sessionservice.rs` | The session service layer behind create/resume/close |
| `peer.go` | `peer.rs` | `Peer` with builder options, `Validator`/`Authorizer` hooks, dispatch, flow routing, `handle_request_sync` — the sans-transport entry the harness drives |
| `handler.go` | `handler.rs` | The handler trait |
| `context.go` | `context.rs` | |
| `capability_gate.go` | `capability_gate.rs` | |
| `flowcontext.go` | `flowcontext.rs` | |
| `registry.go` | `registry.rs` | The flow registry — the seam a new flow family registers through |
| `subflow.go` | `subflow.rs` | |
| `evidence.go` | `evidence.rs` | |
| `resolve.go` | `resolve.rs` | |
| `discovery.go` | `discovery.rs` | |
| `invitation.go` | `invitation.rs` | |
| `profile.go` | `profile.rs` | |
| `orchestrator_messages.go` | `orchestrator_messages.rs` | |
| `channel_transport.go` | `channel_transport.rs` | The in-memory transport pair, used by tests |
| `transport.go` | `transport.rs` | The `Transport` trait only — synchronous, sans-async; real transports are adapters |
| `mls/` (interface + noop) | `mls.rs` | Interface and the noop implementation; real MLS stays with its own stack |

**Excluded from the mirror:** `ws/`, `httpsse/`, `stdio/`, `relay/`
(transports — adapter work), `openid4x/` (the OpenID4 profile — that is the
engine core's flow family, built on this crate after the spike opens), and
`schema/` (JSON-Schema parameter validation; the `jsonschema` crate enters as
a dev-dependency for test-time validation, not as a core dependency).

## Conventions

The crate follows the workspace rules: `#![deny(unsafe_code)]`,
`#![deny(missing_docs)]`, the panic lints outside tests, `clippy -D warnings`,
`rust-version` 1.82. Where go-wmp reaches for ambient state — `crypto/rand`
for tokens and request ids, the wall clock for expiry — the Rust port takes
the value from the caller (an entropy source, a clock value), so tests are
deterministic and the future SDK/engine adapters own the effects.

Where go-wmp types carry `time.Time`, the Rust port holds the RFC 3339 text
until the session machinery needs typed comparison; typed timestamps land
with `session.rs`/`sessionservice.rs`, one representation for the whole
crate.
