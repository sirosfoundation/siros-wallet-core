# The engine switching model: local and remote, per session, never mid-flow

Nov 3, 2026. The target architecture for how the SDKs and the
wallet-frontend switch between the local (in-process) engine and the
remote (container) engine.

## The rule

**The engine is a user choice, made per session, never mid-flow.** A wallet
that runs the local engine can switch to the remote engine (or back) only
after the current flow completes and the user explicitly confirms — the
spec's standing rule (2026-10-21). No silent failover, no automatic
fallback, no mid-flow switch.

The switch is at the **Transport level**, not the Engine level: the SDK's
existing `Transport` interface is the seam. `WmpUniFFITransport` speaks to
the in-process Rust engine; `WmpWebSocketTransport` speaks to the remote
engine. The `WmpPeer`, the profile dispatch, the flow events, the
`FlowClient`, the consent UI — everything downstream of the Transport is
identical in both modes.

## The three deployment modes

```
┌────────────────────────────────────────────────────────────────────┐
│ The engine core (engine-core + engine-ports)                       │
│   One implementation, three adapters                               │
└────────────────────────────────────────────────────────────────────┘
          │                      │                          │
          ▼                      ▼                          ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ Native SDK       │  │ WASM module      │  │ Server container     │
│ (Kotlin / Swift) │  │ (browser)        │  │ (drop-in replacement) │
│                  │  │                  │  │                      │
│ adapter-sdk      │  │ adapter-wasm     │  │ adapter-server       │
│ (UniFFI)         │  │ (wasm-bindgen)   │  │ (tokio, rustls)      │
│                  │  │                  │  │                      │
│ HttpClient =     │  │ HttpClient =     │  │ HttpClient =        │
│   OkHttp /       │  │   browser fetch  │  │   reqwest + rustls  │
│   URLSession     │  │   (or the CORS   │  │                      │
│                  │  │   proxy)         │  │                      │
│ Host =           │  │ Host =           │  │ Host =              │
│   Signer +       │  │   browser        │  │   remote WMP peer   │
│   consent UI     │  │   consent UI      │  │   (the wallet        │
│                  │  │                  │  │   client)           │
│ Deployed:        │  │ Deployed:        │  │ Deployed:            │
│  in-process in   │  │  in the browser, │  │  as a container,    │
│  the native app  │  │  alongside the   │  │  alongside the Go   │
│                  │  │  presentation   │  │  backend, or in a   │
│                  │  │  crates (the    │  │  TEE                │
│                  │  │  wallet-frontend)│  │                      │
└──────────────────┘  └──────────────────┘  └──────────────────────┘
```

## How each deployment switches

### Native SDKs (Kotlin/Swift)

The SDK picks a `Transport` per session:

| Mode | Transport | Engine runs | HTTP fetches go through |
| --- | --- | --- | --- |
| **Local** | `WmpUniFFITransport` | In-process (the Rust engine core, loaded as an AAR/XCFramework) | The SDK's `HttpClient` port: OkHttp / URLSession (native TLS, system roots, VPNs) |
| **Remote** | `WmpWebSocketTransport` (or `WmpHttpSseTransport`) | In the container | The remote engine's HTTP client (server-side) |

The switch: the user chooses (or the app's settings default), the SDK
creates the `WmpSession` with the chosen `Transport`, and the session
lives its life on that engine. A switch means: finish the flow, close the
session, create a new session on the other transport, and start the next
flow there.

### Wallet frontend (browser)

The frontend picks a mode per session:

| Mode | How | Engine runs | HTTP fetches go through |
| --- | --- | --- | --- |
| **Local (WASM)** | The WASM module of the engine core, loaded alongside the presentation crates | In the browser | The browser's `fetch`, through the backend's CORS proxy for the issuers and verifiers the browser can't reach directly |
| **Remote** | The WMP-over-HTTP transport (POST + SSE) to the remote engine | In the container | The remote engine's HTTP client (server-side, no CORS) |

The switch: same rule — per session, after the user confirms, never
mid-flow.

### Native app webview (the hybrid)

When the wallet-frontend runs inside a native app's webview (Android
WebView / iOS WKWebView), it **does not load its own WASM engine**. The
webview talks to the native SDK's in-process engine through a JavaScript
bridge:

```
Wallet frontend (webview)  ←JavaScript bridge→  Native SDK  ←UniFFI→  Engine core
```

The SDK exposes the `WmpEngine` handle to the webview (through
`addJavascriptInterface` on Android, `WKScriptMessageHandler` on iOS).
The frontend's WMP client calls the same `send`/`takeNotifications`
interface through the bridge. The engine runs in-process in the native
app, exactly as if the SDK's own UI were driving it.

This is the fourth integration point the architecture review's three
targets didn't name explicitly: the webview is a **consumer of the SDK
adapter**, not a separate adapter.

## What the engine core doesn't know

The engine core (`engine-core` + `engine-ports`) is the same in all four
deployments. It does not know:

- Whether it's in-process or remote (the adapter's `Host` port
  implementation answers that: the SDK's `Host` is the native UI; the
  server's `Host` is the remote WMP peer; the WASM `Host` is the
  browser's consent dialog)
- Whether the HTTP fetches go through the platform stack, the browser, a
  CORS proxy, or rustls in a TEE (the adapter's `HttpClient` port answers
  that)
- Whether the session survives a transport reconnection (the adapter's
  `KeyValue` port and the WMP resume protocol answer that)

The core knows only: the port traits it `await`s, the flow families
registered on its runtime, and the WMP messages it sends and receives.

## What's built and what remains

| Component | Status |
| --- | --- |
| `wmp-core` (the WMP library: types, session, peer, flows) | ✅ complete, 47 tests |
| `engine-ports` (the port traits) | ✅ defined |
| `engine-core` (the flow runtime, S0 shape) | ✅ the seam proven |
| `engine-adapter-sdk` (the UniFFI bindings) | ✅ async smoke + in-process engine handle |
| `engine-adapter-server` (the container host) | ✅ both transports, token validation, health probes |
| The Kotlin `WmpUniFFITransport` | ✅ written (the SDK copies it) |
| The Swift `WmpUniFFITransport` | ✅ written (the SDK copies it) |
| The WASM adapter | ⬜ wasm32 build of engine-core + wasm-bindgen bindings |
| The webview JavaScript bridge | ⬜ SDK-side (Android/iOS), consumes the `WmpEngine` handle |
| The AAR / XCFramework packaging | ⬜ Makefile targets defined, need CI |
| The flow families (OID4VCI, OID4VP) | ⬜ S1–S3, gated on the spike |

## The switching summary

| Deployment | Local engine | Remote engine | Switch rule |
| --- | --- | --- | --- |
| Native SDK (Kotlin/Swift) | `WmpUniFFITransport` (in-process Rust core) | `WmpWebSocketTransport` (to the container) | Per session, user choice, never mid-flow |
| Wallet frontend (browser) | WASM module (engine core in the browser) | WMP over HTTP (POST + SSE to the container) | Per session, user choice, never mid-flow |
| Native webview | The SDK's in-process engine (through the JavaScript bridge) | — (the webview always uses the SDK's engine) | Not applicable: the webview delegates to the SDK |
| Server container | — (the engine IS the server) | — | Not applicable |
