# The native SDK integration: what the Rust engine plugs into

Nov 3, 2026. An analysis of siros-sdk-kotlin and siros-sdk-swift, and
how the Rust engine core (`wmp-core` + `engine-core` through
`engine-adapter-sdk`) integrates.

## What the SDKs have today

Both SDKs are **already structured for this integration** — they have the
WMP client layer, the profile seam, the flow event stream, and the keystore
that signs. The Rust engine replaces the *remote engine* with an
*in-process engine*, keeping every other layer.

### The WMP client layer (already in both SDKs)

| Kotlin | Swift | What it does |
| --- | --- | --- |
| `WmpSession` | `WmpSession` | Session create / resume / close, auth-token management, the transport lifecycle |
| `WmpPeer` | `WmpPeer` | Central dispatch node: routes flow events, method calls, and resolve requests to registered profiles |
| `WmpWebSocketTransport` | `WmpWebSocketTransport` | The WebSocket binding (`wmp.v1` subprotocol, okhttp / URLSession) |
| `WmpHttpSseTransport` | `WmpHttpSseTransport` | The HTTPS binding (POST + SSE) |
| `WmpRegistry` | `WmpRegistry` | Profile registration and dispatch by flow type / method name |
| `WmpCodec` | `WmpCodec` | JSON-RPC 2.0 encode/decode |
| `WmpProfile` | `WmpProfile` | The extension interface: `name`, `capabilities`, `init(ctx)` |
| `WmpFlowHandler` | `WmpFlowHandler` | Flow dispatch: `flowTypes`, `startFlow`, `handleAction`, `handleProgress`, `handleComplete`, `handleError` |

### The flow layer

| Kotlin | Swift | What it does |
| --- | --- | --- |
| `FlowClient` | `FlowClient` | Drives a flow: sends actions, collects progress |
| `FlowStepCatalog` | `FlowStepCatalog` | Named step constants (PARSING_OFFER, AWAITING_TX_CODE, etc.) |
| `FlowTypes` | `FlowTypes` | The flow result and error types |

### The OpenID4x profile (the flow families)

Both SDKs already have `OpenID4xProfile` — a Kotlin/Swift implementation
of the OID4VCI and OID4VP flow types, registered on the WMPPeer as a
`WmpFlowHandler`. Today these flows run on the remote Go engine (via the
`WmpWebSocketTransport` or `WmpHttpSseTransport` to `go-wallet-backend
--mode=engine`). The profile sends `wmp.flow.start` to the remote engine,
collects the flow events, and drives the UI.

### The keystore (the Host)

| Kotlin | Swift | What it does |
| --- | --- | --- |
| `Signer` interface | `Signer` protocol | `sign(keyId, data) -> ByteArray` — the exact shape of the engine's `Host::request_sign` |
| `WscdManager` | `WscdManager` | The UniFFI bindings of `siros-wscd-manager` — already an in-process Rust library, with plugins for FIDO2, R2PS, softkey |
| `KeystoreManager` | `KeystoreManager` | Key lifecycle, attestation, the PRF-derived wallet key |

### The wallet layer

| Kotlin | Swift | What it does |
| --- | --- | --- |
| `WalletViewModel` / `WalletEngineSession` | `WalletViewModel` / `WalletEngineSession` | Drives the engine session, handles sign requests (`signRequestChannel`), consent, credential selection |
| `EncryptedCredentialStore` | `EncryptedCredentialStore` | The private data container |
| `DCAPIGetCredentialActivity` / `SirosCredentialRegistry` | `DCAPIGetCredential` | The Android/iOS credential manager integration |

## What the Rust engine replaces

**Only the transport and the profile's backing.** The SDK's architecture
already separates the WMP client layer from the flow logic from the
keystore; the Rust engine slots in as:

1. **The in-process WMP peer** — `wmp-core` replaces the
   `WmpWebSocketTransport` + the remote engine. The SDK's `WmpPeer`
   talks to `wmp-core`'s `Peer` through the UniFFI bindings instead of
   through a WebSocket.

2. **The flow families** — `engine-core`'s registered `FlowHandler`s
   replace the `OpenID4xProfile`'s remote calls. The profile's
   `startFlow` calls the engine's exported async function instead of
   sending `wmp.flow.start` over the transport.

3. **The Host** — the SDK's existing `Signer` interface, consent UI, and
   credential selection become the `engine_ports::Host` implementation.
   The engine calls `request_sign`; the SDK's `signRequestChannel` already
   carries these.

## The integration, concretely

### Phase 1: in-process WMP (what works today)

The SDK registers the Rust WMP library as its transport, replacing the
WebSocket to the remote engine:

```kotlin
// The SDK's WmpSession gets a new Transport implementation:
// instead of WmpWebSocketTransport(url), it gets WmpUniFFITransport(),
// which is a thin Kotlin wrapper over the UniFFI bindings of wmp-core's
// ChannelTransport.
//
// The WmpPeer's registry, the profile dispatch, the flow events, and the
// FlowClient all work unchanged — they talk through the same
// WmpSession.send/receive interface.
```

No SDK changes beyond adding the `WmpUniFFITransport` class and the AAR
dependency. The existing `WmpWebSocketTransport` stays as the fallback
(the remote engine mode); the user chooses per-session, and the engine
never switches mid-flow (the spec's rule).

### Phase 2: in-process flow families (when S1–S3 land)

The `OpenID4xProfile` gets a second mode: instead of sending
`wmp.flow.start` through the transport, it calls the engine's exported
async function:

```kotlin
class InProcessOpenID4xProfile : WmpFlowHandler {
    override val flowTypes = listOf("oid4vci", "oid4vp")

    override suspend fun startFlow(params: FlowStartParams): FlowStartResult {
        // Call the engine core's FlowRuntime through the UniFFI bindings.
        return uniffi.engine_adapter_sdk.startFlow(
            httpClient = PlatformHttpClient(),   // the engine's HttpClient port
            host = SdkHost(),                    // the engine's Host port
            flowType = params.flowType,
            flowId = params.flowId,
            params = params.params,
        )
    }
}
```

The `PlatformHttpClient` is the engine's `HttpClient` port implemented
with OkHttp / URLSession — the same HTTP stack the SDK already uses, so
TLS, proxies and VPNs behave natively. The `SdkHost` is the engine's
`Host` port implemented by the SDK's existing `Signer` and consent UI:

```kotlin
class SdkHost : Host {
    override suspend fun requestSign(params: SignParams): SignResult {
        // The existing signRequestChannel, unchanged.
        val signature = keystoreManager.sign(params.keyId, params.toSign)
        return SignResult(signature)
    }

    override suspend fun requestConsent(params: ConsentParams): ConsentResult {
        // The existing consent UI, unchanged.
        val consented = consentDialog.show(params.purpose, params.requestedClaims)
        return ConsentResult(consented)
    }

    override suspend fun requestTxCode(flowId: String): String {
        // The existing PIN entry dialog, unchanged.
        return pinDialog.show()
    }
}
```

### Phase 3: the WASM module (the wallet-frontend)

The same `engine-core` + `engine-ports` compiled to wasm32, with the
browser's `fetch` as the `HttpClient` and the browser's consent dialog as
the `Host`. The wallet-frontend already uses the wallet-core presentation
crates in WASM; the engine core joins them in the same module.

## What the SDKs need from us

| What | Crate | Status |
| --- | --- | --- |
| WMP message types, session, peer | `wmp-core` | ✅ complete, tested |
| The port traits (HttpClient, Host, Pdp, Clock, Rng) | `engine-ports` | ✅ defined |
| UniFFI bindings with async callbacks | `engine-adapter-sdk` | ✅ smoke-tested on JVM |
| The flow runtime | `engine-core` | ✅ S0 shape (the seam is proven) |
| The OID4VCI / OID4VP flow families | `engine-core` | ⬜ S1–S3 (gated on the spike) |
| The AAR / XCFramework packaging | `engine-adapter-sdk` | ⬜ Makefile targets exist, need CI wiring |
| The thin transport adapter (`WmpUniFFITransport`) | SDK-side | ⬜ a Kotlin/Swift class wrapping the ChannelTransport |

## What the SDKs already provide (unchanged)

| What | Where |
| --- | --- |
| The consent UI, the PIN entry, the credential selection | The existing screens |
| The key custody (`Signer`, `WscdManager`, PRF-derived keys) | The keystore module |
| The credential storage (private data container) | `EncryptedCredentialStore` |
| The DC API / credential manager integration | `DCAPIGetCredentialActivity` |
| The existing remote-engine fallback | `WmpWebSocketTransport` to the Go engine |

## The summary

The SDKs are **already structured for this integration** — the WMP
profile seam, the flow event stream, the Signer interface, and the
transport abstraction are all in place. The Rust engine replaces the
transport (Phase 1) and the flow families' backing (Phase 2) without
changing the SDK's architecture. The Host implementation is the SDK's
existing UI and keystore, surfaced through the engine-ports traits.

The biggest SDK-side work is the **thin transport adapter** (a Kotlin/Swift
class wrapping wmp-core's ChannelTransport through UniFFI) and the
**AAR/XCFramework packaging** — both mechanical, neither architectural.
