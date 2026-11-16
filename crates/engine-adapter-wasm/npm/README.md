# @sirosfoundation/siros-wallet-core

The SIROS wallet engine for the browser: the full OID4VCI and OID4VP
flows compiled to WebAssembly, driving over a plain JSON-RPC surface.

The engine is sans-network by design — every environmental effect goes
through a port the page supplies: the HTTP behind your `fetch`, the
wallet's keys and UI callbacks behind a host object, the trust
decisions behind a PDP callback. The [OIDF conformance suites][plan]'s
wallet plans (OID4VCI both grants, OID4VP every response mode including
the Digital Credentials API channel) pass against this exact module.

[plan]: https://github.com/sirosfoundation/siros-conformance

## Install

```sh
npm install @sirosfoundation/siros-wallet-core
```

## Use

The module is a standard wasm-bindgen `--target web` build: `init`
takes the wasm URL and returns a promise; the engine constructor takes
the config object with the page's callbacks.

```js
import init, { WasmEngine } from '@sirosfoundation/siros-wallet-core';

// Bundler-friendly: the URL resolves beside the JS the bundler emits.
const wasm = await init(
  new URL('@sirosfoundation/siros-wallet-core/engine_adapter_wasm_bg.wasm', import.meta.url)
);

const engine = new WasmEngine({
  // The engine's HTTP: the page's fetch behind the port.
  fetch: async (request) => {
    const response = await fetch(request.url, {
      method: request.method,
      headers: new Headers(
        request.headers.flatMap((h, i, all) => (i % 2 === 0 ? [[h, all[i + 1]]] : []))
      ),
      body: request.body.length ? new Uint8Array(request.body) : undefined,
    });
    const body = new Uint8Array(await response.arrayBuffer());
    return {
      status: response.status,
      headers: [...response.headers].flatMap(([name, value]) => [name, value]),
      body: [...body],
    };
  },

  // The wallet's host side: the keys, the consent, the presentation.
  host: 'mini', // or a host object — see the repository docs
  // host: { sign, match, consent, txCode, openAuthorization, vp, ... }

  // The trust decisions (the go-trust AuthZEN shape).
  pdp: { evaluate: async (request) => ({ trusted: true }) },

  // The flow stash — localStorage keeps the authorization-code resume
  // across a page reload.
  kv: {
    get: async (key) => localStorage.getItem('kv:' + key),
    put: async (key, value) => localStorage.setItem('kv:' + key, value),
    del: async (key) => localStorage.removeItem('kv:' + key),
  },
});

// Create a wallet session, then drive the flows over JSON-RPC.
const session = await engine.request('wmp.session.create', {
  wmp: { version: '0.1', sender: 'my-wallet' },
  capabilities_offered: { flows: { max_concurrent: 16 } },
  security: { mode: 'tls' },
});

// An OID4VP authorization request (by value, by reference, or the
// Digital Credentials API's request object — the engine parses all
// the forms).
const result = await engine.request('wmp.flow.start', {
  wmp: { session_id: session.wmp.session_id, version: '0.1' },
  flow_id: 'flow-1',
  flow_type: 'oid4vp',
  params: 'openid4vp://?request_uri=https://verifier.example/request',
});
```

The engine's notifications (`wmp.flow.progress`, `wmp.flow.complete`,
`wmp.flow.error`) reach the page through the optional `onNotification`
callback — the completion carries the flow results the resolved
`wmp.flow.start` answer alone does not (the Digital Credentials API
response is one: OpenID4VP 1.0 §8.4's data returns through the host,
never an HTTP POST).

The full WMP method surface, the host callback contracts, and the
conformance harness live in the
[repository](https://github.com/sirosfoundation/siros-wallet-core).

## Requirements

- A browser or worker with WebAssembly (ESM).
- The page supplies every environmental effect — the module itself
  makes no network calls except through the `fetch` callback.

## License

BSD-2-Clause — see [LICENSE](./LICENSE).
