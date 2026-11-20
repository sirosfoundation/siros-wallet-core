// The library's engine and backend seams — the review's coverage asks:
// the notification-completion path (the double-store regression, finding
// 1), the backend's 304 answers (finding 4), the tagged-binary wire, the
// authzen decision mapping (the non-boolean decisions), and the offer
// resolution through the page's fetch port.

import test from "node:test";
import assert from "node:assert/strict";

import {
  MiniWallet,
  MemoryWalletStorage,
  AlwaysTrustedPlugin,
  AuthzenTrustPlugin,
  GoWalletBackendTarget,
  NullCipher,
} from "../dist/index.js";
import { reviveTaggedBinary, stringifyWithTaggedBinary } from "../dist/adopt.js";

const fakeEngineWallet = (options) =>
  new MiniWallet({
    storage: new MemoryWalletStorage(),
    pdp: new AlwaysTrustedPlugin(),
    ui: { consent: async () => ({ consented: true }) },
    engine: { init: async () => {}, WasmEngine: options.WasmEngine },
    onEvent: options.onEvent,
    fetch: options.fetch,
  });

// ── The notification completion (finding 1's regression pin) ───────────

test("a flow completing through the notification sink stores each credential exactly once", async () => {
  const events = [];
  let flowId = null;
  let sink = null;
  class FakeEngine {
    constructor(config) {
      sink = (text) => config.onNotification(text);
    }
    async request(method, params) {
      if (method === "wmp.session.create") return { wmp: { session_id: "ses-test" } };
      if (method === "wmp.flow.start") {
        flowId = params.flow_id;
        // The bare started envelope — the completion joins via the sink.
        return { flow_id: params.flow_id, flow_type: "oid4vci", wmp: {} };
      }
      throw new Error(`unexpected engine call: ${method}`);
    }
  }
  const wallet = fakeEngineWallet({
    WasmEngine: FakeEngine,
    onEvent: (e) => events.push(e),
  });
  const pending = wallet.receiveCredential({
    credential_issuer: "https://issuer.example",
    credential_configuration_ids: ["nym_auth"],
    grants: {},
  });
  // The flow is in flight (the start answered the bare envelope); the
  // completion arrives as a notification frame.
  await new Promise((resolve) => setImmediate(resolve));
  sink(JSON.stringify({
    method: "wmp.flow.complete",
    params: {
      flow_id: flowId,
      result: {
        credentials: [{
          format: "mso_mdoc",
          credential_configuration_id: "nym_auth",
          credential: "AAECAw",
          credential_metadata: { auxiliary_data: [] },
        }],
      },
    },
  }));
  const result = await pending;
  assert.ok(result, "the flow resolves with the completion's result");
  const list = await wallet.credentials();
  assert.equal(list.length, 1, "exactly ONE stored credential (the regression stored two)");
  const received = events.filter((e) => e.type === "credential-received");
  assert.equal(received.length, 1, "exactly ONE credential-received event");
});

test("a late wmp.flow.error for a settled flow never reaches the page", async () => {
  const events = [];
  let flowId = null;
  let sink = null;
  class FakeEngine {
    constructor(config) {
      sink = (text) => config.onNotification(text);
    }
    async request(method, params) {
      if (method === "wmp.session.create") return { wmp: { session_id: "ses-test" } };
      if (method === "wmp.flow.start") {
        flowId = params.flow_id;
        return {
          flow_id: params.flow_id,
          flow_type: "oid4vci",
          credentials: [{ format: "mso_mdoc", credential: "AA", credential_configuration_id: "c" }],
        };
      }
      throw new Error(`unexpected engine call: ${method}`);
    }
  }
  const wallet = fakeEngineWallet({
    WasmEngine: FakeEngine,
    onEvent: (e) => events.push(e),
  });
  const result = await wallet.receiveCredential({
    credential_issuer: "https://issuer.example",
    credential_configuration_ids: ["nym_auth"],
    grants: {},
  });
  assert.ok(result.credentials, "the sync completion settles");
  // The stale frame for the long-settled flow: neither a rejection nor a
  // page event — nothing changes.
  sink(JSON.stringify({ method: "wmp.flow.error", params: { flow_id: flowId, error: { code: -31006, message: "stale" } } }));
  assert.equal(events.filter((e) => e.type === "flow-error").length, 0, "a settled flow's late error is not the page's news");
  assert.equal((await wallet.credentials()).length, 1);
});

// ── The backend's 304 answers (finding 4's regression pin) ─────────────

test("a 304 private-data answer returns the cached records — the next put keeps every key", async () => {
  const cipher = new NullCipher();
  const firstBlob = Array.from(await cipher.wrap({ a: "1", b: "2" }));
  let posted = null;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const method = init.method ?? "GET";
    if (u.endsWith("/user/session/private-data") && method === "GET") {
      const headers = init.headers ?? {};
      if (headers["If-None-Match"] === "e1") return new Response(null, { status: 304 });
      return new Response(JSON.stringify({ privateData: { data: firstBlob } }), {
        status: 200,
        headers: { "Content-Type": "application/json", ETag: "e1" },
      });
    }
    if (u.endsWith("/user/session/private-data") && method === "POST") {
      posted = JSON.parse(String(init.body));
      return new Response("{}", { status: 200, headers: { ETag: "e2" } });
    }
    throw new Error(`unexpected fetch: ${method} ${u}`);
  };
  try {
    const target = new GoWalletBackendTarget("https://backend.example");
    const storage = target.storage(cipher);
    assert.equal(await storage.get("a"), "1", "the first read primes the cache and the etag");
    await storage.put("c", "3", ); // the read 304s: the cache must answer
    const unwrapped = await cipher.unwrap(new Uint8Array(posted.privateData.data));
    assert.deepEqual(Object.keys(unwrapped).sort(), ["a", "b", "c"],
      "the rewrite carries EVERY record (the regression kept only the new key)");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a 404 private-data answer is EMPTY — a wiped backend is not resurrected from the cache", async () => {
  const cipher = new NullCipher();
  let posted = null;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const method = init.method ?? "GET";
    if (u.endsWith("/user/session/private-data") && method === "GET") {
      return new Response("not found", { status: 404 });
    }
    if (u.endsWith("/user/session/private-data") && method === "POST") {
      posted = JSON.parse(String(init.body));
      return new Response("{}", { status: 200, headers: { ETag: "e-new" } });
    }
    throw new Error(`unexpected fetch: ${method} ${u}`);
  };
  try {
    const target = new GoWalletBackendTarget("https://backend.example");
    const storage = target.storage(cipher);
    await storage.put("only-key", "x");
    const unwrapped = await cipher.unwrap(new Uint8Array(posted.privateData.data));
    assert.deepEqual(Object.keys(unwrapped), ["only-key"],
      "the post-wipe rewrite carries exactly what the (empty) server state plus the new key says");
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ── The tagged-binary wire ─────────────────────────────────────────────

test("the tagged-binary wire round-trips buffers inside nested structures", () => {
  // The Uint8Array shape AND the raw ArrayBuffer members
  // navigator.credentials.create returns (rawId, attestationObject,
  // clientDataJSON): the ArrayBuffer alone serialized as {} and the AS
  // could not verify the registration.
  const value = {
    name: "ceremony",
    challenge: new Uint8Array([1, 2, 3, 250]),
    list: [{ rawId: new Uint8Array([9, 8]) }, "plain"],
    credential: {
      rawId: new ArrayBuffer(3),
      response: {
        attestationObject: new ArrayBuffer(4),
        clientDataJSON: new Uint8Array([7, 7, 7]),
      },
    },
  };
  new Uint8Array(value.credential.rawId).set([11, 22, 33]);
  new Uint8Array(value.credential.response.attestationObject).set([44, 55, 66, 77]);
  const back = reviveTaggedBinary(JSON.parse(stringifyWithTaggedBinary(value)));
  assert.equal(back.name, "ceremony");
  assert.ok(back.challenge instanceof Uint8Array);
  assert.deepEqual(Array.from(back.challenge), [1, 2, 3, 250]);
  assert.ok(back.list[0].rawId instanceof Uint8Array);
  assert.deepEqual(Array.from(back.list[0].rawId), [9, 8]);
  assert.equal(back.list[1], "plain");
  assert.ok(ArrayBuffer.isView(back.credential.rawId), "the raw ArrayBuffer member arrives as bytes, not {}");
  assert.deepEqual(Array.from(back.credential.rawId), [11, 22, 33]);
  assert.deepEqual(Array.from(back.credential.response.attestationObject), [44, 55, 66, 77]);
  assert.deepEqual(Array.from(back.credential.response.clientDataJSON), [7, 7, 7]);
});

// ── The authzen decision mapping ────────────────────────────────────────

test("the authzen plugin maps boolean and non-boolean decisions to the engine's trust answer", async () => {
  const cases = [
    [{ decision: "Permit" }, { trusted: true, decision: "Permit" }],
    [{ decision: "Deny" }, { trusted: false, decision: "Deny" }],
    [{ decision: true }, { trusted: true, decision: "Permit" }],
    [{ decision: false }, { trusted: false, decision: "Deny" }],
    [{ decision: "Indeterminate", context: { why: "no registry" } }, { trusted: false, decision: "Indeterminate" }],
    [{}, { trusted: false, decision: "Deny" }],
    ["not json", { trusted: false, decision: "Deny" }],
  ];
  const realFetch = globalThis.fetch;
  try {
    for (const [wire, expected] of cases) {
      globalThis.fetch = async () =>
        new Response(typeof wire === "string" ? wire : JSON.stringify(wire), { status: 200 });
      const plugin = new AuthzenTrustPlugin("https://pdp.example/evaluation");
      const answer = await plugin.evaluate({});
      assert.deepEqual({ trusted: answer.trusted, decision: answer.decision }, expected);
      if (wire.context) assert.deepEqual(answer.context, wire.context, "the context rides along");
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ── The offer resolution through the page's fetch port ─────────────────

test("an https offer URI resolves through the page's fetch port into the flow's start params", async () => {
  const starts = [];
  class FakeEngine {
    constructor(config) {
      this.config = config;
    }
    async request(method, params) {
      if (method === "wmp.session.create") return { wmp: { session_id: "ses-x" } };
      if (method === "wmp.flow.start") {
        starts.push(params);
        // The bare started envelope: the flow stays open (the sink never
        // fires in this test) — the start params are the assertion.
        return { flow_id: params.flow_id, flow_type: "oid4vci", wmp: {} };
      }
      throw new Error(`unexpected engine call: ${method}`);
    }
  }
  const offer = {
    credential_issuer: "https://issuer.example",
    credential_configuration_ids: ["nym_auth"],
    grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "x" } },
  };
  const wallet = fakeEngineWallet({
    WasmEngine: FakeEngine,
    onEvent: () => {},
    fetch: async (request) => ({
      status: 200,
      headers: ["content-type", "application/json"],
      body: Array.from(new TextEncoder().encode(JSON.stringify(offer))),
    }),
  });
  wallet.receiveCredential("https://issuer.example/offers?session_id=abc");
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(starts.length, 1, "exactly one flow start");
  assert.equal(starts[0].params.credential_issuer, "https://issuer.example");
  assert.deepEqual(starts[0].params.credential_configuration_ids, ["nym_auth"]);
  assert.ok(starts[0].params.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
    "the pre-authorized grant rides the start params");
});
