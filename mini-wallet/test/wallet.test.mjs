// The mini-wallet's node-testable surface: the storage contract, the
// migration (the deferred onboarding), and the offer/request
// normalization. The wasm flows are the page's browser tests (the engine
// loads there); these pin everything the library owns around it.

import test from "node:test";
import assert from "node:assert/strict";

import {
  LocalStorageWalletStorage,
  MemoryWalletStorage,
  memoryStore,
  migrateWalletStorage,
  MiniWallet,
  isOfferUri,
  normalizeOffer,
  unwrapOffer,
  unwrapAuthorizationRequest,
} from "../dist/index.js";

// ── The storage contract ───────────────────────────────────────────────

test("the memory backend stores and lists", async () => {
  const s = new MemoryWalletStorage();
  assert.equal(await s.get("a"), null);
  await s.put("a", "1");
  await s.put("b", "2");
  assert.equal(await s.get("a"), "1");
  assert.deepEqual((await s.list()).sort(), ["a", "b"]);
  assert.deepEqual(await s.list("a"), ["a"]);
  await s.del("a");
  assert.equal(await s.get("a"), null);
  assert.deepEqual(await s.list(), ["b"]);
});

test("the localStorage backend namespaces and lists", async () => {
  const store = memoryStore();
  const s = new LocalStorageWalletStorage("demo", store);
  await s.put("credential:1", "{}");
  await s.put("stash:flow", "state");
  // An unrelated page key never shows in the wallet's listing.
  store.setItem("other:key", "x");
  assert.deepEqual((await s.list()).sort(), ["credential:1", "stash:flow"]);
  assert.deepEqual(await s.list("credential:"), ["credential:1"]);
  assert.equal(await s.get("credential:1"), "{}");
  await s.del("credential:1");
  assert.equal(await s.get("credential:1"), null);
});

// ── The migration: the deferred onboarding ─────────────────────────────

test("a migration copies everything, verifies, then deletes the source", async () => {
  const source = new MemoryWalletStorage();
  await source.put("credential:1", "c1");
  await source.put("credential:2", "c2");
  await source.put("key:device", "the-device-jwk");
  await source.put("stash:flow", "flow-state");
  const target = new MemoryWalletStorage();

  const report = await migrateWalletStorage(source, target);

  assert.deepEqual(report.keys.sort(), ["credential:1", "credential:2", "key:device", "stash:flow"]);
  assert.equal(report.failed, undefined);
  assert.equal(await target.get("key:device"), "the-device-jwk");
  assert.equal(await source.get("key:device"), null, "the source is empty after a clean migration");
  assert.deepEqual(await source.list(), []);
});

test("a failing target aborts before anything is deleted", async () => {
  const source = new MemoryWalletStorage();
  await source.put("credential:1", "good");
  await source.put("credential:2", "lost");
  const flaky = {
    map: new Map(),
    async get(key) {
      return this.map.get(key) ?? null;
    },
    async put(key, value) {
      // The second write "succeeds" but the read-back loses it.
      this.map.set(key, value === "lost" ? "" : value);
    },
    async del(key) {
      this.map.delete(key);
    },
    async list() {
      return [...this.map.keys()];
    },
  };
  await source.list(); // warm
  const seeded = new MemoryWalletStorage();
  await seeded.put("credential:1", "good");
  await seeded.put("credential:2", "lost");
  const report = await migrateWalletStorage(seeded, flaky);
  assert.equal(report.failed, "credential:2", "the lost write is named");
  assert.equal(await seeded.get("credential:1"), "good", "the SOURCE keeps everything on failure");
});

test("the wallet swaps its backend after a clean migration", async () => {
  const first = new MemoryWalletStorage();
  await first.put(
    "credential:1",
    JSON.stringify({ format: "mso_mdoc", credential: "the-credential", received_at_unix: 1 }),
  );
  const wallet = new MiniWallet({ storage: first, pdp: { evaluate: async () => ({ trusted: true }) } });
  const next = new MemoryWalletStorage();
  const report = await wallet.migrate(next);
  assert.equal(report.failed, undefined);
  const creds = await wallet.credentials();
  assert.equal(creds.length, 1, "the credential survived into the new backend");
  assert.equal(creds[0].key, "credential:1");
  assert.deepEqual(await first.list(), [], "the old backend is drained");
});

// ── The offer / request normalization ────────────────────────────────────

const offer = {
  credential_issuer: "https://issuer.example",
  credential_configuration_ids: ["eu.europa.ec.eudi.nym_auth.1"],
  grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "abc" } },
};

test("offer URIs are recognized and unwrapped", () => {
  assert.ok(isOfferUri("https://issuer.example/credential-offer/of_1"));
  assert.ok(isOfferUri("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2Fo"));
  assert.ok(!isOfferUri("not a uri"));

  const uri = unwrapOffer("https://issuer.example/credential-offer/of_1");
  assert.equal(uri.uri, "https://issuer.example/credential-offer/of_1");
  assert.equal(uri.source, "uri");

  const deep = unwrapOffer(
    `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`,
  );
  assert.equal(deep.source, "deep-link");
  assert.deepEqual(deep.offer, offer);

  assert.throws(() => unwrapOffer("openid-credential-offer://?nothing=1"), /neither/);
  assert.throws(() => unwrapOffer("web+something://"), /not an offer/);
});

test("offers normalize into the flow's start params", () => {
  const n = normalizeOffer(offer, "uri");
  assert.equal(n.credential_issuer, "https://issuer.example");
  assert.deepEqual(n.credential_configuration_ids, ["eu.europa.ec.eudi.nym_auth.1"]);
  assert.equal(n.source, "uri");
  // The credentials[] alias (the batch member some issuers send) reads too.
  const batch = normalizeOffer({ ...offer, credentials: offer.credential_configuration_ids }, "uri");
  assert.deepEqual(batch.credential_configuration_ids, offer.credential_configuration_ids);
  assert.throws(() => normalizeOffer({ grants: {} }, "uri"), /no credential_issuer/);
  assert.throws(() => normalizeOffer({ ...offer, grants: undefined }, "uri"), /no grants/);
});

test("authorization requests unwrap into the oid4vp flow's params", () => {
  const deep = unwrapAuthorizationRequest(
    "openid4vp://?client_id=https%3A%2F%2Fverifier.example&request_uri=https%3A%2F%2Fverifier.example%2Fvp%2Frequest%2F1",
  );
  assert.equal(deep.source, "deep-link");
  assert.equal(deep.params.client_id, "https://verifier.example");
  assert.equal(deep.params.request_uri, "https://verifier.example/vp/request/1");

  const uri = unwrapAuthorizationRequest("https://verifier.example/vp/request/1");
  assert.equal(uri.source, "uri");
  assert.deepEqual(uri.params, { request_uri: "https://verifier.example/vp/request/1" });

  assert.throws(() => unwrapAuthorizationRequest("not a request"), /not an authorization request/);
});

// ── The wallet's construction contract ──────────────────────────────────

test("the wallet requires a PDP and defaults its storage", () => {
  assert.throws(() => new MiniWallet({}), /pdp/);
  const wallet = new MiniWallet({ pdp: { evaluate: async () => ({ trusted: true }) } });
  assert.ok(wallet, "the pdp alone constructs — the storage defaults to the browser localStorage");
});

test("the wallet stores delivered credentials with their response metadata", async () => {
  const storage = new MemoryWalletStorage();
  const wallet = new MiniWallet({ storage, pdp: { evaluate: async () => ({ trusted: true }) } });
  const w2 = new MiniWallet({
    storage,
    pdp: { evaluate: async () => ({ trusted: true }) },
  });
  // The completion handler runs only with the engine (the wasm); the
  // storage round-trip below is what the page consumes:
  await storage.put(
    "credential:1",
    JSON.stringify({
      format: "mso_mdoc",
      credential_configuration_id: "eu.europa.ec.eudi.nym_auth.1",
      credential: "the-mdoc",
      credential_metadata: { auxiliary_data: [{ type: "hash_commitment", opening: "the-ssc-opening" }] },
      received_at_unix: 1795000000,
    }),
  );
  const creds = await w2.credentials();
  assert.equal(creds.length, 1);
  assert.equal(creds[0].format, "mso_mdoc");
  assert.equal(creds[0].configurationId, "eu.europa.ec.eudi.nym_auth.1");
  const raw = await w2.rawCredential("credential:1");
  assert.equal(raw.credential, "the-mdoc");
  assert.equal(raw.credential_metadata.auxiliary_data[0].opening, "the-ssc-opening",
    "the nym_auth ssc opening rides the stored record — what the zkp presenter reads back");
  assert.equal(await w2.rawCredential("stash:flow"), null, "only credential records come back raw");
});

// ── The adopt flow: the page's mini-wallet becomes a permanent wallet ────

/** A mock go-wallet-backend: the passkey begin/finish, the private-data
 *  blob store with ETags — the shapes the real one serves. */
function mockBackend() {
  const state = { account: null, blob: null, etag: null, asks: 0 };
  const server = {
    async registerPasskey(ui) {
      const credential = await ui.create({ challenge: "the-begin-options" });
      state.account = "user-1";
      return { account: "user-1" };
    },
    storage() {
      const read = () => (state.blob ? JSON.parse(new TextDecoder().decode(new Uint8Array(state.blob))) : {});
      const write = (records) => {
        state.blob = Array.from(new TextEncoder().encode(JSON.stringify(records)));
        state.etag = `"${state.blob.length}"`;
      };
      return {
        async get(key) { return read()[key] ?? null; },
        async put(key, value) { const r = read(); r[key] = value; write(r); },
        async del(key) { const r = read(); delete r[key]; write(r); },
        async list(prefix) {
          const keys = Object.keys(read());
          return prefix === undefined ? keys : keys.filter((k) => k.startsWith(prefix));
        },
      };
    },
    trustPlugin() {
      return { async evaluate() { return { trusted: true, decision: "Permit" }; } };
    },
    get backend() { return "https://backend.example"; },
  };
  return { state, server };
}

test("adopt moves the credential into the backend and swaps the authz", async () => {
  const { state, server } = mockBackend();
  const storage = new MemoryWalletStorage();
  await storage.put(
    "credential:1",
    JSON.stringify({ format: "mso_mdoc", credential: "the-mdoc", credential_metadata: { the: "ssc" }, received_at_unix: 1 }),
  );
  await storage.put("key:device", '{"kty":"EC"}');
  const events = [];
  const wallet = new MiniWallet({
    storage,
    pdp: { evaluate: async () => ({ trusted: true }) },
    onEvent: (e) => events.push(e),
  });

  const report = await wallet.adopt({
    target: server,
    ui: {
      ask: async (a) => {
        state.asks += 1;
        if (a.backend !== "https://backend.example") throw new Error("the ask's backend context");
        if (a.credentials.length !== 1) throw new Error("the ask's credential context");
        return true;
      },
      create: async (options) => ({ id: "created-over-" + JSON.stringify(options.challenge) }),
    },
  });

  assert.equal(state.account, "user-1", "the passkey registered");
  assert.equal(report.account, "user-1");
  assert.deepEqual(report.keys.sort(), ["credential:1", "key:device"]);
  assert.equal(report.failed, undefined);
  // The records live on the backend now; the local copies are gone.
  assert.deepEqual(await storage.list(), []);
  const backendRecords = JSON.parse(new TextDecoder().decode(new Uint8Array(state.blob)));
  // The KV values are the records' serialized envelopes (the storage
  // contract: opaque strings).
  assert.equal(JSON.parse(backendRecords["credential:1"]).credential, "the-mdoc");
  assert.equal(backendRecords["key:device"], '{"kty":"EC"}');
  // The wallet's further reads come from the backend.
  const creds = await wallet.credentials();
  assert.equal(creds.length, 1);
  assert.equal(creds[0].key, "credential:1");
  // The authz swapped to the backend's PDP-proxy.
  assert.ok(events.some((e) => e.type === "adopted" && e.backend === "https://backend.example"));
  const raw = await wallet.rawCredential("credential:1");
  assert.equal(raw.credential_metadata.the, "ssc", "the ssc opening moved with the record");
});

test("a refused ask adopts nothing", async () => {
  const { state, server } = mockBackend();
  const storage = new MemoryWalletStorage();
  await storage.put("credential:1", JSON.stringify({ format: "mso_mdoc", credential: "x" }));
  const wallet = new MiniWallet({ storage, pdp: { evaluate: async () => ({ trusted: true }) } });
  const report = await wallet.adopt({
    target: server,
    ui: { ask: async () => false, create: async () => ({}) },
  });
  assert.equal(report, null, "the ask's veto aborts");
  assert.equal(state.account, null, "no passkey registered");
  assert.equal((await wallet.credentials()).length, 1, "the credential stays local");
});

test("a failed move keeps the local wallet intact", async () => {
  const { server } = mockBackend();
  const flaky = {
    ...server,
    storage() {
      const inner = server.storage();
      return {
        ...inner,
        async put(key, value) {
          if (key === "credential:2") return; // the write "succeeds" but the read-back loses it
          return inner.put(key, value);
        },
      };
    },
  };
  const storage = new MemoryWalletStorage();
  await storage.put("credential:2", JSON.stringify({ format: "mso_mdoc", credential: "lost" }));
  const wallet = new MiniWallet({ storage, pdp: { evaluate: async () => ({ trusted: true }) } });
  const report = await wallet.adopt({
    target: flaky,
    ui: { ask: async () => true, create: async () => ({}) },
  });
  assert.equal(report.failed, "credential:2");
  assert.equal((await wallet.credentials()).length, 1, "the LOCAL wallet keeps everything on failure");
});

// ── The backend configuration: the PDP-proxy from the first issuance ────

test("a backend-configured wallet trusts through the backend's PDP-proxy", async () => {
  const evaluations = [];
  const tokens = [];
  // A stand-in backend: the /v1/evaluate the trust layer hits.
  const backendUrl = "https://backend.example";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith("/v1/evaluate")) {
      evaluations.push({ auth: init?.headers?.Authorization ?? null, body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ decision: true }), { headers: { "Content-Type": "application/json" } });
    }
    throw new Error("unexpected fetch: " + url);
  };
  try {
    const storage = new MemoryWalletStorage();
    const wallet = new MiniWallet({
      storage,
      backend: {
        url: backendUrl,
        token: async () => { tokens.push("the-pre-registration-token"); return "the-pre-registration-token"; },
      },
    });
    // The trust layer consults the backend's proxy with the
    // pre-registration token — before any user exists.
    const answer = await wallet.evaluateTrust({ action: "credential-issuer" });
    assert.equal(answer.trusted, true);
    assert.equal(evaluations.length, 1);
    assert.equal(evaluations[0].auth, "Bearer the-pre-registration-token",
      "the initial issuance's trust carries the pre-registration tenant token");
    assert.equal(tokens.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("after the adopt the session's token carries the evaluations", async () => {
  const evaluations = [];
  const backendUrl = "https://backend.example";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith("/v1/evaluate")) {
      evaluations.push(init?.headers?.Authorization ?? null);
      return new Response(JSON.stringify({ decision: true }), { headers: { "Content-Type": "application/json" } });
    }
    throw new Error("unexpected fetch: " + url);
  };
  try {
    const storage = new MemoryWalletStorage();
    await storage.put("credential:1", JSON.stringify({ format: "mso_mdoc", credential: "x" }));
    const wallet = new MiniWallet({
      storage,
      backend: { url: backendUrl, token: async () => "the-pre-registration-token" },
    });
    await wallet.evaluateTrust({ action: "credential-issuer" });
    const target = {
      backend: backendUrl,
      registerPasskey: async (ui) => { await ui.create({}); return { account: "user-1" }; },
      storage: () => new MemoryWalletStorage(),
      trustPlugin: () => ({ async evaluate() { return { trusted: true }; } }),
      // The factory shape: sessionToken() returns the PROVIDER.
      sessionToken: () => async () => "the-session-token",
    };
    await wallet.adopt({ target, ui: { ask: async () => true, create: async (o) => ({ o }) } });
    await wallet.evaluateTrust({ action: "credential-verifier" });
    // The continuity: pre-registration first, the session's after.
    assert.deepEqual(evaluations, [
      "Bearer the-pre-registration-token",
      "Bearer the-session-token",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
