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
