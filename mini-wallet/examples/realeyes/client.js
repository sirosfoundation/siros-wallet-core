// The realeyes example page: the embedded issuer flow (the demo-web's
// stub face check mints the offer) beside the mini-wallet that receives
// it — the pattern the library exists for. The UI here is deliberately
// terminal-simple: the page owns every decision (the consent answers
// true for the harness; a real page asks its person).

import { MiniWallet, LocalStorageWalletStorage, AlwaysTrustedPlugin } from "/lib/index.js";
import init, { WasmEngine } from "/engine/engine_adapter_wasm.js";

const out = document.getElementById("out");
const cred = document.getElementById("cred");
const log = (text) => {
  out.textContent = text;
};

document.getElementById("run").addEventListener("click", async () => {
  try {
    log("1/4 minting the offer through the page's issuer flow (the integrator mint)…");
    const minted = await fetch("/api/mint", { method: "POST" }).then((r) => r.json());
    if (!minted.offer_uri) throw new Error(`the mint gave no offer: ${JSON.stringify(minted).slice(0, 200)}`);
    log(`2/4 the offer: ${minted.offer_uri.slice(0, 60)}…\nreceiving into the mini-wallet…`);

    const storage = new LocalStorageWalletStorage("realeyes-example");
    // The page's fetch: the issuer URLs onto this harness's proxy — the
    // engine's EVERY request (the offer, the metadata, the token, the
    // credential) crosses here; the MiniWallet's offer fetch too.
    const ISSUER = "https://sirosid-realeyes-siros-issuer.fly.dev";
    const pageFetch = async (request) => {
      const req = request;
      const headers = {};
      for (let i = 0; i + 1 < req.headers.length; i += 2) headers[req.headers[i]] = req.headers[i + 1];
      const url = req.url.startsWith(ISSUER)
        ? "/api/issuer" + req.url.slice(ISSUER.length)
        : req.url;
      const init = { method: req.method, headers };
      // The engine's port sends body: null on bodyless requests (the
      // fetch API refuses a body on GET/HEAD), and its bodies are BYTE
      // ARRAYS - fetch stringifies a bare array comma-joined, so the
      // bytes must cross as bytes.
      if (req.body != null && req.method !== "GET" && req.method !== "HEAD") {
        init.body = typeof req.body === "string" ? req.body : new Uint8Array(req.body);
      }
      const response = await fetch(url, init);
      const flat = [];
      response.headers.forEach((value, name) => flat.push(name, value));
      // The port's body is BYTES (the engine's Vec<u8>), not text.
      const body = Array.from(new TextEncoder().encode(await response.text()));
      return { status: response.status, headers: flat, body };
    };
    const wallet = new MiniWallet({
      // The storage: this browser's localStorage — unencrypted for now;
      // a passkey migrates it later without losing anything.
      storage,
      fetch: pageFetch,
      // The trust layer — the DEMO SHIM for the INITIAL issuance
      // (AlwaysTrustedPlugin, no authzen client). The backend
      // configuration flips this to gdc's PDP-proxy the moment
      // go-wallet-backend#566's pre-registration tenant token ships
      // (the slot is wired below); post-adopt the session's token
      // carries the evaluations either way.
      pdp: new AlwaysTrustedPlugin(),
      // ALL UI delegated: the consent is this page's answer (the harness
      // says yes; a real page asks).
      ui: { consent: async () => ({ consented: true }) },
      wasmUrl: "/engine/engine_adapter_wasm_bg.wasm",
      // The engine module, loaded the page's way (a URL import here; a
      // bundler resolves the package name in a real app).
      engine: { init, WasmEngine },
      onEvent: (e) => {
        if (e.type === "progress") log(`… ${e.step}`);
      },
    });

    const result = await wallet.receiveCredential(minted.offer_uri);
    const list = await wallet.credentials();
    if (!list.length) throw new Error(`the flow completed with no credential: ${JSON.stringify(result).slice(0, 300)}`);

    log("3/4 the credential received; reading the stored record…");
    const raw = await wallet.rawCredential(list[0].key);
    const sscOpening = raw?.credential_metadata?.auxiliary_data?.[0]?.opening;
    const deviceKey = await storage.get("key:device");

    cred.style.display = "block";
    cred.innerHTML = `
      <p><strong>Stored in this browser's localStorage:</strong></p>
      <ul>
        <li>format: <code>${String(raw.format)}</code></li>
        <li>configuration: <code>${String(raw.credential_configuration_id)}</code></li>
        <li>the credential: <code>${String(raw.credential).slice(0, 48)}…</code> (${String(raw.credential).length} chars)</li>
        <li>the ssc opening (the zkp proofs' seed): <code>${sscOpening ? String(sscOpening).slice(0, 24) + "…" : "ABSENT"}</code></li>
        <li>the device key: <code>${deviceKey ? "present (an ES256 JWK)" : "ABSENT"}</code></li>
      </ul>`;
    log("4/4 the credential received. The adopt runs as a modal…");

    // The permanent-wallet arc: the ask (this page's), the passkey
    // (the browser's real WebAuthn ceremony over gdc's AS), the move
    // (the migration contract onto gdc's private-data store). The
    // backend rides the page's proxy (the browser cannot cross-origin
    // it); a real deployment serves the page from the backend's own
    // origin or its CORS list.
    const adopt = await wallet.adopt({
      target: new (await import("/lib/index.js")).GoWalletBackendTarget("/api/backend", "default"),
      // The adopt as a MODAL (the decision: the page serves from the
      // wallet's origin, the onboard/set-passkey/move arc runs as a
      // modal) — the library renders the steps; the ceremony stays the
      // browser's own prompt.
      modal: true,
      ui: {
        ask: async () => true,
        create: (options) => navigator.credentials.create(options),
      },
    });
    if (!adopt) {
      log("4/4 done — the credential stays in the page's wallet (the adopt declined).");
    } else if (adopt.failed) {
      log(`the adopt's move failed at ${adopt.failed} — the page's wallet is intact.`);
    } else {
      cred.innerHTML += `<p><strong>Adopted:</strong> account <code>${adopt.account}</code> on <code>gdc</code> — ${adopt.keys.length} records moved; the wallet's authz is now the backend's PDP-proxy (the session's token).</p>`;
      log("done — a permanent wallet on the gdc backend holds the credential.");
    }
  } catch (e) {
    log(`the flow stopped: ${e && e.data ? JSON.stringify(e).slice(0, 700) : (e && e.message ? e.message : JSON.stringify(e).slice(0, 700))}`);
  }
});
