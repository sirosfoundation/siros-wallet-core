#!/usr/bin/env node
// The realeyes example's harness: the page hosts the mini-wallet and its
// own embedded issuer flow rides the LIVE demo-web (the stub face check
// mints a real pre-authorized offer server-side); this little server
// serves the static pieces and proxies the two origins the browser
// cannot reach directly (CORS):
//   /api/pdp/*    -> the realeyes go-trust PDP (the AuthZEN evaluation,
//                   the answer mapped to the engine's {trusted, …})
//   /api/demo/*   -> the live demo-web (the start/complete/status mint)
// Everything else is static: the library dist, the engine wasm, the page.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { SignJWT, importJWK } from "jose";

const ISSUER = process.env.ISSUER_URL || "https://sirosid-realeyes-siros-issuer.fly.dev";
const BACKEND = process.env.BACKEND_URL || "https://sirosid-gdc-wallet-proxy.fly.dev";
// The integrator's JWK (the Mode A assertion's signing key). REQUIRED:
// point it at your environment's integrator JWK file.
const JWK_PATH = process.env.INTEGRATOR_JWK_FILE;
if (!JWK_PATH) {
  console.error("INTEGRATOR_JWK_FILE is not set — point it at your integrator JWK (the assertion's signing key).");
  process.exit(1);
}
const PDP = process.env.PDP_URL || "https://sirosid-realeyes-pdp.fly.dev";
const BIND = process.env.BIND || "127.0.0.1:8128";
const HERE = fileURLToPath(new URL(".", import.meta.url));

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
};

const DOCTYPE = "eu.europa.ec.eudi.nym_auth.1";

/** The Mode A integrator: sign the client-assertion with the
 *  environment's persistent JWK and push the synthetic subject — the
 *  same role the demo-web plays for its page. The birth date is a
 *  canned over-18 estimate. */
async function mint() {
  const jwk = JSON.parse(await readFile(JWK_PATH, "utf8"));
  const key = await importJWK(jwk, jwk.alg || "ES256");
  const { d: _d, ...publicJwk } = jwk;
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: jwk.alg || "ES256", kid: jwk.kid, jwk: publicJwk })
    .setIssuer(jwk.kid)
    .setSubject(jwk.kid)
    .setAudience(ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
  const response = await fetch(`${ISSUER}/api/v1/issuance/sessions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${assertion}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      credential: DOCTYPE,
      subject: {
        [DOCTYPE]: {
          birth_date: "1994-06-06",
          issuing_country: "SE",
          personal_administrative_number: `example-${crypto.randomUUID()}`,
        },
      },
      authentic_source: "mini-wallet-example",
      ttl_seconds: 900,
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`the issuer refused the mint: ${response.status} ${JSON.stringify(body).slice(0, 200)}`);
  return body;
}

// DEMO/DEV ONLY — never deploy this server: the /api/* routes are open
// reflectors (the issuer and backend proxies forward whatever arrives,
// unauthenticated) and the mint signs assertions with YOUR integrator
// key. It exists so a browser page can reach origins that serve no CORS.
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "POST" && url.pathname === "/api/mint") {
      const session = await mint();
      return json(res, 200, {
        offer_uri: session.offer_uri,
        wallet_redirect: session.wallet_redirect,
        session_id: session.session_id,
      });
    }
    if (url.pathname.startsWith("/api/backend/")) {
      // The wallet-backend proxy: the AS (the passkey register
      // begin/finish), the per-user private-data store, the PDP-proxy
      // (/v1/evaluate). The browser cannot cross-origin it.
      const path = url.pathname.slice("/api/backend".length) + url.search;
      const init = { method: req.method, headers: {} };
      const HOPB = new Set(["host", "connection", "content-length", "accept-encoding", "accept", "user-agent", "origin", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-language"]);
      for (const [k, v] of Object.entries(req.headers)) {
        if (!HOPB.has(k)) init.headers[k] = v;
      }
      if (req.method !== "GET" && req.method !== "HEAD") init.body = await readBody(req);
      const upstream = await fetch(`${BACKEND}${path}`, init);
      const text = await upstream.text();
      console.log(`[backend] ${req.method} ${path} -> ${upstream.status}`);
      const out = { "content-type": upstream.headers.get("content-type") ?? "application/json" };
      const setCookie = upstream.headers.getSetCookie?.() ?? [];
      if (setCookie.length) out["set-cookie"] = setCookie.join("||");
      res.writeHead(upstream.status, out);
      return res.end(text);
    }
    if (url.pathname.startsWith("/api/issuer/")) {
      // The issuer proxy: a browser wallet cannot cross-origin the
      // issuer (no CORS on the OID4VCI surface); the page's fetch port
      // rewrites issuer URLs onto this proxy.
      const path = url.pathname.slice("/api/issuer".length) + url.search;
      // Forward the meaningful headers verbatim — the engine's DPoP
      // and the access token's Authorization ride the same hop (dropping
      // them made the credential endpoint answer "missing access token"
      // with the token right there in the request; found on the wire).
      const HOP = new Set(["host", "connection", "content-length", "accept-encoding", "accept", "user-agent", "origin", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "accept-language"]);
      const init = { method: req.method, headers: {} };
      for (const [k, v] of Object.entries(req.headers)) {
        if (!HOP.has(k)) init.headers[k] = v;
      }
      if (req.method !== "GET" && req.method !== "HEAD") {
        init.body = await readBody(req);
      }
      const upstream = await fetch(`${ISSUER}${path}`, init);
      const text = await upstream.text();
      // Method, path, status — NOTHING ELSE: the request headers carry
      // Authorization tokens and DPoP proofs, the bodies carry
      // pre-authorized codes. A proxy that logs them leaks every
      // credential the demo mints.
      console.log(`[issuer] ${req.method} ${path} -> ${upstream.status}`);
      res.writeHead(upstream.status, {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
      });
      return res.end(text);
    }
    if (req.method === "POST" && url.pathname.startsWith("/api/pdp")) {
      // The AuthZEN evaluation, forwarded; the go-trust answer mapped to
      // the engine's Pdp answer ({trusted, decision?, context?}).
      const body = await readBody(req);
      const upstream = await fetch(`${PDP}/evaluation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
      });
      const answer = await upstream.json().catch(() => ({}));
      return json(res, upstream.status, {
        trusted: answer.decision === "Permit",
        decision: answer.decision,
        context: answer.context,
      });
    }
    // Static: / -> the page; /lib/* -> the built library; /engine/* ->
    // the published engine (its js + wasm). Each route guards against
    // its OWN root: /lib and /engine resolve OUTSIDE the example's
    // directory (../../dist, ../../node_modules), so a HERE-prefix guard
    // 404s the harness's own assets — the guard must name the root it
    // serves from, never a broader one.
    const distRoot = join(HERE, "../../dist");
    const engineRoot = join(HERE, "../../node_modules/@sirosfoundation/siros-wallet-core");
    let file = null;
    let fileRoot = null;
    if (url.pathname === "/") { file = join(HERE, "index.html"); fileRoot = HERE; }
    else if (url.pathname.startsWith("/lib/")) { file = join(distRoot, url.pathname.slice(5)); fileRoot = distRoot; }
    else if (url.pathname.startsWith("/engine/")) { file = join(engineRoot, url.pathname.slice(8)); fileRoot = engineRoot; }
    else if (url.pathname === "/client.js") { file = join(HERE, "client.js"); fileRoot = HERE; }
    if (!file || !fileRoot || !normalize(file).startsWith(normalize(fileRoot))) return notFound(res);
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
      return res.end(body);
    } catch {
      return notFound(res);
    }
  } catch (e) {
    return json(res, 500, { message: e.message });
  }
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function notFound(res) {
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
}

const [host, port] = BIND.split(":");
server.listen(Number(port), host, () => {
  console.log(`the realeyes mini-wallet example on http://${BIND}`);
  console.log(`  issuer: ${ISSUER} · pdp: ${PDP}`);
});
