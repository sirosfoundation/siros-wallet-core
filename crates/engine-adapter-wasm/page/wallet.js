// The mini-wallet harness: the page that drives the raw engine against
// the OIDF certification suites (docs/oidf-conformance.md). Playwright
// navigates this page by URL and answers its dialogs; the suites judge
// the engine by its HTTP traffic.
//
// The URL contract:
//   ?offer=<url>            — an OID4VCI credential offer (the suite's
//                             offer link / QR target)
//   ?request=<url>          — an OID4VP authorization request URL
//   ?code=…&state=…         — the AS redirect back (the auth-code grant's
//                             second WMP call)
//
// The engine config comes from the same origin's mini-wallet.json (the
// fetch and PDP endpoints of the conformance compose stack), or
// window.MINI_WALLET_CONFIG if the page wants to inline it.

// The engine's callbacks from the plain endpoints of mini-wallet.json.
// JSON cannot carry functions, so the page builds them: the fetch
// forwards to the suite's endpoints (CORS is the suite's), the PDP
// evaluates through the trust proxy, and the kv persists the flow stash
// and the credentials in localStorage — the authorization-code resume
// survives the redirect's page reload.
async function engineConfig() {
  if (window.MINI_WALLET_CONFIG) return window.MINI_WALLET_CONFIG;
  const endpoints = await loadEndpoints();

  const fetchImpl = async (request) => {
    const headers = new Headers();
    for (let i = 0; i < request.headers.length; i += 2) {
      headers.append(request.headers[i], request.headers[i + 1]);
    }
    const response = await fetch(request.url, {
      method: request.method,
      headers,
      body: request.body.length ? new Uint8Array(request.body) : undefined,
    });
    const body = new Uint8Array(await response.arrayBuffer());
    const flat = [];
    for (const [name, value] of response.headers.entries()) {
      flat.push(name, value);
    }
    return { status: response.status, headers: flat, body: Array.from(body) };
  };

  // The engine's EvaluationRequest, translated to the trust proxy's
  // AuthZEN shape (go-trust's POST /evaluation): the subject is the
  // issuer or verifier's identifier, the resource the key material,
  // the action the trust role. The answer translates back — tolerantly:
  // go-trust answers decision: "PERMIT" (AuthZEN), and the internal
  // shape also carries trusted/reason/trust_framework for the context.
  // The engine's EvaluationRequest, translated to go-trust's AuthZEN
  // /evaluation: the subject is the issuer's identifier, the resource
  // the key material (go-trust requires the resource's id too — the
  // issuer's identifier), the action the trust role. The answer's
  // decision is a boolean; the context's reason names the registry.
  const evaluate = (request) =>
    fetch(endpoints.trustProxyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        subject: { type: 'key', id: request.subject },
        resource: {
          type: 'jwk',
          id: request.subject,
          key: Array.from(new TextEncoder().encode(request.key_material)),
        },
        action: { name: request.resource_type || 'credential-issuer' },
      }),
    })
      .then((r) => r.json())
      .then((answer) => {
        const reason = answer.context && answer.context.reason;
        return {
          trusted: answer.decision === true || answer.trusted === true,
          decision: typeof reason === 'string'
            ? reason
            : ((reason && (reason.registry || reason.type)) || '') + '',
        };
      });

  // The kv over localStorage: the flow stash and the credential store
  // survive the redirect's page reload.
  const kv = {
    get: (key) => { console.log('[mini-wallet] kv.get:', key); return Promise.resolve(localStorage.getItem('mini-wallet-kv:' + key)); },
    put: (key, value) => { console.log('[mini-wallet] kv.put:', key, String(value).slice(0, 80)); localStorage.setItem('mini-wallet-kv:' + key, value); return Promise.resolve(); },
    del: (key) => { console.log('[mini-wallet] kv.del:', key); localStorage.removeItem('mini-wallet-kv:' + key); return Promise.resolve(); },
  };

  window.__mini_debug = { clientKey: endpoints.clientKeyJwk ? 'present' : 'absent' };
  return {
    fetch: fetchImpl,
    host: 'mini',
    txCode: endpoints.txCode,
    // The user-agent navigations: the authorization-code flow's AS
    // login, and the direct_post answer's redirect_uri (OID4VP §8.2).
    openAuthorization,
    // The registered client key (private_key_jwt's signing key) — the
    // mini host parses the JWK and routes its sign asks by the kid, so
    // the client assertion is signed by the key the plan registered.
    clientKeyJwk: endpoints.clientKeyJwk,
    pdp: { evaluate },
    kv,
  };
}

// The endpoints from mini-wallet.json, cached once loaded — the
// wallet identity (client_id, the client key's kid) rides the flow
// start params, so it is read outside the engine config too.
let endpointsData = null;
async function loadEndpoints() {
  if (!endpointsData) {
    const response = await fetch('mini-wallet.json');
    endpointsData = await response.json();
  }
  return endpointsData;
}

async function ensureEngine() {
  if (!window.__engine) {
    try {
      // The wasm module boots asynchronously: await it before anything
      // touches the Engine constructor.
      await window.__engine_boot;
      const config = await engineConfig();
      window.__engine = await Engine.new(config);  // set by wallet_glue.js
    } catch (err) {
      window.__last_error = { engine_boot: String(err && (err.message || err)) };
      throw err;
    }
  }
  return window.__engine;
}

async function wmp(method, params) {
  const engine = await ensureEngine();
  try {
    return await engine.request(method, params);
  } catch (err) {
    // The JSON-RPC error object: surface the code and message, keep
    // the object on the window for the tests to inspect.
    window.__last_error = err;
    console.error('[mini-wallet]', method, err && err.code, err && err.message);
    throw err;
  }
}

// The pending state from an authorization-code start: the flow stays
// open and the redirect's answer arrives as wmp.flow.action.
let pendingAuthFlow = null;

function query(name) {
  return new URLSearchParams(window.location.search).get(name);
}

// The authorization step: navigate. Playwright answers the suite's AS
// login page, and the AS redirects back to this page with ?code&state.
async function openAuthorization(url) {
  window.location.assign(url);
}

async function startOffer(offerUrl) {
  const e = await loadEndpoints();
  const session = await wmp('wmp.session.create', {
    wmp: { version: '0.1', sender: 'mini-wallet' },
    capabilities_offered: { flows: { max_concurrent: 16 } },
    security: { mode: 'tls' },
  });
  console.log('[mini-wallet] session create:', JSON.stringify(session));
  const sessionId = session && session.wmp && session.wmp.session_id;
  const flowId = 'flow-' + crypto.randomUUID();
  const result = await wmp('wmp.flow.start', {
    wmp: { session_id: sessionId, version: '0.1' },
    flow_id: flowId,
    flow_type: 'oid4vci',
    // The offer URL plus the wallet's client identity, in the object
    // form the engine's flow start reads: the registered client_id, the
    // client key's kid (the private_key_jwt assertion's kid — the app
    // knows the kid it registered), and the page's own URL as the
    // redirect_uri (the authorization-code grant: the AS sends the code
    // back here, and the load handler resumes the flow from ?code and
    // ?state). The offer parser takes the credential_offer member as
    // the scheme URL directly.
    params: {
      credential_offer: offerUrl,
      client_id: e.clientId,
      client_key_kid: e.clientKeyId,
      redirect_uri: window.location.origin + '/',
    },
  });
  // The authorization-code grant returns with the flow still open: the
  // redirect answers through wmp.flow.action, and the page reload
  // carries the pending flow, the session resumption token and the
  // state forward.
  if (!result.completed) {
    sessionStorage.setItem('mini-wallet-pending', JSON.stringify({
      flow_id: flowId,
      session_id: sessionId,
      resumption_token: session.resumption_token,
      state: result.state,
    }));
  }
  window.__last_result = result;
  document.body.setAttribute('data-flow-state', 'started');
  return result;
}

async function resumeAuthorizationCode() {
  const code = query('code');
  const state = query('state');
  const pending = JSON.parse(sessionStorage.getItem('mini-wallet-pending') || 'null');
  if (!code || !pending || !pending.flow_id) return;
  // The page reloaded: a fresh engine, whose in-memory session store is
  // empty — the wmp session does not survive the reload, and needs not
  // to. The stateless resume carries the flow in the KeyValue port (the
  // kv over localStorage): the authorization stash holds the verifier,
  // the state and the offer params, so a fresh session answers the open
  // flow. The stash's CSRF state is checked against the redirect's.
  const session = await wmp('wmp.session.create', {
    wmp: { version: '0.1', sender: 'mini-wallet' },
    capabilities_offered: { flows: { max_concurrent: 16 } },
    security: { mode: 'tls' },
  });
  const sessionId = session.wmp.session_id;
  const result = await wmp('wmp.flow.action', {
    wmp: { session_id: sessionId, version: '0.1' },
    flow_id: pending.flow_id,
    action: 'authorization_complete',
    params: { code: code, state: state ?? pending.state },
  });
  window.__last_result = result;
  document.body.setAttribute('data-flow-state', 'completed');
  sessionStorage.removeItem('mini-wallet-pending');
  return result;
}

async function startRequest(requestUrl) {
  const session = await wmp('wmp.session.create', {
    wmp: { version: '0.1', sender: 'mini-wallet' },
    capabilities_offered: { flows: { max_concurrent: 16 } },
    security: { mode: 'tls' },
  });
  const sessionId = session.wmp.session_id;
  const flowId = 'flow-' + crypto.randomUUID();
  const result = await wmp('wmp.flow.start', {
    wmp: { session_id: sessionId, version: '0.1' },
    flow_id: flowId,
    flow_type: 'oid4vp',
    // The engine's request parser: the raw openid4vp:// URL — the
    // by-reference form extracts its request_uri itself, and the §5
    // validations compare the request object against the outer URL.
    params: requestUrl,
  });
  window.__last_result = result;
  document.body.setAttribute('data-flow-state', 'presented');
  return result;
}

window.addEventListener('load', async () => {
  try {
    if (query('code')) {
      await resumeAuthorizationCode();
    } else if (query('offer')) {
      await startOffer(query('offer'));
    } else if (query('request')) {
      await startRequest(query('request'));
    }
  } catch (err) {
    window.__boot_error = String(err && (err.message || err));
    // The full error shape (the code, the data.reason) for debugging.
    try {
      window.__boot_error_detail = JSON.parse(JSON.stringify(err));
    } catch (_) {
      window.__boot_error_detail = { message: String(err && (err.message || err)) };
    }
    document.body.setAttribute('data-flow-state', 'error');
  }
});
