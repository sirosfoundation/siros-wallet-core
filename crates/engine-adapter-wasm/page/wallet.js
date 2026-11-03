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
  const response = await fetch('mini-wallet.json');
  const endpoints = await response.json();

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

  const evaluate = (request) =>
    fetch(endpoints.trustProxyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    }).then((r) => r.json());

  // The kv over localStorage: the flow stash and the credential store
  // survive the redirect's page reload.
  const kv = {
    get: (key) => Promise.resolve(localStorage.getItem('mini-wallet-kv:' + key)),
    put: (key, value) => { localStorage.setItem('mini-wallet-kv:' + key, value); return Promise.resolve(); },
    del: (key) => { localStorage.removeItem('mini-wallet-kv:' + key); return Promise.resolve(); },
  };

  return {
    fetch: fetchImpl,
    host: 'mini',
    txCode: endpoints.txCode,
    pdp: { evaluate },
    kv,
  };
}

async function ensureEngine() {
  if (!window.__engine) {
    const config = await engineConfig();
    window.__engine = await Engine.new(config);  // set by wallet_glue.js
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
    flow_type: 'oid4vci',
    // The engine's offer parser: the by-reference form.
    params: { credential_offer_uri: offerUrl },
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
  // The page reloaded: a fresh engine. Restore the session from the
  // resumption token, then answer the open flow with the code.
  if (pending.resumption_token) {
    await wmp('wmp.session.resume', {
      wmp: { version: '0.1' },
      resumption_token: pending.resumption_token,
    });
  }
  const result = await wmp('wmp.flow.action', {
    wmp: { session_id: pending.session_id, version: '0.1' },
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
    // The engine's request parser: the by-reference form.
    params: { request_uri: requestUrl },
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
    document.body.setAttribute('data-flow-state', 'error');
  }
});
