// The zkp presenter seam: the library's default answer to the engine's
// `vp` ask, over the browser presenter wasm (proving/siros-zkp-req-wasm,
// wasm-pack --target web) and the Longfellow circuits artifact the page
// serves. The page's CONSENT stays the page's (the separate consent ask);
// a page providing its own `ui.vp` replaces this construction entirely.
//
// The chain mirrors the Kotlin/Swift presenters exactly (the same wasm
// module the conformance page uses):
//
//   prepare(query, metadata, credential, seed, handover, verifier_id)
//     → dataToSign → the DEVICE KEY's ES256 (WebCrypto; the key never
//     crosses the wasm boundary) → job → prove → assemble → vpTokenJson
//
// The handover is OpenID4VP 1.0 B.2.6.1's redirect form, built from the
// engine's verified facts:
//   ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, thumbprint,
//                                       response_uri]))]
// the thumbprint the engine passed (base64url of RFC 7638's digest),
// null when the request carried no response encryption.

/** The presenter configuration. */
export interface PresenterOptions {
  /** The presenter wasm's JS glue URL (wasm-pack --target web: the
   *  generated .js; the .wasm sits beside it). */
  wasmUrl: string;
  /** The Longfellow circuits artifact (`circuits.zst`) the page serves —
   *  the same pinned file the verifier's image bakes. */
  circuitsUrl: string;
  /** The system to prove with when the request's own advertised formats
   *  name none. Defaults to the Longfellow nym_auth circuit. */
  system?: string;
}

/** The wasm module's surface as this seam uses it (wasm-bindgen's
 *  generated names; the module is loaded dynamically from the page). */
interface PresenterModule {
  default: (input?: string | URL) => Promise<void>;
  ZkpPresenter: {
    prepare(input: unknown): PresenterPrepared;
  };
  ZkpProvers: new () => PresenterProvers;
  vpTokenJson(entries: unknown): string;
}

interface PresenterPrepared {
  dataToSign(): Uint8Array;
  job(deviceSignature: Uint8Array): unknown;
  assemble(output: unknown): Uint8Array;
}

interface PresenterProvers {
  loadLongfellow(circuitsZst: Uint8Array): void;
  prove(job: unknown): { pseudonym(): Uint8Array; zkProof(): Uint8Array };
}

/** The refusal the wasm throws ({error_code, kind, code}) — the engine's
 *  sign-refusal answer when the presenter cannot construct the proof. */
export interface PresenterRefusal {
  error_code: string;
  kind: string;
  code: string;
}

/** The engine's `vp` ask, the members this seam reads (snake_case, the
 *  ports' serde shape). */
export interface VpAskParams {
  flow_id: string;
  audience: string;
  nonce: string;
  selections: Array<{
    credential_query_id: string;
    credential_id: string;
    disclosed_claims: string[];
  }>;
  response_uri: string;
  verifier_jwk_thumbprint: string;
  verifier_session_id: string;
  transaction_data: string[];
  selection_handle?: string | null;
  verified_request?: {
    client_id: string;
    client_id_scheme?: string;
    signed?: boolean;
    signature_verification?: string;
  } | null;
  response_encryption?: unknown;
}

/** The engine's `match` ask, the members this seam captures (the query
 *  and the client metadata are the presenter's inputs; the trust context
 *  carries the PDP's verified verifier ids). */
export interface MatchAskParams {
  flow_id: string;
  dcql_query?: { credentials?: Array<Record<string, unknown>> } | null;
  scope?: string;
  verifier?: {
    name?: string;
    client_id?: string;
    client_id_scheme?: string;
    trust_context?: { verifier_ids?: string[] } | null;
  } | null;
  client_metadata?: Record<string, unknown> | null;
  transaction_data?: string[];
}

// ── The host-ask shapes ─────────────────────────────────────────────────

/**
 * The engine's host asks serialize raw-JSON members as JS **Map**
 * objects (serde_wasm_bindgen's default), not plain objects — a host
 * that reads `params.dcql_query.credentials` sees undefined and every
 * zkp query reads as empty (the typed STRUCT members — the verifier
 * info, the selections — arrive as plain objects; only the raw
 * `serde_json::Value` members are Maps). This adapter reads both.
 */
export const asRecord = (value: unknown): Record<string, unknown> | null => {
  const deep = fromEngineJson(value);
  return deep && typeof deep === "object" && !Array.isArray(deep)
    ? (deep as Record<string, unknown>)
    : null;
};

/**
 * The engine's raw-JSON members serialize as JS Maps RECURSIVELY — a
 * nested DCQL credential query is a Map too, and `JSON.stringify(Map)`
 * silently answers `{}`. This walks the whole value and rebuilds plain
 * objects; use it for EVERY raw-JSON member the host asks carry.
 */
export const fromEngineJson = (value: unknown): unknown => {
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [key, member] of value) out[String(key)] = fromEngineJson(member);
    return out;
  }
  if (Array.isArray(value)) return value.map(fromEngineJson);
  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    // serde_wasm_bindgen wraps raw JSON numbers in its internal tagged
    // object — a `ver: 1` param arrives as {"$serde_json::private::Number":"1"}
    // and a strict parser reads an object where the number belongs
    // (found live: the presenter refused the query as dcql_malformed).
    // Unwrap the artifact back to the number it is.
    const [firstKey, firstValue] = entries[0] ?? [];
    if (entries.length === 1 && firstKey === "$serde_json::private::Number") {
      const parsed = Number(firstValue);
      if (Number.isFinite(parsed)) return parsed;
    }
    const out: Record<string, unknown> = {};
    for (const [key, member] of entries) out[key] = fromEngineJson(member);
    return out;
  }
  return value;
};

// ── The small codecs the handover needs (definite-length CBOR) ──────────

const cborHead = (major: number, length: number): number[] => {
  if (length < 24) return [major * 0x20 + length];
  if (length < 0x100) return [major * 0x20 + 24, length];
  throw new Error("cbor: length beyond this encoder's needs");
};

const cborText = (value: string): Uint8Array => {
  const bytes = new TextEncoder().encode(value);
  return new Uint8Array([...cborHead(3, bytes.length), ...bytes]);
};

const cborBytes = (value: Uint8Array): Uint8Array =>
  new Uint8Array([...cborHead(2, value.length), ...value]);

const cborNull = (): Uint8Array => new Uint8Array([0xf6]);

const cborArray = (items: Uint8Array[]): Uint8Array => {
  const head = cborHead(4, items.length);
  const total = items.reduce((n, item) => n + item.length, 0);
  const out = new Uint8Array(head.length + total);
  out.set(head, 0);
  let at = head.length;
  for (const item of items) {
    out.set(item, at);
    at += item.length;
  }
  return out;
};

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer));

/** base64url (unpadded) decode — the thumbprint and the seed's opening. */
const fromBase64Url = (value: string): Uint8Array => {
  const pad = value.length % 4 === 2 ? "==" : value.length % 4 === 3 ? "=" : "";
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
};

/**
 * OpenID4VP 1.0 B.2.6.1's `OpenID4VPHandover`, the redirect channel's
 * binding: `["OpenID4VPHandover", SHA-256(cbor([client_id, nonce,
 * thumbprint, response_uri]))]` — the thumbprint null when the request
 * carried no response encryption (the engine passed it empty).
 */
export async function openId4VpHandover(clientId: string, nonce: string, thumbprintB64u: string, responseUri: string): Promise<Uint8Array> {
  const thumbprint = thumbprintB64u ? cborBytes(fromBase64Url(thumbprintB64u)) : cborNull();
  const info = cborArray([cborText(clientId), cborText(nonce), thumbprint, cborText(responseUri)]);
  const digest = await sha256(info);
  return cborArray([cborText("OpenID4VPHandover"), cborBytes(new Uint8Array(digest))]);
}

/**
 * The credential's `secret_seed` from its stored metadata: the auxiliary
 * data v0.1 delivery whose path ends in `ssc` — the opening the issuer
 * delivered beside the credential (the same extraction the Kotlin and
 * WMP wallets' seed sources run; fails closed to null on any other
 * shape, so the presenter refuses rather than proves with garbage).
 */
export function secretSeedOf(metadata: unknown): Uint8Array | null {
  const entries = (metadata as { auxiliary_data?: Array<Record<string, unknown>> } | null)?.auxiliary_data;
  if (!Array.isArray(entries)) return null;
  const slots = entries.filter((entry) => {
    const path = (entry as { path?: unknown }).path;
    return Array.isArray(path) && path.length > 0 && path[path.length - 1] === "ssc";
  });
  if (slots.length !== 1) return null;
  const opening = (slots[0] as { opening?: unknown }).opening;
  if (typeof opening !== "string") return null;
  const seed = fromBase64Url(opening);
  return seed.length === 16 ? seed : null;
}

// ── The seam itself ─────────────────────────────────────────────────────

/**
 * The zkp presenter port: answers the engine's `vp` ask for `zkp_req`
 * queries. One instance per wallet; the wasm module and the circuits load
 * once (the artifact is fetched the moment the first presentation needs
 * it — a page that wants it warm can call {@link ZkpPresenterPort.ready}).
 */
export class ZkpPresenterPort {
  readonly #options: PresenterOptions;
  readonly #sign: (bytes: Uint8Array) => Promise<Uint8Array>;
  readonly #rawCredential: (key: string) => Promise<Record<string, unknown> | null>;
  readonly #credentials: () => Promise<Array<{ key: string }>>;
  #loaded: Promise<{ module: PresenterModule; provers: PresenterProvers } | null> | null = null;
  /** The match asks captured per flow — the presenter's inputs. */
  readonly #context = new Map<string, { query: string | null; metadata: string | null }>();

  constructor(options: PresenterOptions, seam: {
    /** The device key's ES256 over raw bytes (WebCrypto; the wallet's custody). */
    sign: (bytes: Uint8Array) => Promise<Uint8Array>;
    /** The stored record of a wallet credential (the base64url credential + its metadata). */
    rawCredential: (key: string) => Promise<Record<string, unknown> | null>;
    /** The wallet's stored credentials (the default match picks among them). */
    credentials: () => Promise<Array<{ key: string }>>;
  }) {
    this.#options = options;
    this.#sign = seam.sign;
    this.#rawCredential = seam.rawCredential;
    this.#credentials = seam.credentials;
  }

  /** Loads the wasm module and the circuits; null when the module is not
   *  a presenter build (the page mounted the seam wrong — every flow then
   *  refuses loudly instead of failing mysteriously). */
  ready(): Promise<{ module: PresenterModule; provers: PresenterProvers } | null> {
    this.#loaded ??= (async () => {
      const module = (await import(this.#options.wasmUrl)) as unknown as PresenterModule;
      await module.default();
      const provers = new module.ZkpProvers();
      const circuits = await fetch(this.#options.circuitsUrl);
      if (!circuits.ok) throw new Error(`the circuits artifact answered ${circuits.status}`);
      provers.loadLongfellow(new Uint8Array(await circuits.arrayBuffer()));
      return { module, provers };
    })().catch(() => {
      this.#loaded = null; // a later flow may retry (a transient fetch)
      return null;
    });
    return this.#loaded;
  }

  /** Captures the match ask (the query + the client metadata — the
   *  presenter's inputs) and, when the page has no `ui.match`, answers
   *  it: every DCQL query selects the first stored credential, with the
   *  claims the query names. Returns null when the page answered. */
  async match(flowId: string, params: MatchAskParams): Promise<{
    selections: Array<{ credential_query_id: string; credential_id: string; disclosed_claims: string[] }>;
    handle: string | null;
  } | null> {
    // The raw-JSON members arrive as Maps, NESTED ones included (see
    // fromEngineJson): the query objects inside credentials are Maps too.
    const dcql = asRecord(params.dcql_query);
    this.#context.set(flowId, {
      query: dcql ? JSON.stringify(dcql) : null,
      metadata: params.client_metadata ? JSON.stringify(asRecord(params.client_metadata) ?? params.client_metadata) : null,
    });
    const queries = ((dcql?.credentials as unknown[] | undefined) ?? [])
      .map((entry) => asRecord(entry) ?? {});
    if (queries.length === 0) return null;
    const stored = await this.#credentials();
    // The default answers ONLY when it is the honest answer: exactly ONE
    // stored credential. With none there is nothing to select; with more
    // than one the choice is ambiguous, and guessing (the first stored
    // key) would bind the proof to a credential the user never picked —
    // the page supplies `ui.match` to make that choice. Both refuse here,
    // and the flow surfaces the empty selection.
    if (stored.length !== 1) return { selections: [], handle: null };
    const first = stored[0]!;
    const selections = queries.map((query) => ({
      credential_query_id: typeof query.id === "string" ? query.id : "",
      credential_id: first.key,
      disclosed_claims: Array.isArray(query.claims)
        ? (query.claims as Array<Record<string, unknown>>)
            .map((claim) => claim.path)
            .filter((path): path is unknown[] => Array.isArray(path))
            .map((path) => JSON.stringify(path))
        : [],
    }));
    return { selections, handle: null };
  }

  /** The `vp` ask's answer: the vp_token of the zkp presentation, or the
   *  sign refusal when the chain cannot construct it. */
  async vp(flowId: string, params: VpAskParams): Promise<{ vp_token: string } | { refusal: { code: string } }> {
    const loaded = await this.ready();
    const selection = params.selections?.[0];
    const context = this.#context.get(flowId);
    if (!loaded || !selection || !context?.query) {
      return { refusal: { code: "SIGN_REFUSED" } };
    }
    // The presenter's `query` input is ONE credential query (§6.1 — the
    // entry the selection answers), never the whole DCQL root: the root
    // has no id/format of its own and the strict parse refuses it as
    // malformed. Find the selected entry by the selection's query id.
    let selectedQuery: string | null = null;
    try {
      const whole = context.query ? (JSON.parse(context.query) as { credentials?: Array<Record<string, unknown>> }) : null;
      const entry = (whole?.credentials ?? []).find((q) => q.id === selection.credential_query_id);
      if (entry) selectedQuery = JSON.stringify(entry);
    } catch { /* the captured query unreadable: the refusal below */ }
    if (!selectedQuery) return { refusal: { code: "SIGN_REFUSED" } };

    const record = await this.#rawCredential(selection.credential_id);
    const credential = typeof record?.credential === "string" ? record.credential : null;
    const seed = secretSeedOf(record?.credential_metadata);
    if (!credential || !seed) {
      // The record's seed is the presentation's fuel: absent (an old
      // record stored before the Map fix, or a plain delivery), the
      // honest answer is the refusal.
      return { refusal: { code: "SIGN_REFUSED" } };
    }

    // The system: the request's own advertised circuits, else the option.
    let system = this.#options.system ?? "urn:circuits:longfellow:nym_auth:v1";
    try {
      const offered = (context.metadata ? JSON.parse(context.metadata) : null) as {
        vp_formats_supported?: { zkp_req?: { system_id_values?: string[] } };
      } | null;
      const named = offered?.vp_formats_supported?.zkp_req?.system_id_values?.[0];
      if (typeof named === "string" && named) system = named;
    } catch { /* the metadata unreadable: the option's default stands */ }

    // The verifier id: ONLY the certificate-authenticated client_id the
    // engine verified (the x509_san_dns form the presenter parses) —
    // never the request's own `audience`. The audience is an
    // unauthenticated string the requesting party chooses; binding a
    // pseudonym proof's handover to it would let a hostile verifier name
    // itself as the subject of the proof. The engine passes the verified
    // facts whenever the authorization request carried a client_id (it
    // always does on a real request); their absence means the engine
    // could not verify the request, and the proof refuses.
    const verifierId = params.verified_request?.client_id;
    if (!verifierId) {
      this.#context.delete(flowId);
      return { refusal: { code: "SIGN_REFUSED" } };
    }
    const handover = await openId4VpHandover(
      verifierId,
      params.nonce,
      params.verifier_jwk_thumbprint,
      params.response_uri,
    );

    try {
      const prepared = loaded.module.ZkpPresenter.prepare({
        system,
        query: selectedQuery,
        clientMetadata: context.metadata ?? "{}",
        credential,
        seed: Array.from(seed),
        handover: Array.from(handover),
        verifierIdForm: "x509_san_dns",
        verifierId,
      });
      const signature = await this.#sign(prepared.dataToSign());
      const job = prepared.job(new Uint8Array(signature));
      const output = loaded.provers.prove(job);
      const presentation = prepared.assemble(output);
      const vpToken = loaded.module.vpTokenJson([{
        query_id: selection.credential_query_id,
        presentations: [Array.from(presentation)],
      }]);
      this.#context.delete(flowId);
      return { vp_token: vpToken };
    } catch (thrown) {
      // The wasm's uniform refusal shape — the engine's ask gets the
      // allowlisted code, never the presenter's internals.
      const refusal = thrown as Partial<PresenterRefusal>;
      this.#context.delete(flowId);
      return { refusal: { code: typeof refusal.code === "string" ? refusal.code : "SIGN_REFUSED" } };
    }
  }
}
