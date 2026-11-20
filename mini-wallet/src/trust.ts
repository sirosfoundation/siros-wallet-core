// The trust plugin layer: where the authzen-client lives. The engine's
// PDP port asks one question — may this wallet trust this subject? — and
// the answer is POLICY, not plumbing: the page picks the plugin.
//
//   AuthzenTrustPlugin   the real one: the authzen-client against the
//                        environment's go-trust PDP (the AuthZEN
//                        evaluation, the answer mapped to the engine's
//                        {trusted, decision?, context?}). The client's
//                        own library plugs in here when it ships; today
//                        the plugin speaks plain fetch to the PDP's
//                        /evaluation and lets the page proxy it (a
//                        browser cannot cross-origin a PDP either).
//   AlwaysTrustedPlugin  the DEMO SHIM: every evaluation answers
//                        trusted — no authzen client, no PDP. Demos and
//                        test benches only; never a production page.

import type { MiniWalletPdp } from "./types.js";

/** One trust evaluation ask — the engine's EvaluationRequest (the
 *  AuthZEN shape: the subject, the action, the resource). */
export type TrustAsk = Record<string, unknown>;

/** The answer the engine's PDP port expects. */
export interface TrustAnswer {
  trusted: boolean;
  decision?: string;
  context?: unknown;
}


/** The trust plugin contract — the engine's PDP port delegates here. */
export interface TrustPlugin {
  evaluate(ask: TrustAsk): Promise<TrustAnswer>;
}

/** The demo shim: always trusted, no authzen client. */
export class AlwaysTrustedPlugin implements TrustPlugin {
  async evaluate(_ask: TrustAsk): Promise<TrustAnswer> {
    return { trusted: true, decision: "Permit" };
  }
}

/** A token for the evaluation's Authorization — the wallet's authz
 *  continuity: before any user exists this is the PRE-REGISTRATION
 *  TENANT TOKEN (go-wallet-backend#566's slot — the page supplies it,
 *  or the backend's anonymous path mints it when it ships); after the
 *  adopt it is the passkey session's token. The plugin never sees the
 *  difference — the provider swaps beneath it. */
export type TrustTokenProvider = () => Promise<string | null>;

/** The authzen-client's home: the AuthZEN evaluation against the
 *  environment's go-trust PDP (a backend's PDP-proxy included — the
 *  wallet-frontend's own /v1/evaluate path). `url` is the evaluation
 *  endpoint — a page-side proxy when the browser cannot reach it
 *  directly; `auth` supplies the evaluation's Authorization when the
 *  endpoint demands one. The authzen-client library itself plugs in
 *  behind this same interface when it ships. */
export class AuthzenTrustPlugin implements TrustPlugin {
  readonly #url: string;
  readonly #auth?: TrustTokenProvider;

  constructor(url: string, auth?: TrustTokenProvider) {
    this.#url = url;
    this.#auth = auth;
  }

  async evaluate(ask: TrustAsk): Promise<TrustAnswer> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.#auth) {
      const token = await this.#auth();
      if (token) headers.Authorization = `Bearer ${token}`;
    }
    // Fail CLOSED on the transport: an error envelope or a captive
    // portal answering 200-with-junk must never be read as trust — and a
    // hung PDP must not hang every flow. (A non-JSON body already fell
    // through to Deny; the status and the timeout close the rest.)
    let response: Response;
    try {
      response = await fetch(this.#url, {
        method: "POST",
        headers,
        body: JSON.stringify(ask),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      return { trusted: false, decision: "Deny" };
    }
    if (!response.ok) return { trusted: false, decision: "Deny" };
    const answer = (await response.json().catch(() => ({}))) as {
      decision?: unknown;
      context?: unknown;
    };
    // go-trust answers the boolean decision; the engine's port wants
    // {trusted, decision?, context?}.
    const decision =
      typeof answer.decision === "boolean"
        ? answer.decision ? "Permit" : "Deny"
        : typeof answer.decision === "string"
          ? answer.decision
          : "Deny";
    return {
      trusted: decision === "Permit",
      decision,
      context: answer.context,
    };
  }
}

/** Adapt any plugin to the engine's PDP port shape (the MiniWallet's
 *  `pdp` option accepts either — the plugin is the first-class form). */
export function asPdp(plugin: TrustPlugin): MiniWalletPdp {
  return { evaluate: (request) => plugin.evaluate(request as TrustAsk) };
}
