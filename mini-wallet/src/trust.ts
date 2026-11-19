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

/** The authzen-client's home: the AuthZEN evaluation against the
 *  environment's go-trust PDP. `url` is the evaluation endpoint — a
 *  page-side proxy when the browser cannot reach the PDP directly; the
 *  authzen-client library itself plugs in behind this same interface
 *  when it ships (the plugin's contract is its contract). */
export class AuthzenTrustPlugin implements TrustPlugin {
  readonly #url: string;

  constructor(url: string) {
    this.#url = url;
  }

  async evaluate(ask: TrustAsk): Promise<TrustAnswer> {
    const response = await fetch(this.#url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ask),
    });
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
