// The adopt modal: the onboard/set-passkey/move arc as a modal on the
// hosting page — the library's DOM-thin rendering of the steps it
// drives (the decision was (a): the page serves from the wallet's
// origin, and the adopt runs as a modal in that page).
//
// DOM-thin by the house style (issuance-flow's badge precedent): the
// geometry is inline and structural; the class names (mw-modal…) let
// the app skin it. No framework, no dependencies. The page's own UI
// callbacks still run — the modal's buttons ARE the ask's answer; the
// ceremony is still the page's `create` (the browser's own prompt).

import type { AdoptAsk } from "./adopt.js";

export interface AdoptModal {
  /** Show the "add a permanent wallet?" step. The buttons resolve the
   *  ask; the return settles when the user answers. */
  ask(ask: AdoptAsk): Promise<boolean>;
  /** The passkey step: shown while the ceremony runs. */
  passkey(): void;
  /** The move step: shown while the records migrate. */
  moving(keys: string[]): void;
  /** The done step: the report. */
  done(report: { account: string; backend: string; keys: string[] }): void;
  /** The failed step: the move failed; the local wallet is intact. */
  failed(failed: string): void;
  /** The ask was declined — the modal closes. */
  declined(): void;
  /** Tear everything down (an error outside the steps). */
  close(): void;
}

const CARD_STYLE = `
  position: fixed; inset: 0; z-index: 2147483000;
  display: flex; align-items: center; justify-content: center;
  background: rgba(9, 14, 20, 0.55);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #16202b;` +
  // The dialog: on its own line for the string's readability.
  `
.mw-card {
  background: #fff; border-radius: 14px; padding: 26px 26px 20px;
  width: min(420px, calc(100vw - 40px)); box-shadow: 0 24px 64px rgba(9,14,20,.35);
  box-sizing: border-box;
}
.mw-card h2 { margin: 0 0 8px; font-size: 1.15rem; }
.mw-card p { margin: 0 0 14px; color: #4a5563; font-size: .95rem; }
.mw-card .mw-row { display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; }
.mw-card button { font: inherit; border-radius: 8px; padding: 9px 18px; cursor: pointer; border: 1px solid #cfd6e0; background: #fff; color: #4a5563; }
.mw-card button.mw-go { background: #1a4fd0; border-color: #1a4fd0; color: #fff; font-weight: 600; }
.mw-card .mw-spin { width: 22px; height: 22px; border-radius: 50%;
  border: 3px solid #dbe3f0; border-top-color: #1a4fd0; margin: 6px auto 10px;
  animation: mw-rotate 0.9s linear infinite; }
@keyframes mw-rotate { to { transform: rotate(360deg); } }
.mw-card .mw-ok { color: #2e7d32; font-weight: 600; }
.mw-card .mw-bad { color: #b3261e; font-weight: 600; }
`;

/** Render the adopt modal into `root` (document.body by default). The
 *  structural styles inject once; the app's mw-* classes skin it. */
export function renderAdoptModal(root?: HTMLElement): AdoptModal {
  const host = root ?? document.body;
  if (!host) throw new Error("the adopt modal needs a DOM");
  const style = document.createElement("style");
  style.textContent = CARD_STYLE.replace(/\s+/g, " ").replace("}} ", "}}");
  document.head.append(style);

  const overlay = document.createElement("div");
  overlay.className = "mw-modal";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.style.cssText = CARD_STYLE.split("\n").filter((l) => l && !l.startsWith(".")).join(" ");
  const card = document.createElement("div");
  card.className = "mw-card";
  overlay.append(card);
  host.append(overlay);

  const buttonRow = (labels: Array<{ text: string; go?: boolean }>): Promise<number> =>
    new Promise((resolve) => {
      const row = document.createElement("div");
      row.className = "mw-row";
      labels.forEach((spec, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = spec.text;
        if (spec.go) button.className = "mw-go";
        button.addEventListener("click", () => resolve(index));
        row.append(button);
      });
      card.append(row);
    });

  const body = (title: string, text: string) => {
    card.replaceChildren();
    const h = document.createElement("h2");
    h.textContent = title;
    card.append(h);
    const p = document.createElement("p");
    p.textContent = text;
    card.append(p);
    return p;
  };

  const settle = <T,>(value: Promise<T>): Promise<T> =>
    value.then((v) => {
      close();
      return v;
    }, (e) => {
      close();
      throw e;
    });

  const close = () => {
    overlay.remove();
    style.remove();
  };

  return {
    ask(ask: AdoptAsk): Promise<boolean> {
      body(
        "Add a permanent wallet?",
        `${ask.credentials.length} credential${ask.credentials.length === 1 ? "" : "s"} would move to ${ask.backend} — a wallet you keep with a passkey.`,
      );
      const answer = buttonRow([
        { text: "Not now" },
        { text: "Set a passkey", go: true },
      ]).then((index) => index === 1);
      // The backdrop declines the ask (the first button's answer).
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          overlay.querySelectorAll("button")[0]?.dispatchEvent(new Event("click"));
        }
      });
      return settle(answer);
    },
    passkey(): void {
      body("Set your passkey", "Follow your browser's prompt — the passkey unlocks your wallet on every device.");
      const spin = document.createElement("div");
      spin.className = "mw-spin";
      card.append(spin);
    },
    moving(keys: string[]): void {
      body("Moving your credential…", `${keys.length} record${keys.length === 1 ? "" : "s"} move into your wallet.`);
      const spin = document.createElement("div");
      spin.className = "mw-spin";
      card.append(spin);
    },
    done(report: { account: string; backend: string; keys: string[] }): void {
      body("Your permanent wallet is set up", `${report.keys.length} record${report.keys.length === 1 ? "" : "s"} moved to ${report.backend}. Your passkey unlocks it.`);
      const ok = document.createElement("p");
      ok.className = "mw-ok";
      ok.textContent = "✓ The credential lives in your wallet now.";
      card.append(ok);
      void buttonRow([{ text: "Close", go: true }]);
    },
    failed(failed: string): void {
      body("The move did not complete", `The record "${failed}" failed to verify against the backend. Your page wallet is untouched — nothing was lost.`);
      const bad = document.createElement("p");
      bad.className = "mw-bad";
      bad.textContent = "You can try again.";
      card.append(bad);
      void buttonRow([{ text: "Close" }]);
    },
    declined(): void {
      close();
    },
    close(): void {
      close();
    },
  };
}
