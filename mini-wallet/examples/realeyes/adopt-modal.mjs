// The adopt modal — the EXAMPLE'S OWN renderer of the AdoptModal
// contract (the library ships no UI: every string, style and layout is
// the hosting page's, per the design brief). This copy is the reference
// implementation: DOM-thin, every style inline on its element (no
// <style> beyond the spinner's keyframes scoped INSIDE the overlay), no
// framework, no dependencies. A page brings its own modal (or none).
//
// The contract lives in the library (types.ts): `adopt`'s `modal`
// option takes this object; the steps arrive as the calls below.

/** One element with the class and the inline styles (the DOM-thin
 *  rule: everything inline, the classes only for the app's skin). */
function styled(element, className, cssText) {
  element.className = className;
  element.style.cssText = cssText;
  return element;
}

const OVERLAY_STYLE =
  "position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;" +
  "justify-content:center;background:rgba(9,14,20,0.55);";
const CARD_STYLE =
  "background:#fff;border-radius:14px;padding:26px 26px 20px;width:min(420px,calc(100vw - 40px));" +
  "box-shadow:0 24px 64px rgba(9,14,20,0.35);box-sizing:border-box;" +
  'font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#16202b;';
const TITLE_STYLE = "margin:0 0 8px;font-size:1.15rem;font-weight:600;";
const TEXT_STYLE = "margin:0 0 14px;color:#4a5563;font-size:0.95rem;";
const SPIN_STYLE =
  "width:22px;height:22px;border-radius:50%;border:3px solid #dbe3f0;" +
  "border-top-color:#1a4fd0;margin:6px auto 10px;animation:mw-rotate 0.9s linear infinite;";
const ROW_STYLE = "display:flex;gap:10px;justify-content:flex-end;margin-top:18px;";
const BUTTON_STYLE =
  "font:inherit;border-radius:8px;padding:9px 18px;cursor:pointer;" +
  "border:1px solid #cfd6e0;background:#fff;color:#4a5563;";
const GO_STYLE =
  "font:inherit;border-radius:8px;padding:9px 18px;cursor:pointer;" +
  "border:1px solid #1a4fd0;background:#1a4fd0;color:#fff;font-weight:600;";
const OK_STYLE = "margin:0 0 14px;color:#2e7d32;font-weight:600;font-size:0.95rem;";
const BAD_STYLE = "margin:0 0 14px;color:#b3261e;font-weight:600;font-size:0.95rem;";

/** The spinner's keyframes: the one piece inline styles cannot carry,
 *  scoped to the modal's own element id (removed with it — document.head
 *  is touched never otherwise). */
const SPINFRAMES = () => `@keyframes mw-rotate{to{transform:rotate(360deg)}}`;

/** Render the built-in adopt modal into `root` (document.body by
 *  default). Returns the AdoptModal controller `adopt` drives. The
 *  page's own ask runs BESIDE the modal and both must consent — the
 *  modal is the button surface, never an override of the page's veto. */
/** Render the example's adopt modal into `root` (document.body by default). */
export function renderAdoptModal(root) {
  const host = root ?? document.body;
  if (!host) throw new Error("the adopt modal needs a DOM");

  const overlay = styled(document.createElement("div"), "mw-modal", OVERLAY_STYLE);
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  const card = styled(document.createElement("div"), "mw-card", CARD_STYLE);
  overlay.append(card);
  // The backdrop declines whatever ask is showing (its first button) —
  // attached ONCE here: a reused modal must not stack a listener per ask.
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      card.querySelector(".mw-row .mw-button")?.click();
    }
  });
  host.append(overlay);

  const style = document.createElement("style");
  style.textContent = SPINFRAMES();
  overlay.append(style); // INSIDE the overlay: removed with it

  const body = (title, text) => {
    card.replaceChildren(style);
    const h = styled(document.createElement("h2"), "mw-title", TITLE_STYLE);
    h.textContent = title;
    const p = styled(document.createElement("p"), "mw-text", TEXT_STYLE);
    p.textContent = text;
    card.append(h, p);
    return p;
  };

  const spin = () => styled(document.createElement("div"), "mw-spin", SPIN_STYLE);

  const row = (labels) =>
    new Promise((resolve) => {
      const r = styled(document.createElement("div"), "mw-row", ROW_STYLE);
      labels.forEach((spec, index) => {
        const button = styled(
          document.createElement("button"),
          spec.go ? "mw-button mw-go" : "mw-button",
          spec.go ? GO_STYLE : BUTTON_STYLE,
        );
        button.type = "button";
        button.textContent = spec.text;
        button.addEventListener("click", () => resolve(index));
        r.append(button);
      });
      card.append(r);
    });

  const close = () => {
    overlay.remove();
  };

  return {
    async ask(ask) {
      const n = ask.credentials.length;
      body(
        "Add a permanent wallet?",
        `${n} credential${n === 1 ? "" : "s"} would move to ${ask.backend} — a wallet you keep with a passkey.`,
      );
      const answer = row([
        { text: "Not now" },
        { text: "Set a passkey", go: true },
      ]).then((index) => index === 1);
      // The modal STAYS after the ask: adopt's later steps (passkey,
      // moving, done, failed) render into it. Close is declined()'s and
      // the done/failed Close buttons' business, never the ask's.
      return answer;
    },
    passkey() {
      body("Set your passkey", "Follow your browser's prompt — the passkey unlocks your wallet on every device.");
      card.append(spin());
    },
    moving(keys) {
      body("Moving your credential…", `${keys.length} record${keys.length === 1 ? "" : "s"} move into your wallet.`);
      card.append(spin());
    },
    done(report) {
      const n = report.keys.length;
      const p = body("Your permanent wallet is set up", `${n} record${n === 1 ? "" : "s"} moved to ${report.backend}. Your passkey unlocks it.`);
      const ok = styled(document.createElement("p"), "mw-ok", OK_STYLE);
      ok.textContent = "✓ The credential lives in your wallet now.";
      p.replaceWith(ok);
      row([{ text: "Close", go: true }]).then(close);
    },
    failed(failed) {
      const p = body("The move did not complete", `The record "${failed}" failed to verify against the backend. Your page wallet is untouched — nothing was lost.`);
      const bad = styled(document.createElement("p"), "mw-bad", BAD_STYLE);
      bad.textContent = "You can try again.";
      p.replaceWith(bad);
      row([{ text: "Close", go: true }]).then(close);
    },
    declined() {
      close();
    },
    close() {
      close();
    },
  };
}
