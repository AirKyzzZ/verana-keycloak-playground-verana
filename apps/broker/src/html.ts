import type { EvidenceMode } from "./config.js";
import type { LoginTransaction } from "./types.js";

export type InteractionStatus = LoginTransaction["status"] | "expired";

export interface InteractionPageInput {
  evidenceMode: EvidenceMode;
  uid: string;
  authorizationRequest?: string;
  qrDataUrl?: string;
  status: InteractionStatus;
  errorCode?: string;
}

const stateCopy: Record<InteractionStatus, { label: string; message: string }> =
  {
    pending: {
      label: "Waiting for wallet",
      message: "Scan the QR code or copy the request into the local holder.",
    },
    verified: {
      label: "Credential verified",
      message: "Returning to Keycloak…",
    },
    denied: {
      label: "Credential denied",
      message: "The credential did not satisfy the Verana trust policy.",
    },
    expired: {
      label: "Request expired",
      message: "Return to Keycloak and start a new login.",
    },
    unavailable: {
      label: "Verifier unavailable",
      message: "The local VS Agent verifier could not be reached.",
    },
    used: {
      label: "Request already used",
      message: "Return to Keycloak and start a new login.",
    },
  };

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character] ?? character,
  );
}

export function renderInteractionPage(input: InteractionPageInput): string {
  const copy = stateCopy[input.status];
  const uid = encodeURIComponent(input.uid);
  const statusUrl = escapeHtml(`/interaction/${uid}/status`);
  const completeUrl = escapeHtml(`/interaction/${uid}/complete`);
  const authorizationRequest = escapeHtml(input.authorizationRequest ?? "");
  const qrDataUrl = input.qrDataUrl ? escapeHtml(input.qrDataUrl) : undefined;
  const errorCode = input.errorCode
    ? `<p class="error-code">Error: ${escapeHtml(input.errorCode)}</p>`
    : "";
  const evidenceBoundary = renderEvidenceBoundary(input.evidenceMode);
  const requestControls =
    input.authorizationRequest && qrDataUrl
      ? `
        <img class="qr" src="${qrDataUrl}" alt="Verana authorization request QR code">
        <label for="authorization-request">Authorization request</label>
        <textarea id="authorization-request" readonly>${authorizationRequest}</textarea>
        <button id="copy-request" type="button">Copy request</button>
      `
      : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verana credential sign in</title>
    <style>
      :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #080b12; color: #f8fafc; }
      main { width: min(30rem, calc(100% - 2rem)); padding: 2rem; border: 1px solid #253047; border-radius: 1rem; background: #111827; box-shadow: 0 1.5rem 4rem #0008; }
      h1 { margin: 0 0 .75rem; font-size: 1.65rem; }
      .badges { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
      .badge { padding: .25rem .55rem; border: 1px solid #475569; border-radius: 999px; color: #cbd5e1; font-size: .72rem; font-weight: 700; letter-spacing: .08em; }
      .status { margin: 0 0 1.25rem; padding: .9rem; border-radius: .65rem; background: #172033; }
      .status strong, .status span { display: block; }
      .status span { margin-top: .25rem; color: #cbd5e1; }
      .qr { display: block; width: min(20rem, 100%); height: auto; margin: 0 auto 1rem; border-radius: .65rem; background: #fff; }
      label { display: block; margin-bottom: .35rem; color: #cbd5e1; font-size: .8rem; }
      textarea { box-sizing: border-box; width: 100%; min-height: 5rem; resize: vertical; border: 1px solid #334155; border-radius: .5rem; padding: .7rem; background: #090f1c; color: #cbd5e1; }
      button { width: 100%; margin-top: .75rem; border: 0; border-radius: .5rem; padding: .8rem 1rem; background: #38bdf8; color: #082f49; font-weight: 800; cursor: pointer; }
      .error-code { color: #fca5a5; font-family: ui-monospace, monospace; font-size: .8rem; }
      .warning { margin: 0 0 1.25rem; padding: .9rem; border: 1px solid #a16207; border-radius: .65rem; color: #fde68a; line-height: 1.55; }
      .warning strong { display: block; }
    </style>
  </head>
  <body>
    <main data-status="${escapeHtml(input.status)}" data-status-url="${statusUrl}" data-complete-url="${completeUrl}">
      <div class="badges"><span class="badge">LOCAL DEMO</span>${renderTestnetBadge(input.evidenceMode)}</div>
      ${evidenceBoundary}
      <h1>Sign in with a Verana credential</h1>
      <p class="status" aria-live="polite"><strong id="status-label">${copy.label}</strong><span id="status-message">${copy.message}</span></p>
      ${errorCode}
      ${requestControls}
    </main>
    <script>
      (() => {
        const root = document.querySelector("main");
        const labels = {
          pending: ["Waiting for wallet", "Scan the QR code or copy the request into the local holder."],
          verified: ["Credential verified", "Returning to Keycloak…"],
          denied: ["Credential denied", "The credential did not satisfy the Verana trust policy."],
          expired: ["Request expired", "Return to Keycloak and start a new login."],
          unavailable: ["Verifier unavailable", "The local VS Agent verifier could not be reached."],
          used: ["Request already used", "Return to Keycloak and start a new login."]
        };
        const renderStatus = (status) => {
          const copy = labels[status] || labels.unavailable;
          root.dataset.status = status;
          document.querySelector("#status-label").textContent = copy[0];
          document.querySelector("#status-message").textContent = copy[1];
        };
        const poll = async () => {
          try {
            const response = await fetch(root.dataset.statusUrl, { cache: "no-store" });
            const result = await response.json();
            renderStatus(result.status);
            if (result.status === "verified") {
              window.top.location.assign(root.dataset.completeUrl);
              return;
            }
            if (result.status === "pending") window.setTimeout(poll, 1000);
          } catch {
            renderStatus("unavailable");
          }
        };
        document.querySelector("#copy-request")?.addEventListener("click", async () => {
          const request = document.querySelector("#authorization-request");
          await navigator.clipboard.writeText(request.value);
        });
        if (root.dataset.status === "pending") window.setTimeout(poll, 1000);
        if (root.dataset.status === "verified") {
          window.top.location.assign(root.dataset.completeUrl);
        }
      })();
    </script>
  </body>
</html>`;
}

function renderEvidenceBoundary(evidenceMode: EvidenceMode): string {
  if (evidenceMode !== "LOCAL_CONTROLLED") return "";

  const mode = escapeHtml(evidenceMode);
  return `<aside class="warning" data-evidence-mode="${mode}">
  <strong>${mode}</strong>
  Real local OpenID4VC and Keycloak flow with a controlled local trust resolver.
  This is not Verana testnet, trusted-HTTPS, physical-wallet, or production evidence.
</aside>`;
}

function renderTestnetBadge(evidenceMode: EvidenceMode): string {
  return evidenceMode === "LIVE_VERANA"
    ? '<span class="badge">TESTNET</span>'
    : "";
}
