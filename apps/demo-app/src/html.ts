import type { EvidenceMode } from "./config.js";
import type { KeycloakIdentity } from "./keycloak-client.js";
import type {
  AcceptedBadge,
  ResolvedPresentation,
  SharedPresentation,
} from "./local-wallet-client.js";

export interface WalletPageState {
  acceptedBadge?: AcceptedBadge;
  csrfToken: string;
  resolution?: ResolvedPresentation;
  shared?: SharedPresentation;
  workflowStatus:
    | "idle"
    | "issuing"
    | "issue_failed"
    | "resolving"
    | "resolve_failed"
    | "resolved"
    | "sharing"
    | "shared"
    | "share_uncertain"
    | "rogue_testing"
    | "rogue_denied"
    | "rogue_failed";
}

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

export function renderHomePage(evidenceMode: EvidenceMode): string {
  return renderDocument(
    "Verana Keycloak playground",
    `
      ${renderEvidenceBoundary(evidenceMode)}
      <div class="badges">
        <span class="badge">LOCAL DEMO</span>
        ${renderTestnetBadge(evidenceMode)}
      </div>
      <h1>Verana credential sign in</h1>
      <p>Use Keycloak Authorization Code with PKCE to reach the protected profile.</p>
      <div class="actions">
        <a class="button" href="/login">Sign in through Keycloak</a>
        <a class="secondary" href="/wallet">Open local holder</a>
      </div>
    `,
  );
}

export function renderProfilePage(
  evidenceMode: EvidenceMode,
  identity: KeycloakIdentity & { veranaSubject: string },
  csrfToken: string,
): string {
  return renderDocument(
    "Protected profile",
    `
      ${renderEvidenceBoundary(evidenceMode)}
      <div class="badges">
        <span class="badge">KEYCLOAK VERIFIED</span>
        ${renderTestnetBadge(evidenceMode)}
      </div>
      <h1>Protected identity</h1>
      <dl>
        <dt>Verana subject</dt>
        <dd>${escapeHtml(identity.veranaSubject)}</dd>
        <dt>Organization group</dt>
        <dd>${escapeHtml("/organizations/acme")}</dd>
        <dt>Realm role</dt>
        <dd>${escapeHtml("employee")}</dd>
      </dl>
      <form method="post" action="/logout">
        <input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}">
        <button type="submit">Log out locally</button>
      </form>
    `,
  );
}

export function renderWalletPage(
  evidenceMode: EvidenceMode,
  state: WalletPageState,
): string {
  const csrfField = `<input type="hidden" name="csrfToken" value="${escapeHtml(state.csrfToken)}">`;
  const credential = state.acceptedBadge
    ? `
        <section class="result">
          <h2>Badge accepted</h2>
          <dl>
            <dt>Credential record</dt>
            <dd>${escapeHtml(state.acceptedBadge.credentialId)}</dd>
            <dt>Subject</dt>
            <dd>${escapeHtml(state.acceptedBadge.subjectId)}</dd>
            <dt>Credential type</dt>
            <dd>${escapeHtml(state.acceptedBadge.vct)}</dd>
          </dl>
        </section>
      `
    : "";
  const resolution = state.resolution
    ? renderResolution(
        state.resolution,
        csrfField,
        state.workflowStatus === "resolved",
      )
    : "";
  const shared = state.shared?.shared
    ? `<p class="success">Presentation shared through the local holder.</p>`
    : "";
  const workflowNotice = renderWorkflowNotice(state.workflowStatus);
  const issueSubject =
    evidenceMode === "LOCAL_CONTROLLED"
      ? `
        <label for="subject-id">Fixed holder subject</label>
        <input id="subject-id" readonly value="local-controlled-user">
      `
      : `
        <label for="subject-id">Opaque demo subject</label>
        <input id="subject-id" name="subjectId" required maxlength="200" value="local-demo-user">
      `;
  const rogueDenialControl =
    evidenceMode === "LOCAL_CONTROLLED"
      ? `
        <form method="post" action="/wallet/test-rogue-denial">
          ${csrfField}
          <button type="submit">Test rogue verifier denial</button>
        </form>
      `
      : "";

  return renderDocument(
    "Local holder",
    `
      ${renderEvidenceBoundary(evidenceMode)}
      <div class="badges">
        <span class="badge">LOCAL HOLDER</span>
        ${renderTestnetBadge(evidenceMode)}
      </div>
      <h1>Local holder workflow</h1>
      <p class="warning">This is local integration evidence, not physical-wallet evidence.</p>
      <ol>
        <li><strong>Issue and accept</strong> the ACME Playground Employee Badge in the local VS Agent holder.</li>
        <li>Start Keycloak login and copy the broker authorization request.</li>
        <li>Paste the broker authorization request below.</li>
        <li><strong>Review Q1/Q3</strong>, the verifier DID, and requested claims.</li>
        <li>Share only if the exact verdict is <code>TRUSTED_AUTHORIZED</code>.</li>
      </ol>
      <form method="post" action="/wallet/issue">
        ${csrfField}
        ${issueSubject}
        <button type="submit">Issue and accept badge</button>
      </form>
      ${credential}
      <form method="post" action="/wallet/resolve">
        ${csrfField}
        <label for="authorization-request">Broker authorization request</label>
        <textarea id="authorization-request" name="authorizationRequest" required maxlength="10000"></textarea>
        <button type="submit">Resolve and review request</button>
      </form>
      ${rogueDenialControl}
      ${workflowNotice}
      ${resolution}
      ${shared}
      <p><a href="/">Return to protected application</a></p>
    `,
  );
}

export function renderControlledRogueDenialPage(
  evidenceMode: EvidenceMode,
  rogueVerifierDid: string,
): string {
  return renderDocument(
    "Rogue verifier denied",
    `
      ${renderEvidenceBoundary(evidenceMode)}
      <h1>Rogue verifier denial</h1>
      <dl>
        <dt>Rogue verifier DID</dt>
        <dd>${escapeHtml(rogueVerifierDid)}</dd>
        <dt>Trust status</dt>
        <dd>UNTRUSTED</dd>
        <dt>Disclosure</dt>
        <dd>Sharing refused</dd>
      </dl>
      <p><a href="/wallet">Return to the local holder</a></p>
    `,
  );
}

export function renderErrorPage(
  evidenceMode: EvidenceMode,
  title: string,
  message: string,
): string {
  return renderDocument(
    title,
    `
      ${renderEvidenceBoundary(evidenceMode)}
      <h1>${escapeHtml(title)}</h1>
      <p class="error">${escapeHtml(message)}</p>
      <p><a href="/">Return to the playground</a></p>
    `,
  );
}

function renderResolution(
  resolution: ResolvedPresentation,
  csrfField: string,
  canShare: boolean,
): string {
  const positive = resolution.verdict === "TRUSTED_AUTHORIZED";
  const requestedClaims = resolution.request.requestedClaims
    .map((claim) => `<li><code>${escapeHtml(claim)}</code></li>`)
    .join("");
  const verdictClass = positive ? "success" : "error";
  const action = !positive
    ? `<p class="error">Sharing refused. The verifier is not both trusted and authorized.</p>`
    : canShare
      ? `
        <form method="post" action="/wallet/share">
          ${csrfField}
          <button type="submit">Share approved claims</button>
        </form>
      `
      : "";

  return `
    <section class="result">
      <h2>Verifier review</h2>
      <p class="${verdictClass}">Verdict: ${escapeHtml(resolution.verdict)}</p>
      <dl>
        <dt>Verifier DID</dt>
        <dd>${escapeHtml(resolution.request.verifierDid ?? "Unavailable")}</dd>
        <dt>Trust status</dt>
        <dd>${escapeHtml(resolution.evidence.trustStatus ?? "Unavailable")}</dd>
        <dt>Authorized for schema</dt>
        <dd>${escapeHtml(String(resolution.evidence.authorized))}</dd>
        <dt>Requested credential type</dt>
        <dd>${escapeHtml(resolution.request.requestedVct ?? "Unavailable")}</dd>
      </dl>
      <h3>Requested claims</h3>
      <ul>${requestedClaims}</ul>
      ${action}
    </section>
  `;
}

function renderWorkflowNotice(
  status: WalletPageState["workflowStatus"],
): string {
  switch (status) {
    case "issuing":
      return `<p class="warning">Badge issuance is in progress.</p>`;
    case "issue_failed":
      return `<p class="error">Badge issuance failed. Any previous sharing approval has been discarded.</p>`;
    case "resolving":
      return `<p class="warning">A new request is being resolved. Any previous sharing approval has been discarded.</p>`;
    case "resolve_failed":
      return `<p class="error">The new request could not be resolved. Resolve and review a new request before sharing.</p>`;
    case "sharing":
      return `<p class="warning">Presentation sharing is in progress.</p>`;
    case "share_uncertain":
      return `<p class="error">Sharing outcome is uncertain. Resolve and review a new request before any further attempt.</p>`;
    case "rogue_testing":
      return `<p class="warning">Rogue verifier denial is being checked. Any previous sharing approval has been discarded.</p>`;
    case "rogue_failed":
      return `<p class="error">Rogue verifier denial could not be verified. Any previous sharing approval has been discarded.</p>`;
    default:
      return "";
  }
}

function renderDocument(title: string, content: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }
      body { min-height: 100vh; margin: 0; background: #080b12; color: #f8fafc; }
      main { width: min(42rem, calc(100% - 2rem)); margin: 3rem auto; padding: 2rem; border: 1px solid #253047; border-radius: 1rem; background: #111827; box-shadow: 0 1.5rem 4rem #0008; }
      h1 { margin: 0 0 .75rem; }
      h2 { margin-top: 0; }
      p, li { color: #cbd5e1; line-height: 1.55; }
      ol { padding-left: 1.25rem; }
      .badges { display: flex; gap: .5rem; margin-bottom: 1.25rem; }
      .badge { padding: .25rem .55rem; border: 1px solid #475569; border-radius: 999px; color: #cbd5e1; font-size: .72rem; font-weight: 700; letter-spacing: .08em; }
      .actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1.5rem; }
      .button, button { display: inline-block; border: 0; border-radius: .5rem; padding: .8rem 1rem; background: #38bdf8; color: #082f49; font-weight: 800; cursor: pointer; text-decoration: none; }
      .secondary { display: inline-block; border: 1px solid #475569; border-radius: .5rem; padding: .75rem 1rem; color: #e2e8f0; text-decoration: none; }
      form { margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid #253047; }
      label, dt { display: block; margin-bottom: .35rem; color: #94a3b8; font-size: .82rem; }
      input, textarea { box-sizing: border-box; width: 100%; border: 1px solid #334155; border-radius: .5rem; padding: .7rem; background: #090f1c; color: #f8fafc; }
      textarea { min-height: 7rem; resize: vertical; }
      dd { margin: 0 0 1rem; overflow-wrap: anywhere; }
      code { color: #bae6fd; }
      .result { margin-top: 1.5rem; padding: 1rem; border: 1px solid #334155; border-radius: .65rem; background: #0b1220; }
      .success { color: #86efac; }
      .warning { color: #fde68a; }
      aside.warning { padding: .9rem; border: 1px solid #a16207; border-radius: .65rem; }
      aside.warning strong { display: block; }
      .error { color: #fca5a5; }
      a { color: #7dd3fc; }
    </style>
  </head>
  <body>
    <main>${content}</main>
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
