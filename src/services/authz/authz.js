// Authorization gate (launch hardening).
//
// Before the agent runs any OFFENSIVE action against an identifiable target, that target must be
// explicitly authorized by the OPERATOR for the current session — an attestation that they own the
// asset or hold written permission (scope) to test it. The AI can NEVER self-authorize: grants come
// only from an operator-issued `/authorize` message (handled in the chat route). Every gated attempt
// (allowed or blocked) is written to a tamper-evident audit trail (authz_events).
//
// This is the difference between a dual-use pentest tool and an abuse machine: not *what* it can do,
// but *who authorized it against which target* — recorded and enforced.

import { query, newId } from '../../db/index.js';

// Dedicated offensive tool-block types — always gated when they name a target. `cloud` is gated in
// DOMAIN mode (it actively probes a remote target's buckets/exposed files); credentialed CSPM
// (`cloud aws|azure|gcp`) carries no target host, so classifyAction leaves it ungated (creds = auth).
const OFFENSIVE_TYPES = new Set(['scan', 'vulnscan', 'wireless', 'bluetooth', 'ghost', 'ad', 'exploit', 'owasp', 'cloud', 'websecrets', 'buckets', 'defaultcreds', 'exposed', 'firewall', 'svcaudit', 'webinput', 'apidiscover', 'authsession', 'loginbypass']);

// Raw shell (`execute`) is gated only when the command drives one of these attack tools (so benign
// shell — ls, cat, whoami, ping, curl to your own infra — is never gated). msfvenom/payload gen is
// intentionally NOT here: it produces a local artifact, it doesn't hit a target.
const OFFENSIVE_CMD_RE =
  /\b(nmap|masscan|hydra|medusa|ncrack|patator|sqlmap|nikto|nuclei|commix|dalfox|wpscan|msfconsole|aircrack-ng|airodump-ng|aireplay-ng|reaver|wifite|bettercap|ettercap|arpspoof|dsniff|bluesnarfer|l2ping|responder|crackmapexec|netexec|nxc|enum4linux|hping3|slowhttptest)\b/i;

// Loopback / the operator's own box — self-testing, never gated.
const SELF_RE = /^(127\.0\.0\.1|0\.0\.0\.0|::1|localhost|localhost\.localdomain)$/i;

// ---- target extraction (best-effort) ----
const URL_RE = /\bhttps?:\/\/([^\s/:"'`|;]+)/i;
const CIDR_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/;
const MAC_RE = /\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b/;
const HOST_RE = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b/i;

// Pull the primary target (URL-host / IP / CIDR / MAC / hostname) from a command or body, normalized.
export function extractTarget(text) {
  const s = String(text || '');
  const url = URL_RE.exec(s);
  if (url) return url[1].toLowerCase();
  const cidr = CIDR_RE.exec(s);
  if (cidr) return cidr[1];
  const mac = MAC_RE.exec(s);
  if (mac) return mac[1].toUpperCase();
  const host = HOST_RE.exec(s);
  if (host) return host[1].toLowerCase();
  return null;
}

// Decide whether a tool block is gated and what target it hits.
export function classifyAction(type, body) {
  let gated = OFFENSIVE_TYPES.has(type);
  if (!gated && type === 'execute' && OFFENSIVE_CMD_RE.test(String(body || ''))) gated = true;
  if (!gated) return { gated: false, target: null };
  const target = extractTarget(body);
  if (!target || SELF_RE.test(target)) return { gated: false, target };
  return { gated: true, target };
}

// ---- per-session authorization store (in-memory cache backed by DB) ----
const cache = new Map(); // sessionId -> Set(target)
function grants(sessionId) {
  let s = cache.get(sessionId);
  if (!s) { s = new Set(); cache.set(sessionId, s); }
  return s;
}

export async function isAuthorized(sessionId, target) {
  if (!sessionId || !target) return false;
  if (grants(sessionId).has(target)) return true;
  try {
    const rows = await query(
      `SELECT 1 FROM target_authorizations WHERE session_id=$1 AND target=$2 AND revoked=false LIMIT 1`,
      [sessionId, target]
    );
    if (rows.length) { grants(sessionId).add(target); return true; }
  } catch (e) {
    console.warn('authz check failed (failing closed):', e.message);
  }
  return false;
}

export async function authorizeTarget({ sessionId, userId, target, note }) {
  grants(sessionId).add(target);
  try {
    await query(
      `INSERT INTO target_authorizations (id, session_id, user_id, target, scope_note, revoked)
       VALUES ($1,$2,$3,$4,$5,false)
       ON CONFLICT (session_id, target)
       DO UPDATE SET revoked=false, scope_note=EXCLUDED.scope_note, created_at=now()`,
      [newId(), sessionId, userId, target, note || null]
    );
  } catch (e) {
    console.warn('authz store failed:', e.message);
  }
}

export async function revokeTarget({ sessionId, target }) {
  grants(sessionId).delete(target);
  try {
    const r = await query(
      `UPDATE target_authorizations SET revoked=true
       WHERE session_id=$1 AND target=$2 AND revoked=false RETURNING id`,
      [sessionId, target]
    );
    return r.length > 0;
  } catch (e) {
    console.warn('authz revoke failed:', e.message);
    return false;
  }
}

export async function listAuthorizations(sessionId) {
  try {
    return await query(
      `SELECT target, scope_note, created_at FROM target_authorizations
       WHERE session_id=$1 AND revoked=false ORDER BY created_at DESC`,
      [sessionId]
    );
  } catch {
    return [];
  }
}

async function recordEvent({ sessionId, userId, type, target, command, decision }) {
  try {
    await query(
      `INSERT INTO authz_events (id, session_id, user_id, action_type, target, command, decision)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [newId(), sessionId, userId, type, target || null, String(command || '').slice(0, 2000), decision]
    );
  } catch (e) {
    console.warn('authz audit failed:', e.message);
  }
}

// The gate itself — called at the top of runTool. When `blocked` is true the caller MUST NOT run
// the action; `message` explains how the operator authorizes it. Every evaluation is audit-logged.
export async function gateAction({ type, body, sessionId, userId }) {
  const { gated, target } = classifyAction(type, body);
  if (!gated) return { blocked: false, target: target || null };
  const ok = await isAuthorized(sessionId, target);
  await recordEvent({ sessionId, userId, type, target, command: body, decision: ok ? 'allowed' : 'blocked' });
  if (ok) return { blocked: false, target };
  return {
    blocked: true,
    target,
    message:
      `⛔ **Authorization required** — nothing was run.\n\n` +
      `This is an offensive action against \`${target}\`. Before it can run, the operator must ` +
      `confirm they OWN this target or hold WRITTEN permission (scope) to test it.\n\n` +
      `If authorized, the operator replies:\n\n    /authorize ${target} <scope note, e.g. client + PO#>\n\n` +
      `The AI cannot grant this itself. This blocked attempt has been logged in the audit trail.`,
  };
}

// Handle an operator authorization command typed in chat. Returns a reply string, or null if
// `content` is not an authz command. Human-in-the-loop: ONLY a real operator message grants scope.
export async function handleAuthzCommand(content, { sessionId, userId }) {
  const m = /^\s*\/(authorize|deauthorize|unauthorize|revoke|authorizations|scope)\b\s*(.*)$/is.exec(content || '');
  if (!m) return null;
  const cmd = m[1].toLowerCase();
  const rest = (m[2] || '').trim();

  if (cmd === 'authorizations' || cmd === 'scope') {
    const list = await listAuthorizations(sessionId);
    if (!list.length) {
      return '🔓 No targets authorized in this session yet.\n\n' +
        'Authorize one with `/authorize <target> <scope note>` before running offensive tools.';
    }
    return '🔐 **Authorized targets (this session):**\n' +
      list.map((a) => `- \`${a.target}\`${a.scope_note ? ' — ' + a.scope_note : ''}`).join('\n');
  }

  const parts = rest.split(/\s+/).filter(Boolean);
  const rawTarget = parts.shift();
  const note = parts.join(' ');
  if (!rawTarget) return `Usage: \`/${cmd} <target> [scope note]\``;
  const target = extractTarget(rawTarget) || rawTarget.toLowerCase();

  if (cmd === 'authorize') {
    await authorizeTarget({ sessionId, userId, target, note });
    return `✅ **Authorized** \`${target}\` for this session${note ? ` — _${note}_` : ''}.\n\n` +
      `Offensive tools can now run against it. Recorded in the audit trail. ` +
      `Revoke anytime with \`/revoke ${target}\`.`;
  }

  const ok = await revokeTarget({ sessionId, target });
  return ok
    ? `🔒 **Revoked** authorization for \`${target}\`. Offensive tools are blocked against it again.`
    : `\`${target}\` wasn't in the authorized list for this session.`;
}
