// pwnedpass — password breach check via HaveIBeenPwned "Pwned Passwords" (k-anonymity).
//
// DEFENSIVE tool: tells a user whether their OWN password(s) have appeared in known data breaches, so they
// can change them. Privacy-preserving by design — the FULL password (and full hash) NEVER leave the machine:
//   1) SHA-1 the password locally → 40 hex chars.
//   2) Send ONLY the first 5 chars (the "range" prefix) to api.pwnedpasswords.com/range/<prefix>.
//   3) The API returns every breached-hash SUFFIX under that prefix (+ how many times each was seen).
//   4) We match the remaining 35 chars LOCALLY → breach count. So the server never learns the password.
// `Add-Padding: true` pads the response so traffic analysis can't infer the prefix either.
//
// Not gated (no target, no third-party harm — you check your own passwords). Instant, no external tool needed.

import crypto from 'node:crypto';

const API = 'https://api.pwnedpasswords.com/range/';

export function sha1Upper(s) {
  return crypto.createHash('sha1').update(String(s), 'utf8').digest('hex').toUpperCase();
}

// Given a range-API response body ("SUFFIX:COUNT\r\n…") and the password's 35-char suffix, return the breach
// count (0 = not found). Pure/local — unit-testable without the network.
export function countFromRange(rangeText, suffix) {
  const want = String(suffix).toUpperCase();
  for (const line of String(rangeText || '').split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    if (line.slice(0, idx).trim().toUpperCase() === want) {
      return parseInt(line.slice(idx + 1), 10) || 0;
    }
  }
  return 0;
}

// Check a single password against the breach corpus. Returns { password, breached, count } (or { error }).
export async function checkOne(password, { signal, fetchImpl = fetch } = {}) {
  const hash = sha1Upper(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  try {
    const res = await fetchImpl(API + prefix, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'CypherMind-PwnedCheck' },
      signal,
    });
    if (!res.ok) return { password, error: `API HTTP ${res.status}` };
    const count = countFromRange(await res.text(), suffix);
    return { password, prefix, breached: count > 0, count };
  } catch (e) {
    return { password, error: e.name === 'AbortError' ? 'aborted' : e.message };
  }
}

// Split raw input (a pasted list or a .txt file body) into distinct passwords, preserving order.
export function parsePasswords(input) {
  const seen = new Set();
  const out = [];
  for (const line of String(input || '').split(/\r?\n/)) {
    const t = line.trim();                          // strip list-formatting edges; internal spaces kept
    if (!t || t.startsWith('#')) continue;          // skip blanks + comments
    if (seen.has(t)) continue; seen.add(t);
    out.push(t);
    if (out.length >= 200) break;                   // safety cap
  }
  return out;
}

// Check many passwords with small concurrency (be polite to the CDN). Returns results in input order.
export async function checkMany(passwords, { signal, concurrency = 5, fetchImpl = fetch } = {}) {
  const results = new Array(passwords.length);
  let i = 0;
  const worker = async () => {
    while (i < passwords.length) {
      const idx = i++;
      results[idx] = await checkOne(passwords[idx], { signal, fetchImpl });
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, passwords.length || 1) }, worker));
  return results;
}

// Partially mask a password for the report (so a shoulder-surfer/log can't read it, but the owner recognises it).
function mask(p) {
  const s = String(p);
  if (s.length <= 2) return s[0] ? s[0] + '•' : '••';
  if (s.length <= 5) return s[0] + '•'.repeat(s.length - 2) + s[s.length - 1];
  return s.slice(0, 2) + '•'.repeat(Math.min(8, s.length - 4)) + s.slice(-2);
}

// Render an instant markdown report.
export function renderPwnedReport(results) {
  const rows = results.map((r) => {
    if (r.error) return `| \`${mask(r.password)}\` | ⚠️ error | — | ${r.error} |`;
    return r.breached
      ? `| \`${mask(r.password)}\` | 🔴 **BREACHED** | ${r.count.toLocaleString()} | change it now + enable 2FA |`
      : `| \`${mask(r.password)}\` | 🟢 not found | 0 | good — keep it unique |`;
  });
  const breached = results.filter((r) => r.breached).length;
  const errs = results.filter((r) => r.error).length;
  return [
    '🔐 **Password Breach Check** — HaveIBeenPwned *Pwned Passwords* (k-anonymity: your full password never left this machine, only a 5-char SHA-1 prefix was sent).',
    '',
    '| Password | Status | Times seen in breaches | Action |',
    '|---|---|---|---|',
    ...rows,
    '',
    `**Summary:** ${breached}/${results.length} breached${errs ? `, ${errs} error(s)` : ''}. ` +
      (breached
        ? 'Any 🔴 password is publicly known — attackers use these in credential-stuffing. Change it everywhere it was reused and turn on 2FA.'
        : 'None of these appear in the known-breach corpus. Still use unique passwords per site + a password manager.'),
    '',
    '_Note: "not found" ≠ strong. It only means this exact string isn\'t in the breach set yet._',
  ].join('\n');
}

export function pwnedLabel(passwords) {
  return `pwnedpass: ${passwords.length} password(s)`;
}
