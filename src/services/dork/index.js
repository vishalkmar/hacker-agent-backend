// OSINT — Google/search-engine DORK sweep (automated).
//
// Powers the ```dork agent tag. The `search` tag runs ONE query; this runs a curated SUITE of the classic
// recon dorks against a target and classifies every hit into a severity-rated finding — so the agent (or
// user) gets "what's already exposed & indexed about this target" in one shot, without hand-writing each
// operator. Runs through the DuckDuckGo HTML endpoint (no API key, same source as `search`), sequentially
// with a small delay so we don't get rate-limited, and degrades gracefully if a query is blocked.
//
// Passive OSINT (only queries a search engine — never touches the target), so like `search`/`recon` it is
// NOT authorization-gated. finding_type 'osint-dork'. Results are LEADS to verify, phrased as such.

import { multiSearch } from '../web/search.js';
import { normSev, dedupCap } from '../appsec/engine.js';

function domainOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }

// The dork catalogue (Instagram "top Google dorks" list + hardening extras). Each:
//   cat, q(D) -> query, sev, type, title, cwe, fix, onTarget (result URL must be on the target domain).
export const DORKS = [
  { cat: 'subdomains', q: (D) => `site:${D} -www`, sev: 'info', type: 'subdomain', onTarget: true,
    title: 'Indexed subdomain/host', cwe: null, fix: 'Inventory every indexed host; ensure non-prod/internal ones are not publicly reachable.' },
  { cat: 'admin-portal', q: (D) => `site:${D} inurl:admin | inurl:login | inurl:signin`, sev: 'info', type: 'admin-panel', onTarget: true,
    title: 'Login / admin portal indexed', cwe: 'CWE-200', fix: 'Restrict admin panels by IP/VPN + MFA; keep them out of search indexes (robots/meta noindex is not security, but reduces exposure).' },
  { cat: 'open-dir', q: (D) => `site:${D} intitle:"index of"`, sev: 'medium', type: 'open-directory', onTarget: true,
    title: 'Open directory listing (index of)', cwe: 'CWE-548', fix: 'Disable directory listing (autoindex off / Options -Indexes); it leaks file names and often backups/config.' },
  { cat: 'config-files', q: (D) => `site:${D} ext:conf | ext:cnf | ext:ini | ext:xml | ext:yml | ext:yaml`, sev: 'high', type: 'exposed-config', onTarget: true,
    title: 'Exposed configuration file', cwe: 'CWE-538', fix: 'Remove config files from the web root; they often contain hostnames, paths and credentials. Rotate anything leaked.' },
  { cat: 'env-files', q: (D) => `site:${D} inurl:.env | intext:"index of" ".env"`, sev: 'critical', type: 'env-exposure', onTarget: true,
    title: 'Exposed environment (.env) file', cwe: 'CWE-312', fix: 'CRITICAL — .env files hold DB creds/API keys/secrets. Remove from web root immediately and ROTATE every secret in them.' },
  { cat: 'sql-errors', q: (D) => `site:${D} intext:"sql syntax near" | intext:"mysql_fetch" | intext:"You have an error in your SQL"`, sev: 'high', type: 'sqli-indicator', onTarget: true,
    title: 'Page leaking SQL errors (SQLi indicator)', cwe: 'CWE-89', fix: 'Leaked SQL errors indicate injectable/unsanitised input — use parameterised queries and hide DB errors. Test the page with the sqli/loginbypass tools.' },
  { cat: 'log-password', q: (D) => `site:${D} filetype:log intext:password | filetype:log intext:pass`, sev: 'high', type: 'log-exposure', onTarget: true,
    title: 'Log file containing passwords', cwe: 'CWE-532', fix: 'Remove log files from the web root; never log credentials/secrets. Rotate anything exposed.' },
  { cat: 'backup-files', q: (D) => `site:${D} ext:bak | ext:bkp | ext:bkf | ext:old | ext:sql | ext:zip | ext:tar.gz`, sev: 'medium', type: 'backup-exposure', onTarget: true,
    title: 'Exposed backup / archive file', cwe: 'CWE-530', fix: 'Delete forgotten backups from the web root (source/DB dumps are gold for attackers); store backups off the web server.' },
  { cat: 'api-keys', q: (D) => `site:${D} intext:"api_key" | intext:"apikey" | intext:"secret_key" | intext:"access_token"`, sev: 'high', type: 'secret-indicator', onTarget: true,
    title: 'Page referencing API keys / secrets', cwe: 'CWE-312', fix: 'Audit for hard-coded keys/tokens in indexed pages/JS; rotate any real secret and move it server-side.' },
  { cat: 'git-exposed', q: (D) => `site:${D} inurl:.git | intitle:"index of" ".git"`, sev: 'high', type: 'git-exposure', onTarget: true,
    title: 'Exposed .git directory', cwe: 'CWE-527', fix: 'Block access to /.git (source & history are recoverable); deploy build artefacts only, not the repo.' },
  { cat: 'public-docs', q: (D) => `site:${D} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx`, sev: 'low', type: 'doc-exposure', onTarget: true,
    title: 'Public document (may leak internal info)', cwe: 'CWE-200', fix: 'Review indexed documents for internal names, emails, credentials or metadata before leaving them public.' },
  { cat: 'pastebin-leak', q: (D) => `site:pastebin.com "${D}" | site:paste.ee "${D}" | site:ghostbin.com "${D}"`, sev: 'high', type: 'paste-leak', onTarget: false,
    title: 'Target mentioned in a public paste (possible leak)', cwe: 'CWE-200', fix: 'Review the paste for leaked credentials/keys/source; request takedown and rotate anything exposed.' },
  { cat: 'github-leak', q: (D) => `site:github.com "${D}" | site:gitlab.com "${D}"`, sev: 'medium', type: 'code-leak', onTarget: false,
    title: 'Target referenced in public code (GitHub/GitLab)', cwe: 'CWE-200', fix: 'Search these repos for hard-coded secrets/config referencing your domain; rotate any real credential found.' },
  { cat: 'cloud-storage', q: (D) => `site:s3.amazonaws.com "${D}" | site:blob.core.windows.net "${D}" | site:storage.googleapis.com "${D}"`, sev: 'medium', type: 'cloud-exposure', onTarget: false,
    title: 'Public cloud-storage object mentioning the target', cwe: 'CWE-200', fix: 'Audit the bucket/container for public objects; lock down ACLs (Block Public Access).' },
];

// Direct, one-click search URLs for a dork (so the playbook is actionable even if live scraping is blocked;
// the agent can also open these with its ```browser tool, which evades bot-detection far better than fetch).
export function searchUrls(query) {
  const e = encodeURIComponent(query);
  return {
    google: `https://www.google.com/search?q=${e}`,
    ddg: `https://duckduckgo.com/?q=${e}`,
    bing: `https://www.bing.com/search?q=${e}`,
  };
}

export function buildDorks(domain) {
  const D = domainOf(domain);
  if (!D) return [];
  return DORKS.map((d) => ({ ...d, query: d.q(D), domain: D, urls: searchUrls(d.q(D)) }));
}

// A site:target result must actually be ON the target domain (kills DuckDuckGo cross-site noise).
export function onTargetMatch(url, domain) {
  const D = domainOf(domain);
  return new RegExp(`(^|\\.|//|@)${D.replace(/[.]/g, '\\.')}(/|:|$|["'\\s])`, 'i').test((url || '') + ' ');
}

// Map a classified hit -> a findings-pipeline object.
export function hitToFinding(h, domain) {
  return {
    finding_type: 'osint-dork',
    severity: normSev(h.sev),
    title: `${h.title} — ${h.url}`.slice(0, 200),
    host: (h.url || '').slice(0, 200) || domainOf(domain),
    evidence: `Search-engine indexed (dork: ${h.cat}). ${h.snippet || ''}`.slice(0, 240),
    cve: h.cwe || null,
    remediation: h.fix,
    source: `dork-${h.cat}`,
  };
}

const sleep = (ms, signal) => new Promise((res, rej) => {
  const t = setTimeout(res, ms);
  if (signal) signal.addEventListener('abort', () => { clearTimeout(t); rej(new Error('aborted')); }, { once: true });
});

// Run the whole dork suite across MULTIPLE engines (Bing + DuckDuckGo) with jittered delays and one retry
// on a block — resilient to per-engine rate-limiting. Per-query failures are swallowed. Returns
// { domain, hits:[{cat,type,sev,title,url,snippet,...}], findings:[...], queriesRun, blocked }.
export async function runDorkSweep(domain, { signal, perQueryMax = 5, delayMs = 1100, only } = {}) {
  const D = domainOf(domain);
  const dorks = buildDorks(D).filter((d) => !only || only.includes(d.cat));
  const hits = [];
  const seen = new Set();
  let queriesRun = 0, blocked = 0;
  for (const d of dorks) {
    if (signal?.aborted) break;
    let results = null;
    for (let attempt = 0; attempt < 2 && results === null; attempt++) {
      try {
        // alternate which engine leads each attempt so we spread load across Bing + DDG
        const engines = attempt === 0 ? ['bing', 'ddg'] : ['ddg', 'bing'];
        const r = await multiSearch(d.query, { max: perQueryMax, signal, engines });
        results = r.results;
      } catch (e) {
        if (String(e.message).includes('aborted')) { results = []; break; }
        if (attempt === 0) { try { await sleep(1500 + Math.random() * 1500, signal); } catch { results = []; } }
        else { blocked++; results = []; }
      }
    }
    if (results && results.length >= 0) queriesRun++;
    for (const r of (results || [])) {
      // For site:target dorks, keep only results actually on the target domain (kills cross-site noise).
      if (d.onTarget && !onTargetMatch(r.url, D)) continue;
      const key = d.cat + '|' + r.url;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ cat: d.cat, type: d.type, sev: d.sev, title: d.title, cwe: d.cwe, fix: d.fix, url: r.url, snippet: (r.snippet || '').slice(0, 200) });
    }
    if (signal?.aborted) break;
    if (delayMs) { try { await sleep(delayMs + Math.random() * 700, signal); } catch { break; } }
  }
  const findings = dedupCap(hits.map((h) => hitToFinding(h, D)), 120);
  // The playbook is ALWAYS returned (reliable value): every dork with its one-click search URLs, ranked by
  // severity, so the agent/user can run/open the high-value ones (e.g. via the ```browser tool) even when
  // live scraping is rate-limited.
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const playbook = dorks
    .map((d) => ({ cat: d.cat, sev: d.sev, title: d.title, query: d.query, urls: d.urls }))
    .sort((a, b) => (order[a.sev] ?? 5) - (order[b.sev] ?? 5));
  return { domain: D, hits, findings, queriesRun, blocked, totalDorks: dorks.length, playbook };
}

export function renderDork(sweep) {
  if (!sweep || !sweep.domain) return '_Give a domain to dork, e.g._ ```dork target.com```';
  const { hits, queriesRun, blocked, totalDorks, domain, playbook = [] } = sweep;
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const parts = [];

  // 1) Live-scrape hits -> exposures + surface (when the engines answered).
  if (hits.length) {
    const bySev = [...hits].sort((a, b) => (order[a.sev] ?? 5) - (order[b.sev] ?? 5));
    const risky = bySev.filter((h) => h.sev !== 'info');
    const surface = bySev.filter((h) => h.sev === 'info');
    parts.push(`**🔍 Dork sweep of ${domain}** — ${hits.length} indexed hit(s) from ${queriesRun}/${totalDorks} dorks${blocked ? ` (${blocked} rate-limited)` : ''}:`);
    if (risky.length) parts.push('**🚩 Exposures (verify each):**\n' + risky.map((h) => `- **${h.sev.toUpperCase()}** ${h.title}${h.cwe ? ` [${h.cwe}]` : ''}\n  ↳ ${h.url}${h.snippet ? `\n  ↳ ${h.snippet}` : ''}`).join('\n'));
    if (surface.length) parts.push('**🌐 Attack surface (indexed):**\n' + surface.slice(0, 25).map((h) => `- ${h.url}`).join('\n'));
  } else {
    const note = blocked ? ` (search engines rate-limited ${blocked}/${totalDorks} live queries from this host)` : '';
    parts.push(`**🔍 Dork sweep of ${domain}** — no auto-scraped hits${note}. Run the high-value dorks below (open them with the \`browser\` tool — a real browser bypasses the bot-block).`);
  }

  // 2) The playbook is ALWAYS shown — the actionable core, ranked by severity.
  if (playbook.length) {
    const top = playbook.filter((d) => d.sev === 'critical' || d.sev === 'high');
    const rest = playbook.filter((d) => d.sev !== 'critical' && d.sev !== 'high');
    const line = (d) => `- **${d.sev.toUpperCase()}** ${d.title}\n  ↳ \`${d.query}\`\n  ↳ ${d.urls.google}`;
    parts.push('**📖 Dork playbook (high-value first):**\n' + top.map(line).join('\n'));
    if (rest.length) parts.push('**More dorks:**\n' + rest.map((d) => `- ${d.sev.toUpperCase()} — \`${d.query}\``).join('\n'));
  }
  return parts.join('\n\n');
}
