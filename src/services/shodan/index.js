// Shodan OSINT client — internet-wide device/service intelligence for recon.
//
// Powers the ```shodan agent tag. Zero-dependency native client against https://api.shodan.io (the archived
// `shodan-client` npm pkg is 6 years old / `got`-based — not used). Passive OSINT: it queries Shodan's own
// scan database, it does NOT send packets to the target, so it is not authorization-gated (like ```dork /
// ```osint). Give it an IP, a domain, or a search query and it returns open ports, service banners, known
// CVEs, TLS certs, subdomains, org/ASN, and geo.
//
// Free spec grammar (```shodan <spec>):
//   host 8.8.8.8                 → all services/ports/CVEs on an IP
//   1.2.3.4                      → (bare IP) same as host
//   search <shodan query>        → banner search (e.g. "apache country:DE", 'ssl:"Target Inc"', product:MongoDB)
//   count <shodan query>         → result count + facets only (NO query credits used)
//   domain example.com           → subdomains + DNS records for a domain
//   example.com                  → (bare domain) same as domain
//   resolve a.com,b.com          → hostnames → IPs
//   reverse 8.8.8.8,1.1.1.1      → IPs → hostnames
//   ports                        → ports Shodan crawls
//   myip                         → your external IP (as Shodan sees it)
//   info                         → API plan + remaining query/scan credits

import { env } from '../../config/env.js';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const DOMAINY = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;

export function shodanEnabled() {
  return !!env.shodan.apiKey;
}

// Core GET against the Shodan REST API. Returns parsed JSON or throws a clean Error with Shodan's message.
async function shodanGet(pathname, params = {}, { signal } = {}) {
  if (!shodanEnabled()) throw new Error('Shodan is not configured — set SHODAN_API_KEY in the backend .env.');
  const url = new URL(env.shodan.baseUrl.replace(/\/$/, '') + pathname);
  url.searchParams.set('key', env.shodan.apiKey);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), env.shodan.timeoutMs);
  // caller's signal aborts ours too
  if (signal) signal.addEventListener('abort', () => ctrl.abort(), { once: true });
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    const text = await res.text();
    let json;
    try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
    if (!res.ok) {
      const msg = json?.error || `HTTP ${res.status}`;
      throw new Error(`Shodan: ${msg}`);
    }
    return json;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Shodan request timed out.');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ---- typed methods ----
export const shodanHost = (ip, { history = false, minify = false, signal } = {}) =>
  shodanGet(`/shodan/host/${encodeURIComponent(ip)}`, { history: history || undefined, minify: minify || undefined }, { signal });

export const shodanSearch = (query, { facets, page = 1, minify = true, signal } = {}) =>
  shodanGet('/shodan/host/search', { query, facets, page, minify }, { signal });

export const shodanCount = (query, { facets, signal } = {}) =>
  shodanGet('/shodan/host/count', { query, facets }, { signal });

export const shodanDomain = (domain, { signal } = {}) =>
  shodanGet(`/dns/domain/${encodeURIComponent(domain)}`, {}, { signal });

export const shodanResolve = (hostnames, { signal } = {}) =>
  shodanGet('/dns/resolve', { hostnames }, { signal });

export const shodanReverse = (ips, { signal } = {}) =>
  shodanGet('/dns/reverse', { ips }, { signal });

export const shodanPorts = ({ signal } = {}) => shodanGet('/shodan/ports', {}, { signal });
export const shodanMyip = ({ signal } = {}) => shodanGet('/tools/myip', {}, { signal });
export const shodanApiInfo = ({ signal } = {}) => shodanGet('/api-info', {}, { signal });

// Parse a free-form spec into { action, arg }.
export function parseShodanSpec(body) {
  const raw = String(body || '').trim();
  if (!raw) return { action: 'help' };
  const m = raw.match(/^(host|search|count|domain|resolve|reverse|ports|myip|info|api-info)\b\s*(.*)$/is);
  if (m) {
    const action = m[1].toLowerCase() === 'api-info' ? 'info' : m[1].toLowerCase();
    return { action, arg: m[2].trim() };
  }
  // no keyword → infer from the shape of the argument
  if (IPV4.test(raw)) return { action: 'host', arg: raw };
  if (DOMAINY.test(raw)) return { action: 'domain', arg: raw };
  return { action: 'search', arg: raw }; // anything else is a search query (has filters/keywords)
}

// Run a spec and return { action, arg, data } or { action, arg, error }.
export async function runShodan(body, { signal } = {}) {
  const { action, arg } = parseShodanSpec(body);
  try {
    let data;
    switch (action) {
      case 'help': return { action: 'help' };
      case 'host': data = await shodanHost(arg, { signal }); break;
      case 'search': data = await shodanSearch(arg, { facets: 'port:10,org:10,country:10', signal }); break;
      case 'count': data = await shodanCount(arg, { facets: 'port:10,org:10,country:10,product:10', signal }); break;
      case 'domain': data = await shodanDomain(arg, { signal }); break;
      case 'resolve': data = await shodanResolve(arg.replace(/\s+/g, ''), { signal }); break;
      case 'reverse': data = await shodanReverse(arg.replace(/\s+/g, ''), { signal }); break;
      case 'ports': data = await shodanPorts({ signal }); break;
      case 'myip': data = await shodanMyip({ signal }); break;
      case 'info': data = await shodanApiInfo({ signal }); break;
      default: data = await shodanSearch(arg, { signal });
    }
    return { action, arg, data };
  } catch (e) {
    return { action, arg, error: e.message };
  }
}

// ---- rendering ----
const HELP = [
  '**Shodan** — internet OSINT. Usage: ```shodan <spec>',
  '• `host 8.8.8.8` (or just an IP) — open ports, banners, CVEs on a host',
  '• `search apache country:DE` / `ssl:"Target Inc"` / `org:"ACME"` — banner search',
  '• `count port:27017` — result count + facets (no query credits used)',
  '• `domain example.com` (or just a domain) — subdomains + DNS records',
  '• `resolve a.com,b.com` · `reverse 8.8.8.8` · `ports` · `myip` · `info`',
].join('\n');

function fmtCves(vulns) {
  if (!vulns) return '';
  const list = Array.isArray(vulns) ? vulns : Object.keys(vulns);
  if (!list.length) return '';
  return `\n  ⚠️ CVEs: ${list.slice(0, 12).join(', ')}${list.length > 12 ? ` (+${list.length - 12} more)` : ''}`;
}

function renderHost(d) {
  const lines = [`**Shodan host: ${d.ip_str || ''}**`];
  const org = [d.org, d.isp && d.isp !== d.org ? `ISP ${d.isp}` : '', d.asn].filter(Boolean).join(' · ');
  if (org) lines.push(org);
  const loc = [d.city, d.country_name].filter(Boolean).join(', ');
  if (loc) lines.push(`📍 ${loc}${d.os ? ` · OS: ${d.os}` : ''}`);
  if (d.hostnames?.length) lines.push(`Hostnames: ${d.hostnames.slice(0, 8).join(', ')}`);
  if (d.ports?.length) lines.push(`Open ports (${d.ports.length}): ${d.ports.slice(0, 30).join(', ')}`);
  // top CVEs across the host
  const allV = (d.data || []).flatMap((s) => (s.vulns ? (Array.isArray(s.vulns) ? s.vulns : Object.keys(s.vulns)) : []));
  const uniqV = [...new Set(allV)];
  if (uniqV.length) lines.push(`⚠️ **${uniqV.length} known CVEs**: ${uniqV.slice(0, 15).join(', ')}${uniqV.length > 15 ? ' …' : ''}`);
  // per-service banners (trimmed)
  for (const s of (d.data || []).slice(0, 12)) {
    const head = `\n:${s.port}/${s.transport || 'tcp'} ${s.product ? `— ${s.product}` : ''}${s.version ? ` ${s.version}` : ''}${s._shodan?.module ? ` [${s._shodan.module}]` : ''}`;
    const extra = [];
    if (s.ssl?.cert?.subject?.CN) extra.push(`TLS CN=${s.ssl.cert.subject.CN}`);
    if (s.http?.title) extra.push(`title="${String(s.http.title).slice(0, 60)}"`);
    if (s.http?.server) extra.push(`Server: ${s.http.server}`);
    lines.push(head + (extra.length ? '  ' + extra.join(' · ') : '') + fmtCves(s.vulns));
  }
  return lines.join('\n');
}

function renderSearch(d, { count = false } = {}) {
  const lines = [`**Shodan ${count ? 'count' : 'search'}** — total matches: ${d.total ?? 0}`];
  const facets = d.facets || {};
  for (const [name, arr] of Object.entries(facets)) {
    lines.push(`  ${name}: ${arr.slice(0, 8).map((f) => `${f.value}(${f.count})`).join(', ')}`);
  }
  if (!count) {
    for (const m of (d.matches || []).slice(0, 15)) {
      const cve = m.vulns ? ` ⚠️${(Array.isArray(m.vulns) ? m.vulns : Object.keys(m.vulns)).length}CVE` : '';
      const title = m.http?.title ? ` "${String(m.http.title).slice(0, 45)}"` : '';
      lines.push(`  • ${m.ip_str}:${m.port} ${m.org || ''}${m.product ? ` [${m.product}]` : ''}${title}${cve}`);
    }
    if ((d.matches || []).length > 15) lines.push(`  … +${d.matches.length - 15} more on this page`);
  }
  return lines.join('\n');
}

function renderDomain(d) {
  const lines = [`**Shodan domain: ${d.domain || ''}**`];
  if (d.tags?.length) lines.push(`Tags: ${d.tags.join(', ')}`);
  const subs = (d.subdomains || []);
  if (subs.length) lines.push(`Subdomains (${subs.length}): ${subs.slice(0, 60).join(', ')}${subs.length > 60 ? ' …' : ''}`);
  const recs = (d.data || []);
  const byType = {};
  for (const r of recs) (byType[r.type] ||= []).push(r);
  for (const [type, arr] of Object.entries(byType)) {
    lines.push(`  ${type} (${arr.length}): ${arr.slice(0, 12).map((r) => `${r.subdomain ? r.subdomain + '→' : ''}${r.value}`).join(', ')}${arr.length > 12 ? ' …' : ''}`);
  }
  return lines.join('\n');
}

export function renderShodan(result) {
  if (!result || result.action === 'help') return HELP;
  if (result.error) {
    let msg = `Shodan (${result.action} ${result.arg || ''}): ${result.error}`;
    // The free OSS plan can't do host/search/domain/dns; count + ports + facets ARE free. Guide the user.
    if (/membership|upgrade|query credit|access/i.test(result.error)) {
      const q = result.arg ? ` \`${result.arg}\`` : '';
      msg += `\n↳ Your Shodan plan can't run \`${result.action}\`. FREE alternatives that need no credits: ` +
        `\`shodan count${q ? q : ' <query>'}\` (totals + country/org/product/port facets) and \`shodan ports\`. ` +
        'Full host lookups / banner search / subdomains need a paid Shodan membership (account.shodan.io → Upgrade).';
    }
    return msg;
  }
  const d = result.data || {};
  switch (result.action) {
    case 'host': return renderHost(d);
    case 'search': return renderSearch(d);
    case 'count': return renderSearch(d, { count: true });
    case 'domain': return renderDomain(d);
    case 'resolve': return '**Shodan resolve**\n' + Object.entries(d).map(([h, ip]) => `  ${h} → ${ip}`).join('\n');
    case 'reverse': return '**Shodan reverse DNS**\n' + Object.entries(d).map(([ip, hs]) => `  ${ip} → ${(hs || []).join(', ')}`).join('\n');
    case 'ports': return `**Shodan crawled ports** (${(d || []).length}): ${(d || []).slice(0, 80).join(', ')} …`;
    case 'myip': return `Your external IP (per Shodan): ${typeof d === 'string' ? d : JSON.stringify(d)}`;
    case 'info': return '**Shodan API info**\n' + Object.entries(d).map(([k, v]) => `  ${k}: ${v}`).join('\n');
    default: return '```\n' + JSON.stringify(d, null, 2).slice(0, 2000) + '\n```';
  }
}

// Turn a Shodan host lookup into findings (open-port + CVE intel) for the session findings panel.
export function shodanFindings(result) {
  if (!result || result.error || result.action !== 'host') return [];
  const d = result.data || {};
  const out = [];
  const ip = d.ip_str || result.arg;
  const allV = [...new Set((d.data || []).flatMap((s) => (s.vulns ? (Array.isArray(s.vulns) ? s.vulns : Object.keys(s.vulns)) : [])))];
  if (allV.length) {
    out.push({
      finding_type: 'osint', severity: 'high', source: 'shodan-cve',
      title: `Shodan: ${allV.length} known CVE(s) on ${ip}`,
      evidence: allV.slice(0, 20).join(', '), target: ip,
      remediation: 'Patch the affected services; verify each CVE against the actual running version (Shodan banners can lag). Restrict exposure with a firewall/allow-list.',
    });
  }
  if (d.ports?.length) {
    out.push({
      finding_type: 'osint', severity: 'info', source: 'shodan-exposure',
      title: `Shodan: ${d.ports.length} port(s) exposed on ${ip}`,
      evidence: `ports ${d.ports.slice(0, 40).join(', ')}${d.org ? ` · ${d.org}` : ''}`, target: ip,
      remediation: 'Confirm every exposed service is intended to be internet-facing; close/firewall the rest.',
    });
  }
  return out;
}
