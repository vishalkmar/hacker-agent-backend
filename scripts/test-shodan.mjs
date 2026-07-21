// Shodan client tests — spec parsing, rendering, findings, error-handling. fetch is MOCKED so the suite is
// deterministic and offline (live API depends on plan/rate-limits). Run: node scripts/test-shodan.mjs
process.env.SHODAN_API_KEY = process.env.SHODAN_API_KEY || 'TESTKEY';
import {
  parseShodanSpec, runShodan, renderShodan, shodanFindings, shodanEnabled,
} from '../src/services/shodan/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

// ---- mock fetch: route by URL path, return canned Shodan JSON ----
const realFetch = globalThis.fetch;
let lastUrl = null;
function mockFetch(map) {
  globalThis.fetch = async (url) => {
    lastUrl = String(url);
    const u = new URL(url);
    const key = Object.keys(map).find((k) => u.pathname.startsWith(k));
    const entry = key ? map[key] : { status: 404, body: { error: 'Invalid path' } };
    return { ok: (entry.status || 200) < 400, status: entry.status || 200, text: async () => JSON.stringify(entry.body) };
  };
}
const restore = () => { globalThis.fetch = realFetch; };

console.log('\n[1] enabled + authz (passive OSINT, ungated)');
ok('shodanEnabled with key', shodanEnabled() === true);
ok('shodan NOT gated (host)', classifyAction('shodan', 'host 8.8.8.8').gated === false);
ok('shodan NOT gated (search)', classifyAction('shodan', 'search apache').gated === false);

console.log('\n[2] spec parsing (keyword + shape inference)');
ok('bare IP -> host', parseShodanSpec('8.8.8.8').action === 'host');
ok('bare domain -> domain', parseShodanSpec('example.com').action === 'domain');
ok('keyword search', parseShodanSpec('search apache country:DE').action === 'search' && parseShodanSpec('search apache country:DE').arg === 'apache country:DE');
ok('keyword count', parseShodanSpec('count port:22').action === 'count');
ok('filter query w/o keyword -> search', parseShodanSpec('org:"ACME" port:443').action === 'search');
ok('myip / info / ports', parseShodanSpec('myip').action === 'myip' && parseShodanSpec('info').action === 'info' && parseShodanSpec('ports').action === 'ports');
ok('api-info alias -> info', parseShodanSpec('api-info').action === 'info');
ok('empty -> help', parseShodanSpec('').action === 'help');

console.log('\n[3] host lookup rendering + findings');
mockFetch({
  '/shodan/host/': { body: {
    ip_str: '203.0.113.9', org: 'ACME Corp', isp: 'ACME', asn: 'AS64500', city: 'Berlin', country_name: 'Germany', os: 'Linux',
    hostnames: ['web.acme.tld'], ports: [22, 80, 443, 27017],
    data: [
      { port: 443, transport: 'tcp', product: 'nginx', version: '1.18', _shodan: { module: 'https' }, ssl: { cert: { subject: { CN: 'acme.tld' } } }, http: { title: 'ACME', server: 'nginx' }, vulns: { 'CVE-2021-23017': {}, 'CVE-2019-9511': {} } },
      { port: 27017, transport: 'tcp', product: 'MongoDB', vulns: ['CVE-2020-7921'] },
    ],
  } },
});
const host = await runShodan('host 203.0.113.9');
const hostOut = renderShodan(host);
ok('host: shows IP + org', /203\.0\.113\.9/.test(hostOut) && /ACME Corp/.test(hostOut));
ok('host: lists open ports', /Open ports \(4\)/.test(hostOut) && /27017/.test(hostOut));
ok('host: aggregates CVEs', /3 known CVEs/.test(hostOut) && /CVE-2021-23017/.test(hostOut) && /CVE-2020-7921/.test(hostOut));
ok('host: per-service banner + TLS CN', /nginx/.test(hostOut) && /TLS CN=acme\.tld/.test(hostOut));
ok('host: URL carried the api key + correct path', /[?&]key=[^&]+/.test(lastUrl) && /\/shodan\/host\/203\.0\.113\.9/.test(lastUrl));
const f = shodanFindings(host);
ok('findings: CVE finding (high)', f.some((x) => x.source === 'shodan-cve' && x.severity === 'high' && /3 known CVE/.test(x.title)));
ok('findings: exposure finding (info)', f.some((x) => x.source === 'shodan-exposure' && /4 port/.test(x.title)));
ok('findings: none for non-host actions', shodanFindings(await runShodan('count x')).length === 0);

console.log('\n[4] search + count + facets rendering');
mockFetch({ '/shodan/host/search': { body: {
  total: 1234, matches: [
    { ip_str: '198.51.100.2', port: 443, org: 'Evil Inc', product: 'Apache', http: { title: 'Admin Login' }, vulns: ['CVE-2017-5638'] },
    { ip_str: '198.51.100.3', port: 80, org: 'Evil Inc', product: 'Apache' },
  ],
  facets: { port: [{ value: 443, count: 800 }, { value: 80, count: 434 }], org: [{ value: 'Evil Inc', count: 1234 }] },
} } });
const search = await runShodan('search product:Apache');
const sOut = renderShodan(search);
ok('search: total matches', /total matches: 1234/.test(sOut));
ok('search: facet lines', /port: 443\(800\)/.test(sOut) && /org: Evil Inc\(1234\)/.test(sOut));
ok('search: match rows + CVE marker', /198\.51\.100\.2:443/.test(sOut) && /⚠️1CVE/.test(sOut) && /Admin Login/.test(sOut));

mockFetch({ '/shodan/host/count': { body: { total: 16248490, matches: [], facets: { country: [{ value: 'US', count: 4976470 }] } } } });
const count = await runShodan('count port:22');
const cOut = renderShodan(count);
ok('count: total + facets, no match rows', /total matches: 16248490/.test(cOut) && /country: US\(4976470\)/.test(cOut) && !/•/.test(cOut));

console.log('\n[5] domain, resolve, reverse rendering');
mockFetch({ '/dns/domain/': { body: { domain: 'acme.tld', tags: ['cloud'], subdomains: ['www', 'mail', 'vpn'], data: [
  { subdomain: 'www', type: 'A', value: '203.0.113.9' }, { subdomain: 'mail', type: 'A', value: '203.0.113.10' }, { subdomain: '', type: 'MX', value: 'mail.acme.tld' },
] } } });
const dom = renderShodan(await runShodan('domain acme.tld'));
ok('domain: subdomains listed', /Subdomains \(3\)/.test(dom) && /www, mail, vpn/.test(dom));
ok('domain: DNS records grouped by type', /A \(2\)/.test(dom) && /MX \(1\)/.test(dom));

mockFetch({ '/dns/resolve': { body: { 'google.com': '142.250.1.1' } } });
ok('resolve rendering', /google\.com → 142\.250\.1\.1/.test(renderShodan(await runShodan('resolve google.com'))));
mockFetch({ '/dns/reverse': { body: { '8.8.8.8': ['dns.google'] } } });
ok('reverse rendering', /8\.8\.8\.8 → dns\.google/.test(renderShodan(await runShodan('reverse 8.8.8.8'))));

console.log('\n[6] error handling + membership hint');
mockFetch({ '/shodan/host/': { status: 401, body: { error: 'Requires membership or higher to access' } } });
const err = renderShodan(await runShodan('host 8.8.8.8'));
ok('membership error surfaced', /Requires membership/.test(err));
ok('membership hint suggests free count', /shodan count/.test(err) && /no credits|facets/i.test(err));
ok('runShodan returns error field (exitCode path)', (await runShodan('host 8.8.8.8')).error !== undefined);
ok('help renders usage', /Usage:/.test(renderShodan({ action: 'help' })));

restore();
console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
