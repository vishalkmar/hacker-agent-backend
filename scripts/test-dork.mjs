// Dork sweep unit tests — query building, on-target filtering, finding classification, render. No network.
// Run: node scripts/test-dork.mjs
import { buildDorks, onTargetMatch, hitToFinding, renderDork, DORKS } from '../src/services/dork/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] dork catalogue + query building');
ok('>=14 dorks in catalogue', DORKS.length >= 14);
const d = buildDorks('https://target.com/x');
ok('domain normalized (scheme/path stripped)', d[0].domain === 'target.com');
ok('env-files dork is critical', d.find((x) => x.cat === 'env-files').sev === 'critical');
ok('config-files dork is high', d.find((x) => x.cat === 'config-files').sev === 'high');
ok('env query uses inurl:.env', /inurl:\.env/.test(d.find((x) => x.cat === 'env-files').query));
ok('pastebin dork searches pastebin (off-target)', /site:pastebin\.com "target\.com"/.test(d.find((x) => x.cat === 'pastebin-leak').query) && d.find((x) => x.cat === 'pastebin-leak').onTarget === false);
ok('image dorks all present', ['subdomains', 'config-files', 'admin-portal', 'open-dir', 'sql-errors', 'pastebin-leak', 'github-leak', 'log-password', 'env-files', 'backup-files'].every((c) => DORKS.some((x) => x.cat === c)));
ok('empty domain -> no dorks', buildDorks('').length === 0);

console.log('\n[2] on-target filtering (kills cross-site noise)');
ok('same domain matches', onTargetMatch('https://acme.tld/admin', 'acme.tld'));
ok('subdomain matches', onTargetMatch('https://dev.acme.tld/x', 'acme.tld'));
ok('unrelated domain rejected', !onTargetMatch('https://evil.com/page', 'acme.tld'));
ok('lookalike prefix domain rejected (acme.tld.attacker.com)', !onTargetMatch('https://acme.tld.attacker.com/x', 'acme.tld'));
ok('lookalike suffix domain rejected (notacme.tld)', !onTargetMatch('https://notacme.tld/x', 'acme.tld'));

console.log('\n[3] hit -> finding classification');
const f = hitToFinding({ cat: 'env-files', sev: 'critical', title: 'Exposed environment (.env) file', cwe: 'CWE-312', fix: 'Rotate secrets', url: 'https://acme.tld/.env', snippet: 'DB_PASSWORD=...' }, 'acme.tld');
ok('finding_type osint-dork', f.finding_type === 'osint-dork');
ok('critical severity + CWE-312', f.severity === 'critical' && f.cve === 'CWE-312');
ok('url in title + host', /acme\.tld\/\.env/.test(f.title) && f.host === 'https://acme.tld/.env');
ok('evidence notes dork category', /dork: env-files/.test(f.evidence));
ok('source = dork-<cat>', f.source === 'dork-env-files');

console.log('\n[4] render');
const sweep = {
  domain: 'acme.tld', queriesRun: 14, totalDorks: 14, blocked: 0,
  hits: [
    { cat: 'env-files', sev: 'critical', title: 'Exposed environment (.env) file', cwe: 'CWE-312', url: 'https://acme.tld/.env', snippet: 'DB_PASSWORD' },
    { cat: 'admin-portal', sev: 'info', title: 'Login / admin portal indexed', cwe: 'CWE-200', url: 'https://acme.tld/admin', snippet: '' },
  ],
};
const r = renderDork(sweep);
ok('render shows exposures section', /Exposures \(verify each\)/.test(r));
ok('render shows CRITICAL .env', /CRITICAL.*environment/.test(r));
ok('render shows attack surface (info)', /Attack surface/.test(r) && /\/admin/.test(r));
ok('no-hits -> steers to browser tool', /no auto-scraped hits/.test(renderDork({ domain: 'x.com', hits: [], queriesRun: 14, totalDorks: 14, blocked: 0, playbook: [] })));
ok('all-blocked -> rate-limit note', /rate-limited 14\/14 live queries/.test(renderDork({ domain: 'x.com', hits: [], queriesRun: 14, totalDorks: 14, blocked: 14, playbook: [] })));
const pbSweep = { domain: 'x.com', hits: [], queriesRun: 0, totalDorks: 14, blocked: 14, playbook: [{ cat: 'env-files', sev: 'critical', title: 'Exposed environment (.env) file', query: 'site:x.com inurl:.env', urls: { google: 'https://www.google.com/search?q=site:x.com+inurl:.env' } }] };
ok('playbook ALWAYS rendered (even fully blocked)', /Dork playbook/.test(renderDork(pbSweep)) && /site:x.com inurl:.env/.test(renderDork(pbSweep)) && /google.com\/search/.test(renderDork(pbSweep)));

console.log('\n[5] authz — dork is OSINT, NOT gated');
ok('dork <domain> not gated (passive OSINT)', classifyAction('dork', 'acme.tld').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
