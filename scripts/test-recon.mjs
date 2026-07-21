// FINAL (recon footprint) unit tests — DNS/subdomain/ASN/tech parsing. No network/DB.
// Run: node scripts/test-recon.mjs
import { spawnSync } from 'node:child_process';
import { buildReconScanCommand, parseReconReport, extractReconScanFindings, renderReconScan } from '../src/services/recon/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['iamalive.app', 'iamalive.app deep', 'https://iamalive.app/x']) {
  const cmd = buildReconScanCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildReconScanCommand('') === null);
ok('deep flag adds nmap top-ports', /--top-ports 100/.test(buildReconScanCommand('x.com deep')) && !/--top-ports/.test(buildReconScanCommand('x.com')));
ok('deep flag not treated as target', /D="myhost"/.test(buildReconScanCommand('myhost deep')));

console.log('\n[2] report parsing (DNS/subs/tech/findings)');
const report = [
  'RECON-BEGIN acme.tld',
  '=== DNS ===',
  'DNS A: 203.0.113.7',
  'DNS NS: ns1.acme.tld.; ns2.acme.tld.',
  'DNS MX: 10 mail.acme.tld.',
  `RECONFIND${T}high${T}axfr${T}DNS zone transfer (AXFR) allowed by ns1.acme.tld${T}leaks full zone${T}acme.tld`,
  `RECONFIND${T}low${T}email-spf${T}No SPF record on acme.tld${T}spoofable${T}acme.tld`,
  `RECONFIND${T}low${T}email-dmarc${T}No DMARC record on acme.tld${T}phishing${T}acme.tld`,
  `RECONFIND${T}info${T}cdn${T}Fronted by/hosted on: cloudflare${T}headers${T}acme.tld`,
  'SUB\twww.acme.tld\t203.0.113.7',
  'SUB\tapi.acme.tld\t203.0.113.8',
  'SUB\tstaging.acme.tld\t203.0.113.9',
  `RECONFIND${T}low${T}sensitive-sub${T}Sensitive subdomain exposed: staging.acme.tld${T}non-prod public${T}staging.acme.tld`,
  `RECONFIND${T}info${T}asset-inventory${T}3 live subdomain(s) discovered for acme.tld${T}crt.sh${T}acme.tld`,
  'TECH\tnginx/1.18.0',
  'TECH\tacme.tld [nginx][React]',
  `RECONFIND${T}info${T}tech-disclosure${T}Technology disclosed via header: X-Powered-By: Express${T}X-Powered-By: Express${T}acme.tld`,
  'RECON-END',
].join('\n');
const p = parseReconReport(report);
ok('3 DNS lines', p.dns.length === 3);
ok('3 subdomains', p.subs.length === 3 && p.subs.some((s) => s.host === 'api.acme.tld' && s.ip === '203.0.113.8'));
ok('2 tech lines', p.tech.length === 2);
const finds = p.findings;
const by = (s) => finds.find((x) => x.source === s);
ok('AXFR -> high + CWE-200', by('recon-axfr')?.severity === 'high' && by('recon-axfr')?.cve === 'CWE-200');
ok('no-SPF -> low + CWE-290', by('recon-email-spf')?.cve === 'CWE-290');
ok('no-DMARC -> CWE-290', by('recon-email-dmarc')?.cve === 'CWE-290');
ok('CDN -> info', by('recon-cdn')?.severity === 'info');
ok('sensitive-sub -> low + CWE-200', by('recon-sensitive-sub')?.severity === 'low');
ok('asset-inventory summary present', !!by('recon-asset-inventory'));
ok('tech-disclosure -> CWE-200', by('recon-tech-disclosure')?.cve === 'CWE-200');
ok('all finding_type recon', finds.every((x) => x.finding_type === 'recon'));

console.log('\n[3] extract + render');
ok('inert on unrelated output', extractReconScanFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns findings when sentinel present', extractReconScanFindings('c', report).length >= 6);
const r = renderReconScan(report);
ok('render shows DNS section', /🧭 DNS/.test(r) && /203\.0\.113\.7/.test(r));
ok('render shows Technology section', /Technology/.test(r) && /nginx/.test(r));
ok('render shows live assets w/ count', /Live assets \/ subdomains \(3\)/.test(r) && /api\.acme\.tld → 203\.0\.113\.8/.test(r));
ok('render shows recon findings (AXFR high)', /Recon findings/.test(r) && /HIGH.*zone transfer/.test(r));
ok('empty -> friendly message', /Recon produced no records/.test(renderReconScan('nothing here')));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
