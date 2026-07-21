// Phase 5 (BURP→CLI) tests — OWASP ZAP finding parser (Burp-Scanner CLI equivalent). Deterministic.
// Run: node scripts/test-zap.mjs
import { parseZap, detectZap } from '../src/services/zap/index.js';
import { detectWebScanner } from '../src/services/scan/webparsers.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] detection + vulnscan routing');
ok('detect zap-baseline.py', detectZap('zap-baseline.py -t http://x -J r.json'));
ok('detect zap.sh -quickurl', detectZap('zap.sh -cmd -quickurl http://x -quickout r.json'));
ok('detect zap-full-scan.py', detectZap('zap-full-scan.py -t http://x'));
ok('non-zap -> false', detectZap('nuclei -u http://x') === false);
ok('vulnscan runs zap as-is (not wrapped in nuclei)', detectWebScanner('zap-baseline.py -t http://x') === 'zap');

console.log('\n[2] JSON report -> rich findings (risk -> severity, CWE, solution)');
const report = JSON.stringify({ '@version': '2.17.0', site: [{ '@name': 'http://target.com', alerts: [
  { alert: 'Cross Site Scripting (Reflected)', riskcode: '3', desc: '<p>Reflected XSS in q param</p>', cweid: '79', solution: '<p>Context-encode <b>output</b></p>', instances: [{ uri: 'http://target.com/?q=x', evidence: '<script>alert(1)</script>' }] },
  { alert: 'SQL Injection', riskcode: '3', cweid: '89', solution: '<p>Use parameterised queries</p>', instances: [{ uri: 'http://target.com/id', evidence: '' }] },
  { alert: 'CSP Header Not Set', riskcode: '2', cweid: '693', solution: '<p>Set CSP</p>', instances: [{ uri: 'http://target.com', evidence: '' }] },
  { alert: 'X-Content-Type-Options Missing', riskcode: '1', cweid: '693', instances: [{ uri: 'http://target.com', evidence: '' }] },
  { alert: 'Informational Item', riskcode: '0', instances: [{ uri: 'http://target.com', evidence: '' }] },
]}]});
const f = parseZap('zap.sh -cmd -quickurl http://x -quickout r.json', report);
const byTitle = (re) => f.find((x) => re.test(x.title));
ok('5 alerts -> 5 findings', f.length === 5, `got ${f.length}`);
ok('XSS riskcode 3 -> high + CWE-79', byTitle(/Cross Site Scripting/)?.severity === 'high' && byTitle(/Cross Site Scripting/)?.cwe === 'CWE-79');
ok('SQLi -> high + CWE-89', byTitle(/SQL Injection/)?.severity === 'high' && byTitle(/SQL Injection/)?.cwe === 'CWE-89');
ok('CSP riskcode 2 -> medium', byTitle(/CSP Header/)?.severity === 'medium');
ok('header riskcode 1 -> low', byTitle(/X-Content-Type/)?.severity === 'low');
ok('info riskcode 0 -> info', byTitle(/Informational/)?.severity === 'info');
ok('solution HTML stripped', /Context-encode output/.test(byTitle(/Cross Site/)?.remediation || '') && !/<b>/.test(byTitle(/Cross Site/)?.remediation || ''));
ok('host + evidence captured', byTitle(/Cross Site/)?.host === 'target.com' && /script/.test(byTitle(/Cross Site/)?.evidence || ''));
ok('source=zap, finding_type=vuln', f.every((x) => x.source === 'zap' && x.finding_type === 'vuln'));

console.log('\n[3] baseline text summary -> findings (WARN=medium, FAIL=high)');
const txt = [
  'WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 6',
  '\thttp://target.com (200 OK)',
  'FAIL-NEW: SQL Injection [40018] x 1',
  'WARN-NEW: X-Content-Type-Options Header Missing [10021] x 6',
  'PASS: Vulnerable JS Library [10003]',
  'FAIL-NEW: 1\tWARN-NEW: 2\tINFO: 0\tPASS: 50',
].join('\n');
const ft = parseZap('zap-baseline.py -t http://target.com', txt);
ok('WARN + FAIL parsed (3 alerts, not PASS/summary)', ft.length === 3, `got ${ft.length}: ${ft.map((x) => x.title).join(' | ')}`);
ok('FAIL -> high', ft.find((x) => /SQL Injection/.test(x.title))?.severity === 'high');
ok('WARN -> medium', ft.find((x) => /CSP/.test(x.title))?.severity === 'medium');
ok('PASS/summary lines ignored', !ft.some((x) => /Vulnerable JS|WARN-NEW: 2/.test(x.title)));

console.log('\n[4] hygiene');
ok('non-zap command -> no findings', parseZap('curl http://x', report).length === 0);
ok('empty output -> none', parseZap('zap.sh', '').length === 0);
ok('multi-site JSON handled', parseZap('zap.sh', JSON.stringify({ site: [{ '@name': 'a', alerts: [{ alert: 'A', riskcode: '2', instances: [{ uri: 'http://a/' }] }] }, { '@name': 'b', alerts: [{ alert: 'B', riskcode: '3', instances: [{ uri: 'http://b/' }] }] }] })).length === 2);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
