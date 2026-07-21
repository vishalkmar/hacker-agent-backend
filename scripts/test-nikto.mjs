// Phase 2 (NIKTO) tests — detection + noise filtering + finding parse (nikto 2.6.0 output).
// Deterministic (no network). Run: node scripts/test-nikto.mjs
import { parseNikto, extractWebFindings, detectWebScanner } from '../src/services/scan/webparsers.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

// real nikto 2.6.0 output (from a live scanme.nmap.org run)
const OUT = `- Nikto v2.6.0
+ Target IP:          45.33.32.156
+ Target Hostname:    scanme.nmap.org
+ Server: Apache/2.4.7 (Ubuntu)
+ Multiple IPs found: 45.33.32.156, 2600:3c01::f03c:91ff:fe18:bb2f
+ ERROR: Failed to check for updates: 403
+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.
+ [013587] /: Suggested security header missing: content-security-policy.
+ [013587] /: Suggested security header missing: strict-transport-security.
+ [999965] /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names.
+ [600050] Apache/2.4.7 appears to be outdated (current is at least 2.4.66).
+ [000001] /admin/: This might be interesting: possible SQL injection point.
+ ERROR: Host maximum execution time of 80 seconds reached
+ Scan terminated: 0 errors and 8 items reported on the remote host
+ 1 host(s) tested`;

console.log('\n[1] detection routing');
ok('detect nikto command', detectWebScanner('nikto -h http://x.com -Tuning 2') === 'nikto');
ok('detect nikto with ssl', detectWebScanner('nikto -h https://x.com -ssl -maxtime 120') === 'nikto');

console.log('\n[2] noise filtering (nikto 2.6.0 operational lines are NOT findings)');
const f = parseNikto(OUT);
ok('only real findings kept (5, not ~11)', f.length === 5, `got ${f.length}: ${f.map((x) => x.title.slice(0, 20)).join(' | ')}`);
ok('drops "Multiple IPs found"', !f.some((x) => /Multiple IPs/.test(x.title)));
ok('drops ERROR lines', !f.some((x) => /ERROR/.test(x.title)));
ok('drops "No CGI Directories"', !f.some((x) => /No CGI/.test(x.title)));
ok('drops "Scan terminated" / host(s) tested', !f.some((x) => /Scan terminated|host\(s\) tested/.test(x.title)));
ok('drops "Server:" banner', !f.some((x) => /^Server:/.test(x.title)));

console.log('\n[3] finding quality');
ok('security-header finding kept', f.some((x) => /content-security-policy/i.test(x.title)));
ok('mod_negotiation -> medium (brute force)', f.find((x) => /mod_negotiation/i.test(x.title))?.severity === 'medium');
ok('outdated Apache -> low', f.find((x) => /outdated/i.test(x.title))?.severity === 'low');
ok('SQLi hint -> medium', f.find((x) => /SQL injection/i.test(x.title))?.severity === 'medium');
ok('nikto id captured in source', f.some((x) => /#\d{5,7}/.test(x.source)));
ok('title stripped of [id] prefix', f.every((x) => !/^\[\d{5,7}\]/.test(x.title)));
ok('finding_type=misconfiguration', f.every((x) => x.finding_type === 'misconfiguration'));

console.log('\n[4] extractWebFindings routes nikto + cvss baseline');
const via = extractWebFindings('nikto -h http://x.com', OUT);
ok('routed through nikto parser', via.length === 5);
ok('cvss baseline present', via.every((x) => typeof x.cvss_score === 'number'));
ok('empty -> none', extractWebFindings('nikto -h x', '').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
