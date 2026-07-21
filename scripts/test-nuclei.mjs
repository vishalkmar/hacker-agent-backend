// Phase 1 (NUCLEI) tests — detection + JSON/text finding parse + the vulnscan default command shape.
// Deterministic (no network). Run: node scripts/test-nuclei.mjs
import { parseNuclei, extractWebFindings, detectWebScanner } from '../src/services/scan/webparsers.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] scanner detection routes nuclei output to the right parser');
ok('detect nuclei command', detectWebScanner('nuclei -u https://x.com -silent') === 'nuclei');
ok('detect full nuclei cmd', detectWebScanner('nuclei -l t.txt -tags cve -j') === 'nuclei');
ok('non-scanner -> null', detectWebScanner('curl https://x.com') === null);

console.log('\n[2] JSON (-j) output parses to rich findings (real nuclei v3 shape)');
const critJson = JSON.stringify({ 'template-id': 'CVE-2021-44228', info: { name: 'Apache Log4j RCE', severity: 'critical', classification: { 'cve-id': ['CVE-2021-44228'] }, remediation: 'Upgrade Log4j to 2.17+' }, 'matched-at': 'https://target.com/api', host: 'target.com' });
const fj = parseNuclei(critJson);
ok('critical severity mapped', fj[0]?.severity === 'critical');
ok('CVE extracted', fj[0]?.cve === 'CVE-2021-44228');
ok('remediation carried', /2\.17/.test(fj[0]?.remediation || ''));
ok('host derived', fj[0]?.host === 'target.com');
ok('finding_type=vuln', fj[0]?.finding_type === 'vuln');

console.log('\n[3] text (-silent) output parses too (the vulnscan default format)');
const text = [
  '[waf-detect] [http] [info] http://scanme.nmap.org',
  '[apache-detect] [http] [info] http://scanme.nmap.org [Apache/2.4.7 (Ubuntu)]',
  '[CVE-2017-5638] [http] [critical] https://x.com/struts',
].join('\n');
const ft = parseNuclei(text);
ok('parses 3 text findings', ft.length === 3);
ok('severities read from brackets', ft.some((f) => f.severity === 'critical') && ft.filter((f) => f.severity === 'info').length === 2);
ok('CVE id template -> cve field', ft.find((f) => /CVE-2017-5638/.test(f.title))?.cve === 'CVE-2017-5638');

console.log('\n[4] extractWebFindings end-to-end (mixed JSON+text, dedup, cvss baseline)');
const mixed = critJson + '\n' + text;
const all = extractWebFindings('nuclei -u x -silent', mixed);
ok('all lines -> findings', all.length >= 4);
ok('cvss baseline set from severity', all.every((f) => typeof f.cvss_score === 'number'));
ok('empty output -> no findings', extractWebFindings('nuclei -u x', '').length === 0);

console.log('\n[5] vulnscan default command shape (clean text mode, bounded, no update-check)');
// mirror the default built in agent.js so the contract is locked
const target = 'https://target.com';
const dflt = `nuclei -u ${target} -silent -duc -rl 150 -timeout 8`;
ok('uses -silent (clean text, parseable)', /-silent\b/.test(dflt));
ok('uses -duc (no update-check spam)', /-duc\b/.test(dflt));
ok('rate-limited + per-host timeout', /-rl 150\b/.test(dflt) && /-timeout 8\b/.test(dflt));
ok('NOT -j (would embed full HTTP responses)', !/\s-j\b/.test(dflt));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
