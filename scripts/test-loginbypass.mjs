// Phase 12 (loginbypass) unit tests — SQLi auth-bypass parsing/detection reporting. No network/DB.
// Run: node scripts/test-loginbypass.mjs
import { spawnSync } from 'node:child_process';
import { buildLoginBypassCommand, parseLoginBypassReport, extractLoginBypassFindings, renderLoginBypass, BYPASS_PAYLOADS } from '../src/services/loginbypass/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['https://s.com/login', 's.com/login', 'https://s.com/login user=email pass=pwd', 'sqlmap -u x', 'https://s.com/admin']) {
  const cmd = buildLoginBypassCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildLoginBypassCommand('') === null);
ok('raw sqlmap passthrough', buildLoginBypassCommand('sqlmap -u http://x --batch') === 'sqlmap -u http://x --batch');
ok('field overrides parsed', /UF="email"/.test(buildLoginBypassCommand('x.com user=email pass=pw')) && /PF="pw"/.test(buildLoginBypassCommand('x.com user=email pass=pw')));
ok('image payloads all present (>=17)', BYPASS_PAYLOADS.length >= 17);
ok("contains the King ' OR 1=1 --", BYPASS_PAYLOADS.some(([p]) => p === "' OR 1=1 --"));
ok("contains admin' --", BYPASS_PAYLOADS.some(([p]) => p === "admin' --"));
ok('every payload is embedded in the heredoc', BYPASS_PAYLOADS.every(([p]) => buildLoginBypassCommand('https://x/login').includes(p)));

console.log('\n[2] report parsing — bypass CONFIRMED');
const hit = [
  'LBSCAN-BEGIN https://acme.tld/login',
  `LBFORM${T}https://acme.tld/login${T}username${T}password`,
  `LBBASE${T}200${T}1500${T}${T}0${T}1`,
  `LBTRY${T}' OR 1=1 --${T}302${T}0${T}https://acme.tld/dashboard${T}0`,
  `LOGINBYPASS${T}critical${T}' OR 1=1 --${T}redirected to https://acme.tld/dashboard (baseline: none)${T}https://acme.tld/login`,
  `LOGINBYPASS${T}critical${T}admin' --${T}session cookie established (none for junk creds)${T}https://acme.tld/login`,
  'LBSCAN-END',
].join('\n');
const p = parseLoginBypassReport(hit);
ok('form parsed', p.form?.action === 'https://acme.tld/login' && p.form?.uf === 'username');
ok('baseline parsed', p.base?.code === '200' && p.base?.fail === '1');
ok('2 bypass findings', p.findings.length === 2, `got ${p.findings.length}`);
ok('finding is critical + CWE-89', p.findings[0].severity === 'critical' && p.findings[0].cve === 'CWE-89');
ok('finding_type auth-bypass', p.findings.every((f) => f.finding_type === 'auth-bypass'));
ok("payload in title", /' OR 1=1 --/.test(p.findings[0].title));
ok('evidence carries technique note', /The King/.test(p.findings[0].evidence));
ok('dedup: same payload twice -> one finding', parseLoginBypassReport(hit + '\n' + `LOGINBYPASS${T}critical${T}' OR 1=1 --${T}dup${T}u`).findings.length === 2);

console.log('\n[3] report parsing — NO bypass');
const miss = [
  'LBSCAN-BEGIN https://safe.tld/login',
  `LBFORM${T}https://safe.tld/login${T}email${T}password`,
  `LBBASE${T}200${T}1500${T}${T}0${T}1`,
  `LBTRY${T}' OR 1=1 --${T}200${T}1500${T}${T}1`,
  `LBTRY${T}admin' --${T}200${T}1502${T}${T}1`,
  'LBSCAN-END',
].join('\n');
ok('no findings when nothing bypassed', extractLoginBypassFindings('c', miss).length === 0);
ok('inert on unrelated output', extractLoginBypassFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns findings on hit', extractLoginBypassFindings('c', hit).length === 2);

console.log('\n[4] render + authz');
const rh = renderLoginBypass(hit);
ok('render shows CRITICAL confirmed', /CRITICAL — SQL injection login bypass CONFIRMED/.test(rh));
ok('render shows the form', /Target login form/.test(rh));
ok('render shows a payload', /' OR 1=1 --/.test(rh));
const rm = renderLoginBypass(miss);
ok('render shows "No SQLi bypass" w/ count', /No SQLi authentication bypass detected/.test(rm) && /2 classic payloads/.test(rm));
const g = classifyAction('loginbypass', 'https://acme.tld/login');
ok('loginbypass <target> gated', g && g.gated === true, JSON.stringify(g));
ok('loginbypass localhost not gated (self-test)', classifyAction('loginbypass', 'http://127.0.0.1/login').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
