// Self-test for the AD (BloodHound/impacket) tool — runs BEFORE relying on the gate in production.
// Validates: every generated command is valid bash (bash -n), findings extraction from ADFIND/roast output,
// honest no-data detection, the authz gate, and — if python3 is present — the offline analyzer RUN FOR REAL
// against sample BloodHound JSON (like the iam analyzer self-test).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildAdCommand, extractAdFindings, isNoAd } from '../src/services/ad/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log('  ✗', name); } };
const bashOk = (cmd) => {
  try { execFileSync('bash', ['-n', '-c', cmd], { stdio: 'pipe' }); return true; }
  catch (e) { console.log('    bash -n FAILED:', String(e.stderr || e).slice(0, 200)); return false; }
};

console.log('== 1. every action builds valid bash ==');
const cases = [
  { action: 'check' },
  { action: 'collect', domain: 'corp.local', user: 'jdoe', pass: 'Passw0rd!', dc: '10.0.0.10', dcip: '10.0.0.10' },
  { action: 'collect', domain: 'corp.local' }, // missing creds → usage msg
  { action: 'analyze' },
  { action: 'analyze', file: 'bh.zip' },
  { action: 'kerberoast', domain: 'corp.local', user: 'jdoe', pass: 'Passw0rd!', dcip: '10.0.0.10' },
  { action: 'asreproast', domain: 'corp.local', dcip: '10.0.0.10', file: 'users.txt' },
  { action: 'asreproast', domain: 'corp.local', dcip: '10.0.0.10', user: 'jdoe', pass: 'p' },
  { action: 'dcsync', domain: 'corp.local', user: 'jdoe', pass: 'Passw0rd!', dcip: '10.0.0.10' },
  { action: 'bogus' },
];
for (const c of cases) ok(`bash -n: ${c.action}${c.user ? ' (creds)' : ''}`, bashOk(buildAdCommand(c)));
ok('collect w/o creds → usage', /AD-USAGE/.test(buildAdCommand({ action: 'collect', domain: 'corp.local' })));
ok('kerberoast uses GetUserSPNs + -m 13100 hint', /GetUserSPNs/.test(buildAdCommand({ action: 'kerberoast', domain: 'c', user: 'u', pass: 'p', dcip: '1.1.1.1' })) && /13100/.test(buildAdCommand({ action: 'kerberoast', domain: 'c', user: 'u', pass: 'p', dcip: '1.1.1.1' })));
ok('analyze embeds base64 python', /base64 -d/.test(buildAdCommand({ action: 'analyze' })));

console.log('== 2. findings extraction (ADFIND lines + roast hashes) ==');
const adfind = [
  'ADFIND\thigh\tad-kerberoast\tKerberoastable user: SVC_SQL\thas SPN(s)\tUse a gMSA',
  'ADFIND\tcritical\tad-delegation\tUnconstrained delegation on computer: WS01\tDA logon captured\tRemove it',
  'ADFIND\tinfo\tad-privileged-group\tPrivileged group: DOMAIN ADMINS (3 members)\t3 direct members\tMinimize DA',
].join('\n');
const f1 = extractAdFindings('python3 /tmp/cm_ad.py', adfind);
ok('parses kerberoast finding (high)', f1.some(f => f.severity === 'high' && /Kerberoastable/.test(f.title)));
ok('parses delegation finding (critical)', f1.some(f => f.severity === 'critical' && f.finding_type === 'ad-delegation'));
ok('parses privileged group (info)', f1.some(f => f.severity === 'info' && /DOMAIN ADMINS/.test(f.title)));
ok('dedups by title', extractAdFindings('x', adfind + '\n' + adfind).length === 3);

const krb = extractAdFindings('impacket-GetUserSPNs corp.local/jdoe -request', '$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQL*$abcdef...');
ok('krb5tgs hash → high finding', krb.some(f => /TGS hash captured/i.test(f.title) && f.cwe === 'CWE-522'));
const asr = extractAdFindings('impacket-GetNPUsers', '$krb5asrep$23$user@CORP:abcdef...');
ok('krb5asrep hash → high finding', asr.some(f => /AS-REP hash captured/i.test(f.title)));
ok('no findings on unrelated output', extractAdFindings('ls', 'file listing').length === 0);

console.log('== 3. honest no-data detection ==');
ok('detects AD-NODATA', isNoAd('AD-NODATA: no BloodHound JSON in the current directory'));
ok('detects invalid credentials', isNoAd('[-] invalid credentials'));
ok('does NOT flag good ADFIND output', !isNoAd(adfind));

console.log('== 4. authz gate (collect/roast gated, analyze/check local) ==');
ok('collect corp.local → gated', classifyAction('ad', 'collect corp.local u=jdoe p=x dc=10.0.0.10').gated === true);
ok('kerberoast → gated', classifyAction('ad', 'kerberoast corp.local u=jdoe p=x dc=10.0.0.10').gated === true);
ok('analyze → NOT gated (local)', classifyAction('ad', 'analyze').gated === false);
ok('check → NOT gated (local)', classifyAction('ad', 'check').gated === false);

console.log('== 5. offline analyzer RUN FOR REAL (if python3 present) ==');
let py3 = true;
try { execFileSync('python3', ['--version'], { stdio: 'pipe' }); } catch { py3 = false; }
if (!py3) {
  console.log('  (python3 not on host — skipping live analyzer run; command validity already covered)');
} else {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-ad-'));
  fs.writeFileSync(path.join(dir, '20260101_users.json'), JSON.stringify({ users: [
    { Properties: { name: 'SVC_SQL@CORP.LOCAL', enabled: true, serviceprincipalnames: ['MSSQL/db01'] } },
    { Properties: { name: 'JBOND@CORP.LOCAL', enabled: true, dontreqpreauth: true } },
    { Properties: { name: 'TEMP@CORP.LOCAL', enabled: true, passwordnotreqd: true } },
  ] }));
  fs.writeFileSync(path.join(dir, '20260101_computers.json'), JSON.stringify({ computers: [
    { Properties: { name: 'WS01.CORP.LOCAL', unconstraineddelegation: true, operatingsystem: 'Windows 7 Enterprise' } },
  ] }));
  fs.writeFileSync(path.join(dir, '20260101_groups.json'), JSON.stringify({ groups: [
    { Properties: { name: 'DOMAIN ADMINS@CORP.LOCAL' }, Members: [{ ObjectIdentifier: 'S-1-5-a' }, { ObjectIdentifier: 'S-1-5-b' }] },
  ] }));
  const cmd = buildAdCommand({ action: 'analyze' });
  let out = '';
  try { out = execFileSync('bash', ['-lc', cmd], { cwd: dir, stdio: 'pipe' }).toString(); }
  catch (e) { out = String(e.stdout || '') + String(e.stderr || ''); }
  const findings = extractAdFindings('python3', out);
  ok('analyzer flags Kerberoastable SVC_SQL', findings.some(f => /Kerberoastable user: SVC_SQL/.test(f.title)));
  ok('analyzer flags AS-REP JBOND', findings.some(f => /AS-REP roastable user: JBOND/.test(f.title)));
  ok('analyzer flags unconstrained delegation WS01', findings.some(f => /Unconstrained delegation on computer: WS01/.test(f.title)));
  ok('analyzer flags legacy OS (Win7)', findings.some(f => /legacy OS: WS01/.test(f.title)));
  ok('analyzer flags PASSWD_NOTREQD TEMP', findings.some(f => /PASSWD_NOTREQD/.test(f.title)));
  ok('analyzer flags DOMAIN ADMINS group', findings.some(f => /DOMAIN ADMINS/.test(f.title)));
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass}/${pass + fail} passed` + (fail ? `  (${fail} FAILED)` : ' ✅'));
process.exit(fail ? 1 : 0);
