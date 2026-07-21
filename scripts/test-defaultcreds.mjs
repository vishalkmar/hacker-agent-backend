// Phase 5 (defaultcreds) unit tests. Run: node scripts/test-defaultcreds.mjs
import { spawnSync } from 'node:child_process';
import { buildDefaultCredsCommand, parseCredReport, extractDefaultCredsFindings, renderDefaultCreds } from '../src/services/defaultcreds/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n + dispatcher');
for (const b of ['iamalive.app', 'https://x.com/admin deep', 'nmap -p80 x', 'changeme https://x']) {
  const cmd = buildDefaultCredsCommand(b);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${b}"`, r.status === 0, r.stderr?.trim());
}
ok('raw passthrough', buildDefaultCredsCommand('hydra -l admin ssh://x') === 'hydra -l admin ssh://x');
ok('deep adds nmap NSE', /nmap .*http-default-accounts/.test(buildDefaultCredsCommand('x.com deep')) && !/nmap .*http-default-accounts/.test(buildDefaultCredsCommand('x.com')));
ok('full URL path is probed directly', buildDefaultCredsCommand('https://x.com/panel').includes('https://x.com/panel'));
ok('parallel via xargs -P', /xargs -P/.test(buildDefaultCredsCommand('x.com')));

console.log('\n[2] CREDFIND parsing + classification');
const rep = [
  '== default-creds scan ==',
  `CREDFIND${T}critical${T}default-cred${T}DEFAULT CREDENTIALS WORK: https://x/admin${T}auth 'admin:admin' -> HTTP 200${T}https://x/admin`,
  `CREDFIND${T}medium${T}exposed-panel${T}Basic-Auth endpoint: https://x/admin${T}HTTP 401${T}https://x/admin`,
  `CREDFIND${T}high${T}anon-access${T}Anonymous FTP login allowed${T}nmap ftp-anon${T}ftp://x`,
].join('\n');
const f = parseCredReport(rep);
ok('3 findings, type=credentials', f.length === 3 && f.every((x) => x.finding_type === 'credentials'));
ok('default-cred critical + CWE-1392', f[0].severity === 'critical' && f[0].cve === 'CWE-1392');
ok('default-cred remediation says change immediately', /change the default cred/i.test(f[0].remediation));
ok('anon-access high + CWE-306', f[2].severity === 'high' && f[2].cve === 'CWE-306');
ok('host carries the url', f[0].host === 'https://x/admin');

console.log('\n[3] extractor + render');
ok('extractor routes on CREDFIND', extractDefaultCredsFindings('defaultcreds x', rep).length === 3);
ok('extractor inert otherwise', extractDefaultCredsFindings('ls', 'nope').length === 0);
const r = renderDefaultCreds(rep);
ok('render separates cred issues vs panels', /Credential \/ access issues/i.test(r) && /Exposed panels/i.test(r));
ok('render highlights the working default cred', /DEFAULT CREDENTIALS WORK/.test(r));
ok('empty -> friendly msg', /No exposed admin panels/.test(renderDefaultCreds('nothing')));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
