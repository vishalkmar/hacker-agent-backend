// Phase 2 (websecrets) unit tests. Run: node scripts/test-websecrets.mjs
import { spawnSync } from 'node:child_process';
import { buildWebSecretsCommand, parseSecretReport, extractWebSecretsFindings, renderWebSecrets } from '../src/services/websecrets/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n');
for (const b of ['iamalive.app', 'https://x.app/p deep', 'trufflehog filesystem .']) {
  const cmd = buildWebSecretsCommand(b);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${b}"`, r.status === 0, r.stderr?.trim());
}
ok('deep -> more assets', /(-ge 80)/.test(buildWebSecretsCommand('x.app deep')) && /(-ge 30)/.test(buildWebSecretsCommand('x.app')));
ok('raw passthrough', buildWebSecretsCommand('trufflehog git .') === 'trufflehog git .');

console.log('\n[2] SECRETFIND parsing + severity + CWE');
const rep = [
  '== websecrets ==',
  `SECRETFIND${T}critical${T}aws-key${T}AWS access key ID exposed in JS${T}AKIAABCDE…[redacted] @ /x.js${T}/x.js`,
  `SECRETFIND${T}medium${T}google-api-key${T}Google API key in JS${T}AIzaSy…[redacted] @ /y.js${T}/y.js`,
  `SECRETFIND${T}medium${T}firebase${T}Firebase client config exposed${T}firebaseConfig @ /y.js${T}/y.js`,
  `SECRETFIND${T}info${T}env-var${T}Client-exposed build env vars${T}NEXT_PUBLIC_API_KEY @ /z.js${T}/z.js`,
  `SECRETFIND${T}medium${T}source-map${T}Exposed JS source map${T}/y.js.map 200${T}/y.js.map`,
].join('\n');
let f = parseSecretReport(rep);
ok('5 findings', f.length === 5, `got ${f.length}`);
ok('all finding_type=secret', f.every((x) => x.finding_type === 'secret'));
ok('aws-key = critical + CWE-798', f[0].severity === 'critical' && f[0].cve === 'CWE-798');
ok('aws-key remediation says rotate', /rotate|revoke/i.test(f[0].remediation));
ok('google key remediation says restrict', /restrict/i.test(f[1].remediation));
ok('env-var = info, no CWE', f[3].severity === 'info' && !f[3].cve);
ok('source-map medium + fix mentions source map', f[4].severity === 'medium' && /source.?map/i.test(f[4].remediation));
ok('host = location url', f[0].host === '/x.js');

console.log('\n[3] extractor + render');
ok('extractor routes on SECRETFIND', extractWebSecretsFindings('websecrets x', rep).length === 5);
ok('extractor inert otherwise', extractWebSecretsFindings('ls', 'no markers here').length === 0);
const r = renderWebSecrets(rep);
ok('render sorts critical first', r.indexOf('CRITICAL') < r.indexOf('MEDIUM') && r.indexOf('MEDIUM') < r.indexOf('INFO'));
ok('render empty -> friendly msg', /No exposed secrets/.test(renderWebSecrets('nothing')));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
