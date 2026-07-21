// Phase 4 (iam) unit tests. Run: node scripts/test-iam.mjs
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { buildIamCommand, parseIamReport, extractIamFindings, renderIam } from '../src/services/iam/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] dispatcher + bash -n');
for (const b of ['/tmp/pol.json', 'analyze /tmp/pol.json', 'aws', 'azure', 'cloudsplaining scan --input-file a.json']) {
  const cmd = buildIamCommand(b);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${b}"`, r.status === 0, r.stderr?.trim());
}
ok('aws -> prowler iam category', /prowler aws --category iam/.test(buildIamCommand('aws')));
ok('file -> base64 python analyzer', /base64 -d/.test(buildIamCommand('/tmp/pol.json')) && /python3/.test(buildIamCommand('/tmp/pol.json')));
ok('raw passthrough', buildIamCommand('parliament --file x.json') === 'parliament --file x.json');

console.log('\n[2] analyzer runs for real (in Kali sandbox) on a bad policy');
const bad = {
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Allow', Action: ['iam:PassRole', 'iam:CreatePolicyVersion'], Resource: '*' },
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole', Resource: '*' },
    { Effect: 'Allow', NotAction: 's3:DeleteBucket', Resource: 'arn:aws:s3:::x/*' },
  ],
};
// Write the policy then run the analyzer, all inside the container (reliable python3 + /tmp).
const script = `cat > /tmp/iam_pol_test.json <<'JSON'\n${JSON.stringify(bad)}\nJSON\n${buildIamCommand('/tmp/iam_pol_test.json')}`;
const run = spawnSync('docker', ['run', '-i', '--rm', 'cyphermind/kali-default:latest', 'bash', '-s'], { input: script, encoding: 'utf8' });
const out = run.stdout || '';
const finds = parseIamReport(out);
ok('analyzer produced findings', finds.length >= 5, `got ${finds.length}: ${run.stderr?.slice(0, 120) || ''}`);
ok('flags full admin (critical)', finds.some((f) => f.source === 'iam-admin' && f.severity === 'critical'));
ok('flags priv-esc (critical)', finds.some((f) => f.source === 'iam-priv-esc' && f.severity === 'critical'));
ok('flags public principal (critical)', finds.some((f) => f.source === 'iam-public-principal'));
ok('flags NotAction (high)', finds.some((f) => f.source === 'iam-notaction' && f.severity === 'high'));

console.log('\n[3] parse + extractor + render on synthetic report');
const rep = [
  `IAMFIND${T}critical${T}admin${T}Full administrative access (Action:* on Resource:*)${T}Action:* Resource:*`,
  `IAMFIND${T}high${T}service-wildcard${T}All s3 actions allowed (s3:*)${T}s3:* on *`,
].join('\n');
const f = parseIamReport(rep);
ok('2 findings, finding_type=iam', f.length === 2 && f.every((x) => x.finding_type === 'iam'));
ok('admin remediation says least privilege', /least privilege|Remove Action/i.test(f[0].remediation));
ok('extractor routes on IAMFIND', extractIamFindings('iam x', rep).length === 2);
ok('extractor inert otherwise', extractIamFindings('ls', 'no markers').length === 0);
ok('extractor does NOT parse prowler here (cloud does)', extractIamFindings('prowler aws', '[{"status_code":"FAIL","severity":"high","check_title":"x"}]').length === 0);
ok('render sorts + labels', /IAM policy risks/.test(renderIam(rep)) && renderIam(rep).indexOf('CRITICAL') < renderIam(rep).indexOf('HIGH'));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
