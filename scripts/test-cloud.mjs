// Phase 1 (cloud) unit tests — parsers, renderer, dispatcher, authz gating. No network/DB.
// Run: node scripts/test-cloud.mjs
import { spawnSync } from 'node:child_process';
import { buildCloudCommand, parseCloudReport, parseProwler, extractCloudFindings, renderCloud } from '../src/services/cloud/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['iamalive.app', 'https://iamalive.app/path', 'aws', 'gcp', 'prowler azure --list-checks']) {
  const cmd = buildCloudCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}

console.log('\n[2] CLOUDFIND report parsing');
const report = [
  'resolved: 104.21.11.117',
  `CLOUDFIND${T}info${T}provider${T}Origin hosted on Vercel${T}x-vercel-id: sin1${T}Lock down Vercel`,
  `CLOUDFIND${T}info${T}provider${T}Fronted by Cloudflare${T}server: cloudflare${T}Hide origin`,
  `CLOUDFIND${T}high${T}exposed-file${T}Exposed sensitive file: /.env${T}HTTP 200, 412 bytes${T}Remove and rotate`,
  `CLOUDFIND${T}high${T}public-bucket${T}Public S3 bucket is world-listable: acme-assets${T}200 + ListBucketResult${T}Block Public Access`,
  '== cloud scan complete ==',
].join('\n');
let f = parseCloudReport(report);
ok('4 findings parsed', f.length === 4, `got ${f.length}`);
ok('provider = info sev', f[0].severity === 'info' && f[0].source === 'provider');
ok('exposed-file = high + remediation', f.some((x) => x.source === 'exposed-file' && x.severity === 'high' && /rotate/i.test(x.remediation)));
ok('public-bucket = high', f.some((x) => x.source === 'public-bucket' && x.severity === 'high'));

console.log('\n[3] renderCloud groups footprint vs risk');
const rendered = renderCloud(report);
ok('shows resolved IP', /104\.21\.11\.117/.test(rendered));
ok('shows Cloud footprint w/ Vercel + Cloudflare', /Vercel/.test(rendered) && /Cloudflare/.test(rendered));
ok('shows misconfig section w/ .env', /Misconfigurations/.test(rendered) && /\.env/.test(rendered));

console.log('\n[4] Prowler JSON (v4 OCSF + v3)');
const v4 = JSON.stringify([
  { status_code: 'FAIL', severity: 'high', check_title: 'S3 bucket is public', resource_uid: 'arn:aws:s3:::acme-data', service_name: 's3', status_detail: 'Bucket allows public read', remediation: { recommendation: { text: 'Enable S3 Block Public Access' } } },
  { status_code: 'PASS', severity: 'low', check_title: 'CloudTrail enabled' },
]);
f = extractCloudFindings('prowler aws -M json-ocsf', v4);
ok('v4: only FAIL -> 1 finding', f.length === 1, `got ${f.length}`);
ok('v4: high + resource + remediation', f[0].severity === 'high' && /acme-data/.test(f[0].host) && /Block Public Access/.test(f[0].remediation));
const v3 = JSON.stringify([
  { Status: 'FAIL', Severity: 'critical', CheckTitle: 'IAM policy allows *:* (admin)', ResourceId: 'arn:aws:iam::role/admin', Remediation: { Recommendation: { Text: 'Scope the policy down' } } },
]);
f = extractCloudFindings('prowler aws', v3);
ok('v3: 1 critical IAM finding', f.length === 1 && f[0].severity === 'critical' && /IAM/.test(f[0].title));
ok('inert on unrelated command', extractCloudFindings('ls', '{"x":1}').length === 0);
ok('extracts CLOUDFIND from any output', extractCloudFindings('bash script', report).length === 4);

console.log('\n[5] authz gating (domain gated, credentialed not)');
const g1 = classifyAction('cloud', 'iamalive.app');
ok('cloud <domain> is GATED w/ target', g1.gated === true && g1.target === 'iamalive.app');
const g2 = classifyAction('cloud', 'aws');
ok('cloud aws (CSPM) NOT gated (no target)', g2.gated === false);
const g3 = classifyAction('cloud', 'gcp myproject');
ok('cloud gcp (CSPM) NOT gated', g3.gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
