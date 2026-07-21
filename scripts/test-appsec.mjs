// AppSec suite self-test — no DB, no network. Verifies:
//  1. every area's build command is valid bash (bash -n) for path / repo-url / image inputs
//  2. each scanner's real JSON output parses into correct findings via the global extractor
//  3. remediation KB, SBOM summary, and CI/CD generator produce sane output
//
// Run: node scripts/test-appsec.mjs
import { spawnSync } from 'node:child_process';
import {
  buildAppsecCommand, extractAppsecFindings, summarizeSbom, remediationFor,
  generateCicdPipeline, SCANNER_AREAS, ALL_AREAS,
} from '../src/services/appsec/index.js';

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => { if (cond) { pass++; console.log(`  ✅ ${name}`); } else { fail++; console.log(`  ❌ ${name} ${extra}`); } };

// ---- 1. bash -n on every generated command --------------------------------------------------
console.log('\n[1] bash -n on generated commands');
const inputs = { container: 'nginx:1.21', default: '.', repo: 'https://github.com/org/repo.git' };
for (const area of SCANNER_AREAS) {
  for (const label of ['default', 'repo', area === 'container' ? 'container' : 'default']) {
    const body = area === 'container' ? inputs.container : inputs[label] || '.';
    const cmd = buildAppsecCommand(area, body);
    const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
    ok(`${area} [${label}] valid bash`, r.status === 0, r.stderr?.trim());
  }
}
// raw passthrough
ok('raw passthrough returns verbatim', buildAppsecCommand('sast', 'semgrep --config auto --json .') === 'semgrep --config auto --json .');

// ---- 2. parsers ----------------------------------------------------------------------------
console.log('\n[2] scanner JSON -> findings');

const semgrep = JSON.stringify({ results: [
  { check_id: 'js.sqli', path: 'src/db.js', start: { line: 42 }, extra: { severity: 'ERROR', lines: 'query("..."+id)', message: 'SQL injection', metadata: { cwe: ['CWE-89: SQL Injection'], owasp: ['A03'], fix: 'use params' } } },
  { check_id: 'js.weak-rand', path: 'src/t.js', start: { line: 5 }, extra: { severity: 'WARNING', message: 'weak random', metadata: {} } },
] });
let f = extractAppsecFindings('semgrep --config auto --json .', semgrep);
ok('semgrep: 2 findings', f.length === 2, `got ${f.length}`);
ok('semgrep: ERROR->high + CWE in title', f[0].severity === 'high' && /CWE-89/.test(f[0].title));
ok('semgrep: WARNING->medium', f[1].severity === 'medium');
ok('semgrep: file:line captured', f[0].host === 'src/db.js:42');

const gitleaks = JSON.stringify([
  { RuleID: 'aws-access-key', Description: 'AWS key', File: 'config.js', StartLine: 12, Match: 'AKIAIOSFODNN7EXAMPLE', Commit: 'abcdef1234', Secret: 'AKIA...' },
]);
f = extractAppsecFindings('gitleaks detect -s . -f json -r x', gitleaks);
ok('gitleaks: 1 secret, high, CWE-798', f.length === 1 && f[0].severity === 'high' && f[0].cve === 'CWE-798');
ok('gitleaks history: remediation mentions history purge', /history/i.test(f[0].remediation));
f = extractAppsecFindings('gitleaks detect --no-git -s . -f json -r x', gitleaks);
ok('gitleaks no-git: remediation omits history purge', !/history/i.test(f[0].remediation));

const trivy = JSON.stringify({ Results: [{
  Target: 'app',
  Vulnerabilities: [{ VulnerabilityID: 'CVE-2021-1234', PkgName: 'lodash', InstalledVersion: '4.17.0', Severity: 'HIGH', Title: 'proto pollution', FixedVersion: '4.17.21', CVSS: { nvd: { V3Score: 7.5 } } }],
  Misconfigurations: [{ ID: 'DS002', Title: 'root user', Severity: 'MEDIUM', Message: 'runs as root', Resolution: 'USER nonroot', Status: 'FAIL' }],
  Secrets: [{ RuleID: 'github-pat', Title: 'token', Severity: 'CRITICAL', Match: 'ghp_x', StartLine: 3 }],
  Licenses: [{ Name: 'GPL-3.0', PkgName: 'foo', Severity: 'HIGH' }],
}] });
f = extractAppsecFindings('trivy image --format json nginx', trivy);
ok('trivy: 4 findings (vuln+config+secret+license)', f.length === 4, `got ${f.length}`);
const vuln = f.find((x) => x.cve === 'CVE-2021-1234');
ok('trivy: CVE + cvss 7.5 + fix', vuln && vuln.cvss_score === 7.5 && /4\.17\.21/.test(vuln.remediation));
ok('trivy: config misconfig present', f.some((x) => x.finding_type === 'config' && /root user/.test(x.title)));
ok('trivy: secret forced high', f.some((x) => x.finding_type === 'secret' && x.severity === 'critical'));
ok('trivy: license risk present', f.some((x) => x.finding_type === 'license' && /GPL/.test(x.title)));

const grype = JSON.stringify({ matches: [
  { vulnerability: { id: 'CVE-2020-1111', severity: 'Critical', cvss: [{ metrics: { baseScore: 9.8 } }], fix: { versions: ['1.2.3'] }, description: 'rce' }, artifact: { name: 'openssl', version: '1.0.0' } },
] });
f = extractAppsecFindings('grype dir:. -o json', grype);
ok('grype: critical CVE with score 9.8 + fix', f.length === 1 && f[0].severity === 'critical' && f[0].cvss_score === 9.8 && /1\.2\.3/.test(f[0].remediation));

const osv = JSON.stringify({ results: [{
  source: { path: 'package-lock.json' },
  packages: [{
    package: { name: 'axios', version: '0.21.0', ecosystem: 'npm' },
    vulnerabilities: [{ id: 'GHSA-xxxx', aliases: ['CVE-2021-3749'], summary: 'ReDoS', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H' }], affected: [{ ranges: [{ events: [{ fixed: '0.21.2' }] }] }] }],
    groups: [{ ids: ['GHSA-xxxx'], max_severity: '7.5' }],
  }],
}] });
f = extractAppsecFindings('osv-scanner --format json -r .', osv);
ok('osv depcve: dependency finding, CVE alias, fix', f.length === 1 && f[0].finding_type === 'dependency' && f[0].cve === 'CVE-2021-3749' && /0\.21\.2/.test(f[0].remediation));
f = extractAppsecFindings('osv-scanner --format json --sbom=x.json', osv);
ok('osv supplychain: --sbom -> finding_type supplychain', f[0].finding_type === 'supplychain');

const checkov = JSON.stringify({ results: { failed_checks: [
  { check_id: 'CKV_AWS_20', check_name: 'S3 not public', file_path: '/main.tf', file_line_range: [10, 20], severity: 'HIGH', guideline: 'https://docs', resource: 'aws_s3_bucket.data' },
] } });
f = extractAppsecFindings('checkov -d . -o json', checkov);
ok('checkov: iac finding high with resource + guideline', f.length === 1 && f[0].finding_type === 'iac' && f[0].severity === 'high' && /aws_s3_bucket/.test(f[0].service) && /docs/.test(f[0].remediation));

// non-scanner command must be inert
ok('inert on unrelated command', extractAppsecFindings('ls -la', '{"foo":1}').length === 0);
// bad JSON must not throw
ok('bad JSON degrades gracefully', extractAppsecFindings('semgrep .', 'not json at all').length === 0);

// ---- 3. SBOM summary / remediation / cicd --------------------------------------------------
console.log('\n[3] SBOM summary, remediation KB, CI/CD generator');
const syft = JSON.stringify({ artifacts: [
  { name: 'express', version: '4.18.0', type: 'npm', licenses: [{ value: 'MIT' }] },
  { name: 'foolib', version: '1.0', type: 'npm', licenses: ['GPL-3.0'] },
] });
const sbom = summarizeSbom(syft);
ok('sbom: 2 components counted', sbom.total === 2, `got ${sbom.total}`);
ok('sbom: flags GPL as risky license', /GPL/.test(sbom.text) && /Copyleft|restricted/i.test(sbom.text));

ok('remediation: SQLi -> parameterised queries', /parameteri/i.test(remediationFor('SQL injection CWE-89 in db.js')));
ok('remediation: hardcoded secret -> rotate', /rotate/i.test(remediationFor('hardcoded api_key found')));
ok('remediation: unknown -> generic guidance', /re-scan|regression/i.test(remediationFor('totally novel weirdness')));

const gh = generateCicdPipeline('github');
ok('cicd github: workflow path + gitleaks + semgrep + trivy', gh.filename.includes('.github/workflows') && /gitleaks/.test(gh.content) && /semgrep/i.test(gh.content) && /trivy/i.test(gh.content));
const gl = generateCicdPipeline('gitlab');
ok('cicd gitlab: .gitlab-ci.yml', gl.filename === '.gitlab-ci.yml' && /stages/.test(gl.content));
const jk = generateCicdPipeline('jenkins');
ok('cicd jenkins: Jenkinsfile', /Jenkinsfile/.test(jk.filename) && /pipeline/.test(jk.content));

// ---- coverage check ------------------------------------------------------------------------
console.log('\n[4] coverage');
ok('14 areas registered', ALL_AREAS.length === 14, `got ${ALL_AREAS.length}: ${ALL_AREAS.join(',')}`);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '⚠️  FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
