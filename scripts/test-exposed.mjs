// Phase 6 (exposed) unit tests — parsers, renderer, dispatcher, authz gating. No network/DB.
// Run: node scripts/test-exposed.mjs
import { spawnSync } from 'node:child_process';
import { buildExposedCommand, parseExposedReport, extractExposedFindings, renderExposed } from '../src/services/exposed/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['iamalive.app', 'iamalive.app deep', 'https://iamalive.app/x', 'nmap -p9200 host', 'nuclei -u https://x']) {
  const cmd = buildExposedCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty body -> null (usage)', buildExposedCommand('') === null);
ok('raw nmap passthrough verbatim', buildExposedCommand('nmap -sV host') === 'nmap -sV host');
ok('deep flag not treated as target', /exposure scan: myhost \(deep\)/.test(buildExposedCommand('myhost deep')));

console.log('\n[2] EXPOFIND report parsing');
const report = [
  '== exposure scan: acme.tld ==',
  `EXPOFIND${T}critical${T}exposed-db${T}Elasticsearch exposed WITHOUT authentication (HTTP 200)${T}http://acme.tld:9200/_cluster/health matched: cluster_name${T}http://acme.tld:9200/_cluster/health`,
  `EXPOFIND${T}critical${T}exposed-api${T}Docker Engine API exposed WITHOUT authentication (HTTP 200)${T}http://acme.tld:2375/version matched: "ApiVersion"${T}http://acme.tld:2375/version`,
  `EXPOFIND${T}high${T}exposed-dashboard${T}Grafana exposed WITHOUT authentication (HTTP 200)${T}matched: "database":"ok"${T}http://acme.tld:3000/api/health`,
  `EXPOFIND${T}high${T}exposed-api${T}Spring Boot Actuator /env exposed${T}HTTP 200 at https://acme.tld/actuator/env${T}https://acme.tld/actuator/env`,
  `EXPOFIND${T}low${T}protected${T}Kibana present but authenticated (http:5601)${T}HTTP 401 at http://acme.tld:5601/api/status${T}http://acme.tld:5601/api/status`,
  '== exposure scan complete ==',
].join('\n');
const finds = parseExposedReport(report);
ok('5 findings parsed', finds.length === 5, `got ${finds.length}`);
const es = finds.find((f) => /Elasticsearch/.test(f.title));
ok('ES -> critical + CWE-306 + exposure type', es && es.severity === 'critical' && es.cve === 'CWE-306' && es.finding_type === 'exposure');
ok('ES remediation mentions localhost/VPN', /localhost|VPN|firewall/i.test(es.remediation));
const dock = finds.find((f) => /Docker/.test(f.title));
ok('Docker -> exposed-api source + critical', dock && dock.source === 'exposed-exposed-api' && dock.severity === 'critical');
const graf = finds.find((f) => /Grafana/.test(f.title));
ok('Grafana -> CWE-284 (dashboard access)', graf && graf.cve === 'CWE-284');
const prot = finds.find((f) => /Kibana/.test(f.title));
ok('protected Kibana -> source ends -protected', prot && prot.source === 'exposed-protected');

console.log('\n[3] extract + inert behavior');
ok('extractExposedFindings returns 5', extractExposedFindings('cmd', report).length === 5);
ok('inert on unrelated output', extractExposedFindings('curl x', 'HTTP 200 OK\nhello world').length === 0);
ok('bad/partial lines degrade gracefully', extractExposedFindings('c', `EXPOFIND${T}high${T}exposed-db`).length === 0);

console.log('\n[4] renderExposed grouping');
const r = renderExposed(report);
ok('empty scan -> friendly clean message', /No unauthenticated/.test(renderExposed('== exposure scan complete ==')));
ok('render groups "Exposed without authentication"', /Exposed without authentication/.test(r));
ok('render groups "Present but authenticated"', /Present but authenticated/.test(r));
ok('render shows Elasticsearch critical', /CRITICAL.*Elasticsearch/.test(r));

console.log('\n[5] authz gating (remote probe -> gated)');
const g = classifyAction('exposed', 'acme.tld');
ok('exposed <target> is gated w/ target', g && g.gated === true && g.target === 'acme.tld', JSON.stringify(g));
ok('exposed against localhost NOT gated (self-test)', classifyAction('exposed', '127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
