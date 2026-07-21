// Phase 10 (apidiscover) unit tests — API spec/endpoint/graphql/methods parsing. No network/DB.
// Run: node scripts/test-apidiscover.mjs
import { spawnSync } from 'node:child_process';
import { buildApiDiscoverCommand, parseApiDiscoverReport, extractApiDiscoverFindings, renderApiDiscover } from '../src/services/apidiscover/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['https://iamalive.app', 'iamalive.app', 'https://x.com/base', 'curl https://x', 'arjun -u https://x']) {
  const cmd = buildApiDiscoverCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildApiDiscoverCommand('') === null);
ok('raw passthrough', buildApiDiscoverCommand('arjun -u https://x.com') === 'arjun -u https://x.com');
ok('trailing slash stripped', /URL="https:\/\/x\.com"/.test(buildApiDiscoverCommand('https://x.com/')));

console.log('\n[2] finding parsing');
const report = [
  'APIDISC-BEGIN https://acme.tld',
  `APIFIND${T}info${T}api-doc${T}API documentation advertised via Link header${T}link: </docs/api>; rel="service-doc"${T}https://acme.tld`,
  `APIFIND${T}medium${T}api-spec${T}Exposed OpenAPI/Swagger spec (24 paths, v3.0.1): /openapi.json${T}public spec${T}https://acme.tld/openapi.json`,
  `APIFIND${T}info${T}api-endpoint${T}API endpoint: GET /users params=2${T}from OpenAPI spec${T}https://acme.tld`,
  `APIFIND${T}info${T}api-endpoint${T}API endpoint: POST /login params=0${T}from OpenAPI spec${T}https://acme.tld`,
  `APIFIND${T}medium${T}graphql-introspection${T}GraphQL introspection is ENABLED: /graphql${T}schema enumerable${T}https://acme.tld/graphql`,
  `APIFIND${T}info${T}api-jssurface${T}12 API path(s) referenced in the app's JavaScript${T}mined from JS${T}https://acme.tld`,
  `APIFIND${T}low${T}http-methods-write${T}State-changing HTTP methods enabled (PUT/DELETE/PATCH)${T}Allow: GET, PUT, DELETE${T}https://acme.tld`,
  `APIFIND${T}low${T}http-trace${T}HTTP TRACE method enabled (Cross-Site Tracing risk)${T}Allow: TRACE${T}https://acme.tld`,
  'APIDISC-END',
].join('\n');
const f = parseApiDiscoverReport(report);
const bySrc = (s) => f.filter((x) => x.source === s);
ok('all findings parsed', f.length === 8, `got ${f.length}`);
ok('api-spec -> medium + CWE-200', bySrc('api-api-spec')[0]?.severity === 'medium' && bySrc('api-api-spec')[0]?.cve === 'CWE-200');
ok('graphql introspection -> medium + CWE-200', bySrc('api-graphql-introspection')[0]?.cve === 'CWE-200');
ok('2 endpoints captured', bySrc('api-api-endpoint').length === 2);
ok('http-methods-write -> CWE-650', bySrc('api-http-methods-write')[0]?.cve === 'CWE-650');
ok('http-trace -> CWE-693', bySrc('api-http-trace')[0]?.cve === 'CWE-693');
ok('all finding_type api-discovery', f.every((x) => x.finding_type === 'api-discovery'));

console.log('\n[3] inert + render + authz');
ok('inert on unrelated output', extractApiDiscoverFindings('curl x', 'HTTP 200 OK\n<html>').length === 0);
ok('extract returns 8', extractApiDiscoverFindings('c', report).length === 8);
const r = renderApiDiscover(report);
ok('render shows exposure issues', /API exposure issues/.test(r));
ok('render shows discovered endpoints w/ count', /Discovered endpoints \(2\)/.test(r));
ok('render shows API surface', /API surface/.test(r));
ok('clean -> friendly message', /No API specs/.test(renderApiDiscover('APIDISC-BEGIN x\nAPIDISC-END')));
const g = classifyAction('apidiscover', 'https://acme.tld');
ok('apidiscover <target> gated', g && g.gated === true, JSON.stringify(g));
ok('apidiscover localhost not gated', classifyAction('apidiscover', 'http://127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
