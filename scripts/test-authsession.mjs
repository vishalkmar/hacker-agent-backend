// Phase 11 (authsession) unit tests — cookie/header/CORS/login/JWT parsing. No network/DB.
// Run: node scripts/test-authsession.mjs
import { spawnSync } from 'node:child_process';
import { buildAuthSessionCommand, parseAuthSessionReport, extractAuthSessionFindings, renderAuthSession } from '../src/services/authsession/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const T = '\t';

console.log('\n[1] bash -n on generated commands');
for (const body of ['https://iamalive.app', 'iamalive.app', 'https://x.com/app', 'curl https://x', 'jwt_tool eyJ']) {
  const cmd = buildAuthSessionCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildAuthSessionCommand('') === null);
ok('raw passthrough', buildAuthSessionCommand('jwt_tool eyJabc') === 'jwt_tool eyJabc');

console.log('\n[2] finding parsing (each type)');
const report = [
  'AUTHSESS-BEGIN https://acme.tld',
  `AUTHFIND${T}medium${T}cookie-httponly${T}Session cookie "sid" is missing HttpOnly${T}set-cookie: sid=abc${T}https://acme.tld`,
  `AUTHFIND${T}medium${T}cookie-secure${T}Cookie "sid" is missing the Secure flag${T}set-cookie: sid=abc${T}https://acme.tld`,
  `AUTHFIND${T}low${T}cookie-samesite${T}Cookie "sid" has no SameSite attribute (CSRF exposure)${T}set-cookie: sid=abc${T}https://acme.tld`,
  `AUTHFIND${T}medium${T}no-hsts${T}No HSTS header${T}HSTS absent${T}https://acme.tld`,
  `AUTHFIND${T}medium${T}clickjacking${T}No X-Frame-Options / CSP frame-ancestors${T}no anti-framing${T}https://acme.tld`,
  `AUTHFIND${T}high${T}cors-credentials${T}CORS reflects an arbitrary Origin AND allows credentials${T}ACAO evil / ACAC true${T}https://acme.tld`,
  `AUTHFIND${T}medium${T}login-nocsrf${T}Login form has no visible CSRF token${T}no csrf field${T}https://acme.tld/login`,
  `AUTHFIND${T}critical${T}jwt-none${T}JWT uses alg:none (signature not verified)${T}{"alg":"none"}${T}https://acme.tld`,
  `AUTHFIND${T}low${T}jwt-noexp${T}JWT has no exp claim${T}payload${T}https://acme.tld`,
  `AUTHFIND${T}info${T}login-found${T}Login form found: https://acme.tld/login${T}password field${T}https://acme.tld/login`,
  'AUTHSESS-END',
].join('\n');
const f = parseAuthSessionReport(report);
const by = (s) => f.find((x) => x.source === s);
ok('all findings parsed', f.length === 10, `got ${f.length}`);
ok('cookie-httponly -> medium + CWE-1004', by('auth-cookie-httponly')?.cve === 'CWE-1004');
ok('cookie-secure -> CWE-614', by('auth-cookie-secure')?.cve === 'CWE-614');
ok('no-hsts -> medium + CWE-319', by('auth-no-hsts')?.severity === 'medium' && by('auth-no-hsts')?.cve === 'CWE-319');
ok('clickjacking -> CWE-1021', by('auth-clickjacking')?.cve === 'CWE-1021');
ok('cors-credentials -> high + CWE-942', by('auth-cors-credentials')?.severity === 'high' && by('auth-cors-credentials')?.cve === 'CWE-942');
ok('login-nocsrf -> CWE-352', by('auth-login-nocsrf')?.cve === 'CWE-352');
ok('jwt-none -> critical + CWE-347', by('auth-jwt-none')?.severity === 'critical' && by('auth-jwt-none')?.cve === 'CWE-347');
ok('jwt-noexp -> CWE-613', by('auth-jwt-noexp')?.cve === 'CWE-613');
ok('all finding_type auth-session', f.every((x) => x.finding_type === 'auth-session'));

console.log('\n[3] inert + render + authz');
ok('inert on unrelated output', extractAuthSessionFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns 10', extractAuthSessionFindings('c', report).length === 10);
const r = renderAuthSession(report);
ok('render shows weaknesses section', /Auth\/session weaknesses/.test(r));
ok('render separates auth surface (info)', /Auth surface/.test(r) && /Login form found/.test(r));
ok('render orders critical first', r.indexOf('alg:none') < r.indexOf('missing HttpOnly'));
ok('clean -> friendly message', /No authentication or session/.test(renderAuthSession('AUTHSESS-BEGIN x\nAUTHSESS-END')));
const g = classifyAction('authsession', 'https://acme.tld');
ok('authsession <target> gated', g && g.gated === true, JSON.stringify(g));
ok('authsession localhost not gated', classifyAction('authsession', 'http://127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
