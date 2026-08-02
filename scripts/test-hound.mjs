// Phase (HOUND) tests — persistent command build, link extraction, GPS/device capture parsing. Deterministic.
// Run: node scripts/test-hound.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildHoundCommand, extractHoundLink, parseHound, detectHound } from '../src/services/hound/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] persistent launch command');
const cmd = buildHoundCommand();
ok('valid bash', (() => { const f = path.join(os.tmpdir(), 'h.sh'); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f]); fs.rmSync(f, { force: true }); return r.status === 0; })());
ok('installs deps (php/wget/unzip) if missing', /php-cli/.test(cmd) && /wget/.test(cmd) && /unzip/.test(cmd));
ok('clones techchipnet/hound', /git clone .*techchipnet\/hound/.test(cmd));
ok('answers the tunnel prompt with Y', /printf 'Y/.test(cmd));
ok('runs hound.sh (persistent server)', /bash hound\.sh/.test(cmd));
ok('clears stale ip/data before run', /rm -f ip\.txt data\.txt/.test(cmd));

console.log('\n[2] link extraction (from the REAL proof output)');
const real = '[+] Starting cloudflared tunnel...\n[*] Direct link: https://grande-yang-personal-granny.trycloudflare.com\n[*] Waiting targets, Press Ctrl + C to exit...';
ok('extracts the trycloudflare link', extractHoundLink(real) === 'https://grande-yang-personal-granny.trycloudflare.com');
ok('no link yet -> null', extractHoundLink('[+] Downloading Cloudflared...') === null);
ok('detectHound', detectHound('bash hound.sh') && detectHound('https://x.trycloudflare.com'));

console.log('\n[3] captured-data parsing -> findings');
const capture = [
  '[+] Target opened the link!',
  '[+] IP: 103.87.12.44',
  'Latitude: 28.6139',
  'Longitude: 77.2090',
  'Accuracy: 21',
  'Operating System: Android 14',
  'Device Model: Pixel 7',
  'Browser: Chrome',
  'ISP: Reliance Jio',
].join('\n');
const f = parseHound('hound.sh', capture);
const gps = f.find((x) => /GPS location captured/.test(x.title));
ok('exact GPS -> CRITICAL finding', gps?.severity === 'critical' && /28\.6139, 77\.2090/.test(gps?.title));
ok('GPS evidence has a Google-Maps link', /google\.com\/maps\?q=28\.6139,77\.2090/.test(gps?.evidence));
ok('accuracy captured', /±21m/.test(gps?.evidence));
const intel = f.find((x) => /device\/network intel/.test(x.title));
ok('device intel -> medium finding', intel?.severity === 'medium');
ok('intel includes OS/IP/ISP', /Android 14/.test(intel?.evidence) && /103\.87\.12\.44/.test(intel?.evidence) && /Reliance Jio/.test(intel?.evidence));

console.log('\n[4] hygiene — never fabricate');
ok('target-opened only (no data) -> info', parseHound('hound.sh', '[+] Target opened the link!').some((x) => x.severity === 'info'));
ok('no capture -> no GPS finding', !parseHound('hound.sh', '[*] Waiting targets...').some((x) => /GPS/.test(x.title)));
ok('non-hound command -> []', parseHound('nmap x', capture).length === 0);
ok('empty output -> []', parseHound('hound.sh', '').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
