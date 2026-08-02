// Phase (CAMPHISH) tests — templates, persistent command, link extraction, cam/GPS/device capture parsing.
// Deterministic. Run: node scripts/test-camphish.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CAMPHISH_TEMPLATES, buildCamphishCommand, extractCamphishLink, parseCamphish, pickTemplate, detectCamphish } from '../src/services/camphish/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { const f = path.join(os.tmpdir(), `cp_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f]); fs.rmSync(f, { force: true }); return r.status === 0; };

console.log('\n[1] templates + selection');
ok('3 templates', Object.keys(CAMPHISH_TEMPLATES).length === 3 && CAMPHISH_TEMPLATES[3] === 'Online Meeting');
ok('pick by number', pickTemplate('2') === 2);
ok('pick youtube', pickTemplate('live youtube tv') === 2);
ok('pick meeting', pickTemplate('online meeting') === 3);
ok('default festival', pickTemplate('anything else') === 1);

console.log('\n[2] persistent launch command (CLOUDFLARED = option 2, not ngrok)');
const cmd = buildCamphishCommand(1);
ok('valid bash', bashOk(cmd));
ok('port-forward option 2 (cloudflared, NOT 1=ngrok)', /printf '2\\n1/.test(cmd));
ok('installs deps + clones CamPhish', /php-cli/.test(cmd) && /git clone .*techchipnet\/CamPhish/.test(cmd));
ok('runs camphish.sh (persistent)', /bash camphish\.sh/.test(cmd));
ok('clears stale cam*.png/LocationLog', /rm -f cam\*\.png LocationLog\.log/.test(cmd));
ok('template number injected', /printf '2\\n3\\n/.test(buildCamphishCommand(3)));

console.log('\n[3] link extraction (from the REAL proof)');
ok('extracts the trycloudflare link', extractCamphishLink('[*] Direct link: https://beauty-versus-sig-llp.trycloudflare.com') === 'https://beauty-versus-sig-llp.trycloudflare.com');
ok('detectCamphish', detectCamphish('bash camphish.sh') && detectCamphish('https://x.trycloudflare.com'));

console.log('\n[4] capture parsing -> findings');
const cap = 'cam2026-07-24.png saved\n[+] Target opened the link!\nIP: 157.49.118.158\nLatitude: 28.6741647\nLongitude: 77.2729999';
const f = parseCamphish('camphish.sh', cap);
ok('webcam shot -> CRITICAL', f.some((x) => /Webcam shot captured/.test(x.title) && x.severity === 'critical' && /cam2026-07-24\.png/.test(x.title)));
ok('GPS -> CRITICAL + maps link', f.some((x) => /GPS location captured: 28\.6741647/.test(x.title) && /google\.com\/maps\?q=/.test(x.evidence)));
ok('device intel (IP) -> medium', f.some((x) => /device\/network intel/.test(x.title) && /157\.49\.118\.158/.test(x.evidence)));
ok('cam finding has camera remediation', f.find((x) => /Webcam/.test(x.title))?.remediation?.includes('front camera'));

console.log('\n[5] hygiene — never fabricate');
ok('no capture -> no cam/GPS finding', !parseCamphish('camphish.sh', '[*] Waiting targets...').some((x) => /Webcam|GPS/.test(x.title)));
ok('opened-only -> info', parseCamphish('camphish.sh', '[+] Target opened the link!').some((x) => x.severity === 'info'));
ok('non-camphish command -> []', parseCamphish('nmap x', cap).length === 0);
ok('empty output -> []', parseCamphish('camphish.sh', '').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
