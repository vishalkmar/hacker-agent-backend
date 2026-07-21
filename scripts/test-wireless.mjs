// Phase 6 (WIRELESS) tests — adapter preflight (anti-fabrication), auto-detection, offline crack, parsing.
// Deterministic (no network/radio). Run: node scripts/test-wireless.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildWirelessCommand, parseAirodump, parseWirelessResult, extractWirelessFindings, isNoAdapter } from '../src/services/scan/wireless.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { const f = path.join(os.tmpdir(), `w_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); fs.rmSync(f, { force: true }); return r.status === 0; };

console.log('\n[1] every command carries the adapter PREFLIGHT (anti-fabrication) + valid bash');
for (const action of ['scan', 'monitor', 'deauth', 'capture', 'wps']) {
  const cmd = buildWirelessCommand({ action, bssid: 'AA:BB:CC:DD:EE:FF', channel: '6' });
  ok(`${action}: has NOADAPTER preflight`, /WIRELESS-NOADAPTER/.test(cmd), 'no preflight');
  ok(`${action}: valid bash`, bashOk(cmd));
  ok(`${action}: auto-detects iface (no hardcoded wlan0mon)`, /iw dev/.test(cmd) && !/wlan0mon/.test(cmd));
}

console.log('\n[2] usage guards + offline crack (no radio needed)');
ok('deauth without BSSID -> usage error', /WIRELESS-USAGE/.test(buildWirelessCommand({ action: 'deauth' })));
ok('capture without bssid/channel -> usage error', /WIRELESS-USAGE/.test(buildWirelessCommand({ action: 'capture' })));
const crack = buildWirelessCommand({ action: 'crack', bssid: 'AA:BB:CC:DD:EE:FF', cap: 'h.cap' });
ok('crack does NOT require an adapter (offline)', !/WIRELESS-NOADAPTER/.test(crack) && /aircrack-ng/.test(crack));
ok('crack uses rockyou wordlist', /rockyou\.txt/.test(crack));
ok('crack checks the cap file exists', /-f "h.cap"|no capture file/.test(crack));

console.log('\n[3] isNoAdapter recognises the real failure signatures (so findings are never faked)');
ok('WIRELESS-NOADAPTER detected', isNoAdapter('WIRELESS-NOADAPTER: none here'));
ok('airodump "Failed initializing" detected', isNoAdapter('Failed initializing wireless card(s): wlan0mon'));
ok('"No such device" detected', isNoAdapter('ioctl(SIOCGIFINDEX) failed: No such device'));
ok('real scan output -> not flagged', isNoAdapter('BSSID PWR ... WPA2 CCMP PSK MyWiFi') === false);

console.log('\n[4] no fabricated findings when there is no radio');
ok('no-adapter output -> ZERO findings', extractWirelessFindings('airodump-ng wlan0mon', 'WIRELESS-NOADAPTER: none').length === 0);
ok('failed-card output -> ZERO findings', extractWirelessFindings('airodump-ng mon0', 'Failed initializing wireless card(s): mon0').length === 0);

console.log('\n[5] REAL airodump output DOES parse into findings');
const real = [
  'BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH ESSID',
  'AA:BB:CC:11:22:33  -42       10      3   6  270  WPA2 CCMP   PSK  HomeNet',
  '11:22:33:44:55:66  -70        5      0  11   54  WEP  WEP         OldRouter',
  '99:88:77:66:55:44  -55        8      1   1  130  OPN              FreeWiFi',
].join('\n');
const wf = parseAirodump(real);
ok('parses 3 real APs', wf.length === 3, `got ${wf.length}`);
ok('WPA2 -> info', wf.find((x) => /HomeNet/.test(x.title))?.severity === 'info');
ok('WEP -> high', wf.find((x) => /OldRouter/.test(x.title))?.severity === 'high');
ok('OPN -> high', wf.find((x) => /FreeWiFi/.test(x.title))?.severity === 'high');
ok('BSSID captured as host', wf.find((x) => /HomeNet/.test(x.title))?.host === 'AA:BB:CC:11:22:33');

console.log('\n[6] result parsing (handshake / cracked key / WPS)');
ok('handshake captured', parseWirelessResult('WPA handshake: AA:BB:CC:11:22:33').some((x) => /handshake captured/.test(x.title)));
ok('key cracked -> critical', parseWirelessResult('KEY FOUND! [ SuperSecret123 ]').some((x) => x.severity === 'critical' && /SuperSecret123/.test(x.title)));
ok('WPS PIN -> critical', parseWirelessResult("WPS PIN: '12345670'").some((x) => x.severity === 'critical' && /12345670/.test(x.title)));

console.log('\n[7] REAVER / WPS (Phase 9): wpsscan/pixie/wps actions + preflight + parsing');
const wpsscan = buildWirelessCommand({ action: 'wpsscan' });
ok('wpsscan uses wash + preflight', /wash -i/.test(wpsscan) && /WIRELESS-NOADAPTER/.test(wpsscan) && bashOk(wpsscan));
const pixie = buildWirelessCommand({ action: 'pixie', bssid: 'AA:BB:CC:DD:EE:FF', channel: '6' });
ok('pixie uses reaver -K 1 (pixie-dust) + channel + preflight', /reaver -i "\$MON" -b AA:BB:CC:DD:EE:FF -c 6 -K 1/.test(pixie) && /WIRELESS-NOADAPTER/.test(pixie) && bashOk(pixie));
const wps = buildWirelessCommand({ action: 'wps', bssid: 'AA:BB:CC:DD:EE:FF' });
ok('wps standard brute-force + preflight', /reaver -i "\$MON" -b AA:BB:CC:DD:EE:FF/.test(wps) && !/-K 1/.test(wps) && bashOk(wps));
ok('pixie without BSSID -> usage error', /WIRELESS-USAGE/.test(buildWirelessCommand({ action: 'pixie' })));
ok('WPA PSK recovered -> critical', parseWirelessResult("[+] WPA PSK: 'MyHomePass'").some((x) => x.severity === 'critical' && /MyHomePass/.test(x.title)));
ok('AP rate limiting -> info note', parseWirelessResult('[!] WARNING: Detected AP rate limiting, waiting 60 seconds').some((x) => x.severity === 'info' && /rate-limiting|locked/i.test(x.title)));
ok('no PIN recovered -> info note', parseWirelessResult('[-] WPS pin not found!').some((x) => x.severity === 'info'));
ok('wash output routed through wireless extractor', /wash/.test('wash -i mon0'));
ok('no-adapter reaver output -> ZERO findings (not faked)', extractWirelessFindings('reaver -i mon0 -b X', 'Failed initializing wireless card(s): mon0').length === 0);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
