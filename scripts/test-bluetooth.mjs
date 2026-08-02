// Phase 12 (BLUESNARFER / Bluetooth) tests — auto-detect adapter, full cheatsheet coverage, anti-fabrication
// preflight, and finding parsing. Deterministic (no radio). Run: node scripts/test-bluetooth.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildBluetoothCommand, parseBtScan, parseBluesnarfer, extractBluetoothFindings, isNoBtAdapter } from '../src/services/scan/bluetooth.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { const f = path.join(os.tmpdir(), `bt_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); fs.rmSync(f, { force: true }); return r.status === 0; };
const M = 'AA:BB:CC:DD:EE:FF';

console.log('\n[1] adapter AUTO-DETECT + anti-fabrication preflight (never hardcoded hci0)');
for (const [a, o] of [['scan', {}], ['contacts', { mac: M }], ['calls', { mac: M }], ['services', { mac: M }], ['info-snarf', { mac: M }], ['flood', { mac: M }]]) {
  const cmd = buildBluetoothCommand({ action: a, ...o });
  ok(`${a}: auto-detects hci (grep ^hci) not hardcoded hci0`, /grep -oE "\^hci/.test(cmd) && !/-i hci0\b/.test(cmd));
  ok(`${a}: BT-NOADAPTER preflight present`, /BT-NOADAPTER/.test(cmd));
  ok(`${a}: valid bash`, bashOk(cmd));
}

console.log('\n[2] full bluesnarfer cheatsheet coverage');
ok('contacts -> -r range (+ optional -s TYPE)', /-s SM -r 1-50/.test(buildBluetoothCommand({ action: 'contacts', mac: M, range: '1-50', type: 'SM' })));
ok('calls -> -s TYPE (DC dialed)', /-s DC -r/.test(buildBluetoothCommand({ action: 'calls', mac: M, type: 'DC' })));
ok('calls default MC (missed)', /-s MC -r/.test(buildBluetoothCommand({ action: 'calls', mac: M })));
ok('search -> -f name', /-f "John"/.test(buildBluetoothCommand({ action: 'search', mac: M, name: 'John' })));
ok('delete -> -w range', /-w 1-5/.test(buildBluetoothCommand({ action: 'delete', mac: M, range: '1-5' })));
ok('list-storage -> -l', /bluesnarfer -b .* -l\b/.test(buildBluetoothCommand({ action: 'list-storage', mac: M })));
ok('custom -> -c ATCMD', /-c 'AT\+CGMI'/.test(buildBluetoothCommand({ action: 'custom', mac: M, atcmd: 'AT+CGMI' })));
ok('info-snarf -> -i', /bluesnarfer -b .* -i\b/.test(buildBluetoothCommand({ action: 'info-snarf', mac: M })));
ok('invalid TYPE ignored (no -s injection)', !/-s XYZ/.test(buildBluetoothCommand({ action: 'contacts', mac: M, type: 'XYZ' })));

console.log('\n[3] usage guards');
ok('contacts without MAC -> usage error', /BT-USAGE/.test(buildBluetoothCommand({ action: 'contacts' })));
ok('search without name -> usage error', /BT-USAGE/.test(buildBluetoothCommand({ action: 'search', mac: M })));
ok('custom without atcmd -> usage error', /BT-USAGE/.test(buildBluetoothCommand({ action: 'custom', mac: M })));
ok('check has NO preflight-exit (must always run to REPORT status)', !/exit 3/.test(buildBluetoothCommand({ action: 'check' })) && bashOk(buildBluetoothCommand({ action: 'check' })));

console.log('\n[4] isNoBtAdapter recognises real no-radio signatures');
ok('BT-NOADAPTER', isNoBtAdapter('BT-NOADAPTER: none'));
ok('No such device', isNoBtAdapter("Can't init device hci0: No such device"));
ok('Device not found', isNoBtAdapter('Device not found'));
ok('real scan output -> not flagged', isNoBtAdapter('AA:BB:CC:11:22:33  Nokia 6') === false);

console.log('\n[5] NEVER fabricate findings without a radio');
ok('no-adapter output -> ZERO findings', extractBluetoothFindings('bluesnarfer -b X', 'BT-NOADAPTER: no radio').length === 0);
ok('no-such-device -> ZERO findings', extractBluetoothFindings('hcitool scan', "Can't init device: No such device").length === 0);

console.log('\n[6] REAL output parses into findings');
const scan = 'Scanning ...\nAA:BB:CC:11:22:33\tNokia 6\n11:22:33:44:55:66\tGalaxy S21';
const sf = parseBtScan(scan);
ok('device scan -> 2 devices', sf.length === 2 && sf.every((x) => x.finding_type === 'bluetooth'));
ok('device MAC + name captured', sf.some((x) => /Nokia 6/.test(x.title) && x.host === 'AA:BB:CC:11:22:33'));
const snarf = 'name : "John Doe", number : "+15551234567"\nname : "Alice", number : "+15559876543"\nIMEI : 490154203237518\nmanufacturer : Nokia';
const pf = parseBluesnarfer(snarf);
ok('contacts exfiltrated -> high', pf.filter((x) => /exfiltrated/.test(x.title)).length === 2 && pf.some((x) => x.severity === 'high'));
ok('contact has PII remediation', pf.some((x) => /exfiltrated/.test(x.title) && /BlueSnarf/i.test(x.remediation || '')));
ok('IMEI leaked -> high', pf.some((x) => /IMEI leaked: 490154203237518/.test(x.title) && x.severity === 'high'));
ok('manufacturer -> info', pf.some((x) => /manufacturer: Nokia/.test(x.title) && x.severity === 'info'));
ok('dedup identical contacts', parseBluesnarfer('name : "Bob", number : "+1555"\nname : "Bob", number : "+1555"').filter((x) => /exfiltrated/.test(x.title)).length === 1);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
