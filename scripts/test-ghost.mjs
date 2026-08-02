// Self-test for the Ghost (Android/ADB) tool — runs BEFORE the authz gate is applied.
// Validates: every generated command is valid bash (bash -n), action coverage, target normalization,
// findings extraction (exposed ADB / live connection / device intel), and honest no-device detection.
import { execFileSync } from 'node:child_process';
import { buildGhostCommand, extractGhostFindings, isNoDevice } from '../src/services/ghost/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log('  ✗', name); } };
const bashOk = (cmd) => {
  try { execFileSync('bash', ['-n', '-c', cmd], { stdio: 'pipe' }); return true; }
  catch (e) { console.log('    bash -n FAILED:', String(e.stderr || e).slice(0, 200)); return false; }
};

console.log('== 1. every action builds valid bash ==');
const actions = [
  ['check'], ['scan', '192.168.1.0/24'], ['connect', '192.168.1.20'], ['disconnect', '192.168.1.20'],
  ['devices'], ['shell', '192.168.1.20', 'id'], ['sysinfo', '192.168.1.20'], ['screenshot', '192.168.1.20'],
  ['screenrecord', '192.168.1.20', '8'], ['pull', '192.168.1.20', '/sdcard/DCIM'], ['apps', '192.168.1.20'],
  ['install', '192.168.1.20', 'app.apk'], ['uninstall', '192.168.1.20', 'com.x.y'], ['run', '192.168.1.20', 'com.x.y'],
  ['logcat', '192.168.1.20'], ['battery', '192.168.1.20'], ['network', '192.168.1.20'], ['wifi', '192.168.1.20', 'off'],
  ['macinet', '192.168.1.20'], ['wpa', '192.168.1.20'], ['extract-apk', '192.168.1.20', 'com.x.y'],
  ['current', '192.168.1.20'], ['input', '192.168.1.20', '26'], ['forward', '192.168.1.20', '8080', '80'],
  ['reboot', '192.168.1.20'], ['shutdown', '192.168.1.20'], ['unlock', '192.168.1.20'], ['bogus-action', 'x'],
];
for (const [action, target, arg, arg2] of actions) {
  const cmd = buildGhostCommand({ action, target, arg, arg2 });
  ok(`bash -n: ${action}`, bashOk(cmd));
}
// USB serial + no-target device actions must also be valid bash
for (const a of ['sysinfo', 'shell', 'apps', 'screenshot', 'pull', 'logcat', 'current']) {
  ok(`bash -n USB serial: ${a}`, bashOk(buildGhostCommand({ action: a, target: '10BG4M1N03003BT', arg: a === 'pull' ? '/sdcard/DCIM' : (a === 'shell' ? 'id' : undefined) })));
  ok(`bash -n no-target: ${a}`, bashOk(buildGhostCommand({ action: a, arg: a === 'pull' ? '/sdcard/DCIM' : (a === 'shell' ? 'id' : undefined) })));
}

console.log('== 1b. authz gate — remote IP gated, USB serial / physical local ungated ==');
ok('sysinfo <IP> → gated (remote)', classifyAction('ghost', 'sysinfo 192.168.1.20').gated === true);
ok('connect <IP> → gated', classifyAction('ghost', 'connect 192.168.1.20').gated === true);
ok('sysinfo <USB-serial> → NOT gated (physical)', classifyAction('ghost', 'sysinfo 10BG4M1N03003BT').gated === false);
ok('sysinfo (no target) → NOT gated', classifyAction('ghost', 'sysinfo').gated === false);
ok('check → NOT gated', classifyAction('ghost', 'check').gated === false);

console.log('== 2. target normalization (default :5555) ==');
ok('bare IP → :5555 + adb connect (TCP mode)', (() => { const c = buildGhostCommand({ action: 'sysinfo', target: '10.0.0.5' }); return c.includes('10.0.0.5:5555') && c.includes('adb connect 10.0.0.5:5555'); })());
ok('IP:port preserved', buildGhostCommand({ action: 'sysinfo', target: '10.0.0.5:5037' }).includes('10.0.0.5:5037'));
ok('USB serial → -s serial, NO adb connect', (() => { const c = buildGhostCommand({ action: 'sysinfo', target: '10BG4M1N03003BT' }); return c.includes('-s 10BG4M1N03003BT') && !c.includes('adb connect'); })());
ok('no target → adb auto-select (no -s, no connect)', (() => { const c = buildGhostCommand({ action: 'sysinfo' }); return !c.includes('-s ') && !c.includes('adb connect') && c.includes('adb shell'); })());
ok('scan uses nmap -p 5555', /nmap.*-p 5555.*--open/.test(buildGhostCommand({ action: 'scan', target: '10.0.0.0/24' })));
ok('connect still needs an IP (usage w/o target)', /GHOST-USAGE/.test(buildGhostCommand({ action: 'connect' })));
ok('input maps power keycode', buildGhostCommand({ action: 'input', target: '10.0.0.5', arg: '26' }).includes('keyevent 26'));
ok('input word→KEYCODE_', buildGhostCommand({ action: 'input', target: '10.0.0.5', arg: 'home' }).includes('KEYCODE_HOME'));
ok('self-install adb present', buildGhostCommand({ action: 'check' }).includes('apt-get install -y adb'));

console.log('== 3. findings extraction ==');
const scanOut = 'Nmap scan report for 192.168.1.20\nPORT     STATE SERVICE\n5555/tcp open  freeciv';
const f1 = extractGhostFindings('nmap -Pn -p 5555 --open 192.168.1.0/24', scanOut);
ok('exposed ADB → critical', f1.some(f => f.severity === 'critical' && /Exposed ADB/i.test(f.title) && f.cwe === 'CWE-306'));

const connOut = 'connected to 192.168.1.20:5555\nList of devices attached\n192.168.1.20:5555 device';
const f2 = extractGhostFindings('adb connect 192.168.1.20:5555', connOut);
ok('live connection → critical', f2.some(f => f.severity === 'critical' && /remote access established/i.test(f.title)));

const propOut = '[ro.product.model]: [Pixel 6]\n[ro.build.version.release]: [13]';
const f3 = extractGhostFindings('adb -s 192.168.1.20:5555 shell getprop', propOut);
ok('device intel → info', f3.some(f => f.severity === 'info' && /Pixel 6/.test(f.title) && /Android 13/.test(f.title)));

ok('no findings on unrelated cmd', extractGhostFindings('ls -la', 'file listing').length === 0);
ok('already-connected not double-flagged', !extractGhostFindings('adb connect x', 'already connected to 192.168.1.20:5555').some(f => /remote access established/i.test(f.title)));

console.log('== 4. honest no-device detection ==');
ok('detects "failed to connect"', isNoDevice('failed to connect to 192.168.1.20:5555'));
ok('detects no devices found', isNoDevice('error: no devices/emulators found'));
ok('detects GHOST-NODEVICE', isNoDevice('GHOST-NODEVICE: ...'));
ok('does NOT flag a good connection', !isNoDevice('connected to 192.168.1.20:5555\ndevice'));

console.log(`\n${pass}/${pass + fail} passed` + (fail ? `  (${fail} FAILED)` : ' ✅'));
process.exit(fail ? 1 : 0);
