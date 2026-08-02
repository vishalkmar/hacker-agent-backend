// Phase 11 (WIRESHARK/tshark) tests — sniff command builder + credential-extraction parser. Deterministic.
// Run: node scripts/test-tshark.mjs
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildSniffCommand, parseTshark, detectTshark } from '../src/services/scan/tshark.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };
const bashOk = (cmd) => { const f = path.join(os.tmpdir(), `t_${Math.random().toString(36).slice(2)}.sh`); fs.writeFileSync(f, cmd); const r = spawnSync('bash', ['-n', f], { encoding: 'utf8' }); fs.rmSync(f, { force: true }); return r.status === 0; };

console.log('\n[1] detection');
ok('detect tshark', detectTshark('tshark -r c.pcap -Y http.request'));
ok('detect tcpdump/dumpcap', detectTshark('tcpdump -i eth0') && detectTshark('dumpcap -i eth0'));
ok('non-capture -> false', detectTshark('nmap -sV x') === false);

console.log('\n[2] every sniff action builds valid bash');
for (const a of ['capture', 'creds', 'http', 'dns', 'hosts', 'protocols', 'read', 'info']) {
  ok(`${a}: valid bash`, bashOk(buildSniffCommand({ action: a, pcap: '/tmp/x.pcap', filter: 'http.request', iface: 'eth0', count: '500' })));
}
ok('capture auto-detects interface', /ip route/.test(buildSniffCommand({ action: 'capture' })) && /-w \/tmp\/sniff\.pcap/.test(buildSniffCommand({ action: 'capture' })));
ok('capture always terminates (duration+count)', /-a duration:\d+ -c \d+/.test(buildSniffCommand({ action: 'capture', count: '500', duration: '30' })));
ok('creds guards on missing pcap', /SNIFF-USAGE/.test(buildSniffCommand({ action: 'creds', pcap: '/tmp/none.pcap' })));
ok('creds has NO backticks (shell-safe)', !/`/.test(buildSniffCommand({ action: 'creds' })));
ok('capture surfaces SNIFF-NOCAPTURE if no file', /SNIFF-NOCAPTURE/.test(buildSniffCommand({ action: 'capture' })));

console.log('\n[3] CREDENTIAL EXTRACTION — HTTP basic-auth base64 decoded (the killer feature)');
const basic = parseTshark('tshark -r c.pcap -Y http.authorization', 'Basic YWRtaW46c2VjcmV0MTIz');
ok('base64 -> admin:secret123 (critical)', basic[0]?.severity === 'critical' && /admin:secret123/.test(basic[0]?.title));
ok('basic-auth finding_type=credential-access', basic[0]?.finding_type === 'credential-access');
ok('has TLS remediation', /enforce TLS/i.test(basic[0]?.remediation || ''));
ok('invalid base64 NOT decoded (no junk finding)', parseTshark('tshark x', 'Basic zzz!!!notb64').length === 0);

console.log('\n[4] SNIFF-CRED marker lines (from the creds extractor) — real captured shapes');
const marks = [
  'SNIFF-CRED\thttp-basic\t45.33.32.156\tBasic YWRtaW46c2VjcmV0MTIz',
  'SNIFF-CRED\thttp-get\tscanme.nmap.org\t/login?user=bob&password=hunter2',
  'SNIFF-CRED\tftp\t10.0.0.5\tPASS\ts3cr3t',
  'SNIFF-CRED\ttelnet\tlogin: root password: toor',
].join('\n');
const fm = parseTshark('tshark -r /tmp/sniff.pcap -Y http.authorization ...', marks);
ok('http-basic decoded from marker', fm.some((x) => /admin:secret123/.test(x.title) && x.severity === 'critical'));
ok('http-get login params -> high (bob/hunter2)', fm.some((x) => /bob \/ hunter2/.test(x.title) && x.severity === 'high'));
ok('ftp PASS -> critical', fm.some((x) => /ftp/.test(x.title) && x.severity === 'critical'));
ok('telnet -> critical', fm.some((x) => /telnet/.test(x.title) && x.severity === 'critical'));

console.log('\n[5] credentials in plain URLs + cleartext protocol detection');
ok('password in URL -> high', parseTshark('tshark -r c.pcap -Y http.request', 'GET http://site.com/login?user=alice&password=pass123').some((x) => /alice \/ pass123/.test(x.title) && x.severity === 'high'));
const phs = 'frame frames:52\n  eth frames:52\n    ip frames:41\n      tcp frames:32\n        http frames:4 bytes:1035';
const fp = parseTshark('tshark -r c.pcap -z io,phs -q', phs);
ok('cleartext HTTP traffic -> medium exposure', fp.some((x) => /Unencrypted HTTP/.test(x.title) && x.severity === 'medium' && x.finding_type === 'exposure'));

console.log('\n[6] hygiene');
ok('non-tshark command -> []', parseTshark('curl http://x', 'Basic YWRtaW46c2VjcmV0MTIz').length === 0);
ok('empty output -> []', parseTshark('tshark -r x', '').length === 0);
ok('dedup identical creds', parseTshark('tshark x', 'Basic YWRtaW46c2VjcmV0MTIz\nBasic YWRtaW46c2VjcmV0MTIz').length === 1);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
