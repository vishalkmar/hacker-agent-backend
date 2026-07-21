// Phase 3 (NETEXEC/nxc) tests — parser modeled on REAL nxc v1.5.1 output + gating.
// Deterministic (no network). Run: node scripts/test-netexec.mjs
import { parseNetexec, detectNetexec } from '../src/services/netexec/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

// captured from a live impacket-smbserver + nxc run
const H = 'SMB                      127.0.0.1       445    HOST01           ';
const REAL = [
  H + '[*] Windows 10 (name:HOST01) (domain:CORP) (signing:False) (SMBv1:True)',
  H + '[+] CORP\\test:Test123 ',
  H + '[-] CORP\\test:WrongPass STATUS_LOGON_FAILURE',
  H + '[*] Enumerated shares',
  H + 'Share           Permissions     Remark',
  H + '-----           -----------     ------',
  H + 'IPC$            READ,WRITE      ',
  H + 'PUBLIC          READ,WRITE      ',
  H + 'C$              NO ACCESS       Default share',
].join('\n');

console.log('\n[1] detection + gating');
ok('detect nxc', detectNetexec('nxc smb 10.0.0.5 --shares'));
ok('detect netexec/cme', detectNetexec('netexec smb x') && detectNetexec('crackmapexec smb x'));
ok('nxc on real target -> GATED (needs /authorize)', classifyAction('execute', 'nxc smb 192.168.1.10 -u a -p b --sam').gated === true);
ok('netexec on real target -> GATED', classifyAction('execute', 'netexec ldap 10.0.0.5 -u a -p b').gated === true);
ok('nxc on localhost -> not gated (self)', classifyAction('execute', 'nxc smb 127.0.0.1').gated === false);

console.log('\n[2] parse real enum + auth + shares output');
const f = parseNetexec('nxc smb 127.0.0.1 --shares', REAL);
const has = (re) => f.find((x) => re.test(x.title));
ok('valid credentials -> high', has(/Valid credentials/)?.severity === 'high');
ok('failed login NOT a finding', !f.some((x) => /WrongPass|LOGON_FAILURE/.test(x.title)));
ok('SMB signing:False -> medium', has(/signing not required/i)?.severity === 'medium');
ok('SMBv1:True -> high', has(/SMBv1 enabled/i)?.severity === 'high');
ok('writable non-default share PUBLIC -> medium', has(/share PUBLIC/)?.severity === 'medium');
ok('IPC$ writable -> low (default)', has(/share IPC\$/)?.severity === 'low');
ok('header/separator rows NOT findings', !f.some((x) => /(Share accessible|Permissions|-----)/.test(x.title)));

console.log('\n[3] admin / Pwn3d! -> critical');
const pwn = parseNetexec('nxc smb 10.0.0.5 -u admin -p pass', H + '[+] CORP\\admin:P@ss (Pwn3d!)');
ok('Pwn3d! -> critical ADMIN', pwn[0]?.severity === 'critical' && /ADMIN access/.test(pwn[0]?.title));

console.log('\n[4] SAM dump + kerberoast + password policy');
const sam = parseNetexec('nxc smb 10.0.0.5 --sam', H + 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::');
ok('SAM NTLM hash -> critical', sam[0]?.severity === 'critical' && /Dumped NTLM hash for Administrator/.test(sam[0]?.title));
ok('SAM remediation points to hashid', /hashid|hashcat -m 1000/.test(sam[0]?.remediation || ''));
const krb = parseNetexec('nxc ldap 10.0.0.5 --kerberoasting o.txt', H + '$krb5tgs$23$*svc$CORP$http/web*$abcd$ef01');
ok('kerberoast TGS -> high', krb[0]?.severity === 'high' && /TGS hash captured/.test(krb[0]?.title));
const pol = parseNetexec('nxc smb 10.0.0.5 --pass-pol', H + 'Minimum password length: 6');
ok('weak min-length policy -> medium', pol[0]?.severity === 'medium' && /minimum length 6/.test(pol[0]?.title));
const polok = parseNetexec('nxc smb 10.0.0.5 --pass-pol', H + 'Minimum password length: 14');
ok('strong min-length -> info', polok[0]?.severity === 'info');

console.log('\n[5] hygiene');
ok('no nxc command -> no findings', parseNetexec('curl http://x', REAL).length === 0);
ok('empty output -> none', parseNetexec('nxc smb x', '').length === 0);
ok('findings carry source=netexec + host ip', f.every((x) => x.source === 'netexec' && x.host === '127.0.0.1'));

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
