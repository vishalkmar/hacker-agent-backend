// Phase 8 (svcaudit) unit tests — SSH/FTP/SMB/RDP config-check parsing. No network/DB.
// Run: node scripts/test-svcaudit.mjs
import { spawnSync } from 'node:child_process';
import { buildSvcAuditCommand, parseSvcAuditReport, extractSvcAuditFindings, renderSvcAudit } from '../src/services/svcaudit/index.js';
import { classifyAction } from '../src/services/authz/authz.js';

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { if (c) { pass++; console.log(`  ✅ ${n}`); } else { fail++; console.log(`  ❌ ${n} ${e}`); } };

console.log('\n[1] bash -n on generated commands');
for (const body of ['scanme.nmap.org', 'scanme.nmap.org deep', 'https://acme.tld/x', 'nmap -sV host', 'enum4linux host']) {
  const cmd = buildSvcAuditCommand(body);
  const r = spawnSync('bash', ['-nc', cmd], { encoding: 'utf8' });
  ok(`build "${body}" valid bash`, r.status === 0, r.stderr?.trim());
}
ok('empty -> null', buildSvcAuditCommand('') === null);
ok('raw passthrough', buildSvcAuditCommand('enum4linux -a host') === 'enum4linux -a host');

// Captured nmap NSE output: a badly-hardened host — weak SSH, anon FTP, SMBv1+unsigned+anon, RDP no-NLA.
const nse = `== service config audit ==
SVCAUDIT-BEGIN acme.tld
Nmap scan report for acme.tld
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 2.3.4
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh           OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
| ssh2-enum-algos:
|   kex_algorithms: (6)
|       curve25519-sha256@libssh.org
|       diffie-hellman-group1-sha1
|       diffie-hellman-group14-sha1
|   encryption_algorithms: (8)
|       aes128-ctr
|       aes128-cbc
|       3des-cbc
|       arcfour256
|   mac_algorithms: (4)
|       hmac-sha2-256
|       hmac-md5
|       umac-64@openssh.com
|   server_host_key_algorithms: (2)
|       ssh-rsa
|       ssh-dss
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|     password
445/tcp  open  microsoft-ds  Samba smbd 3.X
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1)
|     2.0.2
| smb-security-mode:
|   message_signing: disabled (dangerous, but default)
| smb-enum-shares:
|   Anonymous access: READ
3389/tcp open  ms-wbt-server
| rdp-enum-encryption:
|   Security layer
|     RDP: SUCCESS
|   RDP Encryption level: Client Compatible
SVCAUDIT-END`;

console.log('\n[2] SSH config parsing');
const f = parseSvcAuditReport(nse);
const bySrc = (s) => f.find((x) => x.source === s);
ok('weak kex flagged (group1/14-sha1)', !!bySrc('svc-ssh-kex') && bySrc('svc-ssh-kex').severity === 'medium');
ok('weak cipher flagged (cbc/3des/arcfour)', !!bySrc('svc-ssh-cipher'));
ok('weak MAC flagged (md5/umac-64)', !!bySrc('svc-ssh-mac'));
ok('deprecated host key flagged (ssh-rsa/dss)', !!bySrc('svc-ssh-hostkey'));
ok('password auth flagged', !!bySrc('svc-ssh-passauth'));
ok('outdated OpenSSH 6.6 -> low', !!bySrc('svc-ssh-version') && bySrc('svc-ssh-version').severity === 'low');

console.log('\n[3] FTP / SMB / RDP parsing');
ok('anonymous FTP -> high', !!bySrc('svc-ftp-anon') && bySrc('svc-ftp-anon').severity === 'high');
ok('FTP cleartext noted', !!bySrc('svc-ftp-cleartext'));
ok('SMBv1 enabled -> high + CWE-477', !!bySrc('svc-smb-v1') && bySrc('svc-smb-v1').severity === 'high' && bySrc('svc-smb-v1').cve === 'CWE-477');
ok('SMB signing not required -> medium', !!bySrc('svc-smb-signing') && bySrc('svc-smb-signing').severity === 'medium');
ok('SMB anonymous share access -> high', !!bySrc('svc-smb-anon'));
ok('RDP no-NLA -> medium', !!bySrc('svc-rdp-nla'));
ok('RDP weak encryption level -> medium', !!bySrc('svc-rdp-enc'));

console.log('\n[4] deep vuln findings');
const vuln = `SVCAUDIT-BEGIN v.tld
| rdp-vuln-ms12-020:
|   VULNERABLE:
|   MS12-020 Remote Desktop Protocol RCE
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 (ms17-010)
SVCAUDIT-END`;
const vf = parseSvcAuditReport(vuln);
ok('MS12-020 -> critical + CVE', vf.some((x) => x.source === 'svc-rdp-ms12020' && x.severity === 'critical' && x.cve === 'CVE-2012-0002'));
ok('MS17-010 EternalBlue -> critical + CVE', vf.some((x) => x.source === 'svc-smb-ms17010' && x.severity === 'critical' && x.cve === 'CVE-2017-0144'));

console.log('\n[5] inert + render + authz');
ok('inert on unrelated output', extractSvcAuditFindings('curl x', 'HTTP 200 OK\nhello').length === 0);
ok('extract returns many findings', extractSvcAuditFindings('c', nse).length >= 10);
ok('clean host -> friendly message', /No SMB\/FTP\/SSH\/RDP/.test(renderSvcAudit('SVCAUDIT-BEGIN x\nSVCAUDIT-END')));
const r = renderSvcAudit(nse);
ok('render groups by service (SSH/FTP/SMB/RDP)', /\*\*SSH:\*\*/.test(r) && /\*\*FTP:\*\*/.test(r) && /\*\*SMB:\*\*/.test(r) && /\*\*RDP:\*\*/.test(r));
const g = classifyAction('svcaudit', 'acme.tld');
ok('svcaudit <target> gated', g && g.gated === true && g.target === 'acme.tld', JSON.stringify(g));
ok('svcaudit localhost not gated', classifyAction('svcaudit', '127.0.0.1').gated === false);

console.log(`\n${fail === 0 ? '🎉 ALL PASS' : '💥 FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
