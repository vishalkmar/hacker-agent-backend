// NetExec (nxc) output parser — turns SMB/WinRM/LDAP/RDP/SSH/MSSQL enumeration & credential-attack output
// into structured findings. NetExec (successor to CrackMapExec) is the workhorse for AD/network attacks:
// host enumeration, credential spraying, share/user/group enumeration, password policy, SAM/LSASS/secrets
// dumps, and kerberoasting. This module reads its distinctive columnar output:
//   PROTO  IP  PORT  HOSTNAME  [marker] detail
// [+] = success/valid, [-] = failure, [*] = info, (Pwn3d!) = admin/code-exec.
//
// Offensive tool — gated by authz when it names a real target (added nxc/netexec to OFFENSIVE_CMD_RE).

const PROTO_RE = /^(SMB|WINRM|LDAP|RDP|SSH|FTP|MSSQL|WMI|VNC|NFS)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)$/i;

export function detectNetexec(command = '') {
  return /\b(nxc|netexec|crackmapexec|cme)\b/i.test(command);
}

// Parse nxc output -> findings[]. `command` is used only to confirm this is nxc output.
export function parseNetexec(command, output) {
  if (!detectNetexec(command) || !output) return [];
  const out = [];
  for (const raw of String(output).split('\n')) {
    const line = raw.replace(/\x1b\[[0-9;]*m/g, '').trim(); // strip ANSI colour
    const m = PROTO_RE.exec(line);
    if (!m) continue;
    const [, protoRaw, ip, port, host, rest] = m;
    const proto = protoRaw.toUpperCase();

    // 1) SAM / secrets / LSASS dump: user:rid:lm:nt:::  -> critical (feed straight into ```hashid)
    const sam = /^([^:\s]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::/i.exec(rest);
    if (sam) {
      out.push({ finding_type: 'credential-access', severity: 'critical', source: 'netexec',
        title: `Dumped NTLM hash for ${sam[1]} on ${host}`, host: ip,
        evidence: rest.slice(0, 200), remediation: 'Rotate the exposed account passwords immediately; restrict admin access; enable LSASS protection (RunAsPPL)/Credential Guard. Crack with ```hashid (hashcat -m 1000).' });
      continue;
    }

    // 2) valid credentials: [+] domain\user:pass   (Pwn3d! => admin/code-exec)
    const cred = /\[\+\]\s+([^\s:]+):(\S+)/.exec(rest);
    if (cred && /\[\+\]/.test(rest)) {
      const admin = /\(Pwn3d!?\)/i.test(rest);
      out.push({ finding_type: 'credential-access', severity: admin ? 'critical' : 'high', source: 'netexec',
        title: `${admin ? 'ADMIN access' : 'Valid credentials'} via ${proto} on ${host}: ${cred[1]}`,
        host: ip, port: Number(port), evidence: rest.slice(0, 200),
        remediation: admin ? 'This account has administrative/code-exec rights on the host — treat as full compromise. Rotate creds, review privileged access, segment the network.' : 'Valid credentials confirmed — enforce MFA, strong/unique passwords, and least privilege; investigate reuse across the estate.' });
      continue;
    }

    // 3) host enumeration line: (name:..) (domain:..) (signing:False) (SMBv1:True)
    if (/signing:/i.test(rest) || /SMBv1:/i.test(rest)) {
      if (/signing:False/i.test(rest))
        out.push({ finding_type: 'misconfiguration', severity: 'medium', source: 'netexec',
          title: `SMB signing not required on ${host}`, host: ip, evidence: rest.slice(0, 200),
          remediation: 'Enforce SMB signing (GPO: "Microsoft network server: Digitally sign communications (always)") to prevent NTLM relay attacks.' });
      if (/SMBv1:True/i.test(rest))
        out.push({ finding_type: 'misconfiguration', severity: 'high', source: 'netexec',
          title: `SMBv1 enabled on ${host}`, host: ip, evidence: rest.slice(0, 200),
          remediation: 'Disable SMBv1 (legacy, exploitable — EternalBlue/MS17-010). Use SMBv2/3 only.' });
      continue;
    }

    // 4) share enumeration rows: <share> <READ|WRITE|READ,WRITE|NO ACCESS> [remark]
    const share = /^(\S+)\s+(READ,WRITE|READ|WRITE|NO ACCESS)\b\s*(.*)$/i.exec(rest);
    if (share && !/^(Share|Permissions|-+)$/i.test(share[1])) {
      const name = share[1];
      const perms = share[2].toUpperCase();
      const writable = /WRITE/.test(perms);
      const isDefault = /^(IPC\$|print\$)$/i.test(name);
      // writable non-default shares are the interesting ones (lateral movement / payload drop)
      const sev = writable && !isDefault ? 'medium' : /^(ADMIN\$|C\$)$/i.test(name) && !/NO ACCESS/.test(perms) ? 'high' : 'low';
      out.push({ finding_type: 'exposure', severity: sev, source: 'netexec',
        title: `${proto} share ${name} accessible (${perms}) on ${host}`, host: ip, evidence: rest.slice(0, 160),
        remediation: writable ? 'Review ACLs on writable shares — attackers use them to drop payloads / move laterally. Restrict to least privilege.' : 'Confirm the share should be network-accessible; apply least-privilege ACLs.' });
      continue;
    }

    // 5) password policy signal
    const minlen = /Minimum password length:\s*(\d+)/i.exec(rest);
    if (minlen) {
      const n = Number(minlen[1]);
      out.push({ finding_type: 'misconfiguration', severity: n < 8 ? 'medium' : 'info', source: 'netexec',
        title: `Password policy: minimum length ${n} on ${host}`, host: ip, evidence: rest.slice(0, 160),
        remediation: n < 8 ? 'Weak minimum password length — enforce >=12-14 chars with complexity/passphrases and a banned-password list.' : null });
      continue;
    }

    // 6) kerberoast / asrep hash lines ($krb5tgs$ / $krb5asrep$)
    if (/\$krb5(tgs|asrep)\$/i.test(rest)) {
      out.push({ finding_type: 'credential-access', severity: 'high', source: 'netexec',
        title: `Kerberos ${/asrep/i.test(rest) ? 'AS-REP' : 'TGS'} hash captured on ${host}`, host: ip,
        evidence: rest.slice(0, 200), remediation: 'Crack offline with ```hashid (hashcat -m 13100/18200). Use strong service-account passwords / gMSA; enable AES; monitor for roasting.' });
    }
  }
  // dedup by title
  const seen = new Set();
  return out.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}
