// PHASE 8 — SMB / FTP / SSH / RDP service configuration checks.
//
// Powers the ```svcaudit agent tag. Phase 7 asks "is the port open?"; Phase 5 asks "does the login take
// default creds?"; Phase 8 asks the third question: "for the services that ARE exposed, is each one
// CONFIGURED securely?" It runs targeted nmap NSE scripts per service and reviews the hardening:
//   • SMB  (139/445): SMBv1 enabled, message signing not required, null/anonymous sessions & shares.
//   • FTP  (21):      anonymous login allowed, cleartext (no FTPS), writable root, banner/version.
//   • SSH  (22):      weak key-exchange (group1/group14-sha1), CBC/arcfour/3des ciphers, MD5/96-bit MACs,
//                     deprecated host keys (ssh-rsa/ssh-dss), password auth, SSHv1.
//   • RDP  (3389):    NLA not required, weak/RDP-only encryption layer, BlueKeep/MS12-020.
// Shell runs the tools between SVCAUDIT-BEGIN/END sentinels; ALL classification lives in the JS parser
// (parseSvcAuditReport) so each rule is unit-testable against captured NSE output. finding_type
// 'service-config'. Actively scans a remote target -> AUTHORIZATION-GATED. bash -n clean.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }

export function buildSvcAuditScan(target, { deep = false } = {}) {
  const host = hostOf(target);
  const lines = [
    `HOST="${host}";`,
    `echo "== service config audit (SMB/FTP/SSH/RDP): $HOST =="`,
    `echo "SVCAUDIT-BEGIN $HOST";`,
    `command -v nmap >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y nmap >/dev/null 2>&1; };`,
    // One nmap pass: version scan + all relevant NSE scripts on the four services' ports. nmap runs a
    // script only against a matching open port, so closed services cost nothing.
    `nmap -Pn -T4 -sV -p21,22,139,445,3389 \\`,
    `  --script "ftp-anon,ftp-syst,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,smb-protocols,smb-security-mode,smb2-security-mode,smb2-capabilities,smb-enum-shares,smb-os-discovery,rdp-ntlm-info,rdp-enum-encryption" \\`,
    `  "$HOST" 2>/dev/null;`,
  ];
  if (deep) {
    lines.push(
      `echo "--- deep: BlueKeep/MS12-020 + SMB vuln NSE ---";`,
      `nmap -Pn -T4 -p3389,445 --script "rdp-vuln-ms12-020,smb-vuln-ms17-010,smb-vuln-ms08-067,smb-double-pulsar-backdoor" "$HOST" 2>/dev/null | grep -iE 'VULNERABLE|ms12-020|ms17-010|ms08-067|double.?pulsar|State:' || true;`,
      `command -v enum4linux >/dev/null 2>&1 && { echo "--- enum4linux (SMB null session) ---"; enum4linux -a "$HOST" 2>/dev/null | grep -iE 'allows sessions using|Server .* allows|Sharename|Mapping: OK|got .* sid' | head -20 || true; };`,
    );
  }
  lines.push(`echo "SVCAUDIT-END";`);
  return lines.join('\n');
}

export function buildSvcAuditCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(nmap|enum4linux|smbclient|smbmap|hydra|ssh-audit|rdesktop|xfreerdp)\b/i.test(raw)) return raw; // passthrough
  const tokens = raw.split(/\s+/);
  const deep = tokens.some((t) => /^(deep|vuln|full)$/i.test(t));
  const target = tokens.find((t) => !/^(deep|vuln|full)$/i.test(t));
  if (!target) return null;
  return buildSvcAuditScan(target, { deep });
}

// Weak-crypto token sets for SSH algorithm review.
const WEAK_KEX = /diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-group1-sha1|gss-gex-sha1|rsa1024-sha1|ecdh-sha2-nistp256/i;
const WEAK_CIPHER = /(^|[\s,])([a-z0-9@.-]*-cbc|arcfour\d*|arcfour|3des-cbc|3des|blowfish-cbc|cast128-cbc|des-cbc|rijndael-cbc)/i;
const WEAK_MAC = /hmac-md5(-96)?|hmac-sha1-96|umac-64(-etm)?|hmac-ripemd160|hmac-sha1(?![-\w])/i;
const WEAK_HOSTKEY = /\bssh-rsa\b|\bssh-dss\b/i;

function push(out, host, sev, type, title, evidence, remediation, cve) {
  out.push({ finding_type: 'service-config', severity: normSev(sev), title: title.slice(0, 200), host: host || null, port: null, evidence: (evidence || '').slice(0, 240), cve: cve || null, remediation, source: `svc-${type}` });
}

export function parseSvcAuditReport(output) {
  const text = String(output || '');
  if (!/SVCAUDIT-BEGIN/.test(text)) return [];
  const seg = text.slice(text.indexOf('SVCAUDIT-BEGIN'));
  const host = (seg.match(/SVCAUDIT-BEGIN\s+(\S+)/) || [])[1] || null;
  const out = [];

  // ---- SSH (22) ----
  // NSE output lines are all prefixed with '|'; the SSH section runs from ssh2-enum-algos up to the next
  // "<port>/tcp" line (e.g. 445/tcp) or the end sentinel. (A naive \n\S lookahead stops at the first '|'.)
  const sshBlock = (seg.match(/ssh2-enum-algos:[\s\S]*?(?=\n\d+\/tcp\s|\nSVCAUDIT-END|$)/i) || [])[0] || '';
  if (sshBlock) {
    if (WEAK_KEX.test(sshBlock)) push(out, host, 'medium', 'ssh-kex', 'SSH offers weak key-exchange algorithms', `ssh2-enum-algos lists e.g. ${(sshBlock.match(WEAK_KEX) || [''])[0]}`, 'Disable SHA-1 / group1 / group14-sha1 kex in sshd_config (KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256 only).', 'CWE-327');
    if (WEAK_CIPHER.test(sshBlock)) push(out, host, 'medium', 'ssh-cipher', 'SSH offers weak/CBC ciphers', `encryption_algorithms include ${(sshBlock.match(WEAK_CIPHER) || [''])[0].trim()}`, 'Restrict Ciphers to AEAD only (chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com); remove *-cbc/arcfour/3des.', 'CWE-327');
    if (WEAK_MAC.test(sshBlock)) push(out, host, 'low', 'ssh-mac', 'SSH offers weak MAC algorithms', `mac_algorithms include ${(sshBlock.match(WEAK_MAC) || [''])[0]}`, 'Restrict MACs to ETM SHA-2 (hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com); drop MD5/SHA1-96/umac-64.', 'CWE-327');
    if (WEAK_HOSTKEY.test(sshBlock)) push(out, host, 'low', 'ssh-hostkey', 'SSH advertises a deprecated host-key type (ssh-rsa/ssh-dss)', `${(sshBlock.match(WEAK_HOSTKEY) || [''])[0]} present`, 'Prefer ed25519/rsa-sha2 host keys; disable ssh-dss and SHA-1 ssh-rsa (HostKeyAlgorithms).', 'CWE-327');
  }
  if (/ssh-auth-methods[\s\S]*?password/i.test(seg)) push(out, host, 'low', 'ssh-passauth', 'SSH allows password authentication', 'ssh-auth-methods lists "password"', 'Prefer key-only auth: set PasswordAuthentication no, ChallengeResponseAuthentication no; require MFA for any interactive login.', 'CWE-287');
  const sshVer = seg.match(/22\/tcp\s+open\s+ssh\s+(OpenSSH\s+[\d.]+\w*)/i);
  if (sshVer) {
    const v = sshVer[1];
    const mver = v.match(/OpenSSH\s+(\d+)\.(\d+)/i);
    const old = mver && (parseInt(mver[1], 10) < 8 || (parseInt(mver[1], 10) === 8 && parseInt(mver[2], 10) < 1));
    push(out, host, old ? 'low' : 'info', 'ssh-version', `SSH service: ${v}${old ? ' (outdated — has known CVEs)' : ''}`, `22/tcp ${v}`, old ? 'Upgrade OpenSSH to a current release; old versions carry user-enum/DoS/crypto CVEs.' : 'Keep OpenSSH patched to the latest release.', null);
  }

  // ---- FTP (21) ----
  if (/ftp-anon:.*Anonymous FTP login allowed|Anonymous FTP login allowed/i.test(seg)) push(out, host, 'high', 'ftp-anon', 'FTP allows anonymous login', 'nmap ftp-anon: Anonymous FTP login allowed', 'Disable anonymous FTP; require authenticated accounts. If file transfer is needed, use SFTP/FTPS with per-user accounts.', 'CWE-287');
  if (/21\/tcp\s+open\s+ftp\b/i.test(seg)) push(out, host, 'low', 'ftp-cleartext', 'FTP is exposed (cleartext protocol)', `${(seg.match(/21\/tcp\s+open\s+ftp\s+([^\n]*)/i) || [, ''])[1].trim()}`.trim() || '21/tcp open ftp', 'FTP transmits credentials and data in cleartext — migrate to SFTP (SSH) or FTPS (explicit TLS) and restrict to a VPN.', 'CWE-319');

  // ---- SMB (139/445) ----
  if (/smb-protocols[\s\S]*?(SMBv1|NT LM 0\.12|dialects:[\s\S]*?\bSMBv1\b)/i.test(seg)) push(out, host, 'high', 'smb-v1', 'SMBv1 is enabled', 'smb-protocols reports the SMBv1 dialect is supported', 'Disable SMBv1 entirely (it is unauthenticated-RCE prone — EternalBlue/WannaCry). Require SMBv2/3 only.', 'CWE-477');
  const sign = seg.match(/(message[_ ]signing[^\n]*)/i);
  if (sign && /disabled|not required|enabled but not required/i.test(sign[1])) push(out, host, 'medium', 'smb-signing', 'SMB message signing is not required', sign[1].trim(), 'Enforce SMB signing (RequireSecuritySignature=1) to prevent NTLM relay / MITM attacks.', 'CWE-347');
  if (/smb-enum-shares[\s\S]*?(Anonymous|access:\s*READ|<none>\s*\n[\s\S]*?ANONYMOUS)/i.test(seg) || /Anonymous access:\s*(READ|READ\/WRITE)/i.test(seg)) push(out, host, 'high', 'smb-anon', 'SMB shares are accessible over a null/anonymous session', 'smb-enum-shares lists shares readable without authentication', 'Disable anonymous/null sessions (RestrictAnonymous=2, RestrictNullSessAccess=1); require authentication for every share.', 'CWE-306');

  // ---- RDP (3389) ----
  if (/rdp-enum-encryption[\s\S]*?(Security layer[\s\S]*?RDP\b)/i.test(seg) && !/CredSSP|NLA/i.test((seg.match(/rdp-enum-encryption[\s\S]*?(?=\n\d+\/tcp|SVCAUDIT-END|\n\|_)/i) || [''])[0])) push(out, host, 'medium', 'rdp-nla', 'RDP does not require Network Level Authentication (NLA)', 'rdp-enum-encryption shows the legacy "RDP" security layer without CredSSP/NLA', 'Require NLA (CredSSP) on RDP; it forces authentication before a session is created and blocks pre-auth attacks.', 'CWE-287');
  if (/rdp-enum-encryption[\s\S]*?RDP Encryption level:\s*(Low|Client Compatible|None)/i.test(seg)) push(out, host, 'medium', 'rdp-enc', 'RDP uses a weak encryption level', (seg.match(/RDP Encryption level:\s*[^\n]+/i) || [''])[0].trim(), 'Set the RDP encryption level to High/FIPS and enable TLS; disable the legacy RDP security layer.', 'CWE-326');
  if (/(rdp-vuln-ms12-020|ms12-020)[\s\S]*?VULNERABLE|CVE-2012-0002[\s\S]*?VULNERABLE/i.test(seg)) push(out, host, 'critical', 'rdp-ms12020', 'RDP is vulnerable to MS12-020 (pre-auth RCE/DoS)', 'nmap rdp-vuln-ms12-020: VULNERABLE', 'Patch MS12-020 immediately and require NLA; restrict RDP to a VPN.', 'CVE-2012-0002');
  if (/smb-vuln-ms17-010[\s\S]*?VULNERABLE|ms17-010[\s\S]*?VULNERABLE/i.test(seg)) push(out, host, 'critical', 'smb-ms17010', 'SMB is vulnerable to MS17-010 (EternalBlue, pre-auth RCE)', 'nmap smb-vuln-ms17-010: VULNERABLE', 'Patch MS17-010 immediately, disable SMBv1, and block 445 at the perimeter.', 'CVE-2017-0144');

  return out;
}

export function extractSvcAuditFindings(command, output) {
  if (!/SVCAUDIT-BEGIN/.test(String(output || ''))) return [];
  return dedupCap(parseSvcAuditReport(output), 200);
}

export function renderSvcAudit(output) {
  const finds = parseSvcAuditReport(output);
  if (!finds.length) return '_No SMB/FTP/SSH/RDP services were found exposed, or all were securely configured on the audited checks._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const svc = (s) => (s.match(/svc-(ssh|ftp|smb|rdp)/) || [, s.startsWith('svc-') ? s.slice(4, 7) : 'other'])[1];
  const groups = { ssh: 'SSH', ftp: 'FTP', smb: 'SMB', rdp: 'RDP' };
  const parts = [];
  for (const [key, label] of Object.entries(groups)) {
    const g = finds.filter((f) => svc(f.source) === key);
    if (g.length) parts.push(`**${label}:**\n` + g.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}${f.cve ? ` [${f.cve}]` : ''}\n  ↳ fix: ${f.remediation}`).join('\n'));
  }
  return parts.join('\n\n') || '_Services audited; no issues on the checked controls._';
}
