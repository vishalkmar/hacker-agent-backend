// PHASE 7 — Firewall & network segmentation review.
//
// Powers the ```firewall agent tag. Maps a target's externally-reachable attack surface and reviews it
// for segmentation weaknesses: which ports answer from the public internet, and whether any of them are
// internal-tier services (SSH/RDP/SMB, databases, container/orchestration control-planes) that should be
// firewalled off or placed behind a VPN/bastion instead of being flat-exposed.
//
// The shell just runs the tools (nmap service scan on a curated risky-port set + optional ACK scan for
// stateful-firewall detection + wafw00f) between NETSCAN-BEGIN/END sentinels; ALL classification lives in
// the JS parser (parseFirewallReport) — so a port→risk decision is unit-testable against captured nmap
// output. Emits findings with finding_type 'network'. Actively scans a remote target -> AUTHORIZATION-GATED.

import { normSev, dedupCap } from '../appsec/engine.js';

function hostOf(t) { return String(t || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/[^\w.\-]/g, '').toLowerCase(); }

// Curated high-signal port set (fast scan). Web + every "should-be-internal" service worth reviewing.
const SCAN_PORTS = '21,22,23,25,53,110,111,135,139,143,161,389,443,445,465,587,993,995,1433,1521,2049,2375,2376,2379,3000,3306,3389,4444,5432,5601,5900,5984,6379,6443,8000,8080,8443,8888,9042,9092,9200,9300,10250,11211,15672,27017';

// Port → {svc, cat, sev, fix}. cat drives the segmentation meta-finding. Ports not listed => treated as
// generic "open port" (info). Web ports are info (expected public); everything else is a review item.
const PORT_RISK = {
  21: { svc: 'FTP', cat: 'remote', sev: 'medium', fix: 'FTP is cleartext — replace with SFTP/FTPS and restrict to a VPN; disable anonymous access.' },
  22: { svc: 'SSH', cat: 'remote', sev: 'medium', fix: 'Restrict SSH to a VPN/bastion and specific source IPs; enforce key-only auth + MFA; never expose 22 to 0.0.0.0/0.' },
  23: { svc: 'Telnet', cat: 'remote', sev: 'high', fix: 'Telnet is unencrypted — disable it entirely and use SSH.' },
  25: { svc: 'SMTP', cat: 'mail', sev: 'info', fix: 'Ensure the MTA is not an open relay; expose only if this is a mail server.' },
  110: { svc: 'POP3', cat: 'mail', sev: 'low', fix: 'Prefer POP3S/IMAPS; restrict to mail infrastructure.' },
  135: { svc: 'MSRPC', cat: 'admin', sev: 'high', fix: 'Windows RPC must never face the internet — block 135 at the edge firewall.' },
  139: { svc: 'NetBIOS', cat: 'admin', sev: 'high', fix: 'Block NetBIOS (139) at the perimeter; it should only exist on the internal LAN.' },
  143: { svc: 'IMAP', cat: 'mail', sev: 'low', fix: 'Prefer IMAPS (993); restrict to mail infrastructure.' },
  161: { svc: 'SNMP', cat: 'mgmt', sev: 'medium', fix: 'SNMP often uses default community strings (public/private) — block it externally, use SNMPv3.' },
  389: { svc: 'LDAP', cat: 'admin', sev: 'high', fix: 'Directory services must be internal-only — block 389/636 at the edge.' },
  445: { svc: 'SMB', cat: 'admin', sev: 'high', fix: 'SMB (445) must NEVER be internet-facing (EternalBlue/ransomware vector) — block at the firewall.' },
  1433: { svc: 'MSSQL', cat: 'db', sev: 'high', fix: 'Databases must be segmented to a private subnet — block 1433 externally, allow only app tier.' },
  1521: { svc: 'Oracle DB', cat: 'db', sev: 'high', fix: 'Block Oracle TNS (1521) externally; place the DB in a private subnet.' },
  2049: { svc: 'NFS', cat: 'db', sev: 'high', fix: 'NFS exports must be internal-only — block 2049 at the perimeter.' },
  2375: { svc: 'Docker API', cat: 'mgmt', sev: 'critical', fix: 'Unauthenticated Docker daemon = full host RCE. Never expose 2375; use TLS+client certs on 2376 and firewall it.' },
  2376: { svc: 'Docker API (TLS)', cat: 'mgmt', sev: 'high', fix: 'Restrict the Docker TLS socket to trusted management IPs only.' },
  2379: { svc: 'etcd', cat: 'mgmt', sev: 'critical', fix: 'etcd holds cluster secrets — must be internal + client-cert auth; block 2379 externally.' },
  3000: { svc: 'Grafana/Node app', cat: 'admin', sev: 'medium', fix: 'Put the dashboard/app behind auth + an IP allow-list; do not expose the raw port.' },
  3306: { svc: 'MySQL', cat: 'db', sev: 'high', fix: 'Databases must be segmented — block 3306 externally, allow only the app subnet.' },
  3389: { svc: 'RDP', cat: 'remote', sev: 'high', fix: 'RDP (3389) is a top ransomware entry point — put it behind a VPN + MFA; never expose to the internet.' },
  4444: { svc: 'metasploit/backdoor?', cat: 'mgmt', sev: 'high', fix: 'Port 4444 open is suspicious (common Meterpreter/backdoor) — investigate for compromise.' },
  5432: { svc: 'PostgreSQL', cat: 'db', sev: 'high', fix: 'Block 5432 externally; keep PostgreSQL in a private subnet reachable only by the app tier.' },
  5601: { svc: 'Kibana', cat: 'admin', sev: 'high', fix: 'Kibana exposes all log data — require auth and restrict to a VPN/allow-list.' },
  5900: { svc: 'VNC', cat: 'remote', sev: 'high', fix: 'VNC is weakly authenticated — never expose 5900; tunnel over SSH/VPN.' },
  5984: { svc: 'CouchDB', cat: 'db', sev: 'high', fix: 'Block CouchDB (5984) externally; require auth and segment it.' },
  6379: { svc: 'Redis', cat: 'db', sev: 'high', fix: 'Redis has no auth by default — bind to localhost/VPN, require a password, block 6379 at the firewall.' },
  6443: { svc: 'Kubernetes API', cat: 'mgmt', sev: 'high', fix: 'Restrict the kube-apiserver to trusted networks; enforce RBAC + client-cert/OIDC auth.' },
  9042: { svc: 'Cassandra', cat: 'db', sev: 'high', fix: 'Segment Cassandra (9042) to a private subnet; enable auth.' },
  9092: { svc: 'Kafka', cat: 'db', sev: 'high', fix: 'Block Kafka (9092) externally; enable SASL/TLS; keep on a private network.' },
  9200: { svc: 'Elasticsearch', cat: 'db', sev: 'high', fix: 'Elasticsearch (9200) is unauthenticated by default — block externally, enable security, segment it.' },
  9300: { svc: 'Elasticsearch transport', cat: 'db', sev: 'high', fix: 'Block the ES transport port (9300) externally; internal cluster traffic only.' },
  10250: { svc: 'Kubelet', cat: 'mgmt', sev: 'critical', fix: 'The kubelet API (10250) can expose pods/exec — block externally, enable auth/authz.' },
  11211: { svc: 'Memcached', cat: 'db', sev: 'high', fix: 'Memcached (11211) has no auth and enables UDP amplification — bind to localhost, block externally.' },
  15672: { svc: 'RabbitMQ mgmt', cat: 'admin', sev: 'medium', fix: 'Restrict the RabbitMQ management UI to a VPN/allow-list; change default guest creds.' },
  27017: { svc: 'MongoDB', cat: 'db', sev: 'high', fix: 'Block MongoDB (27017) externally; enable auth; keep it in a private subnet.' },
  // expected-public web ports (attack-surface inventory, not a defect on their own)
  80: { svc: 'HTTP', cat: 'web', sev: 'info', fix: 'Expected public web port; ensure it redirects to HTTPS.' },
  443: { svc: 'HTTPS', cat: 'web', sev: 'info', fix: 'Expected public web port.' },
  8080: { svc: 'HTTP-alt', cat: 'web', sev: 'low', fix: 'Alt HTTP port — confirm it is meant to be public and not an exposed admin/app backend.' },
  8443: { svc: 'HTTPS-alt', cat: 'web', sev: 'low', fix: 'Alt HTTPS port — confirm it is meant to be public.' },
  8000: { svc: 'HTTP-dev', cat: 'web', sev: 'low', fix: 'Port 8000 is often a dev/app server — confirm it should be internet-facing.' },
  8888: { svc: 'HTTP-alt/Jupyter?', cat: 'web', sev: 'low', fix: 'Port 8888 often hosts Jupyter/dev tools — confirm exposure is intended and authenticated.' },
};

const CAT_LABEL = { db: 'database', mgmt: 'control-plane', admin: 'admin/management', remote: 'remote-access', mail: 'mail', web: 'web' };

export function buildFirewallScan(target, { deep = false } = {}) {
  const host = hostOf(target);
  const ports = deep ? '-p-' : `-p ${SCAN_PORTS}`;
  const lines = [
    `HOST="${host}";`,
    `echo "== firewall / network segmentation review: $HOST${deep ? ' (deep / all-ports)' : ''} =="`,
    `echo "NETSCAN-BEGIN $HOST";`,
    `command -v nmap >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; apt-get install -y nmap >/dev/null 2>&1; };`,
    // Main service/version scan with --reason so we can tell open vs filtered (=firewall) vs closed.
    `nmap -Pn -T4 --reason -sV --version-light ${ports} "$HOST" 2>/dev/null;`,
    // ACK scan on a few key ports to detect a stateful firewall (filtered = firewalled, unfiltered = none).
    `echo "--- ACK (firewall state) ---";`,
    `nmap -Pn -T4 -sA -p 22,80,443,3389,3306 "$HOST" 2>/dev/null | grep -E '^[0-9]+/tcp|filtered|unfiltered' || true;`,
  ];
  if (deep) {
    lines.push(
      `echo "--- top-UDP (SNMP/DNS/NTP amplification exposure) ---";`,
      `nmap -Pn -sU -T4 --top-ports 20 "$HOST" 2>/dev/null | grep -E '^[0-9]+/udp' || true;`,
    );
  }
  lines.push(
    `echo "--- WAF detection ---";`,
    `command -v wafw00f >/dev/null 2>&1 || pip install wafw00f >/dev/null 2>&1 || true;`,
    `command -v wafw00f >/dev/null 2>&1 && wafw00f "https://$HOST" 2>/dev/null | grep -iE 'is behind|seems to be behind|No WAF|generic detection' || echo "wafw00f unavailable";`,
    `echo "NETSCAN-END";`,
  );
  return lines.join('\n');
}

export function buildFirewallCommand(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;
  if (/^(nmap|masscan|wafw00f|hping3|nping)\b/i.test(raw)) return raw; // raw tool passthrough
  const tokens = raw.split(/\s+/);
  const deep = tokens.some((t) => /^(deep|full|all[-_]?ports)$/i.test(t));
  const target = tokens.find((t) => !/^(deep|full|all[-_]?ports)$/i.test(t));
  if (!target) return null;
  return buildFirewallScan(target, { deep });
}

// ---- classification lives here (unit-testable against captured nmap output) ----
export function parseFirewallReport(output) {
  const text = String(output || '');
  if (!/NETSCAN-BEGIN/.test(text)) return [];
  const seg = text.slice(text.indexOf('NETSCAN-BEGIN'));
  const host = (seg.match(/NETSCAN-BEGIN\s+(\S+)/) || [])[1] || null;
  const findings = [];
  const openRisky = []; // {port, svc, cat}
  let filteredCount = 0, openCount = 0;

  // Port lines: "22/tcp open ssh OpenSSH 6.6" / "3306/tcp filtered mysql" / "80/tcp open|filtered http"
  const portRe = /^(\d+)\/tcp\s+(open|filtered|closed|open\|filtered)\s+(\S+)?(.*)$/gim;
  let m;
  const seenOpen = new Set();
  while ((m = portRe.exec(seg)) !== null) {
    const port = parseInt(m[1], 10);
    const state = m[2].toLowerCase();
    const svcName = (m[3] || '').trim();
    const version = (m[4] || '').trim();
    if (state === 'filtered') { filteredCount++; continue; }
    if (state !== 'open') continue;
    if (seenOpen.has(port)) continue;
    seenOpen.add(port);
    openCount++;
    const info = PORT_RISK[port];
    const label = info ? info.svc : (svcName || 'unknown');
    const evidence = `${port}/tcp open ${svcName}${version ? ' ' + version.trim() : ''}`.trim();
    if (info && info.cat !== 'web') {
      openRisky.push({ port, svc: info.svc, cat: info.cat });
      findings.push({
        finding_type: 'network', severity: normSev(info.sev), title: `${info.svc} exposed to the internet on ${port}/tcp`,
        host, port, evidence, cve: null, remediation: info.fix, source: `fw-port-${port}`,
      });
    } else if (info && info.cat === 'web') {
      findings.push({
        finding_type: 'network', severity: normSev(info.sev), title: `Public ${info.svc} service on ${port}/tcp`,
        host, port, evidence, cve: null, remediation: info.fix, source: `fw-web-${port}`,
      });
    } else {
      findings.push({
        finding_type: 'network', severity: 'info', title: `Open port ${port}/tcp (${label}) reachable from the internet`,
        host, port, evidence, cve: null, remediation: 'Confirm this port is intended to be public; if it is an internal service, block it at the edge firewall.', source: `fw-port-${port}`,
      });
    }
  }

  // Segmentation meta-finding: any internal-tier service reachable externally = flat/weak segmentation.
  const internal = openRisky.filter((p) => p.cat === 'db' || p.cat === 'mgmt');
  if (internal.length) {
    const list = internal.map((p) => `${p.svc}:${p.port}`).join(', ');
    findings.push({
      finding_type: 'network', severity: internal.some((p) => p.cat === 'mgmt') ? 'critical' : 'high',
      title: `Network segmentation weakness: ${internal.length} internal-tier service(s) reachable from the internet`,
      host, port: null, evidence: `Externally reachable ${internal.map((p) => CAT_LABEL[p.cat]).join('/')} services: ${list}`,
      cve: 'CWE-668', remediation: 'These belong on a private subnet/VLAN. Move databases and control-plane services behind the app tier, allow ingress only from specific security groups, and expose nothing but the web/load-balancer tier to 0.0.0.0/0.',
      source: 'fw-segmentation',
    });
  }

  // Firewall presence: filtered ports (or the nmap "all ... filtered" line) => stateful filtering present.
  const allFiltered = /All \d+ scanned ports on .* are (filtered|in ignored)/i.test(seg) || /\d+ filtered tcp ports/i.test(seg);
  const ackUnfiltered = /\bunfiltered\b/i.test(seg);
  if (filteredCount > 0 || allFiltered) {
    findings.push({
      finding_type: 'network', severity: 'info', title: 'Perimeter firewall / packet filtering detected',
      host, port: null, evidence: allFiltered ? 'nmap: scanned ports reported filtered' : `${filteredCount} port(s) in filtered state`,
      cve: null, remediation: 'Good — a stateful firewall is dropping traffic. Verify the allow-list is least-privilege and default-deny.', source: 'fw-present',
    });
  } else if (openCount > 0 && ackUnfiltered) {
    findings.push({
      finding_type: 'network', severity: 'low', title: 'No perimeter packet filtering detected (ACK scan unfiltered)',
      host, port: null, evidence: 'nmap -sA reported unfiltered — the host appears directly exposed with no stateful firewall',
      cve: 'CWE-693', remediation: 'Place the host behind a stateful firewall / security group with a default-deny inbound policy; expose only required ports.', source: 'fw-absent',
    });
  }

  // WAF result (web tier).
  const wafHit = seg.match(/is behind (?:a |the )?([A-Za-z0-9 .\-()]+?)(?: WAF| \(| firewall|\.|\n)/i) || seg.match(/seems to be behind (?:a |the )?([A-Za-z0-9 .\-()]+)/i);
  if (wafHit) {
    findings.push({
      finding_type: 'network', severity: 'info', title: `Web Application Firewall present: ${wafHit[1].trim()}`,
      host, port: null, evidence: wafHit[0].trim().slice(0, 160), cve: null,
      remediation: 'Good — a WAF is fronting the web tier. Ensure the origin only accepts traffic from the WAF/CDN IP ranges so it cannot be bypassed directly.', source: 'fw-waf',
    });
  } else if (/No WAF detected/i.test(seg)) {
    findings.push({
      finding_type: 'network', severity: 'low', title: 'No Web Application Firewall detected on the web tier',
      host, port: null, evidence: 'wafw00f: No WAF detected', cve: null,
      remediation: 'Consider fronting the web app with a WAF/CDN (Cloudflare, AWS WAF, ModSecurity) to filter common web attacks.', source: 'fw-nowaf',
    });
  }

  return findings;
}

export function extractFirewallFindings(command, output) {
  if (!/NETSCAN-BEGIN/.test(String(output || ''))) return [];
  return dedupCap(parseFirewallReport(output), 200);
}

export function renderFirewall(output) {
  const finds = parseFirewallReport(output);
  if (!finds.length) return '_No open ports found on the scanned set — the host appears fully firewalled (or is not responding)._';
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  finds.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  const risks = finds.filter((f) => /^(critical|high|medium)$/.test(f.severity));
  const posture = finds.filter((f) => /^fw-(present|waf)$/.test(f.source));
  const surface = finds.filter((f) => !risks.includes(f) && !posture.includes(f));
  const parts = [];
  if (risks.length) parts.push('**🚨 Segmentation / exposure risks:**\n' + risks.map((f) => `- **${f.severity.toUpperCase()}** ${f.title}\n  ↳ ${f.evidence}\n  ↳ fix: ${f.remediation}`).join('\n'));
  if (surface.length) parts.push('**🌐 Exposed attack surface:**\n' + surface.map((f) => `- ${f.title} — ${f.evidence}`).join('\n'));
  if (posture.length) parts.push('**🛡️ Defensive posture:**\n' + posture.map((f) => `- ${f.title}`).join('\n'));
  return parts.join('\n\n');
}
