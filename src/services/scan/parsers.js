// Tolerant parsers that turn scanner text output into structured findings.

const RISKY = {
  ftp: 'low', telnet: 'low', 'ms-wbt-server': 'low', rdp: 'low', smb: 'low',
  'netbios-ssn': 'low', 'microsoft-ds': 'low', vnc: 'low', mysql: 'low', 'ms-sql-s': 'low',
  postgresql: 'low', redis: 'low', mongodb: 'low', memcached: 'low', rpcbind: 'low',
};

function portSeverity(service = '') {
  const s = service.toLowerCase();
  return RISKY[s] || 'info';
}

// nmap normal output: lines like "80/tcp open http Apache httpd 2.4.49"
// plus host context from "Nmap scan report for example.com (1.2.3.4)".
export function parseNmap(text, source = 'nmap') {
  const findings = [];
  let host = null;
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    const hostM = /^Nmap scan report for\s+(.+)$/i.exec(line);
    if (hostM) {
      host = hostM[1].replace(/[()]/g, '').trim();
      continue;
    }
    const m = /^(\d{1,5})\/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$/i.exec(line);
    if (m) {
      const port = parseInt(m[1], 10);
      const protocol = m[2].toLowerCase();
      const service = m[4];
      const version = (m[5] || '').trim();
      findings.push({
        finding_type: 'open_port',
        severity: portSeverity(service),
        title: `${port}/${protocol} open${service ? ' — ' + service : ''}${version ? ' (' + version + ')' : ''}`,
        host,
        port,
        protocol,
        service,
        version: version || null,
        evidence: line,
        source,
      });
    }
  }
  return findings;
}

// One host/domain per line (subfinder, assetfinder, amass -passive).
export function parseSubdomains(text, source = 'subfinder') {
  const findings = [];
  const seen = new Set();
  for (const raw of String(text).split('\n')) {
    const d = raw.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$/i.test(d) && !seen.has(d)) {
      seen.add(d);
      findings.push({
        finding_type: 'subdomain',
        severity: 'info',
        title: `Subdomain: ${d}`,
        host: d,
        evidence: d,
        source,
      });
    }
  }
  return findings;
}

// httpx default: lines containing URLs (often with [status] [title]).
export function parseHttpx(text, source = 'httpx') {
  const findings = [];
  const seen = new Set();
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    const m = /(https?:\/\/[^\s\]]+)/i.exec(line);
    if (m && !seen.has(m[1])) {
      seen.add(m[1]);
      let host = '';
      try {
        host = new URL(m[1]).hostname;
      } catch {
        /* ignore */
      }
      findings.push({
        finding_type: 'live_host',
        severity: 'info',
        title: `Live: ${m[1]}`,
        host,
        evidence: line,
        source,
      });
    }
  }
  return findings;
}

// Identify the scanner from the command so we pick the right parser.
export function detectScanner(command = '') {
  const c = command.toLowerCase();
  if (/\bnmap\b/.test(c)) return 'nmap';
  if (/\bmasscan\b/.test(c)) return 'nmap'; // masscan -oG-ish lines differ; nmap parser catches some
  if (/\b(subfinder|assetfinder|amass|sublist3r|findomain)\b/.test(c)) return 'subdomains';
  if (/\bhttpx\b/.test(c)) return 'httpx';
  return null;
}

// Main entry: given a command and its output, return structured findings.
export function extractFindings(command, output) {
  const kind = detectScanner(command);
  if (!kind || !output) return [];
  if (kind === 'nmap') return parseNmap(output, /masscan/i.test(command) ? 'masscan' : 'nmap');
  if (kind === 'subdomains') {
    const src = (/(subfinder|assetfinder|amass|sublist3r|findomain)/i.exec(command) || [])[1] || 'subfinder';
    return parseSubdomains(output, src.toLowerCase());
  }
  if (kind === 'httpx') return parseHttpx(output);
  return [];
}
