// Parsers for web vulnerability scanners -> structured findings.
import { extractCVEs, severityToScore } from './cvss.js';

const SEV_WORDS = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

// nuclei: default `[template-id] [protocol] [severity] matched-url [extra]`
// also supports -jsonl (one JSON object per line).
export function parseNuclei(text, source = 'nuclei') {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line) continue;

    // JSONL mode
    if (line.startsWith('{')) {
      try {
        const j = JSON.parse(line);
        const info = j.info || {};
        const sev = (info.severity || 'info').toLowerCase();
        const url = j['matched-at'] || j.host || j.matched || '';
        const cve = (info.classification?.['cve-id'] || []).join(', ') || extractCVEs(JSON.stringify(j)).join(', ');
        out.push({
          finding_type: 'vuln',
          severity: SEV_WORDS.includes(sev) ? sev : 'info',
          title: `${info.name || j['template-id'] || 'nuclei'}${url ? ' @ ' + url : ''}`,
          host: safeHost(url),
          evidence: line.slice(0, 800),
          cve: cve || null,
          remediation: info.remediation || null,
          source,
        });
      } catch {
        /* ignore bad json line */
      }
      continue;
    }

    // text mode: [template] [proto] [severity] url
    const m = /\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[(critical|high|medium|low|info|unknown)\]\s*(\S+)?/i.exec(line);
    if (m) {
      const sev = m[3].toLowerCase();
      const url = m[4] || '';
      out.push({
        finding_type: 'vuln',
        severity: sev === 'unknown' ? 'info' : sev,
        title: `${m[1]}${url ? ' @ ' + url : ''}`,
        host: safeHost(url),
        evidence: line.slice(0, 500),
        cve: extractCVEs(m[1]).join(', ') || null,
        source,
      });
    }
  }
  return dedupeByTitle(out);
}

// sqlmap: look for injectable parameter / DBMS confirmations.
export function parseSqlmap(text, source = 'sqlmap') {
  const out = [];
  const t = String(text);
  // "Parameter: id (GET)" ... "Type: ... Title: ..."
  const paramRe = /Parameter:\s*([^\s(]+)\s*\(([^)]+)\)/gi;
  let m;
  while ((m = paramRe.exec(t)) !== null) {
    out.push({
      finding_type: 'sqli',
      severity: 'high',
      title: `SQL injection in parameter "${m[1]}" (${m[2]})`,
      evidence: t.slice(Math.max(0, m.index - 20), m.index + 220).replace(/\s+/g, ' ').trim(),
      remediation: 'Use parameterized queries / prepared statements; validate & escape input.',
      source,
    });
  }
  const dbms = /back-end DBMS:\s*([^\n]+)/i.exec(t);
  if (dbms && out.length) out.forEach((f) => (f.version = dbms[1].trim()));
  if (!out.length && /is vulnerable|might be injectable|injectable/i.test(t)) {
    out.push({
      finding_type: 'sqli',
      severity: 'high',
      title: 'Possible SQL injection (sqlmap)',
      evidence: t.slice(0, 300),
      source,
    });
  }
  return out;
}

// nikto: lines starting with "+ " are findings.
export function parseNikto(text, source = 'nikto') {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line.startsWith('+ ')) continue;
    const body = line.slice(2).trim();
    if (/^(Target|Start Time|End Time|Server:|SSL Info|host\(s\) tested)/i.test(body)) continue;
    const osvdb = /OSVDB-\d+/i.exec(body)?.[0];
    out.push({
      finding_type: 'misconfiguration',
      severity: /xss|sql|rce|traversal|disclosure|injection/i.test(body) ? 'medium' : 'low',
      title: body.slice(0, 160),
      evidence: body.slice(0, 500),
      cve: extractCVEs(body).join(', ') || null,
      source: osvdb ? `${source} (${osvdb})` : source,
    });
  }
  return dedupeByTitle(out);
}

// dalfox: [POC]/[VULN]/[G] lines indicate XSS.
export function parseDalfox(text, source = 'dalfox') {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (/\[(POC|VULN|G)\]/i.test(line)) {
      const url = /(https?:\/\/\S+)/i.exec(line)?.[1] || '';
      out.push({
        finding_type: 'xss',
        severity: 'high',
        title: `XSS${url ? ' @ ' + url : ''}`,
        host: safeHost(url),
        evidence: line.slice(0, 500),
        remediation: 'Context-aware output encoding; CSP; sanitize untrusted input.',
        source,
      });
    }
  }
  return dedupeByTitle(out);
}

export function detectWebScanner(command = '') {
  const c = command.toLowerCase();
  if (/\bnuclei\b/.test(c)) return 'nuclei';
  if (/\bsqlmap\b/.test(c)) return 'sqlmap';
  if (/\bnikto\b/.test(c)) return 'nikto';
  if (/\bdalfox\b/.test(c)) return 'dalfox';
  return null;
}

export function extractWebFindings(command, output) {
  const kind = detectWebScanner(command);
  if (!kind || !output) return [];
  const f =
    kind === 'nuclei' ? parseNuclei(output)
    : kind === 'sqlmap' ? parseSqlmap(output)
    : kind === 'nikto' ? parseNikto(output)
    : kind === 'dalfox' ? parseDalfox(output)
    : [];
  // baseline cvss from severity if not set
  for (const x of f) if (x.cvss_score == null) x.cvss_score = severityToScore(x.severity);
  return f;
}

function safeHost(url) {
  try {
    return url ? new URL(url).hostname : null;
  } catch {
    return null;
  }
}
function dedupeByTitle(arr) {
  const seen = new Set();
  return arr.filter((f) => {
    const k = f.finding_type + '|' + f.title;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
