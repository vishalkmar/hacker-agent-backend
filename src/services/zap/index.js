// OWASP ZAP output parser — the CLI/headless equivalent of Burp Suite's Scanner (Burp itself is GUI-only).
// Turns ZAP's headless scan output into findings: both the JSON report (site[].alerts[], rich: risk, CWE,
// solution) and the zap-baseline.py text summary (WARN-NEW/FAIL-NEW: Name [pluginid] x N). Auto-invoked for
// any zap command via runAndCapture.

const RISK = { '0': 'info', '1': 'low', '2': 'medium', '3': 'high' }; // ZAP riskcode -> severity (no "critical")

export function detectZap(command = '') {
  return /\bzap-baseline(\.py)?\b|\bzap-full-scan(\.py)?\b|\bzap-api-scan(\.py)?\b|\bzap\.sh\b|\bzaproxy\b|\bzap-cli\b/i.test(command);
}

function safeHost(url) {
  try { return url ? new URL(url).hostname : null; } catch { return null; }
}
function stripHtml(s) { return String(s || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(); }
function dedup(arr) {
  const seen = new Set();
  return arr.filter((f) => (seen.has(f.title) ? false : seen.add(f.title)));
}

export function parseZap(command, output) {
  if (!detectZap(command) || !output) return [];
  const text = String(output);
  const out = [];

  // 1) JSON report — richest. ZAP writes {"site":[{"@name":..,"alerts":[{alert,riskcode,cweid,solution,instances:[{uri,evidence}]}]}]}
  const jsonMatch = text.match(/\{[\s\S]*?"site"[\s\S]*\}\s*$/) || text.match(/\{[\s\S]*"alerts"[\s\S]*\}/);
  if (jsonMatch) {
    try {
      const j = JSON.parse(jsonMatch[0]);
      const sites = Array.isArray(j.site) ? j.site : [j.site].filter(Boolean);
      for (const s of sites) {
        for (const a of s.alerts || []) {
          const sev = RISK[String(a.riskcode)] || 'info';
          const uri = a.instances?.[0]?.uri || s['@name'] || '';
          const cweid = a.cweid && a.cweid !== '-1' && a.cweid !== '0' ? `CWE-${a.cweid}` : null;
          out.push({
            finding_type: 'vuln', severity: sev, source: 'zap',
            title: `${a.alert || a.name}${uri ? ' @ ' + uri : ''}`,
            host: safeHost(uri),
            evidence: (a.instances?.[0]?.evidence || stripHtml(a.desc)).slice(0, 300),
            cwe: cweid,
            remediation: stripHtml(a.solution).slice(0, 300) || null,
          });
        }
      }
      if (out.length) return dedup(out);
    } catch { /* fall through to text parse */ }
  }

  // 2) zap-baseline.py text summary: "WARN-NEW: <name> [<pluginid>] x <count>"  /  "FAIL-NEW: ..."
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const m = /^(WARN|FAIL)(?:-NEW|-INPROG)?:\s+(.+?)\s+\[(\d+)\](?:\s+x\s+(\d+))?/.exec(line);
    if (m) {
      // FAIL = above the fail threshold (treat higher); WARN = alert raised
      out.push({
        finding_type: 'vuln', severity: m[1] === 'FAIL' ? 'high' : 'medium', source: 'zap',
        title: `${m[2]} [${m[3]}]`,
        evidence: line.slice(0, 200),
      });
    }
  }
  return dedup(out);
}
