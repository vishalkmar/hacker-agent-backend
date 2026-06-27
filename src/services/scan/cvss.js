// CVSS helpers: severity<->baseline score, CVSS v3.1 base-score from a vector, CVE extraction.

const SEV_TO_SCORE = { critical: 9.5, high: 8.0, medium: 5.5, low: 3.0, info: 0.0, none: 0.0 };

export function severityToScore(sev) {
  return SEV_TO_SCORE[(sev || 'info').toLowerCase()] ?? 0;
}

export function scoreToSeverity(score) {
  const s = Number(score) || 0;
  if (s >= 9.0) return 'critical';
  if (s >= 7.0) return 'high';
  if (s >= 4.0) return 'medium';
  if (s > 0) return 'low';
  return 'info';
}

export function extractCVEs(text) {
  const m = String(text || '').match(/CVE-\d{4}-\d{4,7}/gi) || [];
  return [...new Set(m.map((x) => x.toUpperCase()))];
}

// Round up to one decimal place per the CVSS v3.1 spec.
function roundUp1(x) {
  return Math.ceil(x * 10) / 10;
}

// Compute a CVSS v3.1 base score from a vector string like
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". Returns { score, severity } or null.
export function cvssFromVector(vector) {
  if (!vector || !/AV:/.test(vector)) return null;
  const p = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (k && v) p[k.trim().toUpperCase()] = v.trim().toUpperCase();
  }
  const scopeChanged = p.S === 'C';
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[p.AV];
  const AC = { L: 0.77, H: 0.44 }[p.AC];
  const PR = (scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 })[p.PR];
  const UI = { N: 0.85, R: 0.62 }[p.UI];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const C = cia[p.C];
  const I = cia[p.I];
  const A = cia[p.A];
  if ([AV, AC, PR, UI, C, I, A].some((x) => x === undefined)) return null;

  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const exploitability = 8.22 * AV * AC * PR * UI;

  let score;
  if (impact <= 0) score = 0;
  else
    score = roundUp1(
      Math.min(scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability, 10)
    );

  return { score, severity: scoreToSeverity(score), vector };
}

// Best-effort: enrich a finding with cvss_score/cvss_vector/cve from its evidence/title.
export function enrichCvss(finding) {
  const blob = `${finding.title || ''} ${finding.evidence || ''} ${finding.cvss_vector || ''}`;
  const vec = /CVSS:3\.[01]\/[A-Z:/]+/i.exec(blob)?.[0];
  if (vec) {
    const c = cvssFromVector(vec);
    if (c) {
      finding.cvss_vector = c.vector;
      finding.cvss_score = c.score;
      finding.severity = c.severity;
    }
  }
  if (!finding.cvss_score) finding.cvss_score = severityToScore(finding.severity);
  const cves = extractCVEs(blob);
  if (cves.length && !finding.cve) finding.cve = cves.join(', ');
  return finding;
}
