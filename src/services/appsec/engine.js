// AppSec / DevSecOps engine — shared plumbing for the code-security tool suite.
//
// Powers the ```sast / ```secrets / ```gitsecrets / ```sca / ```depcve / ```iac / ```container /
// ```config / ```license / ```supplychain / ```codereview / ```remediation / ```fixverify /
// ```cicd agent tools. Everything here is provider/host agnostic: the build functions emit a
// single self-installing bash command (apt → pipx/pip → go → curl binary) so a scan works on the
// lean Kali image, and the parsers turn each scanner's JSON into the platform's canonical finding
// shape ({ title, finding_type, severity, host, evidence, source, cve, cvss_score, remediation }).
//
// Design notes:
//  - JSON is always written to a temp file and `cat`-ed, so the captured stdout is clean JSON even
//    though scanners spew progress to stderr (which our runner merges into the observation).
//  - Every generated command is single-statement bash that passes `bash -n`.
//  - Parsers are defensive: unknown/partial JSON never throws, it just yields fewer findings.

// ---- self-install ---------------------------------------------------------------------------
// Ensure `bin` exists on PATH; try apt, then pipx/pip, then `go install`, then a raw curl binary.
// All install chatter is silenced so it never pollutes the JSON we parse.
export function ensure(bin, { apt, pip, go, curl, dest = '/usr/local/bin' } = {}) {
  const steps = [`command -v ${bin} >/dev/null 2>&1 || {`, 'apt-get update -y >/dev/null 2>&1;'];
  if (apt) steps.push(`apt-get install -y ${apt} >/dev/null 2>&1 ||`);
  if (pip) steps.push(`pipx install ${pip} >/dev/null 2>&1 || pip install ${pip} --break-system-packages >/dev/null 2>&1 ||`);
  if (go) steps.push(`(command -v go >/dev/null 2>&1 && go install ${go} >/dev/null 2>&1 && cp "$(go env GOPATH)/bin/${bin}" ${dest}/ 2>/dev/null) ||`);
  if (curl) steps.push(`(curl -sSfL ${curl} -o ${dest}/${bin} && chmod +x ${dest}/${bin}) ||`);
  steps.push('true;');
  steps.push('}; ');
  return steps.join(' ');
}

// Centralised installers (trivy/grype/syft ship an official install.sh; the rest go via apt/pip/go).
// Each is a self-contained `command -v <bin> || { ...install... }` guard that is silent on success.
const guard = (bin, body) => `command -v ${bin} >/dev/null 2>&1 || { apt-get update -y >/dev/null 2>&1; ${body} true; }; `;
export const INSTALL = {
  semgrep: guard('semgrep', 'apt-get install -y semgrep >/dev/null 2>&1 || pip install semgrep --break-system-packages >/dev/null 2>&1 ||'),
  bandit: guard('bandit', 'pip install bandit --break-system-packages >/dev/null 2>&1 ||'),
  gitleaks: guard('gitleaks', 'apt-get install -y gitleaks >/dev/null 2>&1 || (command -v go >/dev/null 2>&1 && go install github.com/gitleaks/gitleaks/v8@latest >/dev/null 2>&1 && cp "$(go env GOPATH)/bin/gitleaks" /usr/local/bin/ 2>/dev/null) ||'),
  trivy: guard('trivy', 'apt-get install -y trivy >/dev/null 2>&1 || curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1 ||'),
  grype: guard('grype', 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1 ||'),
  syft: guard('syft', 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1 ||'),
  osv: guard('osv-scanner', '(command -v go >/dev/null 2>&1 && go install github.com/google/osv-scanner/cmd/osv-scanner@latest >/dev/null 2>&1 && cp "$(go env GOPATH)/bin/osv-scanner" /usr/local/bin/ 2>/dev/null) || pip install osv-scanner --break-system-packages >/dev/null 2>&1 ||'),
  checkov: guard('checkov', 'pip install checkov --break-system-packages >/dev/null 2>&1 ||'),
  dockle: guard('dockle', 'apt-get install -y dockle >/dev/null 2>&1 ||'),
};

// The set of scanner binaries this suite drives — used to decide whether generic finding
// extraction should even look at a command's output (keeps it inert for unrelated commands).
export const SCANNER_BINS = /\b(semgrep|bandit|gitleaks|trivy|grype|syft|osv-scanner|checkov|dockle|npm audit|pip-audit|yarn audit)\b/i;

// ---- severity ------------------------------------------------------------------------------
const SEV_MAP = {
  critical: 'critical', crit: 'critical',
  high: 'high', error: 'high',
  medium: 'medium', moderate: 'medium', warning: 'medium', warn: 'medium',
  low: 'low',
  info: 'info', informational: 'info', note: 'info', unknown: 'info', none: 'info', negligible: 'info',
};
export function normSev(s) {
  return SEV_MAP[String(s || '').trim().toLowerCase()] || 'info';
}
// Map a CVSS base score to a severity bucket (used when a tool gives a score but no label).
export function sevFromCvss(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return null;
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n > 0) return 'low';
  return 'info';
}

// ---- tolerant JSON extraction --------------------------------------------------------------
// Scanner stdout may carry a leading/trailing line or two (a shell prompt, a warning). Find the
// first balanced JSON value and parse it. Returns null on failure — callers degrade gracefully.
export function parseJsonLoose(text) {
  const s = String(text || '');
  const direct = tryParse(s.trim());
  if (direct !== undefined) return direct;
  const start = firstJsonStart(s);
  if (start < 0) return null;
  const open = s[start];
  const close = open === '{' ? '}' : ']';
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) {
        const val = tryParse(s.slice(start, i + 1));
        if (val !== undefined) return val;
      }
    }
  }
  return null;
}
function firstJsonStart(s) {
  const a = s.indexOf('{');
  const b = s.indexOf('[');
  if (a < 0) return b;
  if (b < 0) return a;
  return Math.min(a, b);
}
function tryParse(s) {
  try { return JSON.parse(s); } catch { return undefined; }
}

const clip = (s, n) => String(s ?? '').slice(0, n);
const loc = (file, line) => (file ? `${file}${line ? ':' + line : ''}` : '');

// ---- per-scanner parsers -------------------------------------------------------------------
// Each returns an array of canonical finding objects.

// Semgrep: { results: [ { check_id, path, start.line, extra.message, extra.severity, extra.metadata } ] }
export function parseSemgrep(json) {
  const results = json?.results;
  if (!Array.isArray(results)) return [];
  return results.map((r) => {
    const meta = r.extra?.metadata || {};
    const cwe = [].concat(meta.cwe || []).find(Boolean);
    const owasp = [].concat(meta.owasp || []).find(Boolean);
    const where = loc(r.path, r.start?.line);
    const sev = r.extra?.severity === 'ERROR' ? 'high' : r.extra?.severity === 'WARNING' ? 'medium' : normSev(meta.impact || 'info');
    return {
      finding_type: 'sast',
      severity: sev,
      title: clip(`${r.check_id}${cwe ? ' — ' + cwe : ''}`, 200),
      host: where || null,
      evidence: clip(r.extra?.lines || r.extra?.message, 240),
      remediation: clip(meta.fix || r.extra?.fix || (owasp ? `OWASP: ${owasp}. ${r.extra?.message || ''}` : r.extra?.message), 400),
      source: 'semgrep',
    };
  });
}

// Bandit (python): { results: [ { test_id, filename, line_number, issue_severity, issue_text, issue_cwe } ] }
export function parseBandit(json) {
  const results = json?.results;
  if (!Array.isArray(results)) return [];
  return results.map((r) => ({
    finding_type: 'sast',
    severity: normSev(r.issue_severity),
    title: clip(`${r.test_id} ${r.issue_text}`, 200),
    host: loc(r.filename, r.line_number) || null,
    evidence: clip(r.code, 240),
    cve: r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : null,
    remediation: clip(r.more_info, 300),
    source: 'bandit',
  }));
}

// Gitleaks: [ { Description, File, StartLine, RuleID, Match, Commit, Secret } ]  (array or {findings:[]})
export function parseGitleaks(json, { history = false } = {}) {
  const arr = Array.isArray(json) ? json : json?.findings || [];
  if (!Array.isArray(arr)) return [];
  return arr.map((r) => ({
    finding_type: 'secret',
    severity: 'high',
    title: clip(`Secret: ${r.RuleID || r.Description || 'hardcoded credential'}`, 200),
    host: loc(r.File, r.StartLine) || null,
    evidence: clip(r.Commit ? `commit ${String(r.Commit).slice(0, 8)} — ${r.Match || r.Description}` : r.Match || r.Description, 240),
    cve: 'CWE-798',
    remediation: `Rotate this credential immediately${history ? ' and purge it from git history (git filter-repo / BFG)' : ''}. Move it to a secret manager / env var and add the path to .gitignore.`,
    source: 'gitleaks',
  }));
}

// Trivy: { Results: [ { Target, Class, Type, Vulnerabilities:[], Misconfigurations:[], Secrets:[], Licenses:[] } ] }
export function parseTrivy(json, { only } = {}) {
  const results = json?.Results;
  if (!Array.isArray(results)) return [];
  const out = [];
  for (const res of results) {
    const target = res.Target;
    if ((!only || only === 'vuln') && Array.isArray(res.Vulnerabilities)) {
      for (const v of res.Vulnerabilities) {
        const score = v.CVSS ? (v.CVSS.nvd?.V3Score ?? v.CVSS.redhat?.V3Score ?? Object.values(v.CVSS)[0]?.V3Score) : null;
        out.push({
          finding_type: 'dependency',
          severity: normSev(v.Severity),
          title: clip(`${v.VulnerabilityID} in ${v.PkgName} ${v.InstalledVersion}`, 200),
          host: target || null,
          service: v.PkgName || null,
          version: v.InstalledVersion || null,
          evidence: clip(v.Title || v.Description, 240),
          cve: /^CVE-/i.test(v.VulnerabilityID) ? v.VulnerabilityID : (v.VulnerabilityID || null),
          cvss_score: score ?? null,
          remediation: v.FixedVersion ? `Upgrade ${v.PkgName} to ${v.FixedVersion}.` : clip(v.PrimaryURL, 200),
          source: 'trivy',
        });
      }
    }
    if ((!only || only === 'config') && Array.isArray(res.Misconfigurations)) {
      for (const m of res.Misconfigurations) {
        if (m.Status && m.Status !== 'FAIL') continue;
        out.push({
          finding_type: 'config',
          severity: normSev(m.Severity),
          title: clip(`${m.ID} ${m.Title}`, 200),
          host: loc(target, m.CauseMetadata?.StartLine) || null,
          evidence: clip(m.Message, 240),
          remediation: clip(m.Resolution, 300),
          source: 'trivy',
        });
      }
    }
    if ((!only || only === 'secret') && Array.isArray(res.Secrets)) {
      for (const s of res.Secrets) {
        out.push({
          finding_type: 'secret',
          severity: normSev(s.Severity) === 'info' ? 'high' : normSev(s.Severity),
          title: clip(`Secret: ${s.RuleID || s.Title}`, 200),
          host: loc(target, s.StartLine) || null,
          evidence: clip(s.Match, 200),
          cve: 'CWE-798',
          remediation: 'Rotate and remove this secret; move to a secret manager.',
          source: 'trivy',
        });
      }
    }
    if ((!only || only === 'license') && Array.isArray(res.Licenses)) {
      for (const l of res.Licenses) {
        out.push(licenseFinding(l.Name || l.License, l.PkgName, normSev(l.Severity), 'trivy', target));
      }
    }
  }
  return out;
}

// Grype: { matches: [ { vulnerability:{id,severity,cvss:[{metrics:{baseScore}}],fix:{versions}}, artifact:{name,version} } ] }
export function parseGrype(json) {
  const matches = json?.matches;
  if (!Array.isArray(matches)) return [];
  return matches.map((m) => {
    const v = m.vulnerability || {};
    const art = m.artifact || {};
    const score = [].concat(v.cvss || []).map((c) => c?.metrics?.baseScore).find((n) => Number.isFinite(n));
    return {
      finding_type: 'dependency',
      severity: normSev(v.severity) === 'info' && score ? sevFromCvss(score) : normSev(v.severity),
      title: clip(`${v.id} in ${art.name} ${art.version}`, 200),
      service: art.name || null,
      version: art.version || null,
      evidence: clip(v.description, 240),
      cve: /^CVE-/i.test(v.id) ? v.id : (v.id || null),
      cvss_score: score ?? null,
      remediation: v.fix?.versions?.length ? `Upgrade ${art.name} to ${v.fix.versions.join(' / ')}.` : clip(v.dataSource, 200),
      source: 'grype',
    };
  });
}

// Syft SBOM: { artifacts: [ { name, version, type, licenses:[{value}|string] } ] }
export function parseSyft(json, { mode = 'sbom' } = {}) {
  const arts = json?.artifacts;
  if (!Array.isArray(arts)) return [];
  const out = [];
  for (const a of arts) {
    const lics = [].concat(a.licenses || []).map((l) => (typeof l === 'string' ? l : l?.value || l?.spdxExpression)).filter(Boolean);
    if (mode === 'license') {
      for (const lic of lics.length ? lics : ['UNKNOWN']) {
        const risk = classifyLicense(lic);
        if (risk.severity === 'info' && lic !== 'UNKNOWN') continue; // only surface risky/unknown
        out.push(licenseFinding(lic, `${a.name} ${a.version}`, risk.severity, 'syft', null, risk.note));
      }
    } else {
      out.push({
        finding_type: 'component',
        severity: 'info',
        title: clip(`${a.name} ${a.version}${a.type ? ' (' + a.type + ')' : ''}`, 200),
        service: a.name || null,
        version: a.version || null,
        evidence: lics.length ? `license: ${lics.join(', ')}` : null,
        source: 'syft',
      });
    }
  }
  return out;
}

// OSV-Scanner: { results:[ { source:{path}, packages:[ { package:{name,version,ecosystem}, vulnerabilities:[{id,summary,severity:[{type,score}]}], groups:[{ids,max_severity}] } ] } ] }
export function parseOsv(json, { finding_type = 'dependency' } = {}) {
  const results = json?.results;
  if (!Array.isArray(results)) return [];
  const out = [];
  for (const res of results) {
    const path = res.source?.path;
    for (const pkg of res.packages || []) {
      const p = pkg.package || {};
      const maxSev = pkg.groups?.map((g) => Number(g.max_severity)).filter(Number.isFinite).sort((a, b) => b - a)[0];
      for (const v of pkg.vulnerabilities || []) {
        const score = [].concat(v.severity || []).map((x) => cvssStringToScore(x.score)).find((n) => Number.isFinite(n)) ?? maxSev;
        const aliasCve = [].concat(v.aliases || []).find((a) => /^CVE-/i.test(a)) || (/^CVE-/i.test(v.id) ? v.id : null);
        out.push({
          finding_type,
          severity: sevFromCvss(score) || normSev(v.database_specific?.severity) || 'medium',
          title: clip(`${v.id} in ${p.name} ${p.version}`, 200),
          host: path || null,
          service: p.name || null,
          version: p.version || null,
          evidence: clip(v.summary || v.details, 240),
          cve: aliasCve,
          cvss_score: Number.isFinite(score) ? Number(score.toFixed?.(1) ?? score) : null,
          remediation: clip(fixedFromOsv(v, p), 300) || `Update ${p.name} to a non-vulnerable version (see ${v.id}).`,
          source: 'osv-scanner',
        });
      }
    }
  }
  return out;
}
function fixedFromOsv(v, p) {
  for (const aff of v.affected || []) {
    for (const r of aff.ranges || []) {
      const fixed = (r.events || []).map((e) => e.fixed).filter(Boolean);
      if (fixed.length) return `Upgrade ${p.name} to ${fixed.join(' / ')}.`;
    }
  }
  return '';
}
// OSV severity is often a CVSS vector string; approximate a base score band from the vector.
function cvssStringToScore(s) {
  const str = String(s || '');
  if (/^\d+(\.\d+)?$/.test(str)) return Number(str);
  // crude: count high-impact metrics in a CVSS vector to bucket it
  if (!/CVSS/i.test(str)) return NaN;
  let n = 4;
  if (/\/AV:N/i.test(str)) n += 2;
  if (/\/PR:N/i.test(str)) n += 1;
  if (/\/UI:N/i.test(str)) n += 0.5;
  if (/\/[CIA]:H/i.test(str)) n += 2;
  return Math.min(n, 10);
}

// Checkov: { results:{ failed_checks:[ {check_id,check_name,file_path,file_line_range,severity,guideline,resource} ] } }
// (checkov may emit an array of framework result-objects; handle both.)
export function parseCheckov(json) {
  const blocks = Array.isArray(json) ? json : [json];
  const out = [];
  for (const b of blocks) {
    const failed = b?.results?.failed_checks;
    if (!Array.isArray(failed)) continue;
    for (const c of failed) {
      out.push({
        finding_type: 'iac',
        severity: normSev(c.severity) === 'info' ? 'medium' : normSev(c.severity),
        title: clip(`${c.check_id} ${c.check_name}`, 200),
        host: loc(c.file_path, Array.isArray(c.file_line_range) ? c.file_line_range[0] : undefined) || null,
        service: c.resource || null,
        evidence: clip(c.check_name, 200),
        remediation: clip(c.guideline || 'See the check documentation for the secure configuration.', 300),
        source: 'checkov',
      });
    }
  }
  return out;
}

// npm audit --json: { vulnerabilities:{ name:{severity,via:[{title,url,cwe,cvss}],fixAvailable} } }
export function parseNpmAudit(json) {
  const vulns = json?.vulnerabilities;
  if (!vulns || typeof vulns !== 'object') return [];
  const out = [];
  for (const [name, v] of Object.entries(vulns)) {
    const via = [].concat(v.via || []).find((x) => typeof x === 'object') || {};
    out.push({
      finding_type: 'dependency',
      severity: normSev(v.severity),
      title: clip(`${via.title || 'Vulnerability'} in ${name}`, 200),
      service: name,
      version: v.range || null,
      evidence: clip(via.url, 200),
      cve: [].concat(via.cwe || []).find(Boolean) || null,
      cvss_score: via.cvss?.score ?? null,
      remediation: v.fixAvailable ? `Run \`npm audit fix\`${v.fixAvailable?.name ? ` (updates ${v.fixAvailable.name})` : ''}.` : 'No fix available yet; consider an alternative package.',
      source: 'npm-audit',
    });
  }
  return out;
}

// ---- license risk --------------------------------------------------------------------------
// Copyleft / network-copyleft / commercial-hostile licenses are risky to ship in a proprietary
// SaaS; permissive ones are fine. UNKNOWN is flagged for manual review.
const LICENSE_RISK = [
  { re: /\bAGPL/i, severity: 'critical', note: 'AGPL: network copyleft — using it in a SaaS can force you to open-source your whole service.' },
  { re: /\b(GPL-3|GPLv3|GPL-2|GPLv2|GPL\b)/i, severity: 'high', note: 'GPL: strong copyleft — derivative works must be GPL. Risky for proprietary distribution.' },
  { re: /\b(LGPL)/i, severity: 'medium', note: 'LGPL: weak copyleft — dynamic linking usually OK, static linking has obligations.' },
  { re: /\b(SSPL|BUSL|Business Source|Elastic-2|Commons Clause)/i, severity: 'high', note: 'Source-available / restricted license — commercial use may be prohibited.' },
  { re: /\b(MPL|EPL|CDDL)/i, severity: 'medium', note: 'File-level copyleft — modified files must be shared.' },
  { re: /\b(CC-BY-NC|NonCommercial|WTFPL|Beerware)/i, severity: 'medium', note: 'Non-standard/non-commercial terms — review before shipping.' },
  { re: /\b(MIT|BSD|Apache|ISC|Unlicense|Zlib|Python-2|PostgreSQL|CC0)/i, severity: 'info', note: 'Permissive — safe to use with attribution.' },
];
export function classifyLicense(name) {
  const s = String(name || '').trim();
  if (!s || /^unknown$/i.test(s) || s === 'NOASSERTION') {
    return { severity: 'low', note: 'License UNKNOWN — could not be detected; review manually before shipping.' };
  }
  for (const r of LICENSE_RISK) if (r.re.test(s)) return { severity: r.severity, note: r.note };
  return { severity: 'low', note: `Uncommon license "${s}" — review its terms.` };
}
function licenseFinding(name, pkg, severity, source, host, note) {
  const risk = note ? { severity, note } : classifyLicense(name);
  return {
    finding_type: 'license',
    severity: severity || risk.severity,
    title: clip(`License risk: ${name || 'UNKNOWN'}${pkg ? ' (' + pkg + ')' : ''}`, 200),
    host: host || null,
    service: pkg || null,
    evidence: clip(risk.note, 240),
    remediation: 'Confirm the license is compatible with your distribution model, or replace the dependency.',
    source: source || 'license',
  };
}

// Dedup by title+host and cap so a noisy scan can't flood the findings table.
export function dedupCap(items, cap = 200) {
  const seen = new Set();
  const out = [];
  for (const f of items) {
    if (!f || !f.title) continue;
    const k = `${f.title}|${f.host || ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
    if (out.length >= cap) break;
  }
  return out;
}
